use crate::ieee_802154::commands::{
    AssociationRequestDeviceType, Ieee802154AssociationRequestCommand,
    Ieee802154AssociationResponseCommand,
};
use crate::ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154AssociationStatus,
    Ieee802154CommandFrame, Ieee802154CommandId, Ieee802154CommandPayload, Ieee802154Frame,
    Ieee802154FrameControl, Ieee802154FrameHeader, Ieee802154FrameType,
};
use ieee_802154::FrameBytes;
use ieee_802154::types::{Eui64, Key, Nwk};
use zigbee::aps::frame::{
    APS_STATUS_SECURITY_FAIL, APS_STATUS_SUCCESS, ApsCommandFrame, ApsCommandFrameCommand,
    ApsCommandId, ApsConfirmKeyCommandFrame, ApsDeliveryMode, ApsFrameControl, ApsFrameType,
    ApsNetworkKeyDescriptor, ApsRequestKeyCommandFrame, ApsRequestKeyType, ApsStandardKeyType,
    ApsTransportKeyCommandFrame, ApsTransportKeyDescriptor, ApsTrustCenterLinkKeyDescriptor,
    ApsTunnelCommandFrame, ApsUpdateDeviceCommandFrame, ApsUpdateDeviceStatus,
    ApsVerifyKeyCommandFrame, EncryptedApsCommandFrame,
};
use zigbee::nwk::frame::{
    BROADCAST_RX_ON_WHEN_IDLE, NwkFrame, NwkFrameType, NwkSecurityHeaderKeyId,
};

use tokio::time::{Duration, Instant};
use zigbee::Command;
use zigbee::nwk::commands::{
    Nwk802154AssociationStatus, NwkCommandId, NwkEndDeviceTimeoutRequestCommand,
    NwkEndDeviceTimeoutResponseCommand, NwkEndDeviceTimeoutResponseStatus, NwkLeaveCommand,
    NwkNetworkStatus, NwkNetworkStatusCommand, NwkRejoinCapabilityInformationDeviceType,
    NwkRejoinRequestCommand, NwkRejoinResponseCommand,
};

use super::{
    MAX_LOCK_DURATION, NwkDeviceType, NwkSecurityMode, ZigbeeNotification, ZigbeeStack, neighbors,
};

impl ZigbeeStack {
    #[allow(clippy::significant_drop_tightening)]
    pub fn process_802154_association_request(
        &self,
        command_frame: &Ieee802154CommandFrame,
        request: &Ieee802154AssociationRequestCommand,
    ) {
        let source_eui64 = match command_frame.header.src_address {
            Some(Ieee802154Address::Eui64(eui64)) => eui64,
            _ => {
                tracing::warn!(
                    "Received association request with unexpected source address: {:?}",
                    command_frame.header.src_address
                );
                return;
            }
        };

        let permitting_joins = self.permitting_joins();

        // Spec 3.6.1.6.1.3: known devices may always re-attach; new children are
        // admitted only while capacity remains
        let (already_known, at_capacity) = {
            let core = self.state.core.try_lock_for(MAX_LOCK_DURATION).unwrap();

            (
                core.nib.neighbors.contains(source_eui64),
                core.nib.neighbors.child_count() >= usize::from(self.tunables.max_children),
            )
        };

        let denial_status = if !permitting_joins {
            Some(Ieee802154AssociationStatus::PanAccessDenied)
        } else if !already_known && at_capacity {
            Some(Ieee802154AssociationStatus::PanAtCapacity)
        } else {
            None
        };

        if let Some(status) = denial_status {
            tracing::info!("Denying association request from {source_eui64:?}: {status:?}");
            self.queue_association_response(source_eui64, Nwk(0xFFFF), status);
            return;
        }

        let short_address = self.allocate_network_address(source_eui64);
        tracing::info!("Device {source_eui64:?} is joining as {short_address:?}");

        self.begin_join(source_eui64);

        // Joiners retry association requests if they miss our response, so the address
        // and table entries must be stable across retries
        self.update_nwk_eui64_mapping(short_address, source_eui64);

        let device_type = match request.device_type {
            AssociationRequestDeviceType::FullFunctionDevice => NwkDeviceType::Router,
            AssociationRequestDeviceType::ReducedFunctionDevice => NwkDeviceType::EndDevice,
        };

        // Spec 3.6.10.5: end device children start with the default keepalive
        // timeout; router children are not aged
        let device_timeout = if device_type == NwkDeviceType::EndDevice {
            self.tunables.end_device_timeout_default.duration()
        } else {
            Duration::from_secs(0xFFFFFFFF)
        };

        self.state
            .core
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .nib
            .neighbors
            .upsert_child(
                neighbors::ChildDescriptor {
                    eui64: source_eui64,
                    network_address: short_address,
                    device_type,
                    rx_on_when_idle: request.receive_on_when_idle,
                    device_timeout,
                    relationship: neighbors::Relationship::Child,
                },
                Instant::now().into_std(),
            );

        // A new child deadline may precede everything the maintenance task knows
        self.maintenance_wake.notify_one();

        self.queue_association_response(
            source_eui64,
            short_address,
            Ieee802154AssociationStatus::AssociationSuccessful,
        );
    }

    /// 802.15.4 spec 6.4.1: association responses are sent indirectly. The joiner
    /// extracts the queued response by polling with a MAC Data Request; once the
    /// response is extracted and acknowledged, the network key follows.
    fn queue_association_response(
        &self,
        eui64: Eui64,
        short_address: Nwk,
        status: Ieee802154AssociationStatus,
    ) {
        // Joiners that miss the response retry the association request, so anything
        // still queued from the previous attempt is stale
        self.drop_indirect_transactions(Some(eui64), short_address);

        let response_frame = self.build_802154_association_response(eui64, short_address, status);

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            match arc_self
                .queue_indirect_frame(Ieee802154Address::Eui64(eui64), response_frame)
                .await
            {
                Ok(()) => {
                    // Zigbee spec 4.6.3.2: the network key is delivered once the
                    // device has confirmed receipt of its short address
                    if matches!(status, Ieee802154AssociationStatus::AssociationSuccessful) {
                        arc_self.send_network_key(short_address, eui64, true);
                    }
                }
                Err(err) => {
                    tracing::warn!("Association response to {eui64:?} was not extracted: {err}");
                }
            }
        });
    }

    /// Pick an unused random network address for a joining device, reusing the previous
    /// one if the device has joined before.
    fn allocate_network_address(&self, eui64: Eui64) -> Nwk {
        let core = self.state.core.try_lock_for(MAX_LOCK_DURATION).unwrap();

        core.nib.address_map.allocate(
            eui64,
            &core.nib.neighbors,
            std::iter::repeat_with(|| Nwk(rand::random::<u16>())),
        )
    }

    fn generate_unused_network_address(&self) -> Nwk {
        let core = self.state.core.try_lock_for(MAX_LOCK_DURATION).unwrap();

        core.nib.address_map.generate_unused(
            &core.nib.neighbors,
            std::iter::repeat_with(|| Nwk(rand::random::<u16>())),
        )
    }

    /// Spec 3.6.1.10.5: two devices use the same network address. The network is
    /// notified unless we learned of the conflict from such a notification; end
    /// device children are moved to a fresh address; routers resolve on their own.
    pub(super) fn handle_address_conflict(&self, address: Nwk, detected_locally: bool) {
        {
            let mut conflicts = self
                .state
                .address_conflicts
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            let now = Instant::now();
            let window = self.tunables.broadcast_delivery_time;

            // Detection re-triggers on every frame from the conflicted devices, so a
            // conflict is handled once per delivery window
            if let Some(conflict) = conflicts.get_mut(&address)
                && now < conflict.handled_at + window
            {
                conflict.heard_from_network |= !detected_locally;
                return;
            }

            conflicts.retain(|_, conflict| now < conflict.handled_at + 2 * window);
            conflicts.insert(
                address,
                super::AddressConflict {
                    handled_at: now,
                    heard_from_network: !detected_locally,
                },
            );
        }

        tracing::warn!("Address conflict detected on {address:?}");

        if detected_locally {
            self.broadcast_address_conflict(address);
        }

        if address == self.state.network_address {
            // A coordinator never changes its address (spec 3.6.1.10.5); the
            // notification tells the conflicting device to move
            tracing::error!("Another device is using our own network address");
            return;
        }

        if let Some(child_eui64) = self.end_device_child_eui64(address) {
            self.reassign_child_address(child_eui64, address);
            return;
        }

        // Routers resolve their own conflicts after hearing the notification; our
        // mapping for the address is ambiguous until the keeper re-announces
        let mut core = self.state.core.try_lock_for(MAX_LOCK_DURATION).unwrap();
        core.nib.address_map.forget_address(address);
        core.nib.routing.remove_route(address);
    }

    /// Spec 3.6.1.10.5: notify the network of an address conflict with a jittered
    /// Network Status broadcast, cancelled when another device reports it first.
    fn broadcast_address_conflict(&self, address: Nwk) {
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            tokio::time::sleep(
                arc_self
                    .tunables
                    .max_broadcast_jitter
                    .mul_f32(rand::random::<f32>()),
            )
            .await;

            let heard_from_network = arc_self
                .state
                .address_conflicts
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .get(&address)
                .is_some_and(|conflict| conflict.heard_from_network);

            if heard_from_network {
                tracing::debug!(
                    "Address conflict on {address:?} was already reported, not rebroadcasting"
                );
                return;
            }

            let conflict_frame = arc_self.nwk_command_frame(
                BROADCAST_RX_ON_WHEN_IDLE,
                NwkNetworkStatusCommand {
                    status_code: NwkNetworkStatus::AddressConflict,
                    network_address: address,
                }
                .serialize()
                .unwrap(),
            );

            arc_self.background_send_nwk_frame(conflict_frame, NwkSecurityMode::NetworkKey, false);
        });
    }

    /// Spec 3.6.1.10.5: pick a new address for an end device child caught in an
    /// address conflict, delivered with an unsolicited, encrypted rejoin response
    /// (indirectly for a sleepy child, so it arrives on its next keepalive poll).
    /// All local state keeps the old address until the child confirms the change
    /// with a device announcement.
    fn reassign_child_address(&self, eui64: Eui64, old_address: Nwk) {
        let new_address = self.generate_unused_network_address();

        tracing::warn!(
            "Moving end device child {eui64:?} away from conflicted {old_address:?} to {new_address:?}"
        );

        self.send_rejoin_response(
            old_address,
            eui64,
            new_address,
            Nwk802154AssociationStatus::AssociationSuccessful,
            true,
        );
    }

    fn build_802154_association_response<P>(
        &self,
        destination_eui64: Eui64,
        short_address: Nwk,
        association_status: Ieee802154AssociationStatus,
    ) -> Ieee802154Frame<P> {
        let (sequence_number, pan_id) = {
            let core = self.state.core.try_lock_for(MAX_LOCK_DURATION).unwrap();
            (core.mac.ieee802154_sequence_number, core.mac.pan_id)
        };

        Ieee802154Frame::Command(Ieee802154CommandFrame {
            header: Ieee802154FrameHeader {
                frame_control: Ieee802154FrameControl {
                    frame_type: Ieee802154FrameType::Command,
                    security_enabled: false,
                    frame_pending: false,
                    ack_request: true,
                    pan_id_compression: true,
                    reserved1: false,
                    sequence_number_suppression: false,
                    information_elements_present: false,
                    dest_addr_mode: Ieee802154AddressingMode::Long,
                    frame_version: 0,
                    src_addr_mode: Ieee802154AddressingMode::Long,
                },
                sequence_number: Some(sequence_number),
                src_address: Some(Ieee802154Address::Eui64(self.state.ieee_address)),
                dest_address: Some(Ieee802154Address::Eui64(destination_eui64)),
                src_pan_id: None,
                dest_pan_id: Some(pan_id),
            },
            command_id: Ieee802154CommandId::AssociationResponse,
            command_payload: Ieee802154CommandPayload::AssociationResponse(
                Ieee802154AssociationResponseCommand {
                    short_address,
                    association_status,
                },
            ),
            fcs: 0x0000,
        })
    }

    pub(super) fn is_neighbor(&self, nwk: Nwk) -> bool {
        self.state
            .core
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .nib
            .neighbors
            .has_network_address(nwk)
    }

    /// Register an install-code-derived link key for a device expected to join:
    /// an `apsDeviceKeyPairSet` entry with `PROVISIONAL_KEY` attributes that
    /// replaces the well-known key for that device's network key delivery.
    pub fn set_provisional_key(&self, ieee: Eui64, key: Key) {
        tracing::info!("Registered provisional link key for {ieee:?}");

        self.state
            .core
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .aib
            .aps_security
            .set_provisional_key(ieee, key);
    }

    /// Reset a joining device's link key state. The provisional key kept in effect,
    /// if any, is sent to the client so the device survives a stack restart.
    fn begin_join(&self, ieee: Eui64) {
        let provisional_key = self
            .state
            .core
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .aib
            .aps_security
            .begin_join(ieee);

        if let Some(key) = provisional_key {
            tracing::info!("Device {ieee:?} is joining with its provisional link key");

            let _ = self
                .notification_tx
                .send(ZigbeeNotification::LinkKeyUpdate { ieee, key });
        }
    }

    /// Build the APS Transport Key command that delivers the network key to a device,
    /// encrypted with the key-transport key derived from the device's link key. A
    /// factory-new joiner only knows the well-known key (or its provisional
    /// install-code key), while a rejoining device holds whatever key it was last
    /// issued — possibly derived from a TCLK seed by the network's previous owner.
    fn build_encrypted_network_key_transport(
        &self,
        destination_eui64: Eui64,
        fresh_join: bool,
    ) -> EncryptedApsCommandFrame {
        let (network_key, key_seq_number) = {
            let core = self.state.core.try_lock_for(MAX_LOCK_DURATION).unwrap();

            (
                core.nib.nwk_security.network_key(),
                core.nib.nwk_security.key_seq_number(),
            )
        };

        let transport_key_command = ApsCommandFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Command,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved1: 0b0,
                security: true,
                ack_request: false,
                extended_header: false,
            },
            counter: self.next_aps_counter(),
            command_id: ApsCommandId::TransportKey,
            command: ApsCommandFrameCommand::TransportKey(ApsTransportKeyCommandFrame {
                standard_key_type: ApsStandardKeyType::StandardNetworkKey,
                key_descriptor: ApsTransportKeyDescriptor::NetworkKey(ApsNetworkKeyDescriptor {
                    key: network_key,
                    sequence_number: key_seq_number,
                    destination_address: destination_eui64,
                    source_address: self.state.ieee_address,
                }),
            }),
        };

        let mut core = self.state.core.try_lock_for(MAX_LOCK_DURATION).unwrap();

        let link_key = if fresh_join {
            core.aib.aps_security.join_link_key(destination_eui64)
        } else {
            core.aib.aps_security.device_link_key(destination_eui64)
        };

        core.aib.aps_security.encrypt_command_with_link_key(
            &link_key,
            NwkSecurityHeaderKeyId::KeyTransportKey,
            &transport_key_command,
        )
    }

    /// Zigbee spec 4.6.3.2: deliver the network key to a joining device. The NWK frame
    /// is unsecured; the APS command is encrypted with the key-transport key derived
    /// from the joiner's link key.
    fn send_network_key(&self, destination: Nwk, destination_eui64: Eui64, fresh_join: bool) {
        let encrypted_command =
            self.build_encrypted_network_key_transport(destination_eui64, fresh_join);

        let nwk_frame = self
            .nwk_data_frame(destination, encrypted_command.to_bytes())
            .unsecured();

        self.background_send_nwk_frame(nwk_frame, NwkSecurityMode::Unsecured, true);

        let _ = self.notification_tx.send(ZigbeeNotification::DeviceJoined {
            nwk: destination,
            ieee: destination_eui64,
            parent: self.state.network_address,
        });
    }

    pub fn handle_encrypted_aps_command_frame(
        &self,
        nwk_frame: &NwkFrame,
        encrypted_command_frame: &EncryptedApsCommandFrame,
    ) {
        let Some(extended_source) = encrypted_command_frame.aux_header.extended_source else {
            tracing::warn!("APS command frames without an extended nonce are not supported");
            return;
        };

        let mut core = self.state.core.try_lock_for(MAX_LOCK_DURATION).unwrap();
        let network_key = core.nib.nwk_security.network_key();

        let decrypted = core.aib.aps_security.decrypt_command(
            extended_source,
            encrypted_command_frame,
            &network_key,
        );
        drop(core);

        match decrypted {
            Some(command_frame) => {
                tracing::debug!("Decrypted APS command frame: {command_frame:?}");
                self.handle_aps_command_frame(nwk_frame, &command_frame, Some(extended_source));
            }
            None => {
                tracing::warn!(
                    "Failed to decrypt APS command frame from {:?} (EUI {:?})",
                    nwk_frame.nwk_header.source,
                    extended_source
                );
                let _ = self
                    .notification_tx
                    .send(ZigbeeNotification::ApsDecryptionFailure {
                        source: nwk_frame.nwk_header.source,
                        source_ieee: extended_source,
                        frame_counter: encrypted_command_frame.aux_header.frame_counter,
                        key_id: format!(
                            "{:?}",
                            encrypted_command_frame.aux_header.security_control.key_id
                        ),
                    });
            }
        }
    }

    pub fn handle_aps_command_frame(
        &self,
        nwk_frame: &NwkFrame,
        command_frame: &ApsCommandFrame,
        aps_source_ieee: Option<Eui64>,
    ) {
        let source = nwk_frame.nwk_header.source;

        match &command_frame.command {
            ApsCommandFrameCommand::TransportKey(cmd) => {
                tracing::warn!("Ignoring transport key from {source:?}: {cmd:?}");
            }
            ApsCommandFrameCommand::UpdateDevice(cmd) => {
                self.handle_update_device(nwk_frame, cmd);
            }
            ApsCommandFrameCommand::RemoveDevice(cmd) => {
                tracing::warn!("Remove device from {source:?} is not yet handled: {cmd:?}");
            }
            ApsCommandFrameCommand::RequestKey(cmd) => {
                self.handle_request_key(nwk_frame, command_frame, cmd, aps_source_ieee);
            }
            ApsCommandFrameCommand::SwitchKey(cmd) => {
                tracing::warn!("Ignoring switch key from {source:?}: {cmd:?}");
            }
            ApsCommandFrameCommand::Tunnel(cmd) => {
                tracing::warn!("Tunnel command from {source:?} is not yet handled: {cmd:?}");
            }
            ApsCommandFrameCommand::VerifyKey(cmd) => {
                self.handle_verify_key(nwk_frame, cmd);
            }
            ApsCommandFrameCommand::ConfirmKey(cmd) => {
                tracing::warn!("Ignoring confirm key from {source:?}: {cmd:?}");
            }
        }
    }

    /// Send a serialized APS frame to an on-network device, with NWK security. Direct
    /// children do not participate in route discovery, so they are addressed directly.
    fn send_secured_aps_payload(&self, destination: Nwk, payload: Vec<u8>) {
        let nwk_frame = self.nwk_data_frame(destination, payload);

        self.background_send_nwk_frame(
            nwk_frame,
            NwkSecurityMode::NetworkKey,
            self.is_neighbor(destination),
        );
    }

    /// Zigbee spec 4.7.3.8: a device requests a unique trust center link key to replace
    /// the well-known key it joined with. The new key is delivered encrypted with the
    /// key-load key derived from the device's current link key.
    fn handle_request_key(
        &self,
        nwk_frame: &NwkFrame,
        command_frame: &ApsCommandFrame,
        request: &ApsRequestKeyCommandFrame,
        aps_source_ieee: Option<Eui64>,
    ) {
        if request.key_type != ApsRequestKeyType::TrustCenterLinkKey {
            tracing::warn!(
                "Application link keys are not supported, ignoring request: {request:?}"
            );
            return;
        }

        // The spec mandates that request key commands be APS encrypted
        if !command_frame.frame_control.security {
            tracing::warn!(
                "Ignoring unencrypted request key command from {:?}",
                nwk_frame.nwk_header.source
            );
            return;
        }

        let Some(source_ieee) = aps_source_ieee else {
            tracing::warn!("Request key command has no extended source, ignoring");
            return;
        };

        tracing::info!("Sending a new trust center link key to {source_ieee:?}");

        // The new key is delivered encrypted with the key it replaces
        let mut core = self.state.core.try_lock_for(MAX_LOCK_DURATION).unwrap();
        let current_key = core.aib.aps_security.device_link_key(source_ieee);
        let new_key = core
            .aib
            .aps_security
            .issue_device_key(source_ieee, Key(rand::random()));
        drop(core);

        // The key must be persisted by the client: a device that completed a key
        // exchange expects its unique key even after we restart
        let _ = self
            .notification_tx
            .send(ZigbeeNotification::LinkKeyUpdate {
                ieee: source_ieee,
                key: new_key.clone(),
            });

        let transport_key_command = ApsCommandFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Command,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved1: 0b0,
                security: true,
                ack_request: false,
                extended_header: false,
            },
            counter: self.next_aps_counter(),
            command_id: ApsCommandId::TransportKey,
            command: ApsCommandFrameCommand::TransportKey(ApsTransportKeyCommandFrame {
                standard_key_type: ApsStandardKeyType::TrustCenterLinkKey,
                key_descriptor: ApsTransportKeyDescriptor::TrustCenterLinkKey(
                    ApsTrustCenterLinkKeyDescriptor {
                        key: new_key,
                        destination_address: source_ieee,
                        source_address: self.state.ieee_address,
                    },
                ),
            }),
        };

        let encrypted_command = self
            .state
            .core
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .aib
            .aps_security
            .encrypt_command_with_link_key(
                &current_key,
                NwkSecurityHeaderKeyId::KeyLoadKey,
                &transport_key_command,
            );

        self.send_secured_aps_payload(nwk_frame.nwk_header.source, encrypted_command.to_bytes());
    }

    /// Zigbee spec 4.4.8.1: a device proves possession of its new link key by sending a
    /// keyed hash of it, which we acknowledge with a Confirm-Key command.
    fn handle_verify_key(&self, nwk_frame: &NwkFrame, verify: &ApsVerifyKeyCommandFrame) {
        if verify.standard_key_type != ApsStandardKeyType::TrustCenterLinkKey {
            tracing::warn!("Ignoring verify key for unsupported key type: {verify:?}");
            return;
        }

        let source_ieee = verify.source_address;

        let verified = self
            .state
            .core
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .aib
            .aps_security
            .verify_device_key(source_ieee, &verify.initiator_verify_key_hash.0);

        let status = match verified {
            None => {
                tracing::warn!("Verify key from {source_ieee:?} without a stored link key");
                // Spec 4.4.8.1.3: failures for unknown devices are sent unencrypted
                self.send_confirm_key(
                    nwk_frame.nwk_header.source,
                    source_ieee,
                    APS_STATUS_SECURITY_FAIL,
                    false,
                );
                return;
            }
            Some(true) => {
                tracing::info!("Device {source_ieee:?} verified its trust center link key");
                APS_STATUS_SUCCESS
            }
            Some(false) => {
                tracing::warn!("Verify key hash mismatch for {source_ieee:?}");
                APS_STATUS_SECURITY_FAIL
            }
        };

        self.send_confirm_key(nwk_frame.nwk_header.source, source_ieee, status, true);
    }

    fn send_confirm_key(
        &self,
        destination: Nwk,
        destination_eui64: Eui64,
        status: u8,
        encrypted: bool,
    ) {
        let confirm_key_command = ApsCommandFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Command,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved1: 0b0,
                security: encrypted,
                ack_request: false,
                extended_header: false,
            },
            counter: self.next_aps_counter(),
            command_id: ApsCommandId::ConfirmKey,
            command: ApsCommandFrameCommand::ConfirmKey(ApsConfirmKeyCommandFrame {
                status,
                standard_key_type: ApsStandardKeyType::TrustCenterLinkKey,
                destination_address: destination_eui64,
            }),
        };

        let payload = if encrypted {
            // Confirm key commands are APS encrypted with the link key itself, i.e. the
            // "data key" (spec 4.4.1.3)
            self.state
                .core
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .aib
                .aps_security
                .encrypt_command(
                    destination_eui64,
                    NwkSecurityHeaderKeyId::DataKey,
                    &confirm_key_command,
                )
                .to_bytes()
        } else {
            confirm_key_command.to_bytes()
        };

        self.send_secured_aps_payload(destination, payload);
    }

    /// Zigbee spec 4.6.3.2.2: a router notifies us that a device joined (or rejoined)
    /// through it. For unsecured joins, the network key is delivered through the router
    /// via a Tunnel command.
    fn handle_update_device(&self, nwk_frame: &NwkFrame, update: &ApsUpdateDeviceCommandFrame) {
        let router_nwk = nwk_frame.nwk_header.source;

        tracing::info!(
            "Device {:?} ({:?}) update from router {router_nwk:?}: {:?}",
            update.device_address,
            update.device_short_address,
            update.status
        );

        // A join or rejoin through a router is authoritative evidence the device is
        // no longer our child: a stale child entry would keep hijacking its unicasts
        // into our indirect queue
        if !matches!(update.status, ApsUpdateDeviceStatus::DeviceLeft) {
            self.forget_moved_child(update.device_address, router_nwk);
        }

        match update.status {
            ApsUpdateDeviceStatus::StandardDeviceUnsecuredJoin => {
                self.begin_join(update.device_address);

                self.update_nwk_eui64_mapping(update.device_short_address, update.device_address);
                self.send_tunneled_network_key(router_nwk, update.device_address, true);

                let _ = self.notification_tx.send(ZigbeeNotification::DeviceJoined {
                    nwk: update.device_short_address,
                    ieee: update.device_address,
                    parent: router_nwk,
                });
            }
            ApsUpdateDeviceStatus::StandardDeviceTrustCenterRejoin => {
                // The spec requires a unique link key for trust center rejoins, but
                // devices that never completed a key exchange are still let in with the
                // well-known key for compatibility
                if !self
                    .state
                    .core
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .aib
                    .aps_security
                    .has_unique_link_key(update.device_address)
                {
                    tracing::warn!(
                        "Trust center rejoin from {:?} without a unique link key",
                        update.device_address
                    );
                }

                self.update_nwk_eui64_mapping(update.device_short_address, update.device_address);
                self.send_tunneled_network_key(router_nwk, update.device_address, false);

                let _ = self.notification_tx.send(ZigbeeNotification::DeviceJoined {
                    nwk: update.device_short_address,
                    ieee: update.device_address,
                    parent: router_nwk,
                });
            }
            ApsUpdateDeviceStatus::StandardDeviceSecuredRejoin => {
                self.update_nwk_eui64_mapping(update.device_short_address, update.device_address);

                let _ = self.notification_tx.send(ZigbeeNotification::DeviceJoined {
                    nwk: update.device_short_address,
                    ieee: update.device_address,
                    parent: router_nwk,
                });
            }
            ApsUpdateDeviceStatus::DeviceLeft => {
                // Spec 4.4.3.2.3: informative only, no action is taken beyond
                // notifying the client
                let _ = self.notification_tx.send(ZigbeeNotification::DeviceLeft {
                    nwk: update.device_short_address,
                    ieee: Some(update.device_address),
                });
            }
        }
    }

    /// Zigbee spec 4.6.3.7: wrap an APS-encrypted Transport Key command in a Tunnel
    /// command so a parent router can forward it to a joiner we cannot reach directly.
    fn send_tunneled_network_key(&self, router_nwk: Nwk, device_eui64: Eui64, fresh_join: bool) {
        let encrypted_transport_key =
            self.build_encrypted_network_key_transport(device_eui64, fresh_join);

        let tunnel_command = ApsCommandFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Command,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved1: 0b0,
                // Tunnel commands themselves are never APS encrypted (spec 4.4.1.3)
                security: false,
                ack_request: false,
                extended_header: false,
            },
            counter: self.next_aps_counter(),
            command_id: ApsCommandId::Tunnel,
            command: ApsCommandFrameCommand::Tunnel(ApsTunnelCommandFrame {
                destination_address: device_eui64,
                tunneled_frame: FrameBytes::from_slice(&encrypted_transport_key.to_bytes())
                    .expect("an encrypted APS command is frame-bounded"),
            }),
        };

        self.send_secured_aps_payload(router_nwk, tunnel_command.to_bytes());
    }

    /// Process the rare NWK frames that arrive without encryption. The only one we
    /// accept is a trust center rejoin request from a device that lost the network key.
    pub(super) fn handle_unsecured_nwk_frame(&self, nwk_frame: &NwkFrame) {
        if nwk_frame.nwk_header.frame_control.frame_type != NwkFrameType::Command {
            tracing::debug!("Ignoring unencrypted non-command NWK frame");
            return;
        }

        if nwk_frame.payload.is_empty() {
            tracing::warn!("Ignoring unencrypted NWK command frame with an empty payload");
            return;
        }

        match NwkCommandId::try_from(nwk_frame.payload[0]) {
            Ok(NwkCommandId::RejoinRequest) => {
                self.handle_rejoin_request(nwk_frame, false);
            }
            _ => {
                tracing::debug!("Ignoring unencrypted NWK command: {}", nwk_frame.payload[0]);
            }
        }
    }

    /// Zigbee spec 3.6.1.4.2: a previously joined device re-attaches to us, either
    /// securely (it still has the network key) or via an unsecured trust center rejoin.
    #[allow(clippy::significant_drop_tightening)]
    pub(super) fn handle_rejoin_request(&self, nwk_frame: &NwkFrame, secured: bool) {
        let rejoin_request = match NwkRejoinRequestCommand::deserialize(&nwk_frame.payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                tracing::warn!("Error parsing rejoin request command: {e:?}");
                return;
            }
        };

        tracing::info!("Rejoin request (secured: {secured}): {rejoin_request:#?}");

        let Some(source_ieee) = nwk_frame.nwk_header.source_ieee else {
            tracing::warn!("Rejoin request source EUI64 is missing");
            return;
        };

        let requested_nwk = nwk_frame.nwk_header.source;
        let capability = &rejoin_request.capability_information;

        // Spec 3.6.1.6.1.3: known devices may always re-attach; new children are
        // admitted only while capacity remains
        let (already_known, at_capacity) = {
            let core = self.state.core.try_lock_for(MAX_LOCK_DURATION).unwrap();

            (
                core.nib.neighbors.contains(source_ieee),
                core.nib.neighbors.child_count() >= usize::from(self.tunables.max_children),
            )
        };

        if !already_known && at_capacity {
            tracing::info!("Denying rejoin request from {source_ieee:?}, no child capacity left");
            self.send_rejoin_response(
                requested_nwk,
                source_ieee,
                Nwk(0xFFFF),
                Nwk802154AssociationStatus::PanAtCapacity,
                secured,
            );
            return;
        }

        // The device keeps its requested address unless it collides with another device
        let conflict = self
            .state
            .core
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .nib
            .address_map
            .claimed_by_other(requested_nwk, source_ieee);

        let assigned_nwk = if conflict {
            self.allocate_network_address(source_ieee)
        } else {
            requested_nwk
        };

        tracing::info!("Device {source_ieee:?} is rejoining as {assigned_nwk:?}");

        self.update_nwk_eui64_mapping(assigned_nwk, source_ieee);

        let device_type = match capability.device_type {
            NwkRejoinCapabilityInformationDeviceType::Router => NwkDeviceType::Router,
            NwkRejoinCapabilityInformationDeviceType::EndDevice => NwkDeviceType::EndDevice,
        };

        // Spec 3.6.10.5: end device children start with the default keepalive
        // timeout; router children are not aged
        let device_timeout = if device_type == NwkDeviceType::EndDevice {
            self.tunables.end_device_timeout_default.duration()
        } else {
            Duration::from_secs(0xFFFFFFFF)
        };

        self.state
            .core
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .nib
            .neighbors
            .upsert_child(
                neighbors::ChildDescriptor {
                    eui64: source_ieee,
                    network_address: assigned_nwk,
                    device_type,
                    rx_on_when_idle: capability.receiver_on_when_idle,
                    device_timeout,
                    // An unsecured rejoin is unauthenticated until the network key
                    // is delivered
                    relationship: if secured {
                        neighbors::Relationship::Child
                    } else {
                        neighbors::Relationship::UnauthenticatedChild
                    },
                },
                Instant::now().into_std(),
            );

        // A new child deadline may precede everything the maintenance task knows
        self.maintenance_wake.notify_one();

        self.send_rejoin_response(
            requested_nwk,
            source_ieee,
            assigned_nwk,
            Nwk802154AssociationStatus::AssociationSuccessful,
            secured,
        );

        // A trust center rejoin means the device no longer has the network key
        if !secured {
            // `send_network_key` also emits the join notification
            self.send_network_key(assigned_nwk, source_ieee, false);
        } else {
            let _ = self.notification_tx.send(ZigbeeNotification::DeviceJoined {
                nwk: assigned_nwk,
                ieee: source_ieee,
                parent: self.state.network_address,
            });
        }
    }

    /// Zigbee spec 3.4.7: the response is secured exactly like the request it answers,
    /// and is sent to the address the device used in its request.
    fn send_rejoin_response(
        &self,
        destination: Nwk,
        destination_ieee: Eui64,
        assigned: Nwk,
        status: Nwk802154AssociationStatus,
        secured: bool,
    ) {
        let mut response_frame = self
            .nwk_command_frame(
                destination,
                NwkRejoinResponseCommand {
                    network_address: assigned,
                    rejoin_status: status,
                }
                .serialize()
                .unwrap(),
            )
            .with_radius(1)
            .with_destination_ieee(Some(destination_ieee));

        let security = if secured {
            NwkSecurityMode::NetworkKey
        } else {
            response_frame = response_frame.unsecured();
            NwkSecurityMode::Unsecured
        };

        // The rejoining device is within radio range
        self.background_send_nwk_frame(response_frame, security, true);
    }

    /// Zigbee spec 3.6.1.10.3: a device announces that it is leaving the network, or
    /// asks us to leave (which a coordinator ignores).
    pub(super) fn handle_leave(&self, nwk_frame: &NwkFrame) {
        let leave_cmd = match NwkLeaveCommand::deserialize(&nwk_frame.payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                tracing::warn!("Error parsing leave command: {e:?}");
                return;
            }
        };

        let source = nwk_frame.nwk_header.source;

        if leave_cmd.request {
            // Spec 3.6.1.10.3.1: coordinators drop leave requests
            tracing::warn!("Ignoring leave request from {source:?}: {leave_cmd:?}");
            return;
        }

        tracing::info!(
            "Device {source:?} is leaving the network (rejoin: {})",
            leave_cmd.rejoin
        );

        let source_ieee = nwk_frame.nwk_header.source_ieee.or_else(|| {
            self.state
                .core
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .nib
                .address_map
                .eui64_for(source)
        });

        if let Some(source_ieee) = source_ieee {
            self.state
                .core
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .nib
                .neighbors
                .remove(source_ieee);
        }

        // The address map entry and any negotiated link key are kept around so that the
        // device can rejoin later
        self.drop_indirect_transactions(source_ieee, source);
        self.state
            .core
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .nib
            .routing
            .remove_route(source);

        let _ = self.notification_tx.send(ZigbeeNotification::DeviceLeft {
            nwk: source,
            ieee: source_ieee,
        });
    }

    /// Spec 3.6.10.2: an end device child negotiates its keepalive timeout. The
    /// response tells the device which keepalive method to use.
    pub(super) fn handle_end_device_timeout_request(&self, nwk_frame: &NwkFrame) {
        let source = nwk_frame.nwk_header.source;

        let request = match NwkEndDeviceTimeoutRequestCommand::deserialize(&nwk_frame.payload) {
            Ok(request) => request,
            Err(e) => {
                // An out-of-range timeout enumeration fails deserialization
                tracing::warn!("Invalid end device timeout request from {source:?}: {e:?}");
                self.send_end_device_timeout_response(
                    source,
                    NwkEndDeviceTimeoutResponseStatus::IncorrectValue,
                );
                return;
            }
        };

        // No end device configuration bits are defined yet, so any requested feature
        // is unknown and rejected
        if request.end_device_configuration != 0 {
            tracing::warn!(
                "End device timeout request from {source:?} with unsupported configuration: {:#04x}",
                request.end_device_configuration
            );
            self.send_end_device_timeout_response(
                source,
                NwkEndDeviceTimeoutResponseStatus::UnsupportedFeature,
            );
            return;
        }

        let timeout = request.request_timeout_enum.duration();

        let updated = self
            .state
            .core
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .nib
            .neighbors
            .set_child_timeout(
                source,
                timeout,
                u16::from(request.end_device_configuration),
                Instant::now().into_std(),
            );

        // Requests from devices that are not our end device children are dropped
        if !updated {
            tracing::warn!("Ignoring end device timeout request from non-child {source:?}");
            return;
        }

        tracing::debug!("Child {source:?} negotiated an end device timeout of {timeout:?}");

        // A renegotiated timeout may move the child's deadline closer
        self.maintenance_wake.notify_one();

        self.send_end_device_timeout_response(source, NwkEndDeviceTimeoutResponseStatus::Success);
    }

    fn send_end_device_timeout_response(
        &self,
        destination: Nwk,
        status: NwkEndDeviceTimeoutResponseStatus,
    ) {
        let parent_information = self.state.parent_information;

        let response_frame = self
            .nwk_command_frame(
                destination,
                NwkEndDeviceTimeoutResponseCommand {
                    status,
                    mac_data_poll_keepalive_supported: parent_information.mac_data_poll_keepalive,
                    end_device_timeout_request_keepalive_supported: parent_information
                        .end_device_timeout_request_keepalive,
                    power_negotation_support: parent_information.power_negotiation,
                }
                .serialize()
                .unwrap(),
            )
            .with_radius(1);

        // The child is a direct neighbor; responses to sleepy children go through the
        // indirect queue via the NWK unicast fork
        self.background_send_nwk_frame(response_frame, NwkSecurityMode::NetworkKey, true);
    }

    pub fn permit_joins(&self, duration: u64) {
        let deadline = if duration == 0 {
            tracing::info!("Permitting joins disabled");
            None
        } else {
            tracing::info!("Permitting joins for {duration} seconds");
            Some(Instant::now() + Duration::from_secs(duration))
        };

        self.state
            .core
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .permitting_joins_until = deadline;
    }

    /// Whether joins are permitted right now.
    pub(super) fn permitting_joins(&self) -> bool {
        self.state
            .core
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .permitting_joins_until
            .is_some_and(|deadline| deadline > Instant::now())
    }
}
