use crate::runtime::Runtime;
use crate::ziggurat_ieee_802154::commands::{
    AssociationRequestDeviceType, Ieee802154AssociationRequestCommand,
    Ieee802154AssociationResponseCommand,
};
use crate::ziggurat_ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154AssociationStatus,
    Ieee802154CommandFrame, Ieee802154CommandPayload, Ieee802154Frame, Ieee802154FrameControl,
    Ieee802154FrameHeader, Ieee802154FrameType,
};
use ziggurat_ieee_802154::FrameBytes;
use ziggurat_ieee_802154::types::{Eui64, Key, Nwk};
use ziggurat_zigbee::aps::frame::{
    APS_STATUS_SECURITY_FAIL, APS_STATUS_SUCCESS, ApsCommandFrame, ApsCommandFrameCommand,
    ApsConfirmKeyCommandFrame, ApsDeliveryMode, ApsFrameControl, ApsFrameType,
    ApsNetworkKeyDescriptor, ApsRequestKeyCommandFrame, ApsRequestKeyType, ApsStandardKeyType,
    ApsTransportKeyCommandFrame, ApsTransportKeyDescriptor, ApsTrustCenterLinkKeyDescriptor,
    ApsTunnelCommandFrame, ApsUpdateDeviceCommandFrame, ApsUpdateDeviceStatus,
    ApsVerifyKeyCommandFrame, EncryptedApsCommandFrame,
};
use ziggurat_zigbee::nwk::frame::{
    BROADCAST_RX_ON_WHEN_IDLE, NwkFrame, NwkPayload, NwkRouteDiscovery, NwkSecurityHeaderKeyId,
};

use std::time::Duration;
use ziggurat_zigbee::nwk::commands::{
    Nwk802154AssociationStatus, NwkCommand, NwkEndDeviceTimeoutRequestCommand,
    NwkEndDeviceTimeoutResponseCommand, NwkEndDeviceTimeoutResponseStatus, NwkLeaveCommand,
    NwkNetworkStatus, NwkNetworkStatusCommand, NwkRejoinCapabilityInformationDeviceType,
    NwkRejoinRequestCommand, NwkRejoinResponseCommand,
};

use super::{
    AddrConflictSource, DeviceLeaveReason, JoinKind, LOCK_ACQUIRE_TIMEOUT, NwkDeviceType,
    NwkSecurityMode, RadioPhy, SendMode, TxPriority, ZigbeeNotification, ZigbeeStack, neighbors,
};

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
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
            let core = self.core();

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

        self.core().nib.neighbors.upsert_child(
            neighbors::ChildDescriptor {
                eui64: source_eui64,
                network_address: short_address,
                device_type,
                rx_on_when_idle: request.receive_on_when_idle,
                device_timeout,
                relationship: neighbors::Relationship::Child,
            },
            self.core_now(),
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
                        arc_self.send_network_key(short_address, eui64, JoinKind::New);
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
        let core = self.core();

        core.nib.address_map.allocate(
            eui64,
            &core.nib.neighbors,
            std::iter::repeat_with(|| Nwk(rand::random::<u16>())),
        )
    }

    fn generate_unused_network_address(&self) -> Nwk {
        let core = self.core();

        core.nib.address_map.generate_unused(
            &core.nib.neighbors,
            std::iter::repeat_with(|| Nwk(rand::random::<u16>())),
        )
    }

    /// Spec 3.6.1.10.5: two devices use the same network address. The network is
    /// notified unless we learned of the conflict from such a notification; end
    /// device children are moved to a fresh address; routers resolve on their own.
    pub(super) fn handle_address_conflict(&self, address: Nwk, source: AddrConflictSource) {
        {
            let mut conflicts = self
                .state
                .address_conflicts
                .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
                .unwrap();

            let now = self.core_now();
            let window = self.tunables.broadcast_delivery_time;

            // Detection re-triggers on every frame from the conflicted devices, so a
            // conflict is handled once per delivery window
            if let Some(conflict) = conflicts.get_mut(&address)
                && now < conflict.handled_at + window
            {
                conflict.heard_from_network |= source == AddrConflictSource::Network;
                return;
            }

            conflicts.retain(|_, conflict| now < conflict.handled_at + 2 * window);
            conflicts.insert(
                address,
                super::AddressConflict {
                    handled_at: now,
                    heard_from_network: source == AddrConflictSource::Network,
                },
            );
        }

        tracing::warn!("Address conflict detected on {address:?}");

        if source == AddrConflictSource::Local {
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
        let mut core = self.core();
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
            R::sleep(
                arc_self
                    .tunables
                    .max_broadcast_jitter
                    .mul_f32(rand::random::<f32>()),
            )
            .await;

            let heard_from_network = arc_self
                .state
                .address_conflicts
                .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
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
                NwkCommand::NetworkStatus(NwkNetworkStatusCommand {
                    status_code: NwkNetworkStatus::AddressConflict,
                    network_address: address,
                }),
            );

            // The retransmit reactor owns the rebroadcasts; this task only applies the
            // jittered delay and the cancel-if-already-reported check above.
            arc_self.send_broadcast_nwk_frame(
                conflict_frame,
                NwkSecurityMode::NetworkKey,
                TxPriority::USER_NORMAL,
            );
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

    fn build_802154_association_response<Payload>(
        &self,
        destination_eui64: Eui64,
        short_address: Nwk,
        association_status: Ieee802154AssociationStatus,
    ) -> Ieee802154Frame<Payload> {
        let (sequence_number, pan_id) = {
            let core = self.core();
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
        self.core().nib.neighbors.has_network_address(nwk)
    }

    /// Register an install-code-derived link key for a device expected to join:
    /// an `apsDeviceKeyPairSet` entry with `PROVISIONAL_KEY` attributes that
    /// replaces the well-known key for that device's network key delivery.
    pub fn set_provisional_key(&self, ieee: Eui64, key: Key) {
        tracing::info!("Registered provisional link key for {ieee:?}");

        self.core().aib.aps_security.set_provisional_key(ieee, key);
    }

    /// Reset a joining device's link key state. The provisional key kept in effect,
    /// if any, is sent to the client so the device survives a stack restart.
    fn begin_join(&self, ieee: Eui64) {
        let provisional_key = self.core().aib.aps_security.begin_join(ieee);

        if let Some(key) = provisional_key {
            tracing::info!("Device {ieee:?} is joining with its provisional link key");

            self.push_notification(ZigbeeNotification::LinkKeyUpdate { ieee, key });
        }
    }

    /// Build the APS Transport Key command that delivers the network key to a device,
    /// encrypted with the key-transport key derived from the device's link key. A
    /// factory-new joiner only knows the well-known key (or its provisional
    /// install-code key), while a rejoining device holds whatever key it was last
    /// issued - possibly derived from a TCLK seed by the network's previous owner.
    fn build_encrypted_network_key_transport(
        &self,
        destination_eui64: Eui64,
        join_kind: JoinKind,
    ) -> EncryptedApsCommandFrame {
        let (network_key, key_seq_number) = {
            let core = self.core();

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

        let mut core = self.core();

        let link_key = if join_kind == JoinKind::New {
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
    fn send_network_key(&self, destination: Nwk, destination_eui64: Eui64, join_kind: JoinKind) {
        let encrypted_command =
            self.build_encrypted_network_key_transport(destination_eui64, join_kind);

        let nwk_frame = self
            .nwk_data_frame(destination, encrypted_command.to_bytes())
            .unsecured();

        self.background_send_nwk_frame(nwk_frame, NwkSecurityMode::Unsecured, SendMode::Direct);

        self.push_notification(ZigbeeNotification::DeviceJoined {
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

        let mut core = self.core();
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
                self.push_notification(ZigbeeNotification::ApsDecryptionFailure {
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
                if self.state.role == NwkDeviceType::Coordinator {
                    self.handle_update_device(nwk_frame, cmd, aps_source_ieee.is_some());
                } else {
                    tracing::debug!("Ignoring update-device from {source:?}: not the trust center");
                }
            }
            ApsCommandFrameCommand::RemoveDevice(cmd) => {
                tracing::warn!("Remove device from {source:?} is not yet handled: {cmd:?}");
            }
            ApsCommandFrameCommand::RequestKey(cmd) => {
                if self.state.role == NwkDeviceType::Coordinator {
                    self.handle_request_key(nwk_frame, command_frame, cmd, aps_source_ieee);
                } else {
                    tracing::debug!("Ignoring request-key from {source:?}: not the trust center");
                }
            }
            ApsCommandFrameCommand::SwitchKey(cmd) => {
                tracing::warn!("Ignoring switch key from {source:?}: {cmd:?}");
            }
            ApsCommandFrameCommand::Tunnel(cmd) => {
                tracing::warn!("Tunnel command from {source:?} is not yet handled: {cmd:?}");
            }
            ApsCommandFrameCommand::VerifyKey(cmd) => {
                if self.state.role == NwkDeviceType::Coordinator {
                    self.handle_verify_key(nwk_frame, cmd);
                } else {
                    tracing::debug!("Ignoring verify-key from {source:?}: not the trust center");
                }
            }
            ApsCommandFrameCommand::ConfirmKey(cmd) => {
                tracing::warn!("Ignoring confirm key from {source:?}: {cmd:?}");
            }
        }
    }

    /// Send a serialized APS frame to an on-network device, with NWK security. Direct
    /// children do not participate in route discovery, so they are addressed directly.
    fn send_secured_aps_payload(&self, destination: Nwk, payload: Vec<u8>) {
        // Routed delivery to a non-neighbor must be allowed to discover a route (NWK data
        // frames default to suppressing discovery).
        let nwk_frame = self
            .nwk_data_frame(destination, payload)
            .with_discover_route(NwkRouteDiscovery::Enable);

        self.background_send_nwk_frame(
            nwk_frame,
            NwkSecurityMode::NetworkKey,
            if self.is_neighbor(destination) {
                SendMode::Direct
            } else {
                SendMode::Route
            },
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

        // Spec 4.7.3.8 step 2: the claimed source (the EUI64 whose link key decrypted
        // the request, and to which the new key will be delivered) must be the device
        // that actually sent the frame, resolved via our trusted address map rather than
        // the spoofable NWK header. Otherwise an attacker who knows the well-known key
        // could request - and receive - a fresh unique key minted for a victim's EUI64.
        // An unmappable sender cannot be bound to the claim, so it is rejected.
        let sender_ieee = self
            .core()
            .nib
            .address_map
            .eui64_for(nwk_frame.nwk_header.source);
        if sender_ieee != Some(source_ieee) {
            tracing::warn!(
                "Ignoring request key from {:?} ({sender_ieee:?}) claiming source {source_ieee:?}",
                nwk_frame.nwk_header.source
            );
            return;
        }

        tracing::info!("Sending a new trust center link key to {source_ieee:?}");

        // The new key is delivered encrypted with the key it replaces
        let mut core = self.core();
        let current_key = core.aib.aps_security.device_link_key(source_ieee);
        let new_key = core
            .aib
            .aps_security
            .issue_device_key(source_ieee, Key(rand::random()));
        drop(core);

        // The key is persisted only once the device proves possession via Verify-Key
        // (see `handle_verify_key`); a device that never completes the exchange must not
        // leave a stored key behind, and its old key stays usable in the meantime.

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

        let encrypted_command = self.core().aib.aps_security.encrypt_command_with_link_key(
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

        // Verify-Key is sent unencrypted, so its body `source_address` is attacker-
        // controllable. Cross-check it against the NWK-resolved sender EUI64 when we
        // know it and drop on mismatch: this rejects spoofed addresses and closes the
        // entry-existence oracle (the encrypted-vs-unencrypted Confirm-Key reply would
        // otherwise reveal whether a stored key exists for an arbitrary EUI64). When
        // the sender's EUI64 is genuinely unknown (early join), fall back to the body
        // value.
        let sender_ieee = nwk_frame.nwk_header.source_ieee.or_else(|| {
            self.core()
                .nib
                .address_map
                .eui64_for(nwk_frame.nwk_header.source)
        });

        if let Some(sender_ieee) = sender_ieee
            && sender_ieee != verify.source_address
        {
            tracing::warn!(
                "Ignoring verify key from {sender_ieee:?} claiming mismatched source {:?}",
                verify.source_address
            );
            return;
        }

        let source_ieee = verify.source_address;

        let verified = self
            .core()
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

                // Persist only now that the device has proven possession (spec 4.7.3.3):
                // the pending key has been promoted to the device's active key.
                let key = self.core().aib.aps_security.device_link_key(source_ieee);
                self.push_notification(ZigbeeNotification::LinkKeyUpdate {
                    ieee: source_ieee,
                    key,
                });

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
            command: ApsCommandFrameCommand::ConfirmKey(ApsConfirmKeyCommandFrame {
                status,
                standard_key_type: ApsStandardKeyType::TrustCenterLinkKey,
                destination_address: destination_eui64,
            }),
        };

        let payload = if encrypted {
            // Confirm key commands are APS encrypted with the link key itself, i.e. the
            // "data key" (spec 4.4.1.3)
            self.core()
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
    fn handle_update_device(
        &self,
        nwk_frame: &NwkFrame,
        update: &ApsUpdateDeviceCommandFrame,
        aps_encrypted: bool,
    ) {
        let router_nwk = nwk_frame.nwk_header.source;

        // Spec Table 4-7: Update-Device must be APS-encrypted when we share a unique link
        // key with the relaying router. Drop an unencrypted one from such a router unless
        // policy explicitly allows it.
        if !aps_encrypted && !self.tunables.allow_unencrypted_router_device_update {
            let router_ieee = nwk_frame
                .nwk_header
                .source_ieee
                .or_else(|| self.core().nib.address_map.eui64_for(router_nwk));
            if let Some(router_ieee) = router_ieee
                && self
                    .core()
                    .aib
                    .aps_security
                    .has_unique_link_key(router_ieee)
            {
                tracing::warn!(
                    "Dropping unencrypted Update-Device from router {router_nwk:?} \
                     ({router_ieee:?}) that holds a unique link key"
                );
                return;
            }
        }

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
                // A new join through a router is only authorized while the trust
                // center window is open; otherwise we withhold the key and let the
                // joiner time out (spec 4.6.3.2)
                if !self.trust_center_permitting_joins() {
                    tracing::info!(
                        "Joins not permitted, ignoring unsecured join of {:?} via {router_nwk:?}",
                        update.device_address
                    );
                    return;
                }

                self.begin_join(update.device_address);

                self.update_nwk_eui64_mapping(update.device_short_address, update.device_address);
                self.send_tunneled_network_key(router_nwk, update.device_address, JoinKind::New);

                self.push_notification(ZigbeeNotification::DeviceJoined {
                    nwk: update.device_short_address,
                    ieee: update.device_address,
                    parent: router_nwk,
                });
            }
            ApsUpdateDeviceStatus::StandardDeviceTrustCenterRejoin => {
                // Spec 4.7.3.6: a trust center rejoin requires a unique link key, since
                // the network key would otherwise be tunneled encrypted with the well-
                // known key. Reject unless the device has one (or policy allows it).
                if !self.may_rejoin_unsecured(update.device_address) {
                    tracing::warn!(
                        "Rejecting trust center rejoin from {:?} without a unique link key",
                        update.device_address
                    );
                    return;
                }

                self.update_nwk_eui64_mapping(update.device_short_address, update.device_address);
                self.send_tunneled_network_key(router_nwk, update.device_address, JoinKind::Rejoin);

                self.push_notification(ZigbeeNotification::DeviceJoined {
                    nwk: update.device_short_address,
                    ieee: update.device_address,
                    parent: router_nwk,
                });
            }
            ApsUpdateDeviceStatus::StandardDeviceSecuredRejoin => {
                self.update_nwk_eui64_mapping(update.device_short_address, update.device_address);

                self.push_notification(ZigbeeNotification::DeviceJoined {
                    nwk: update.device_short_address,
                    ieee: update.device_address,
                    parent: router_nwk,
                });
            }
            ApsUpdateDeviceStatus::DeviceLeft => {
                // Spec 4.4.3.2.3: informative only, no action is taken beyond
                // notifying the client
                let router_ieee = nwk_frame
                    .nwk_header
                    .source_ieee
                    .or_else(|| self.core().nib.address_map.eui64_for(router_nwk));

                self.push_notification(ZigbeeNotification::DeviceLeft {
                    nwk: update.device_short_address,
                    ieee: Some(update.device_address),
                    reason: DeviceLeaveReason::RouterReported {
                        router: router_nwk,
                        router_ieee,
                    },
                });
            }
        }
    }

    /// Zigbee spec 4.6.3.7: wrap an APS-encrypted Transport Key command in a Tunnel
    /// command so a parent router can forward it to a joiner we cannot reach directly.
    fn send_tunneled_network_key(&self, router_nwk: Nwk, device_eui64: Eui64, join_kind: JoinKind) {
        let encrypted_transport_key =
            self.build_encrypted_network_key_transport(device_eui64, join_kind);

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
        match &nwk_frame.payload {
            NwkPayload::Command(NwkCommand::RejoinRequest(cmd)) => {
                self.handle_rejoin_request(nwk_frame, cmd.clone(), false);
            }
            NwkPayload::Command(other) => {
                tracing::debug!("Ignoring unencrypted NWK command: {:?}", other.command_id());
            }
            NwkPayload::Opaque(_) => {
                tracing::debug!("Ignoring unencrypted non-command NWK frame");
            }
        }
    }

    /// Zigbee spec 3.6.1.4.2: a previously joined device re-attaches to us, either
    /// securely (it still has the network key) or via an unsecured trust center rejoin.
    #[allow(clippy::significant_drop_tightening)]
    /// Spec 4.7.3.6: an unsecured / trust center rejoin re-delivers the network key. It
    /// is only safe for a device that already holds a unique link key (so the key is not
    /// exposed under the well-known key); the `allow_unsecured_rejoins` policy overrides
    /// this for migration scenarios.
    fn may_rejoin_unsecured(&self, eui64: Eui64) -> bool {
        self.tunables.allow_unsecured_rejoins
            || self.core().aib.aps_security.has_unique_link_key(eui64)
    }

    pub(super) fn handle_rejoin_request(
        &self,
        nwk_frame: &NwkFrame,
        rejoin_request: NwkRejoinRequestCommand,
        secured: bool,
    ) {
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
            let core = self.core();

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
            .core()
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

        self.core().nib.neighbors.upsert_child(
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
            self.core_now(),
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
            // Spec 4.7.3.6: an unsecured rejoin re-delivers the network key encrypted
            // with the well-known key unless the device holds a unique link key. Reject
            // when it has neither, so the network key is never exposed to anyone who
            // knows the well-known key.
            if !self.may_rejoin_unsecured(source_ieee) {
                tracing::warn!(
                    "Rejecting unsecured rejoin from {source_ieee:?} without a unique link key"
                );
                return;
            }
            // `send_network_key` also emits the join notification
            self.send_network_key(assigned_nwk, source_ieee, JoinKind::Rejoin);
        } else {
            self.push_notification(ZigbeeNotification::DeviceJoined {
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
                NwkCommand::RejoinResponse(NwkRejoinResponseCommand {
                    network_address: assigned,
                    rejoin_status: status,
                }),
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
        self.background_send_nwk_frame(response_frame, security, SendMode::Direct);
    }

    /// Zigbee spec 3.6.1.10.3: a device announces that it is leaving the network, or
    /// asks us to leave (which a coordinator ignores).
    pub(super) fn handle_leave(&self, nwk_frame: &NwkFrame, leave_cmd: NwkLeaveCommand) {
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

        let source_ieee = nwk_frame
            .nwk_header
            .source_ieee
            .or_else(|| self.core().nib.address_map.eui64_for(source));

        if let Some(source_ieee) = source_ieee {
            self.core().nib.neighbors.remove(source_ieee);
        }

        // The address map entry and any negotiated link key are kept around so that the
        // device can rejoin later
        self.drop_indirect_transactions(source_ieee, source);
        self.core().nib.routing.remove_route(source);

        self.push_notification(ZigbeeNotification::DeviceLeft {
            nwk: source,
            ieee: source_ieee,
            reason: DeviceLeaveReason::Announced {
                rejoin: leave_cmd.rejoin,
            },
        });
    }

    /// Spec 3.6.10.2: an end device child negotiates its keepalive timeout. The
    /// response tells the device which keepalive method to use.
    pub(super) fn handle_end_device_timeout_request(
        &self,
        nwk_frame: &NwkFrame,
        request: NwkEndDeviceTimeoutRequestCommand,
    ) {
        let source = nwk_frame.nwk_header.source;

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

        let updated = self.core().nib.neighbors.set_child_timeout(
            source,
            timeout,
            u16::from(request.end_device_configuration),
            self.core_now(),
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

    pub(super) fn send_end_device_timeout_response(
        &self,
        destination: Nwk,
        status: NwkEndDeviceTimeoutResponseStatus,
    ) {
        let parent_information = self.state.parent_information;

        let response_frame = self
            .nwk_command_frame(
                destination,
                NwkCommand::EndDeviceTimeoutResponse(NwkEndDeviceTimeoutResponseCommand {
                    status,
                    mac_data_poll_keepalive_supported: parent_information.mac_data_poll_keepalive,
                    end_device_timeout_request_keepalive_supported: parent_information
                        .end_device_timeout_request_keepalive,
                    power_negotation_support: parent_information.power_negotiation,
                }),
            )
            .with_radius(1);

        // The child is a direct neighbor; responses to sleepy children go through the
        // indirect queue via the NWK unicast fork
        self.background_send_nwk_frame(
            response_frame,
            NwkSecurityMode::NetworkKey,
            SendMode::Direct,
        );
    }

    /// Open (or close, with `duration == 0`) the join window. The trust center
    /// authorization window always tracks `duration`; the coordinator's beacon and
    /// direct-association window only follows it when `accept_direct_joins` is set,
    /// leaving a steered join authorized without advertising us as a parent.
    pub fn permit_joins(&self, duration: u64, accept_direct_joins: bool) {
        let deadline = (duration != 0).then(|| self.core_now() + Duration::from_secs(duration));

        tracing::info!(
            "Permitting joins for {duration} seconds (accept_direct_joins: {accept_direct_joins})"
        );

        let mut core = self.core();
        core.trust_center_joins_until = deadline;
        if accept_direct_joins {
            core.permitting_joins_until = deadline;
        }
    }

    /// Whether the coordinator advertises and accepts direct joins right now.
    pub(super) fn permitting_joins(&self) -> bool {
        self.core()
            .permitting_joins_until
            .is_some_and(|deadline| deadline > self.core_now())
    }

    /// Whether the trust center authorizes new joins through a router right now.
    pub(super) fn trust_center_permitting_joins(&self) -> bool {
        self.core()
            .trust_center_joins_until
            .is_some_and(|deadline| deadline > self.core_now())
    }
}
