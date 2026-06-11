use crate::ieee_802154::commands::{
    AssociationRequestDeviceType, Ieee802154AssociationRequestCommand,
    Ieee802154AssociationResponseCommand,
};
use crate::ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154AssociationStatus,
    Ieee802154CommandFrame, Ieee802154CommandId, Ieee802154CommandPayload, Ieee802154Frame,
    Ieee802154FrameControl, Ieee802154FrameHeader, Ieee802154FrameType,
};
use crate::zigbee_aps::{
    APS_STATUS_SECURITY_FAIL, APS_STATUS_SUCCESS, ApsCommandFrame, ApsCommandFrameCommand,
    ApsCommandId, ApsConfirmKeyCommandFrame, ApsDeliveryMode, ApsFrameControl, ApsFrameType,
    ApsNetworkKeyDescriptor, ApsRequestKeyCommandFrame, ApsRequestKeyType, ApsStandardKeyType,
    ApsTransportKeyCommandFrame, ApsTransportKeyDescriptor, ApsTrustCenterLinkKeyDescriptor,
    ApsTunnelCommandFrame, ApsUpdateDeviceCommandFrame, ApsUpdateDeviceStatus,
    ApsVerifyKeyCommandFrame, EncryptedApsCommandFrame,
};
use crate::zigbee_nwk::{
    BROADCAST_RX_ON_WHEN_IDLE, NwkFrame, NwkFrameType, NwkSecurityHeaderKeyId,
};
use ieee_802154::types::{Eui64, Key, Nwk};

use std::collections::VecDeque;
use tokio::time::{Duration, Instant};
use zigbee_parts::Command;
use zigbee_parts::commands::{
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
                log::warn!(
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
            let neighbors = self
                .state
                .neighbors
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            (
                neighbors.contains(source_eui64),
                neighbors.child_count() >= usize::from(self.constants.max_children),
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
            log::info!("Denying association request from {source_eui64:?}: {status:?}");
            self.queue_association_response(source_eui64, Nwk(0xFFFF), status);
            return;
        }

        let short_address = self.allocate_network_address(source_eui64);
        log::info!("Device {source_eui64:?} is joining as {short_address:?}");

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
            self.constants.end_device_timeout_default.duration()
        } else {
            Duration::from_secs(0xFFFFFFFF)
        };

        {
            let mut neighbors = self
                .state
                .neighbors
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            let neighbor_entry = neighbors.upsert(source_eui64, || neighbors::TableEntry {
                extended_address: source_eui64,
                network_address: short_address,
                device_type,
                rx_on_when_idle: request.receive_on_when_idle,
                end_device_configuration: 0x0000,
                timeout_at: Instant::now() + device_timeout,
                device_timeout,
                relationship: neighbors::Relationship::Child,
                transmit_failure: 0,
                lqas: VecDeque::new(),
                outgoing_cost: 0,
                last_link_status_timestamp: Instant::now(),
                incoming_beacon_timestamp: 0,
                beacon_transmission_time_offset: 0,
                keepalive_received: false,
                mac_unicast_bytes_transmitted: 0,
                mac_unicast_bytes_received: 0,
                router_added_timestamp: Instant::now(),
                router_connectivity: 0,
                router_neighbor_set_diversity: 0,
                router_outbound_activity: 0,
                router_inbound_activity: 0,
                security_timer: 0,
            });

            // A device may re-associate with different capabilities (e.g. re-flashed
            // from router to end device), so existing entries are refreshed too
            neighbor_entry.network_address = short_address;
            neighbor_entry.device_type = device_type;
            neighbor_entry.rx_on_when_idle = request.receive_on_when_idle;
            neighbor_entry.device_timeout = device_timeout;
            neighbor_entry.timeout_at = Instant::now() + device_timeout;
            neighbor_entry.relationship = neighbors::Relationship::Child;
        }

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
                    log::warn!("Association response to {eui64:?} was not extracted: {err}");
                }
            }
        });
    }

    /// Pick an unused random network address for a joining device, reusing the previous
    /// one if the device has joined before.
    fn allocate_network_address(&self, eui64: Eui64) -> Nwk {
        if let Some(existing) = self
            .state
            .address_map
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .get(&eui64)
        {
            return *existing;
        }

        self.generate_unused_network_address()
    }

    #[allow(clippy::significant_drop_tightening)]
    fn generate_unused_network_address(&self) -> Nwk {
        let address_map = self
            .state
            .address_map
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();
        let neighbors = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();

        loop {
            let candidate = Nwk(rand::random::<u16>());

            // Assigned addresses lie within 0x0001-0xFFF7
            if candidate.as_u16() == 0x0000 || candidate.as_u16() >= 0xFFF8 {
                continue;
            }

            if candidate == self.state.network_address
                || address_map.values().any(|&nwk| nwk == candidate)
                || neighbors.has_network_address(candidate)
            {
                continue;
            }

            return candidate;
        }
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
            let window = self.constants.broadcast_delivery_time;

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

        log::warn!("Address conflict detected on {address:?}");

        if detected_locally {
            self.broadcast_address_conflict(address);
        }

        if address == self.state.network_address {
            // A coordinator never changes its address (spec 3.6.1.10.5); the
            // notification tells the conflicting device to move
            log::error!("Another device is using our own network address");
            return;
        }

        if let Some(child_eui64) = self.end_device_child_eui64(address) {
            self.reassign_child_address(child_eui64, address);
            return;
        }

        // Routers resolve their own conflicts after hearing the notification; our
        // mapping for the address is ambiguous until the keeper re-announces
        self.state
            .address_map
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .retain(|_, &mut nwk| nwk != address);
        self.state
            .routing
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .remove_route(address);
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
                    .constants
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
                log::debug!(
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

        log::warn!(
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

    fn build_802154_association_response(
        &self,
        destination_eui64: Eui64,
        short_address: Nwk,
        association_status: Ieee802154AssociationStatus,
    ) -> Ieee802154Frame {
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
                sequence_number: Some(
                    *self
                        .state
                        .ieee802154_sequence_number
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap(),
                ),
                src_address: Some(Ieee802154Address::Eui64(self.state.ieee_address)),
                dest_address: Some(Ieee802154Address::Eui64(destination_eui64)),
                src_pan_id: None,
                dest_pan_id: Some(*self.state.pan_id.try_lock_for(MAX_LOCK_DURATION).unwrap()),
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
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .has_network_address(nwk)
    }

    /// Register an install-code-derived link key for a device expected to join:
    /// an `apsDeviceKeyPairSet` entry with `PROVISIONAL_KEY` attributes that
    /// replaces the well-known key for that device's network key delivery.
    pub fn set_provisional_key(&self, ieee: Eui64, key: Key) {
        log::info!("Registered provisional link key for {ieee:?}");

        self.state
            .aps_security
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .set_provisional_key(ieee, key);
    }

    /// Reset a joining device's link key state. The provisional key kept in effect,
    /// if any, is sent to the client so the device survives a stack restart.
    fn begin_join(&self, ieee: Eui64) {
        let provisional_key = self
            .state
            .aps_security
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .begin_join(ieee);

        if let Some(key) = provisional_key {
            log::info!("Device {ieee:?} is joining with its provisional link key");

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
                    key: self
                        .state
                        .security_material_primary
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap()
                        .key
                        .clone(),
                    sequence_number: self.state.active_key_seq_number,
                    destination_address: destination_eui64,
                    source_address: self.state.ieee_address,
                }),
            }),
        };

        let mut aps_security = self
            .state
            .aps_security
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();

        let link_key = if fresh_join {
            aps_security.join_link_key(destination_eui64)
        } else {
            aps_security.device_link_key(destination_eui64)
        };

        aps_security.encrypt_command_with_link_key(
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
            log::warn!("APS command frames without an extended nonce are not supported");
            return;
        };

        let network_key = self
            .state
            .security_material_primary
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .key
            .clone();

        let decrypted = self
            .state
            .aps_security
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .decrypt_command(extended_source, encrypted_command_frame, &network_key);

        match decrypted {
            Some(command_frame) => {
                log::debug!("Decrypted APS command frame: {command_frame:?}");
                self.handle_aps_command_frame(nwk_frame, &command_frame, Some(extended_source));
            }
            None => {
                log::warn!(
                    "Failed to decrypt APS command frame from {:?}",
                    nwk_frame.nwk_header.source
                );
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
                log::warn!("Ignoring transport key from {source:?}: {cmd:?}");
            }
            ApsCommandFrameCommand::UpdateDevice(cmd) => {
                self.handle_update_device(nwk_frame, cmd);
            }
            ApsCommandFrameCommand::RemoveDevice(cmd) => {
                log::warn!("Remove device from {source:?} is not yet handled: {cmd:?}");
            }
            ApsCommandFrameCommand::RequestKey(cmd) => {
                self.handle_request_key(nwk_frame, command_frame, cmd, aps_source_ieee);
            }
            ApsCommandFrameCommand::SwitchKey(cmd) => {
                log::warn!("Ignoring switch key from {source:?}: {cmd:?}");
            }
            ApsCommandFrameCommand::Tunnel(cmd) => {
                log::warn!("Tunnel command from {source:?} is not yet handled: {cmd:?}");
            }
            ApsCommandFrameCommand::VerifyKey(cmd) => {
                self.handle_verify_key(nwk_frame, cmd);
            }
            ApsCommandFrameCommand::ConfirmKey(cmd) => {
                log::warn!("Ignoring confirm key from {source:?}: {cmd:?}");
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
            log::warn!("Application link keys are not supported, ignoring request: {request:?}");
            return;
        }

        // The spec mandates that request key commands be APS encrypted
        if !command_frame.frame_control.security {
            log::warn!(
                "Ignoring unencrypted request key command from {:?}",
                nwk_frame.nwk_header.source
            );
            return;
        }

        let Some(source_ieee) = aps_source_ieee else {
            log::warn!("Request key command has no extended source, ignoring");
            return;
        };

        log::info!("Sending a new trust center link key to {source_ieee:?}");

        // The new key is delivered encrypted with the key it replaces
        let mut aps_security = self
            .state
            .aps_security
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();
        let current_key = aps_security.device_link_key(source_ieee);
        let new_key = aps_security.issue_device_key(source_ieee);
        drop(aps_security);

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
            .aps_security
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
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
            log::warn!("Ignoring verify key for unsupported key type: {verify:?}");
            return;
        }

        let source_ieee = verify.source_address;

        let verified = self
            .state
            .aps_security
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .verify_device_key(source_ieee, &verify.initiator_verify_key_hash.0);

        let status = match verified {
            None => {
                log::warn!("Verify key from {source_ieee:?} without a stored link key");
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
                log::info!("Device {source_ieee:?} verified its trust center link key");
                APS_STATUS_SUCCESS
            }
            Some(false) => {
                log::warn!("Verify key hash mismatch for {source_ieee:?}");
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
                .aps_security
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
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

        log::info!(
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
                    .aps_security
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .has_unique_link_key(update.device_address)
                {
                    log::warn!(
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
                tunneled_frame: encrypted_transport_key.to_bytes(),
            }),
        };

        self.send_secured_aps_payload(router_nwk, tunnel_command.to_bytes());
    }

    /// Process the rare NWK frames that arrive without encryption. The only one we
    /// accept is a trust center rejoin request from a device that lost the network key.
    pub(super) fn handle_unsecured_nwk_frame(&self, nwk_frame: &NwkFrame) {
        if nwk_frame.nwk_header.frame_control.frame_type != NwkFrameType::Command {
            log::debug!("Ignoring unencrypted non-command NWK frame");
            return;
        }

        if nwk_frame.payload.is_empty() {
            log::warn!("Ignoring unencrypted NWK command frame with an empty payload");
            return;
        }

        match NwkCommandId::try_from(nwk_frame.payload[0]) {
            Ok(NwkCommandId::RejoinRequest) => {
                self.handle_rejoin_request(nwk_frame, false);
            }
            _ => {
                log::debug!("Ignoring unencrypted NWK command: {}", nwk_frame.payload[0]);
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
                log::warn!("Error parsing rejoin request command: {e:?}");
                return;
            }
        };

        log::info!("Rejoin request (secured: {secured}): {rejoin_request:#?}");

        let Some(source_ieee) = nwk_frame.nwk_header.source_ieee else {
            log::warn!("Rejoin request source EUI64 is missing");
            return;
        };

        let requested_nwk = nwk_frame.nwk_header.source;
        let capability = &rejoin_request.capability_information;

        // Spec 3.6.1.6.1.3: known devices may always re-attach; new children are
        // admitted only while capacity remains
        let (already_known, at_capacity) = {
            let neighbors = self
                .state
                .neighbors
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            (
                neighbors.contains(source_ieee),
                neighbors.child_count() >= usize::from(self.constants.max_children),
            )
        };

        if !already_known && at_capacity {
            log::info!("Denying rejoin request from {source_ieee:?}, no child capacity left");
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
        let conflict = requested_nwk == self.state.network_address
            || self
                .state
                .address_map
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .iter()
                .any(|(&eui64, &nwk)| nwk == requested_nwk && eui64 != source_ieee);

        let assigned_nwk = if conflict {
            self.allocate_network_address(source_ieee)
        } else {
            requested_nwk
        };

        log::info!("Device {source_ieee:?} is rejoining as {assigned_nwk:?}");

        self.update_nwk_eui64_mapping(assigned_nwk, source_ieee);

        let device_type = match capability.device_type {
            NwkRejoinCapabilityInformationDeviceType::Router => NwkDeviceType::Router,
            NwkRejoinCapabilityInformationDeviceType::EndDevice => NwkDeviceType::EndDevice,
        };

        // Spec 3.6.10.5: end device children start with the default keepalive
        // timeout; router children are not aged
        let device_timeout = if device_type == NwkDeviceType::EndDevice {
            self.constants.end_device_timeout_default.duration()
        } else {
            Duration::from_secs(0xFFFFFFFF)
        };

        {
            let mut neighbors = self
                .state
                .neighbors
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            let neighbor_entry = neighbors.upsert(source_ieee, || neighbors::TableEntry {
                extended_address: source_ieee,
                network_address: assigned_nwk,
                device_type,
                rx_on_when_idle: capability.receiver_on_when_idle,
                end_device_configuration: 0x0000,
                timeout_at: Instant::now() + device_timeout,
                device_timeout,
                relationship: neighbors::Relationship::Child,
                transmit_failure: 0,
                lqas: VecDeque::new(),
                outgoing_cost: 0,
                last_link_status_timestamp: Instant::now(),
                incoming_beacon_timestamp: 0,
                beacon_transmission_time_offset: 0,
                keepalive_received: false,
                mac_unicast_bytes_transmitted: 0,
                mac_unicast_bytes_received: 0,
                router_added_timestamp: Instant::now(),
                router_connectivity: 0,
                router_neighbor_set_diversity: 0,
                router_outbound_activity: 0,
                router_inbound_activity: 0,
                security_timer: 0,
            });

            // A device may rejoin with different capabilities, so existing entries
            // are refreshed too
            neighbor_entry.network_address = assigned_nwk;
            neighbor_entry.device_type = device_type;
            neighbor_entry.rx_on_when_idle = capability.receiver_on_when_idle;
            neighbor_entry.device_timeout = device_timeout;
            neighbor_entry.timeout_at = Instant::now() + device_timeout;
            neighbor_entry.relationship = if secured {
                neighbors::Relationship::Child
            } else {
                neighbors::Relationship::UnauthenticatedChild
            };
        }

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
                log::warn!("Error parsing leave command: {e:?}");
                return;
            }
        };

        let source = nwk_frame.nwk_header.source;

        if leave_cmd.request {
            // Spec 3.6.1.10.3.1: coordinators drop leave requests
            log::warn!("Ignoring leave request from {source:?}: {leave_cmd:?}");
            return;
        }

        log::info!(
            "Device {source:?} is leaving the network (rejoin: {})",
            leave_cmd.rejoin
        );

        let source_ieee = nwk_frame.nwk_header.source_ieee.or_else(|| {
            self.state
                .address_map
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .iter()
                .find_map(|(&eui64, &nwk)| if nwk == source { Some(eui64) } else { None })
        });

        if let Some(source_ieee) = source_ieee {
            self.state
                .neighbors
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .remove(source_ieee);
        }

        // The address map entry and any negotiated link key are kept around so that the
        // device can rejoin later
        self.drop_indirect_transactions(source_ieee, source);
        self.state
            .routing
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
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
                log::warn!("Invalid end device timeout request from {source:?}: {e:?}");
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
            log::warn!(
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
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .set_child_timeout(source, timeout, u16::from(request.end_device_configuration));

        // Requests from devices that are not our end device children are dropped
        if !updated {
            log::warn!("Ignoring end device timeout request from non-child {source:?}");
            return;
        }

        log::debug!("Child {source:?} negotiated an end device timeout of {timeout:?}");

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
            log::info!("Permitting joins disabled");
            None
        } else {
            log::info!("Permitting joins for {duration} seconds");
            Some(Instant::now() + Duration::from_secs(duration))
        };

        *self
            .state
            .permitting_joins_until
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap() = deadline;
    }

    /// Whether joins are permitted right now.
    pub(super) fn permitting_joins(&self) -> bool {
        self.state
            .permitting_joins_until
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .is_some_and(|deadline| deadline > Instant::now())
    }
}
