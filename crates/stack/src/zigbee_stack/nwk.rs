use crate::ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154DataFrame, Ieee802154Frame,
    Ieee802154FrameControl, Ieee802154FrameHeader, Ieee802154FrameType,
};
use ieee_802154::FrameBytes;
use ieee_802154::types::{Eui64, Nwk};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::time::{Instant, timeout_at};
use zigbee::Command;
use zigbee::nwk::commands::{
    NwkCommandId, NwkNetworkStatus, NwkNetworkStatusCommand, NwkRouteRecordCommand,
};
use zigbee::nwk::frame::{
    BROADCAST_ALL_ROUTERS_AND_COORDINATOR, BROADCAST_LOW_POWER_ROUTERS, EncryptedNwkFrame,
    NwkAuxHeader, NwkFrame, NwkFrameControl, NwkFrameType, NwkHeader, NwkRouteDiscovery,
    NwkSecurityHeaderControlField, NwkSecurityHeaderKeyId, NwkSecurityLevel, NwkSourceRoute,
};

use super::routing::Route;
use super::{
    MAX_LOCK_DURATION, NwkBroadcastTransaction, NwkSecurityMode, ZigbeeStack, ZigbeeStackError,
};

impl ZigbeeStack {
    pub fn update_nwk_eui64_mapping(&self, nwk: Nwk, eui64: Eui64) {
        let conflict = {
            let mut address_map = self
                .state
                .address_map
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            if address_map.get(&eui64) == Some(&nwk) {
                return;
            }

            // Spec 3.6.1.10.2: a network address claimed by a second IEEE address is
            // an address conflict; the mapping is not updated
            let conflict = address_map
                .iter()
                .any(|(&other_eui64, &other_nwk)| other_nwk == nwk && other_eui64 != eui64);

            if !conflict {
                match address_map.insert(eui64, nwk) {
                    None => {
                        log::debug!("Added new address mapping: {eui64:?} -> {nwk:?}")
                    }
                    Some(old_nwk) => {
                        log::warn!(
                            "Updated address mapping: {eui64:?} -> {nwk:?} (was {old_nwk:?})",
                        )
                    }
                }
            }

            conflict
        };

        if conflict {
            self.handle_address_conflict(nwk, true);
        }
    }

    /// Filter broadcast frames based on the NWK broadcast transaction table
    pub fn filter_broadcast(&self, nwk_frame: &NwkFrame, sender_nwk: Nwk) -> bool {
        let now = Instant::now();

        // We cannot handle broadcasts until the network has been running for at least
        // the time it takes to deliver one broadcast
        if !self.state.hack_ignore_broadcast_startup_wait_period
            && (self.state.start_time + self.constants.broadcast_delivery_time > now)
        {
            log::debug!("Filtering broadcast, network started too recently.");
            return true;
        }

        let key = (
            nwk_frame.nwk_header.source,
            nwk_frame.nwk_header.sequence_number,
        );

        // The passive ack contract is formed when the transaction is created: only
        // routers that were neighbors at that point are expected to relay
        let expected_relayers = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .expected_broadcast_relayers();

        let mut broadcast_transaction_table = self
            .state
            .broadcast_transaction_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();

        // Expired entries can be dropped wholesale
        broadcast_transaction_table.retain(|_, entry| entry.expiration_time > now);

        if let Some(transaction) = broadcast_transaction_table.get_mut(&key) {
            // Spec 3.6.6: a neighbor relaying a broadcast we know about is its
            // passive acknowledgment of that broadcast
            transaction.heard_from.insert(sender_nwk);
            transaction.acked_notify.notify_one();
            return true;
        }

        broadcast_transaction_table.insert(
            key,
            NwkBroadcastTransaction {
                source_nwk: nwk_frame.nwk_header.source,
                sequence_number: nwk_frame.nwk_header.sequence_number,
                expiration_time: now + self.constants.broadcast_delivery_time,
                expected_relayers,
                // Whoever delivered the frame to us has already broadcast it
                heard_from: HashSet::from([sender_nwk]),
                acked_notify: Arc::new(Notify::new()),
            },
        );

        false
    }

    /// Wait until the broadcast is passively acknowledged or the ack collection
    /// window closes, waking on every recorded ack. Returns whether the broadcast
    /// is acknowledged.
    async fn await_broadcast_passive_acks(&self, key: (Nwk, u8)) -> bool {
        let acked_notify = self
            .state
            .broadcast_transaction_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .get(&key)
            .map(|transaction| transaction.acked_notify.clone());

        // An expired (absent) entry means the delivery window has already closed
        let Some(acked_notify) = acked_notify else {
            return true;
        };

        let deadline = Instant::now() + self.constants.passive_ack_timeout;

        loop {
            if self.broadcast_passively_acked(key) {
                return true;
            }

            if timeout_at(deadline, acked_notify.notified()).await.is_err() {
                // The window closed; an ack recorded at the boundary still counts
                return self.broadcast_passively_acked(key);
            }
        }
    }

    /// Spec 3.6.6: a broadcast is fully delivered once every router that was in the
    /// transaction's audience and is still a live neighbor has been heard relaying
    /// it. Routers that became neighbors after the transmission owe no passive ack;
    /// routers that ceased being neighbors can never give one.
    ///
    /// In dense neighborhoods and with unbounded neighbor tables it is unreasonable to
    /// wait for all ~40 nearby routers to acknowledge a broadcast. We instead just wait
    /// for _enough_ of them (8) to have rebroadcast it.
    fn broadcast_passively_acked(&self, key: (Nwk, u8)) -> bool {
        let live_relayers = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .expected_broadcast_relayers();

        // An expired (absent) entry means the delivery window has already closed
        self.state
            .broadcast_transaction_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .get(&key)
            .is_none_or(|transaction| {
                let audience: Vec<Nwk> = transaction
                    .expected_relayers
                    .iter()
                    .filter(|nwk| live_relayers.contains(nwk))
                    .copied()
                    .collect();

                let heard = audience
                    .iter()
                    .filter(|nwk| transaction.heard_from.contains(nwk))
                    .count();

                heard
                    >= audience
                        .len()
                        .min(self.constants.broadcast_passive_ack_quorum)
            })
    }

    pub fn handle_decrypted_frame(&self, nwk_frame: &NwkFrame, sender_nwk: Nwk, lqi: u8, rssi: i8) {
        // Update the frame counter for the relaying device
        if let Some(aux_header) = &nwk_frame.aux_header
            && let Some(relaying_eui64) = aux_header.extended_source
        {
            self.state
                .security_material_primary
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .incoming_frame_counter_set
                .insert(relaying_eui64, aux_header.frame_counter);

            log::debug!(
                "Incremented frame counter for {relaying_eui64:?} to {}",
                aux_header.frame_counter
            );
        }

        // Update the address cache
        if let Some(src_eui64) = nwk_frame.nwk_header.source_ieee {
            self.update_nwk_eui64_mapping(nwk_frame.nwk_header.source, src_eui64);
        }

        // Spec 3.6.1.10.2: a frame addressed to our network address but a different
        // IEEE address means another device is using our address
        if nwk_frame.nwk_header.destination == self.state.network_address
            && let Some(destination_ieee) = nwk_frame.nwk_header.destination_ieee
            && destination_ieee != self.state.ieee_address
        {
            self.handle_address_conflict(self.state.network_address, true);
        }

        // Handle LQA calculation
        self.maybe_age_neighbors();
        self.maybe_recompute_lqa(sender_nwk, lqi, rssi);

        // Network input may never panic: a command frame with no command byte is
        // malformed and dropped
        if nwk_frame.nwk_header.frame_control.frame_type == NwkFrameType::Command
            && nwk_frame.payload.is_empty()
        {
            log::warn!("Ignoring NWK command frame with an empty payload");
            return;
        }

        // Spec 3.6.6: link status and route request broadcasts bypass the broadcast
        // transaction table; route requests have their own cost-comparing dedup logic
        // and relayed copies share the originator's sequence number
        let bypasses_transaction_table = nwk_frame.nwk_header.frame_control.frame_type
            == NwkFrameType::Command
            && matches!(
                NwkCommandId::try_from(nwk_frame.payload[0]),
                Ok(NwkCommandId::RouteRequest | NwkCommandId::LinkStatus)
            );

        if nwk_frame.nwk_header.destination.as_u16()
            >= BROADCAST_ALL_ROUTERS_AND_COORDINATOR.as_u16()
            && !bypasses_transaction_table
        {
            if self.filter_broadcast(nwk_frame, sender_nwk) {
                log::debug!("Filtering broadcast, stopping further processing");
                return;
            }

            // Spec 3.6.1.10.2: a fresh broadcast claiming our address as its source
            // means another device is using our address. Our own broadcasts never
            // reach this point: the send path pre-fills the transaction table. The
            // frame is discarded instead of relayed (3.6.1.10).
            if nwk_frame.nwk_header.source == self.state.network_address {
                if self.state.start_time + self.constants.broadcast_delivery_time < Instant::now() {
                    self.handle_address_conflict(self.state.network_address, true);
                }
                return;
            }

            // A fresh broadcast is relayed onward to the rest of the mesh
            self.maybe_relay_broadcast(nwk_frame);
        }

        // Handle NWK commands
        if nwk_frame.nwk_header.frame_control.frame_type == NwkFrameType::Command {
            match NwkCommandId::try_from(nwk_frame.payload[0]) {
                Ok(NwkCommandId::LinkStatus) => {
                    // TODO: Error handling for decoding?
                    self.handle_link_status(nwk_frame, lqi);
                }
                Ok(NwkCommandId::RouteReply) => {
                    // TODO: Error handling for decoding?
                    self.handle_route_reply(nwk_frame);
                }
                Ok(NwkCommandId::RouteRecord) => {
                    let route_record_cmd =
                        match NwkRouteRecordCommand::deserialize(&nwk_frame.payload) {
                            Ok(cmd) => cmd,
                            Err(err) => {
                                log::warn!("Failed to parse route record command: {err:?}");
                                return;
                            }
                        };
                    log::debug!("Route record command frame received: {route_record_cmd:?}");
                    self.state
                        .routing
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap()
                        .store_route_record(nwk_frame.nwk_header.source, route_record_cmd.relays);
                }
                Ok(NwkCommandId::RouteRequest) => {
                    self.handle_route_request(nwk_frame, sender_nwk);
                }
                Ok(NwkCommandId::RejoinRequest) => {
                    self.handle_rejoin_request(nwk_frame, true);
                }
                Ok(NwkCommandId::Leave) => {
                    self.handle_leave(nwk_frame);
                }
                Ok(NwkCommandId::NetworkStatus) => {
                    self.handle_network_status(nwk_frame);
                }
                Ok(NwkCommandId::EndDeviceTimeoutRequest) => {
                    self.handle_end_device_timeout_request(nwk_frame);
                }
                Err(_) => {
                    log::warn!("Unknown NWK command: {}", nwk_frame.payload[0]);
                }
                _ => {
                    log::warn!("Unhandled NWK command: {:?}", nwk_frame.payload[0]);
                }
            }
        }
    }

    /// A NWK command frame originated by us, with stack-wide defaults: secured, route
    /// discovery suppressed, radius `2 * max_depth`, sequence number assigned on send,
    /// our EUI64 as the extended source. Deviations chain `with_*` overrides.
    pub(super) fn nwk_command_frame(&self, destination: Nwk, payload: Vec<u8>) -> NwkFrame {
        NwkFrame {
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Command,
                    protocol_version: self.constants.protocol_version,
                    discover_route: NwkRouteDiscovery::Suppress,
                    multicast: false,
                    security: true,
                    source_route: false,
                    destination: false,
                    extended_source: true,
                    end_device_initiator: false,
                },
                destination,
                source: self.state.network_address,
                radius: 2 * self.constants.max_depth,
                sequence_number: 0, // Rewritten on send
                destination_ieee: None,
                source_ieee: Some(self.state.ieee_address),
                multicast_control: None,
                source_route: None,
            },
            aux_header: None, // Applied at encryption time
            payload: FrameBytes::from_slice(&payload).expect("NWK payload is frame-bounded"),
        }
    }

    /// A NWK data frame originated by us; same defaults as [`Self::nwk_command_frame`]
    /// except data frames carry no extended source.
    pub(super) fn nwk_data_frame(&self, destination: Nwk, payload: Vec<u8>) -> NwkFrame {
        NwkFrame {
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Data,
                    protocol_version: self.constants.protocol_version,
                    discover_route: NwkRouteDiscovery::Suppress,
                    multicast: false,
                    security: true,
                    source_route: false,
                    destination: false,
                    extended_source: false,
                    end_device_initiator: false,
                },
                destination,
                source: self.state.network_address,
                radius: 2 * self.constants.max_depth,
                sequence_number: 0, // Rewritten on send
                destination_ieee: None,
                source_ieee: None,
                multicast_control: None,
                source_route: None,
            },
            aux_header: None, // Applied at encryption time
            payload: FrameBytes::from_slice(&payload).expect("NWK payload is frame-bounded"),
        }
    }

    pub fn background_send_nwk_frame(
        &self,
        nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        route_directly: bool,
    ) {
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            arc_self
                .send_nwk_frame(nwk_frame, security, route_directly)
                .await
                .unwrap_or_else(|err| {
                    log::error!("Failed to send NWK frame: {err}");
                });
        });
    }

    pub async fn send_nwk_frame(
        &self,
        nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        route_directly: bool,
    ) -> Result<(), ZigbeeStackError> {
        if nwk_frame.nwk_header.destination.as_u16() >= BROADCAST_LOW_POWER_ROUTERS.as_u16() {
            self.send_broadcast_nwk_frame(nwk_frame, security).await
        } else {
            self.send_unicast_nwk_frame(nwk_frame, security, route_directly)
                .await
        }
    }

    pub(super) fn next_nwk_sequence_number(&self) -> u8 {
        let mut sequence_number = self
            .state
            .sequence_number
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();
        *sequence_number = sequence_number.wrapping_add(1);
        *sequence_number
    }

    fn apply_nwk_aux_header(&self, nwk_frame: &mut NwkFrame, security: NwkSecurityMode) {
        if security == NwkSecurityMode::NetworkKey {
            nwk_frame.aux_header = Some(NwkAuxHeader {
                security_control: NwkSecurityHeaderControlField {
                    security_level: NwkSecurityLevel::NoSecurity,
                    key_id: NwkSecurityHeaderKeyId::NetworkKey,
                    extended_nonce: true,
                    require_verified_frame_counter: false,
                },
                frame_counter: 0, // This field is rewritten and is always up-to-date
                extended_source: Some(self.state.ieee_address),
                key_sequence_number: self.state.active_key_seq_number,
            });
        }
    }

    fn encrypt_nwk_frame(
        &self,
        nwk_frame: &mut NwkFrame,
        security: NwkSecurityMode,
    ) -> EncryptedNwkFrame {
        match security {
            NwkSecurityMode::NetworkKey => {
                // The encryption frame counter always increments
                nwk_frame.aux_header.as_mut().unwrap().frame_counter =
                    self.next_nwk_frame_counter();

                nwk_frame.encrypt(
                    &self
                        .state
                        .security_material_primary
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap()
                        .key,
                )
            }
            NwkSecurityMode::Unsecured => EncryptedNwkFrame {
                nwk_header: nwk_frame.nwk_header.clone(),
                aux_header: None,
                ciphertext: nwk_frame.payload.clone(),
            },
        }
    }

    fn increment_tx_total(&self) {
        let tx_total = {
            let mut tx_total = self.state.tx_total.try_lock_for(MAX_LOCK_DURATION).unwrap();
            *tx_total = tx_total.wrapping_add(1);
            *tx_total
        };

        // Handle `tx_total` wrapping
        if tx_total == 0x0000 {
            self.state
                .neighbors
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .reset_transmit_failures();
        }
    }

    /// The outbound route for a frame we originate, preferring stored source routes
    /// (concentrator behavior). None falls back to ad-hoc route discovery.
    fn outbound_route(&self, destination: Nwk) -> Option<Route> {
        if !self.state.is_concentrator || self.state.hack_force_route_discovery {
            return None;
        }

        // Our own end device children are always addressed directly; a stale route
        // record could otherwise outlive a device rejoining as our child
        if self.end_device_child_eui64(destination).is_some() {
            return None;
        }

        self.state
            .routing
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .route_to(destination, self.constants.max_source_route)
    }

    pub async fn send_unicast_nwk_frame(
        &self,
        mut nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        route_directly: bool,
    ) -> Result<(), ZigbeeStackError> {
        let destination = nwk_frame.nwk_header.destination;

        // Compute a next-hop address
        let next_hop_address = if route_directly {
            destination
        } else {
            match self.outbound_route(destination) {
                Some(Route::NextHop(next_hop)) => next_hop,
                Some(Route::SourceRouted(relays)) => {
                    // Spec 3.6.4.3.1: the MAC destination is the relay closest to
                    // us, which is listed last; the relay index starts at one less
                    // than the relay count
                    let next_hop = *relays.last().unwrap();
                    nwk_frame.nwk_header.frame_control.source_route = true;
                    nwk_frame.nwk_header.frame_control.discover_route = NwkRouteDiscovery::Suppress;
                    nwk_frame.nwk_header.source_route = Some(NwkSourceRoute {
                        relay_index: relays.len() as u8 - 1,
                        relays,
                    });
                    next_hop
                }
                None => self.discover_route(destination).await?,
            }
        };

        nwk_frame.nwk_header.sequence_number = self.next_nwk_sequence_number();

        let result = self
            .transmit_unicast_nwk_frame(nwk_frame, next_hop_address, security)
            .await;

        // A dead next hop invalidates every route through it and any stored source
        // route to the destination; the next transmission will rediscover
        if result.is_err() {
            self.invalidate_routes_via(next_hop_address);

            if self
                .state
                .routing
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .remove_route_record(destination)
            {
                log::info!("Removed source route to {destination:?} after delivery failure");
            }

            // Failed deliveries push the MTORR scheduler toward an early
            // advertisement; expired indirect transactions to our own sleepy
            // children are not routing failures
            if self.sleepy_child_eui64(next_hop_address).is_none() {
                self.note_delivery_failure();
            }
        }

        result
    }

    /// Wrap an encrypted NWK payload in a unicast 802.15.4 data frame. The sequence
    /// number is assigned at transmit time.
    fn build_unicast_802154_data_frame(
        &self,
        next_hop_address: Nwk,
        payload: Vec<u8>,
    ) -> Ieee802154Frame {
        Ieee802154Frame::Data(Ieee802154DataFrame {
            header: Ieee802154FrameHeader {
                frame_control: Ieee802154FrameControl {
                    frame_type: Ieee802154FrameType::Data,
                    security_enabled: false,
                    frame_pending: false,
                    ack_request: true,
                    pan_id_compression: true,
                    reserved1: false,
                    sequence_number_suppression: false,
                    information_elements_present: false,
                    dest_addr_mode: Ieee802154AddressingMode::Short,
                    frame_version: 0,
                    src_addr_mode: Ieee802154AddressingMode::Short,
                },
                sequence_number: Some(
                    *self
                        .state
                        .ieee802154_sequence_number
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap(),
                ),
                dest_pan_id: Some(*self.state.pan_id.try_lock_for(MAX_LOCK_DURATION).unwrap()),
                dest_address: Some(Ieee802154Address::Nwk(next_hop_address)),
                src_pan_id: None,
                src_address: Some(Ieee802154Address::Nwk(self.state.network_address)),
            },
            payload: FrameBytes::from_slice(&payload).expect("NWK payload is frame-bounded"),
            fcs: 0x0000, // It'll be replaced
        })
    }

    /// Secure, encrypt and wrap a fully-formed NWK frame into a transmittable
    /// 802.15.4 unicast, without sending it.
    pub(super) fn finish_unicast_nwk_frame(
        &self,
        mut nwk_frame: NwkFrame,
        next_hop_address: Nwk,
        security: NwkSecurityMode,
    ) -> Ieee802154Frame {
        self.apply_nwk_aux_header(&mut nwk_frame, security);
        let encrypted_nwk_frame = self.encrypt_nwk_frame(&mut nwk_frame, security);

        self.build_unicast_802154_data_frame(next_hop_address, encrypted_nwk_frame.to_bytes())
    }

    /// Encrypt a fully-formed NWK frame and unicast it to the given next hop, with
    /// retries. Unlike [`Self::send_unicast_nwk_frame`], the sequence number is not
    /// touched: relayed frames keep the originator's sequence number (spec 3.6.4.3).
    pub(super) async fn transmit_unicast_nwk_frame(
        &self,
        mut nwk_frame: NwkFrame,
        next_hop_address: Nwk,
        security: NwkSecurityMode,
    ) -> Result<(), ZigbeeStackError> {
        // Sleepy children cannot hear direct transmissions: the finished frame waits
        // in the indirect queue until the child polls for it. No retry loop applies;
        // the child re-polling is the retry mechanism and expiry the failure signal.
        if let Some(child_eui64) = self.sleepy_child_eui64(next_hop_address) {
            let frame = self.finish_unicast_nwk_frame(nwk_frame, next_hop_address, security);

            self.increment_tx_total();

            return self
                .queue_indirect_frame(Ieee802154Address::Eui64(child_eui64), frame)
                .await;
        }

        self.apply_nwk_aux_header(&mut nwk_frame, security);

        for attempt in 0..=self.constants.unicast_retries {
            let encrypted_nwk_frame = self.encrypt_nwk_frame(&mut nwk_frame, security);

            let ieee802154_frame = self
                .build_unicast_802154_data_frame(next_hop_address, encrypted_nwk_frame.to_bytes());

            // When forwarding packets to another node, update the counters for the neighbor
            // TODO: maybe wrap the send state into some sort of struct to avoid
            // needing to do this?
            let relaying_ieee = self
                .state
                .address_map
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .iter()
                .find_map(|(&eui64, &nwk)| {
                    if nwk == next_hop_address {
                        Some(eui64)
                    } else {
                        None
                    }
                });

            if let Some(relaying_ieee) = relaying_ieee {
                self.state
                    .neighbors
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .record_outbound_activity(relaying_ieee);
            }

            // And the routing table counters
            self.state
                .routing
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .record_usage(nwk_frame.nwk_header.destination);

            self.increment_tx_total();

            match self.send_802154_frame(ieee802154_frame).await {
                Ok(_) => {
                    break;
                }
                Err(e) => {
                    log::warn!("Failed to send unicast frame: {e}");

                    if attempt + 1 > self.constants.unicast_retries {
                        log::error!("Failed to send unicast frame after {attempt} attempts");
                        return Err(e);
                    }
                    log::debug!(
                        "Retrying unicast frame send, attempt {} of {}",
                        attempt,
                        self.constants.unicast_retries
                    );

                    tokio::time::sleep(self.constants.unicast_retry_delay).await;
                }
            }
        }

        Ok(())
    }

    pub async fn send_broadcast_nwk_frame(
        &self,
        mut nwk_frame: NwkFrame,
        security: NwkSecurityMode,
    ) -> Result<(), ZigbeeStackError> {
        nwk_frame.nwk_header.sequence_number = self.next_nwk_sequence_number();

        let key = (
            nwk_frame.nwk_header.source,
            nwk_frame.nwk_header.sequence_number,
        );

        // The passive ack contract is formed at transmission time: only routers that
        // are neighbors right now are expected to relay
        let expected_relayers = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .expected_broadcast_relayers();

        // Record our own broadcast so that copies relayed back to us by neighbors are
        // filtered instead of re-processed (spec 3.6.6)
        self.state
            .broadcast_transaction_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .insert(
                key,
                NwkBroadcastTransaction {
                    source_nwk: nwk_frame.nwk_header.source,
                    sequence_number: nwk_frame.nwk_header.sequence_number,
                    expiration_time: Instant::now() + self.constants.broadcast_delivery_time,
                    expected_relayers,
                    heard_from: HashSet::new(),
                    acked_notify: Arc::new(Notify::new()),
                },
            );

        // Spec 3.6.6: retransmit only while the passive ack quorum has not been
        // heard within the ack collection window
        for attempt in 0..=self.constants.max_broadcast_retries {
            if attempt > 0 {
                if self.await_broadcast_passive_acks(key).await {
                    log::debug!("Broadcast {key:?} passively acknowledged");
                    return Ok(());
                }

                // Fresh jitter decorrelates the retransmission wave: every router
                // that missed its acks hits the same deadline together, preserving
                // the relative timing (and collisions) of the original wave
                tokio::time::sleep(
                    self.constants
                        .max_broadcast_jitter
                        .mul_f32(rand::random::<f32>()),
                )
                .await;

                // Acks may have trickled in during the jitter sleep
                if self.broadcast_passively_acked(key) {
                    log::debug!("Broadcast {key:?} passively acknowledged");
                    return Ok(());
                }

                log::debug!(
                    "Broadcast {key:?} is missing passive acks, retransmitting \
                     (attempt {attempt} of {})",
                    self.constants.max_broadcast_retries,
                );
            }

            let _ = self
                .transmit_broadcast_nwk_frame(nwk_frame.clone(), security)
                .await;
        }

        Ok(())
    }

    /// Encrypt a fully-formed NWK frame and broadcast a single copy of it. The sequence
    /// number is not touched: relayed broadcasts and route request retries keep their
    /// original sequence number.
    pub(super) async fn transmit_broadcast_nwk_frame(
        &self,
        mut nwk_frame: NwkFrame,
        security: NwkSecurityMode,
    ) -> Result<(), ZigbeeStackError> {
        self.apply_nwk_aux_header(&mut nwk_frame, security);

        let encrypted_nwk_frame = self.encrypt_nwk_frame(&mut nwk_frame, security);

        let ieee802154_frame = Ieee802154Frame::Data(Ieee802154DataFrame {
            header: Ieee802154FrameHeader {
                frame_control: Ieee802154FrameControl {
                    frame_type: Ieee802154FrameType::Data,
                    security_enabled: false,
                    frame_pending: false,
                    ack_request: false,
                    pan_id_compression: true,
                    reserved1: false,
                    sequence_number_suppression: false,
                    information_elements_present: false,
                    dest_addr_mode: Ieee802154AddressingMode::Short,
                    frame_version: 0,
                    src_addr_mode: Ieee802154AddressingMode::Short,
                },
                sequence_number: Some(
                    *self
                        .state
                        .ieee802154_sequence_number
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap(),
                ),
                dest_pan_id: Some(*self.state.pan_id.try_lock_for(MAX_LOCK_DURATION).unwrap()),
                // All broadcasts are sent to the 802.15.4 broadcast address, since the
                // distinction between Zigbee groups and broadcasts is at a higher layer
                dest_address: Some(Ieee802154Address::Nwk(Nwk(0xFFFF))),
                src_pan_id: None,
                src_address: Some(Ieee802154Address::Nwk(self.state.network_address)),
            },
            payload: FrameBytes::from_slice(&encrypted_nwk_frame.to_bytes())
                .expect("an encrypted NWK frame is frame-bounded"),
            fcs: 0x0000, // It'll be replaced
        });

        self.increment_tx_total();

        self.send_802154_frame(ieee802154_frame).await
    }

    /// Zigbee spec 3.6.4.3: relay a unicast frame addressed to another device.
    pub(super) fn relay_unicast_nwk_frame(
        &self,
        mut nwk_frame: NwkFrame,
        sender_nwk: Nwk,
        lqi: u8,
        rssi: i8,
    ) {
        // Update the frame counter for the relaying device, exactly as for frames
        // addressed to us
        if let Some(aux_header) = &nwk_frame.aux_header
            && let Some(relaying_eui64) = aux_header.extended_source
        {
            self.state
                .security_material_primary
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .incoming_frame_counter_set
                .insert(relaying_eui64, aux_header.frame_counter);
        }

        // Transit frames are link quality measurements for the transmitting neighbor
        // just like frames addressed to us
        self.maybe_recompute_lqa(sender_nwk, lqi, rssi);

        // Receiving a unicast from a neighbor counts as inbound activity
        self.state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .record_inbound_activity(sender_nwk);

        // Spec 3.6.2.2: the radius is decremented on receipt and a frame that reaches
        // zero is never retransmitted
        nwk_frame.nwk_header.radius = nwk_frame.nwk_header.radius.saturating_sub(1);
        if nwk_frame.nwk_header.radius == 0 {
            log::debug!("Not relaying frame, radius is exhausted");
            return;
        }

        let destination = nwk_frame.nwk_header.destination;

        // Spec 3.6.4.5.5: each relay appends its network address to a transiting
        // route record command before forwarding it
        if nwk_frame.nwk_header.frame_control.frame_type == NwkFrameType::Command
            && matches!(
                nwk_frame
                    .payload
                    .first()
                    .map(|&id| NwkCommandId::try_from(id)),
                Some(Ok(NwkCommandId::RouteRecord))
            )
        {
            let mut route_record_cmd = match NwkRouteRecordCommand::deserialize(&nwk_frame.payload)
            {
                Ok(cmd) => cmd,
                Err(err) => {
                    log::warn!("Dropping malformed transiting route record: {err:?}");
                    return;
                }
            };

            route_record_cmd.relays.push(self.state.network_address);
            nwk_frame.payload = FrameBytes::from_slice(&route_record_cmd.serialize().unwrap())
                .expect("a relayed route record is frame-bounded");
        }

        let next_hop_address = if let Some(source_route) = &mut nwk_frame.nwk_header.source_route {
            // Spec 3.6.4.3.2: a source-routed frame names its own path; the relay
            // list is followed instead of the routing table
            let index = usize::from(source_route.relay_index);

            let next_hop = if index == 0 {
                // The final relay forwards directly to the NWK destination
                destination
            } else {
                if source_route.relays.get(index) != Some(&self.state.network_address) {
                    log::debug!("Dropping source routed frame not addressed through us");
                    return;
                }

                source_route.relay_index -= 1;
                source_route.relays[index - 1]
            };

            // Delivery to our own end device child skips the rest of the relay list
            let next_hop = if self.end_device_child_eui64(destination).is_some() {
                destination
            } else {
                next_hop
            };

            self.state
                .routing
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .note_source_routed_frame(nwk_frame.nwk_header.source);

            next_hop
        } else if self.is_neighbor(destination) {
            // Children and direct neighbors are addressed directly, everything else
            // goes through the routing table
            destination
        } else {
            let next_hop = self
                .state
                .routing
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .next_hop(destination);

            match next_hop {
                Some(next_hop) => next_hop,
                None => {
                    log::debug!("No active route to relay frame to {destination:?}, dropping");
                    return;
                }
            }
        };

        log::debug!(
            "Relaying frame from {:?} to {destination:?} via {next_hop_address:?}",
            nwk_frame.nwk_header.source
        );

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            // The originator's sequence number is preserved when relaying
            if let Err(err) = arc_self
                .transmit_unicast_nwk_frame(
                    nwk_frame.clone(),
                    next_hop_address,
                    NwkSecurityMode::NetworkKey,
                )
                .await
            {
                log::warn!(
                    "Failed to relay frame to {destination:?} via {next_hop_address:?}: {err}"
                );
                arc_self.handle_relay_failure(&nwk_frame, next_hop_address);
            }
        });
    }

    /// Zigbee spec 3.6.4.8.1: when relaying fails, the routes through the dead link are
    /// invalidated and the failure is reported back to the frame's originator.
    fn handle_relay_failure(&self, nwk_frame: &NwkFrame, next_hop: Nwk) {
        self.invalidate_routes_via(next_hop);

        let source = nwk_frame.nwk_header.source;

        let destination_ieee = self
            .state
            .address_map
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .iter()
            .find_map(|(&eui64, &nwk)| if nwk == source { Some(eui64) } else { None });

        // Spec 3.6.4.8.1: failures while relaying along a source route are reported
        // as such, so the concentrator can drop the stored route
        let status_code = if nwk_frame.nwk_header.source_route.is_some() {
            NwkNetworkStatus::SourceRouteFailure
        } else {
            NwkNetworkStatus::LinkFailure
        };

        let network_status_frame = self
            .nwk_command_frame(
                source,
                NwkNetworkStatusCommand {
                    status_code,
                    network_address: nwk_frame.nwk_header.destination,
                }
                .serialize()
                .unwrap(),
            )
            .with_destination_ieee(destination_ieee);

        self.background_send_nwk_frame(network_status_frame, NwkSecurityMode::NetworkKey, false);
    }

    /// Zigbee spec 3.6.6: re-broadcast a newly seen broadcast frame after a random
    /// jitter, preserving the originator's source address and sequence number.
    fn maybe_relay_broadcast(&self, nwk_frame: &NwkFrame) {
        // Broadcast NWK commands are not generically relayed: link status and leave
        // frames have a radius of 1, and route requests accumulate path cost in their
        // own relay logic
        if nwk_frame.nwk_header.frame_control.frame_type != NwkFrameType::Data {
            return;
        }

        // Our own broadcasts are relayed back to us by neighbors
        if nwk_frame.nwk_header.source == self.state.network_address {
            return;
        }

        let mut relayed_frame = nwk_frame.clone();

        relayed_frame.nwk_header.radius = relayed_frame.nwk_header.radius.saturating_sub(1);
        if relayed_frame.nwk_header.radius == 0 {
            log::debug!("Not relaying broadcast, radius is exhausted");
            return;
        }

        let key = (
            relayed_frame.nwk_header.source,
            relayed_frame.nwk_header.sequence_number,
        );

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            // The relay is jittered to avoid synchronized rebroadcasts (spec 3.6.6)
            tokio::time::sleep(
                arc_self
                    .constants
                    .max_broadcast_jitter
                    .mul_f32(rand::random::<f32>()),
            )
            .await;

            // Retransmissions follow the same passive acknowledgment rule as our own
            // broadcasts; the neighbor we heard the frame from is already counted
            for attempt in 0..=arc_self.constants.max_broadcast_retries {
                if attempt > 0 {
                    if arc_self.await_broadcast_passive_acks(key).await {
                        log::debug!("Relayed broadcast {key:?} passively acknowledged");
                        return;
                    }

                    // Fresh jitter decorrelates the retransmission wave, which is
                    // synchronized by the shared ack deadline
                    tokio::time::sleep(
                        arc_self
                            .constants
                            .max_broadcast_jitter
                            .mul_f32(rand::random::<f32>()),
                    )
                    .await;

                    // Acks may have trickled in during the jitter sleep
                    if arc_self.broadcast_passively_acked(key) {
                        log::debug!("Relayed broadcast {key:?} passively acknowledged");
                        return;
                    }
                }

                if let Err(err) = arc_self
                    .transmit_broadcast_nwk_frame(
                        relayed_frame.clone(),
                        NwkSecurityMode::NetworkKey,
                    )
                    .await
                {
                    log::warn!("Failed to relay broadcast: {err}");
                }
            }
        });
    }
}
