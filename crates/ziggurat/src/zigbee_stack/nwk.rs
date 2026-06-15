use crate::ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154DataFrame, Ieee802154Frame,
    Ieee802154FrameControl, Ieee802154FrameHeader, Ieee802154FrameType,
};
use ieee_802154::FrameBytes;
use ieee_802154::types::{Eui64, Nwk};
use spinel::client::TxPriority;
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
    AddrConflictSource, MAX_DEPTH, NwkSecurityMode, PROTOCOL_VERSION, SendMode, ZigbeeStack,
    ZigbeeStackError,
};

impl ZigbeeStack {
    pub fn update_nwk_eui64_mapping(&self, nwk: Nwk, eui64: Eui64) {
        let conflict = self.core().nib.address_map.update_mapping(eui64, nwk);

        if conflict {
            self.handle_address_conflict(nwk, AddrConflictSource::Local);
        }
    }

    /// Filter broadcast frames based on the NWK broadcast transaction table
    pub fn filter_broadcast(&self, nwk_frame: &NwkFrame, sender_nwk: Nwk) -> bool {
        let now = Instant::now();

        // We cannot handle broadcasts until the network has been running for at least
        // the time it takes to deliver one broadcast
        if !self.state.hack_ignore_broadcast_startup_wait_period
            && (self.state.start_time + self.tunables.broadcast_delivery_time > now)
        {
            tracing::debug!("Filtering broadcast, network started too recently.");
            return true;
        }

        // The passive ack contract is formed when the transaction is created: only
        // routers that were neighbors at that point are expected to relay
        let mut core = self.core();
        let audience = core.nib.neighbors.expected_broadcast_relayers();

        let duplicate = core.nib.broadcasts.filter_received(
            nwk_frame.nwk_header.source,
            nwk_frame.nwk_header.sequence_number,
            sender_nwk,
            audience,
            now.into_std(),
        );
        drop(core);

        if duplicate {
            // A duplicate is its sender's passive ack: retransmission loops
            // re-evaluate completeness
            self.broadcast_acked.notify_waiters();
        }

        duplicate
    }

    /// Wait until the broadcast is passively acknowledged or the ack collection
    /// window closes, waking on every recorded ack. Returns whether the broadcast
    /// is acknowledged.
    async fn await_broadcast_passive_acks(&self, key: (Nwk, u8)) -> bool {
        let deadline = Instant::now() + self.tunables.passive_ack_timeout;

        loop {
            if self.broadcast_passively_acked(key) {
                return true;
            }

            if timeout_at(deadline, self.broadcast_acked.notified())
                .await
                .is_err()
            {
                // The window closed; an ack recorded at the boundary still counts
                return self.broadcast_passively_acked(key);
            }
        }
    }

    /// Whether the broadcast's passive ack quorum has been heard from the audience
    /// members that are still live neighbors.
    fn broadcast_passively_acked(&self, key: (Nwk, u8)) -> bool {
        let core = self.core();
        let live_relayers = core.nib.neighbors.expected_broadcast_relayers();

        core.nib
            .broadcasts
            .passively_acked(key.0, key.1, &live_relayers)
    }

    pub fn handle_decrypted_frame(&self, nwk_frame: &NwkFrame, sender_nwk: Nwk, lqi: u8, rssi: i8) {
        // Update the frame counter for the relaying device
        if let Some(aux_header) = &nwk_frame.aux_header
            && let Some(relaying_eui64) = aux_header.extended_source
        {
            let old_frame_counter = self
                .core()
                .nib
                .nwk_security
                .note_inbound_frame_counter(relaying_eui64, aux_header.frame_counter);

            tracing::debug!(
                "Incremented frame counter for {relaying_eui64:?} from {:?} to {}",
                old_frame_counter,
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
            self.handle_address_conflict(self.state.network_address, AddrConflictSource::Local);
        }

        // Handle LQA calculation
        self.maybe_age_neighbors();
        self.maybe_recompute_lqa(sender_nwk, lqi, rssi);

        // Network input may never panic: a command frame with no command byte is
        // malformed and dropped
        if nwk_frame.nwk_header.frame_control.frame_type == NwkFrameType::Command
            && nwk_frame.payload.is_empty()
        {
            tracing::warn!("Ignoring NWK command frame with an empty payload");
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
                tracing::debug!("Filtering broadcast, stopping further processing");
                return;
            }

            // Spec 3.6.1.10.2: a fresh broadcast claiming our address as its source
            // means another device is using our address. Our own broadcasts never
            // reach this point: the send path pre-fills the transaction table. The
            // frame is discarded instead of relayed (3.6.1.10).
            if nwk_frame.nwk_header.source == self.state.network_address {
                if self.state.start_time + self.tunables.broadcast_delivery_time < Instant::now() {
                    self.handle_address_conflict(
                        self.state.network_address,
                        AddrConflictSource::Local,
                    );
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
                                tracing::warn!("Failed to parse route record command: {err:?}");
                                return;
                            }
                        };
                    tracing::debug!("Route record command frame received: {route_record_cmd:?}");
                    self.core()
                        .nib
                        .routing
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
                    tracing::warn!("Unknown NWK command: {}", nwk_frame.payload[0]);
                }
                _ => {
                    tracing::warn!("Unhandled NWK command: {:?}", nwk_frame.payload[0]);
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
                    protocol_version: PROTOCOL_VERSION,
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
                radius: 2 * MAX_DEPTH,
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
                    protocol_version: PROTOCOL_VERSION,
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
                radius: 2 * MAX_DEPTH,
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
        route_directly: SendMode,
    ) {
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            arc_self
                .send_nwk_frame(nwk_frame, security, route_directly, TxPriority::USER_NORMAL)
                .await
                .unwrap_or_else(|err| {
                    tracing::error!("Failed to send NWK frame: {err}");
                });
        });
    }

    pub async fn send_nwk_frame(
        &self,
        nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        route_directly: SendMode,
        priority: TxPriority,
    ) -> Result<(), ZigbeeStackError> {
        if nwk_frame.nwk_header.destination.as_u16() >= BROADCAST_LOW_POWER_ROUTERS.as_u16() {
            self.send_broadcast_nwk_frame(nwk_frame, security, priority)
                .await
        } else {
            self.send_unicast_nwk_frame(nwk_frame, security, route_directly, priority)
                .await
        }
    }

    pub(super) fn next_nwk_sequence_number(&self) -> u8 {
        let mut core = self.core();
        core.nib.sequence_number = core.nib.sequence_number.wrapping_add(1);
        core.nib.sequence_number
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
                key_sequence_number: self.core().nib.nwk_security.active_key_seq_number(),
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

                nwk_frame.encrypt(&self.core().nib.nwk_security.network_key())
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
            let mut core = self.core();
            core.nib.tx_total = core.nib.tx_total.wrapping_add(1);
            core.nib.tx_total
        };

        // Handle `tx_total` wrapping
        if tx_total == 0x0000 {
            self.core().nib.neighbors.reset_transmit_failures();
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

        self.core()
            .nib
            .routing
            .route_to(destination, self.tunables.max_source_route)
    }

    pub async fn send_unicast_nwk_frame(
        &self,
        mut nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        route_directly: SendMode,
        priority: TxPriority,
    ) -> Result<(), ZigbeeStackError> {
        let destination = nwk_frame.nwk_header.destination;

        // Compute a next-hop address
        let next_hop_address = if route_directly == SendMode::Direct {
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
            .transmit_unicast_nwk_frame(nwk_frame, next_hop_address, security, priority)
            .await;

        // A dead next hop invalidates every route through it and any stored source
        // route to the destination; the next transmission will rediscover
        if result.is_err() {
            self.invalidate_routes_via(next_hop_address);

            if self.core().nib.routing.remove_route_record(destination) {
                tracing::info!("Removed source route to {destination:?} after delivery failure");
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
    fn build_unicast_802154_data_frame<P>(
        &self,
        next_hop_address: Nwk,
        payload: P,
    ) -> Ieee802154Frame<P> {
        let (ieee802154_sequence_number, pan_id) = {
            let core = self.core();
            (core.mac.ieee802154_sequence_number, core.mac.pan_id)
        };
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
                sequence_number: Some(ieee802154_sequence_number),
                dest_pan_id: Some(pan_id),
                dest_address: Some(Ieee802154Address::Nwk(next_hop_address)),
                src_pan_id: None,
                src_address: Some(Ieee802154Address::Nwk(self.state.network_address)),
            },
            payload,
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
    ) -> Ieee802154Frame<EncryptedNwkFrame> {
        self.apply_nwk_aux_header(&mut nwk_frame, security);
        let encrypted_nwk_frame = self.encrypt_nwk_frame(&mut nwk_frame, security);

        self.build_unicast_802154_data_frame(next_hop_address, encrypted_nwk_frame)
    }

    /// Encrypt a fully-formed NWK frame and unicast it to the given next hop, with
    /// retries. Unlike [`Self::send_unicast_nwk_frame`], the sequence number is not
    /// touched: relayed frames keep the originator's sequence number (spec 3.6.4.3).
    pub(super) async fn transmit_unicast_nwk_frame(
        &self,
        mut nwk_frame: NwkFrame,
        next_hop_address: Nwk,
        security: NwkSecurityMode,
        priority: TxPriority,
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

        for attempt in 0..=self.tunables.unicast_retries {
            let encrypted_nwk_frame = self.encrypt_nwk_frame(&mut nwk_frame, security);
            let ieee802154_frame =
                self.build_unicast_802154_data_frame(next_hop_address, encrypted_nwk_frame);

            // When forwarding packets to another node, update the counters for the neighbor
            // TODO: maybe wrap the send state into some sort of struct to avoid
            // needing to do this?
            {
                let mut core = self.core();
                let relaying_ieee = core.nib.address_map.eui64_for(next_hop_address);

                if let Some(relaying_ieee) = relaying_ieee {
                    core.nib.neighbors.record_outbound_activity(relaying_ieee);
                }

                // And the routing table counters
                core.nib
                    .routing
                    .record_usage(nwk_frame.nwk_header.destination);
            }

            self.increment_tx_total();

            match self.send_802154_frame(ieee802154_frame, priority).await {
                Ok(_) => {
                    break;
                }
                Err(e) => {
                    tracing::warn!("Failed to send unicast frame: {e}");

                    if attempt + 1 > self.tunables.unicast_retries {
                        tracing::error!("Failed to send unicast frame after {attempt} attempts");
                        return Err(e);
                    }
                    tracing::debug!(
                        "Retrying unicast frame send, attempt {} of {}",
                        attempt,
                        self.tunables.unicast_retries
                    );

                    tokio::time::sleep(self.tunables.unicast_retry_delay).await;
                }
            }
        }

        Ok(())
    }

    pub async fn send_broadcast_nwk_frame(
        &self,
        mut nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        priority: TxPriority,
    ) -> Result<(), ZigbeeStackError> {
        nwk_frame.nwk_header.sequence_number = self.next_nwk_sequence_number();

        let key = (
            nwk_frame.nwk_header.source,
            nwk_frame.nwk_header.sequence_number,
        );

        // The passive ack contract is formed at transmission time: only routers that
        // are neighbors right now are expected to relay
        {
            let mut core = self.core();
            let audience = core.nib.neighbors.expected_broadcast_relayers();

            core.nib.broadcasts.record_transmission(
                key.0,
                key.1,
                audience,
                Instant::now().into_std(),
            );
        }

        // Spec 3.6.6: retransmit only while the passive ack quorum has not been
        // heard within the ack collection window
        for attempt in 0..=self.tunables.max_broadcast_retries {
            if attempt > 0 {
                if self.await_broadcast_passive_acks(key).await {
                    tracing::debug!("Broadcast {key:?} passively acknowledged");
                    return Ok(());
                }

                // Fresh jitter decorrelates the retransmission wave: every router
                // that missed its acks hits the same deadline together, preserving
                // the relative timing (and collisions) of the original wave
                tokio::time::sleep(
                    self.tunables
                        .max_broadcast_jitter
                        .mul_f32(rand::random::<f32>()),
                )
                .await;

                // Acks may have trickled in during the jitter sleep
                if self.broadcast_passively_acked(key) {
                    tracing::debug!("Broadcast {key:?} passively acknowledged");
                    return Ok(());
                }

                tracing::debug!(
                    "Broadcast {key:?} is missing passive acks, retransmitting \
                     (attempt {attempt} of {})",
                    self.tunables.max_broadcast_retries,
                );
            }

            let _ = self
                .transmit_broadcast_nwk_frame(nwk_frame.clone(), security, priority)
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
        priority: TxPriority,
    ) -> Result<(), ZigbeeStackError> {
        self.apply_nwk_aux_header(&mut nwk_frame, security);

        let encrypted_nwk_frame = self.encrypt_nwk_frame(&mut nwk_frame, security);

        let (ieee802154_sequence_number, pan_id) = {
            let core = self.core();
            (core.mac.ieee802154_sequence_number, core.mac.pan_id)
        };

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
                sequence_number: Some(ieee802154_sequence_number),
                dest_pan_id: Some(pan_id),
                // All broadcasts are sent to the 802.15.4 broadcast address, since the
                // distinction between Zigbee groups and broadcasts is at a higher layer
                dest_address: Some(Ieee802154Address::Nwk(Nwk(0xFFFF))),
                src_pan_id: None,
                src_address: Some(Ieee802154Address::Nwk(self.state.network_address)),
            },
            payload: encrypted_nwk_frame,
            fcs: 0x0000, // It'll be replaced
        });

        self.increment_tx_total();

        self.send_802154_frame(ieee802154_frame, priority).await
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
            self.core()
                .nib
                .nwk_security
                .note_inbound_frame_counter(relaying_eui64, aux_header.frame_counter);
        }

        // Transit frames are link quality measurements for the transmitting neighbor
        // just like frames addressed to us
        self.maybe_recompute_lqa(sender_nwk, lqi, rssi);

        // Receiving a unicast from a neighbor counts as inbound activity
        self.core()
            .nib
            .neighbors
            .record_inbound_activity(sender_nwk);

        // Spec 3.6.2.2: the radius is decremented on receipt and a frame that reaches
        // zero is never retransmitted
        nwk_frame.nwk_header.radius = nwk_frame.nwk_header.radius.saturating_sub(1);
        if nwk_frame.nwk_header.radius == 0 {
            tracing::debug!("Not relaying frame, radius is exhausted");
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
                    tracing::warn!("Dropping malformed transiting route record: {err:?}");
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
                    tracing::debug!("Dropping source routed frame not addressed through us");
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

            self.core()
                .nib
                .routing
                .note_source_routed_frame(nwk_frame.nwk_header.source);

            next_hop
        } else if self.is_neighbor(destination) {
            // Children and direct neighbors are addressed directly, everything else
            // goes through the routing table
            destination
        } else {
            let next_hop = self.core().nib.routing.next_hop(destination);

            match next_hop {
                Some(next_hop) => next_hop,
                None => {
                    tracing::debug!("No active route to relay frame to {destination:?}, dropping");
                    return;
                }
            }
        };

        tracing::debug!(
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
                    TxPriority::USER_NORMAL,
                )
                .await
            {
                tracing::warn!(
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

        let destination_ieee = self.core().nib.address_map.eui64_for(source);

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

        self.background_send_nwk_frame(
            network_status_frame,
            NwkSecurityMode::NetworkKey,
            SendMode::Route,
        );
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
            tracing::debug!("Not relaying broadcast, radius is exhausted");
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
                    .tunables
                    .max_broadcast_jitter
                    .mul_f32(rand::random::<f32>()),
            )
            .await;

            // Retransmissions follow the same passive acknowledgment rule as our own
            // broadcasts; the neighbor we heard the frame from is already counted
            for attempt in 0..=arc_self.tunables.max_broadcast_retries {
                if attempt > 0 {
                    if arc_self.await_broadcast_passive_acks(key).await {
                        tracing::debug!("Relayed broadcast {key:?} passively acknowledged");
                        return;
                    }

                    // Fresh jitter decorrelates the retransmission wave, which is
                    // synchronized by the shared ack deadline
                    tokio::time::sleep(
                        arc_self
                            .tunables
                            .max_broadcast_jitter
                            .mul_f32(rand::random::<f32>()),
                    )
                    .await;

                    // Acks may have trickled in during the jitter sleep
                    if arc_self.broadcast_passively_acked(key) {
                        tracing::debug!("Relayed broadcast {key:?} passively acknowledged");
                        return;
                    }
                }

                if let Err(err) = arc_self
                    .transmit_broadcast_nwk_frame(
                        relayed_frame.clone(),
                        NwkSecurityMode::NetworkKey,
                        TxPriority::USER_NORMAL,
                    )
                    .await
                {
                    tracing::warn!("Failed to relay broadcast: {err}");
                }
            }
        });
    }
}
