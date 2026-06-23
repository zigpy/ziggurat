use crate::runtime::{Elapsed, Runtime};
use crate::ziggurat_ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154DataFrame, Ieee802154Frame,
    Ieee802154FrameControl, Ieee802154FrameHeader, Ieee802154FrameType,
};
use std::sync::atomic::Ordering as AtomicOrdering;
use tokio::sync::oneshot;
use ziggurat_ieee_802154::FrameBytes;
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::{RadioPhy, TxResult};
use ziggurat_zigbee::Instant as CoreInstant;
use ziggurat_zigbee::nwk::commands::{
    NwkCommand, NwkCommandId, NwkEndDeviceTimeoutResponseStatus, NwkNetworkStatus,
    NwkNetworkStatusCommand,
};
use ziggurat_zigbee::nwk::frame::{
    BROADCAST_ALL_DEVICES, BROADCAST_ALL_ROUTERS_AND_COORDINATOR, BROADCAST_LOW_POWER_ROUTERS,
    EncryptedNwkFrame, NwkAuxHeader, NwkFrame, NwkFrameControl, NwkFrameType, NwkHeader,
    NwkPayload, NwkRouteDiscovery, NwkSecurityHeaderControlField, NwkSecurityHeaderKeyId,
    NwkSecurityLevel, NwkSourceRoute,
};

use super::routing::{Route, Status as RouteStatus};
use super::{
    AddrConflictSource, LOCK_ACQUIRE_TIMEOUT, MAX_DEPTH, NwkSecurityMode, PROTOCOL_VERSION,
    PendingFrame, PendingRoute, SendKind, SendMode, SendRequest, TxCompletion, TxPriority,
    ZigbeeStack, ZigbeeStackError,
};

/// The outcome of resolving a unicast's MAC next hop without blocking (see
/// [`ZigbeeStack::resolve_next_hop`]).
enum NextHop {
    /// Transmit to this next hop now.
    Resolved(Nwk),
    /// No route known; the frame must wait for route discovery.
    NeedDiscovery,
    /// No route known and the frame's `discover_route` flag forbids discovering one.
    Discard,
}

/// Where a queued destination's route discovery stands when the reactor inspects it (see
/// [`ZigbeeStack::discovery_state`]).
enum DiscoveryState {
    /// A route is active; the queued frames can be sent.
    Resolved,
    /// Discovery is not progressing: its window elapsed, it failed, or no entry exists.
    Lapsed,
    /// Discovery is still in flight with time remaining.
    InFlight,
}

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    pub fn update_nwk_eui64_mapping(&self, nwk: Nwk, eui64: Eui64) {
        let conflict = self.core().nib.address_map.update_mapping(eui64, nwk);

        if conflict {
            self.handle_address_conflict(nwk, AddrConflictSource::Local);
        }
    }

    /// Filter broadcast frames based on the NWK broadcast transaction table
    pub fn filter_broadcast(&self, nwk_frame: &NwkFrame, sender_nwk: Nwk) -> bool {
        let now = self.core_now();

        // We cannot handle broadcasts until the network has been running for at least
        // the time it takes to deliver one broadcast (core time starts at zero).
        if !self.state.hack_ignore_broadcast_startup_wait_period
            && (CoreInstant::from_micros(0) + self.tunables.broadcast_delivery_time > now)
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
            now,
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
        let deadline = self.core_now() + self.tunables.passive_ack_timeout;

        loop {
            if self.broadcast_passively_acked(key) {
                return true;
            }

            if self
                .timeout_at_core(deadline, self.broadcast_acked.notified())
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

        // Spec 3.6.6: link status and route request broadcasts bypass the broadcast
        // transaction table; route requests have their own cost-comparing dedup logic
        // and relayed copies share the originator's sequence number
        let bypasses_transaction_table = matches!(
            &nwk_frame.payload,
            NwkPayload::Command(NwkCommand::RouteRequest(_) | NwkCommand::LinkStatus(_))
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
                if CoreInstant::from_micros(0) + self.tunables.broadcast_delivery_time
                    < self.core_now()
                {
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
        if let NwkPayload::Command(command) = &nwk_frame.payload {
            match command {
                NwkCommand::LinkStatus(cmd) => self.handle_link_status(nwk_frame, cmd.clone(), lqi),
                NwkCommand::RouteReply(cmd) => self.handle_route_reply(nwk_frame, cmd.clone()),
                NwkCommand::RouteRecord(cmd) => {
                    tracing::debug!("Route record command frame received: {cmd:?}");
                    self.core()
                        .nib
                        .routing
                        .store_route_record(nwk_frame.nwk_header.source, cmd.relays.clone());
                }
                NwkCommand::RouteRequest(cmd) => {
                    self.handle_route_request(nwk_frame, cmd.clone(), sender_nwk);
                }
                NwkCommand::RejoinRequest(cmd) => {
                    self.handle_rejoin_request(nwk_frame, cmd.clone(), true);
                }
                NwkCommand::Leave(cmd) => self.handle_leave(nwk_frame, cmd.clone()),
                NwkCommand::NetworkStatus(cmd) => {
                    self.handle_network_status(nwk_frame, cmd.clone())
                }
                NwkCommand::EndDeviceTimeoutRequest(cmd) => {
                    self.handle_end_device_timeout_request(nwk_frame, cmd.clone());
                }
                // Spec 3.6.10.2: a timeout request whose enumeration is out of range fails
                // to parse, but still gets a courtesy response naming the incorrect value
                NwkCommand::Unparsed(raw)
                    if raw.first().copied().map(NwkCommandId::try_from)
                        == Some(Ok(NwkCommandId::EndDeviceTimeoutRequest)) =>
                {
                    self.send_end_device_timeout_response(
                        nwk_frame.nwk_header.source,
                        NwkEndDeviceTimeoutResponseStatus::IncorrectValue,
                    );
                }
                NwkCommand::Unparsed(raw) => {
                    tracing::warn!("Ignoring unparseable NWK command: {raw:02x?}");
                }
                other => {
                    tracing::warn!("Unhandled NWK command: {:?}", other.command_id());
                }
            }
        }
    }

    /// A NWK command frame originated by us, with stack-wide defaults: secured, route
    /// discovery suppressed, radius `2 * max_depth`, sequence number assigned on send,
    /// our EUI64 as the extended source. Deviations chain `with_*` overrides.
    pub(super) const fn nwk_command_frame(
        &self,
        destination: Nwk,
        command: NwkCommand,
    ) -> NwkFrame {
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
                    reserved1: 0,
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
            payload: NwkPayload::Command(command),
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
                    reserved1: 0,
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
            payload: NwkPayload::Opaque(
                FrameBytes::from_slice(&payload).expect("NWK payload is frame-bounded"),
            ),
        }
    }

    /// Fire-and-forget originate of a unicast NWK frame at normal priority. Nothing is
    /// awaited, so a failed transmit is handled by the sender, not reported back here.
    /// Unicast only; broadcasts go through [`Self::send_broadcast_nwk_frame`].
    pub fn background_send_nwk_frame(
        &self,
        nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        mode: SendMode,
    ) {
        debug_assert!(
            nwk_frame.nwk_header.destination.as_u16() < BROADCAST_LOW_POWER_ROUTERS.as_u16(),
            "background_send_nwk_frame is unicast only; got broadcast {:?}",
            nwk_frame.nwk_header.destination
        );
        self.originate_unicast(nwk_frame, security, mode, TxPriority::USER_NORMAL, None);
    }

    /// Originate a unicast: assign its NWK sequence number, resolve a next hop, and
    /// either enqueue it, queue it awaiting route discovery, or drop it
    /// (discovery suppressed).
    fn originate_unicast(
        &self,
        mut nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        mode: SendMode,
        priority: TxPriority,
        completion: Option<TxCompletion>,
    ) {
        let destination = nwk_frame.nwk_header.destination;
        nwk_frame.nwk_header.sequence_number = self.next_nwk_sequence_number();

        match self.resolve_next_hop(&mut nwk_frame, mode) {
            NextHop::Resolved(next_hop) => {
                self.enqueue_unicast(nwk_frame, next_hop, security, priority, completion);
            }
            NextHop::NeedDiscovery => {
                self.enqueue_awaiting_route(nwk_frame, security, priority, completion)
            }
            NextHop::Discard => {
                tracing::debug!(
                    "Dropping frame to {destination:?}: no route and discovery suppressed"
                );
                if let Some(completion) = completion {
                    let _ = completion.send(Err(ZigbeeStackError::RouteDiscoverySuppressed));
                }
            }
        }
    }

    /// Resolve the MAC next hop for a unicast without ever blocking. A source-routed
    /// result rewrites `nwk_frame`'s header in place (spec 3.6.4.3.1). When no route is
    /// known the frame's `discover_route` flag decides between discovery and discard.
    fn resolve_next_hop(&self, nwk_frame: &mut NwkFrame, mode: SendMode) -> NextHop {
        let destination = nwk_frame.nwk_header.destination;

        if mode == SendMode::Direct {
            return NextHop::Resolved(destination);
        }

        // End device children never route-discover; their parent delivers directly.
        if self.end_device_child_eui64(destination).is_some() {
            return NextHop::Resolved(destination);
        }

        // A stored source route (concentrator behavior) wins over the routing table.
        match self.outbound_route(destination) {
            Some(Route::NextHop(next_hop)) => return NextHop::Resolved(next_hop),
            Some(Route::SourceRouted(relays)) => {
                // Spec 3.6.4.3.1: the MAC destination is the relay closest to us, listed
                // last; the relay index starts one below the relay count.
                let next_hop = *relays.last().unwrap();
                nwk_frame.nwk_header.frame_control.source_route = true;
                nwk_frame.nwk_header.frame_control.discover_route = NwkRouteDiscovery::Suppress;
                nwk_frame.nwk_header.source_route = Some(NwkSourceRoute {
                    relay_index: relays.len() as u8 - 1,
                    relays,
                });
                return NextHop::Resolved(next_hop);
            }
            None => {}
        }

        // An active ad-hoc route, unless we are deliberately forcing rediscovery.
        if !self.state.hack_force_route_discovery {
            let core = self.core();
            if core.nib.routing.route_status(destination) == Some(RouteStatus::Active)
                && let Some(next_hop) = core.nib.routing.next_hop(destination)
            {
                return NextHop::Resolved(next_hop);
            }
        }

        // No usable route. Spec 3.6.3.3: only initiate discovery if the frame allows it.
        if nwk_frame.nwk_header.frame_control.discover_route == NwkRouteDiscovery::Suppress {
            NextHop::Discard
        } else {
            NextHop::NeedDiscovery
        }
    }

    pub async fn send_nwk_frame(
        &self,
        nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        mode: SendMode,
        priority: TxPriority,
    ) -> Result<(), ZigbeeStackError> {
        if nwk_frame.nwk_header.destination.as_u16() >= BROADCAST_LOW_POWER_ROUTERS.as_u16() {
            self.send_broadcast_nwk_frame(nwk_frame, security, priority)
                .await
        } else {
            self.send_unicast_nwk_frame(nwk_frame, security, mode, priority)
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
                ciphertext: nwk_frame.payload.to_bytes(),
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

    /// Originate a unicast and await its delivery result. The completion resolves once
    /// the frame leaves the radio (or, for a sleepy child, once it polls), or with an
    /// error on transmit failure, route-discovery failure, or discovery being
    /// suppressed.
    pub async fn send_unicast_nwk_frame(
        &self,
        nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        mode: SendMode,
        priority: TxPriority,
    ) -> Result<(), ZigbeeStackError> {
        let (completion_tx, completion_rx) = oneshot::channel();
        self.originate_unicast(nwk_frame, security, mode, priority, Some(completion_tx));
        completion_rx
            .await
            .unwrap_or(Err(ZigbeeStackError::TransmitFailed(TxResult::Aborted)))
    }

    /// Wrap an encrypted NWK payload in a unicast 802.15.4 data frame. The sequence
    /// number is assigned at transmit time.
    fn build_unicast_802154_data_frame<Payload>(
        &self,
        next_hop_address: Nwk,
        payload: Payload,
    ) -> Ieee802154Frame<Payload> {
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

    /// Enqueue a send into the priority queue and wake the sender task.
    pub(super) fn enqueue_send(
        &self,
        kind: SendKind,
        priority: TxPriority,
        completion: Option<TxCompletion>,
    ) {
        let seq = self.send_seq.fetch_add(1, AtomicOrdering::Relaxed);
        self.send_queue
            .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
            .unwrap()
            .push(SendRequest {
                seq,
                priority,
                kind,
                completion,
            });
        self.send_wake.notify_one();
    }

    /// Enqueue a unicast whose next hop is already resolved. A sleepy child goes to the
    /// indirect queue. Everything else goes to the sender, which encrypts and retries
    /// at dequeue so frame-counter order matches on-air order. The NWK sequence number
    /// is left untouched: relayed frames keep the originator's (spec 3.6.4.3). A
    /// `completion`, if supplied, is resolved by whichever queue takes the frame: the
    /// sender on transmit, or the indirect queue on the child's poll or expiry.
    pub(super) fn enqueue_unicast(
        &self,
        nwk_frame: NwkFrame,
        next_hop: Nwk,
        security: NwkSecurityMode,
        priority: TxPriority,
        completion: Option<TxCompletion>,
    ) {
        if let Some(child_eui64) = self.sleepy_child_eui64(next_hop) {
            let frame = self.finish_unicast_nwk_frame(nwk_frame, next_hop, security);
            self.increment_tx_total();

            let destination = Ieee802154Address::Eui64(child_eui64);
            match completion {
                Some(completion) => self.enqueue_indirect_frame(destination, frame, completion),
                None => drop(self.push_indirect_frame(destination, frame)),
            }
            return;
        }

        self.enqueue_send(
            SendKind::Unicast {
                nwk_frame,
                next_hop,
                security,
            },
            priority,
            completion,
        );
    }

    /// Push a frame for the sender task and await its transmit result.
    pub(super) async fn send(
        &self,
        kind: SendKind,
        priority: TxPriority,
    ) -> Result<(), ZigbeeStackError> {
        let (completion_tx, completion_rx) = oneshot::channel();
        self.enqueue_send(kind, priority, Some(completion_tx));
        completion_rx
            .await
            .unwrap_or(Err(ZigbeeStackError::TransmitFailed(TxResult::Aborted)))
    }

    /// Enqueue a unicast awaiting a route and start discovery if necessary.
    fn enqueue_awaiting_route(
        &self,
        nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        priority: TxPriority,
        completion: Option<TxCompletion>,
    ) {
        let destination = nwk_frame.nwk_header.destination;

        let start_discovery = {
            let mut pending = self
                .state
                .pending_routes
                .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
                .unwrap();
            let is_new = !pending.contains_key(&destination);
            pending
                .entry(destination)
                .or_insert_with(|| PendingRoute {
                    frames: Vec::new(),
                    attempts_remaining: self.tunables.pending_route_discovery_attempts,
                })
                .frames
                .push(PendingFrame {
                    nwk_frame,
                    security,
                    priority,
                    completion,
                });
            is_new
        };

        if start_discovery {
            tracing::debug!("Queuing frame and starting route discovery for {destination:?}");
            self.send_route_discovery(destination);
        }
        self.pending_route_wake.notify_one();
    }

    /// The pending-route reactor: a single long-lived task that owns every in-flight
    /// route discovery. It sleeps until the nearest discovery deadline (or a wake
    /// signal), then sends the frames whose route resolved and retries or discards
    /// those whose discovery lapsed.
    pub(super) async fn pending_route_task(&self) {
        loop {
            let next_deadline = self.earliest_discovery_deadline();

            match next_deadline {
                Some(deadline) => {
                    let _ = self
                        .timeout_at_core(deadline, self.pending_route_wake.notified())
                        .await;
                }
                None => self.pending_route_wake.notified().await,
            }

            self.drive_pending_routes();
        }
    }

    /// The soonest live discovery deadline across all queued destinations, or `None`
    /// when nothing is waiting on a deadline (the reactor then sleeps on its wake
    /// signal).
    fn earliest_discovery_deadline(&self) -> Option<CoreInstant> {
        let destinations: Vec<Nwk> = self
            .state
            .pending_routes
            .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
            .unwrap()
            .keys()
            .copied()
            .collect();

        let now = self.core_now();
        let core = self.core();
        destinations
            .iter()
            .filter_map(|destination| core.nib.routing.discovery_deadline(*destination, now))
            .min()
    }

    /// One reactor pass: classify each queued destination and act on it.
    fn drive_pending_routes(&self) {
        let destinations: Vec<Nwk> = self
            .state
            .pending_routes
            .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
            .unwrap()
            .keys()
            .copied()
            .collect();

        for destination in destinations {
            match self.discovery_state(destination) {
                DiscoveryState::Resolved => self.release_queued_frames(destination),
                DiscoveryState::Lapsed => self.retry_or_fail_discovery(destination),
                DiscoveryState::InFlight => {}
            }
        }
    }

    /// Where `destination`'s route discovery currently stands, read from the routing
    /// table.
    fn discovery_state(&self, destination: Nwk) -> DiscoveryState {
        let now = self.core_now();
        let core = self.core();
        match core.nib.routing.route_status(destination) {
            Some(RouteStatus::Active) => DiscoveryState::Resolved,
            Some(RouteStatus::DiscoveryUnderway) => {
                // `discovery_deadline` only returns a live (future) deadline, so its
                // absence means the discovery window has elapsed.
                if core
                    .nib
                    .routing
                    .discovery_deadline(destination, now)
                    .is_some()
                {
                    DiscoveryState::InFlight
                } else {
                    DiscoveryState::Lapsed
                }
            }
            // DiscoveryFailed / Inactive / no entry: nothing in flight.
            _ => DiscoveryState::Lapsed,
        }
    }

    /// A route exists: re-resolve each queued frame and enqueue it. A frame whose route
    /// vanished in the race is dropped with an error.
    fn release_queued_frames(&self, destination: Nwk) {
        let bucket = self
            .state
            .pending_routes
            .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
            .unwrap()
            .remove(&destination);

        let Some(bucket) = bucket else {
            return;
        };

        tracing::debug!(
            "Releasing {} queued frame(s) to {destination:?}",
            bucket.frames.len()
        );

        for queued in bucket.frames {
            let PendingFrame {
                mut nwk_frame,
                security,
                priority,
                completion,
            } = queued;

            match self.resolve_next_hop(&mut nwk_frame, SendMode::Route) {
                NextHop::Resolved(next_hop) => {
                    self.enqueue_unicast(nwk_frame, next_hop, security, priority, completion);
                }
                NextHop::NeedDiscovery | NextHop::Discard => {
                    if let Some(completion) = completion {
                        let _ = completion.send(Err(ZigbeeStackError::RouteInactiveAfterDiscovery));
                    }
                }
            }
        }
    }

    /// A discovery window lapsed: retry the discovery if the destination has attempts
    /// left, otherwise mark it failed and discard every frame waiting on it.
    fn retry_or_fail_discovery(&self, destination: Nwk) {
        let discarded = {
            let mut pending = self
                .state
                .pending_routes
                .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
                .unwrap();

            let Some(bucket) = pending.get_mut(&destination) else {
                return;
            };

            bucket.attempts_remaining = bucket.attempts_remaining.saturating_sub(1);

            if bucket.attempts_remaining > 0 {
                None
            } else {
                Some(pending.remove(&destination).unwrap().frames)
            }
        };

        match discarded {
            None => {
                tracing::debug!("Route discovery to {destination:?} timed out, retrying");
                self.send_route_discovery(destination);
                self.pending_route_wake.notify_one();
            }
            Some(frames) => {
                self.core().nib.routing.mark_discovery_failed(destination);
                tracing::debug!(
                    "Route discovery to {destination:?} failed, dropping {} frame(s)",
                    frames.len()
                );
                for PendingFrame { completion, .. } in frames {
                    if let Some(completion) = completion {
                        let _ =
                            completion.send(Err(ZigbeeStackError::RouteDiscoveryTimeout(Elapsed)));
                    }
                }
            }
        }
    }

    /// The single transmit task: drains [`send_queue`](ZigbeeStack::send_queue) highest
    /// priority first, encrypting each frame as it is sent so frame-counter order
    /// always matches on-air order. Serializing all transmits here is what keeps the
    /// counter monotonic; concurrent senders would race it and risk replay rejection.
    pub(super) async fn sender_task(&self) {
        loop {
            loop {
                let request = self
                    .send_queue
                    .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
                    .unwrap()
                    .pop();

                let Some(request) = request else {
                    break;
                };

                let result = match request.kind {
                    SendKind::Unicast {
                        nwk_frame,
                        next_hop,
                        security,
                    } => {
                        self.process_unicast_send(nwk_frame, next_hop, security)
                            .await
                    }
                    SendKind::Broadcast {
                        nwk_frame,
                        security,
                    } => self.process_broadcast_send(nwk_frame, security).await,
                    SendKind::Raw { frame } => self.send_802154_frame(frame).await,
                };

                match request.completion {
                    Some(completion) => {
                        let _ = completion.send(result);
                    }
                    None => {
                        if let Err(err) = result {
                            tracing::warn!("Background send failed: {err}");
                        }
                    }
                }
            }

            self.send_wake.notified().await;
        }
    }

    /// Encrypt and unicast a dequeued frame to the next hop, with NWK retries.
    async fn process_unicast_send(
        &self,
        mut nwk_frame: NwkFrame,
        next_hop_address: Nwk,
        security: NwkSecurityMode,
    ) -> Result<(), ZigbeeStackError> {
        self.apply_nwk_aux_header(&mut nwk_frame, security);

        for attempt in 0..=self.tunables.unicast_retries {
            let encrypted_nwk_frame = self.encrypt_nwk_frame(&mut nwk_frame, security);
            let ieee802154_frame =
                self.build_unicast_802154_data_frame(next_hop_address, encrypted_nwk_frame);

            // When forwarding packets to another node, update the counters for the neighbor
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

            match self.send_802154_frame(ieee802154_frame).await {
                Ok(_) => {
                    break;
                }
                Err(e) => {
                    // Spec Table 3-75: an unacknowledged unicast is a transmit failure
                    // recorded against the next hop. Counted per MCPS-DATA.request, like
                    // `nwkTxTotal` above, so the two stay on the same denominator.
                    if let ZigbeeStackError::NwkNoAck { .. } = e {
                        let mut core = self.core();
                        if let Some(next_hop_eui64) =
                            core.nib.address_map.eui64_for(next_hop_address)
                        {
                            core.nib.neighbors.record_transmit_failure(next_hop_eui64);
                        }
                    }

                    tracing::warn!("Failed to send unicast frame: {e}");

                    if attempt + 1 > self.tunables.unicast_retries {
                        tracing::error!("Failed to send unicast frame after {attempt} attempts");
                        self.handle_unicast_send_failure(&nwk_frame, next_hop_address);
                        return Err(e);
                    }
                    tracing::debug!(
                        "Retrying unicast frame send, attempt {} of {}",
                        attempt,
                        self.tunables.unicast_retries
                    );

                    R::sleep(self.tunables.unicast_retry_delay).await;
                }
            }
        }

        Ok(())
    }

    /// A unicast exhausted its retries at the sender. The next hop is dead: invalidate
    /// routes through it. A frame we originated also drops any stored source route and
    /// pushes the MTORR scheduler; a frame we were relaying reports the failure back
    /// to its originator (spec 3.6.4.8.1).
    fn handle_unicast_send_failure(&self, nwk_frame: &NwkFrame, next_hop: Nwk) {
        if nwk_frame.nwk_header.source != self.state.network_address {
            self.handle_relay_failure(nwk_frame, next_hop);
            return;
        }

        let destination = nwk_frame.nwk_header.destination;
        self.invalidate_routes_via(next_hop);

        if self.core().nib.routing.remove_route_record(destination) {
            tracing::info!("Removed source route to {destination:?} after delivery failure");
        }

        // Expired indirect transactions to our own sleepy children are not routing
        // failures, so they do not push the MTORR scheduler.
        if self.sleepy_child_eui64(next_hop).is_none() {
            self.note_delivery_failure();
        }
    }

    /// Spec 3.6.6: a coordinator/router with rx-off end-device children must re-deliver
    /// every 0xFFFF broadcast to each of them as a MAC unicast through the indirect
    /// queue, since a sleeping radio never hears the broadcast itself. The NWK source is
    /// skipped (it already has the frame). Each copy is queued without waiting: it is only
    /// handed to the radio when the child polls, or dropped when it expires.
    fn fan_out_broadcast_to_sleepy_children(
        &self,
        nwk_frame: &NwkFrame,
        security: NwkSecurityMode,
    ) {
        if nwk_frame.nwk_header.destination != BROADCAST_ALL_DEVICES {
            return;
        }

        let sleepy_children: Vec<(Eui64, Nwk)> = self
            .core()
            .nib
            .neighbors
            .sleepy_children()
            .into_iter()
            .filter(|(_, child_nwk)| *child_nwk != nwk_frame.nwk_header.source)
            .collect();

        for (child_eui64, child_nwk) in sleepy_children {
            let finished = self.finish_unicast_nwk_frame(nwk_frame.clone(), child_nwk, security);
            self.increment_tx_total();

            // We don't await the result
            let _result_rx =
                self.push_indirect_frame(Ieee802154Address::Eui64(child_eui64), finished);
        }
    }

    pub async fn send_broadcast_nwk_frame(
        &self,
        mut nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        priority: TxPriority,
    ) -> Result<(), ZigbeeStackError> {
        nwk_frame.nwk_header.sequence_number = self.next_nwk_sequence_number();

        // Sleepy children never hear the over-the-air broadcast; queue a unicast copy
        // for each (spec 3.6.6).
        self.fan_out_broadcast_to_sleepy_children(&nwk_frame, security);

        let key = (
            nwk_frame.nwk_header.source,
            nwk_frame.nwk_header.sequence_number,
        );

        // The passive ack contract is formed at transmission time: only routers that
        // are neighbors right now are expected to relay
        {
            let mut core = self.core();
            let audience = core.nib.neighbors.expected_broadcast_relayers();

            core.nib
                .broadcasts
                .record_transmission(key.0, key.1, audience, self.core_now());
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
                R::sleep(
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

    /// Queue a fully-formed NWK frame for a single broadcast copy, encrypted and sent by
    /// the sender task at dequeue. The sequence number is not touched: relayed broadcasts
    /// and route request retries keep their original sequence number.
    pub(super) async fn transmit_broadcast_nwk_frame(
        &self,
        nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        priority: TxPriority,
    ) -> Result<(), ZigbeeStackError> {
        self.send(
            SendKind::Broadcast {
                nwk_frame,
                security,
            },
            priority,
        )
        .await
    }

    /// Encrypt and broadcast a single dequeued copy of a frame.
    async fn process_broadcast_send(
        &self,
        mut nwk_frame: NwkFrame,
        security: NwkSecurityMode,
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

        // Spec 3.6.4.5.5: each relay appends its network address to a transiting route
        // record command before forwarding it. Other command types (and frames we could
        // not decode) are relayed verbatim.
        if let NwkPayload::Command(command) = &mut nwk_frame.payload {
            match command {
                NwkCommand::RouteRecord(route_record) => {
                    // Spec 3.6.4.5.5: with no room left for our address the route record
                    // is discarded rather than overflowing the frame.
                    if route_record.relays.len() >= usize::from(self.tunables.max_source_route) {
                        tracing::warn!("Dropping transiting route record: relay list is full");
                        return;
                    }
                    route_record.relays.push(self.state.network_address);
                }
                // A relay SHALL append its address to a transiting route record; one we
                // could not parse cannot have it appended, so it is discarded rather than
                // forwarded with an incomplete relay list (spec 3.6.4.5.5).
                NwkCommand::Unparsed(raw)
                    if raw.first().copied() == Some(NwkCommandId::RouteRecord as u8) =>
                {
                    tracing::warn!("Dropping malformed transiting route record");
                    return;
                }
                _ => {}
            }
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

        // The originator's sequence number is preserved when relaying. The transmit and
        // any failure handling (route invalidation, the network status back to the
        // originator) happen in the sender; nothing is awaited here.
        self.enqueue_unicast(
            nwk_frame,
            next_hop_address,
            NwkSecurityMode::NetworkKey,
            TxPriority::USER_NORMAL,
            None,
        );
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

        // The originator may be several hops away with no route cached; allow this
        // report to discover one.
        let network_status_frame = self
            .nwk_command_frame(
                source,
                NwkCommand::NetworkStatus(NwkNetworkStatusCommand {
                    status_code,
                    network_address: nwk_frame.nwk_header.destination,
                }),
            )
            .with_destination_ieee(destination_ieee)
            .with_discover_route(NwkRouteDiscovery::Enable);

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

        // Spec 3.6.6: deliver another device's 0xFFFF broadcast to our own sleepy
        // children as MAC unicasts (a no-op for non-0xFFFF destinations).
        self.fan_out_broadcast_to_sleepy_children(nwk_frame, NwkSecurityMode::NetworkKey);

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
            R::sleep(
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
                    R::sleep(
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
