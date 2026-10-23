use crate::broadcast_budget::BroadcastAdmission;
use crate::frame_token::TrafficClass;
use crate::runtime::Runtime;
use crate::ziggurat_ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154DataFrame, Ieee802154Frame,
    Ieee802154FrameControl, Ieee802154FrameHeader, Ieee802154FrameType, Ieee802154FrameVersion,
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;
use ziggurat_ieee_802154::FrameBytes;
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::RadioPhy;
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
    AddrConflictSource, Broadcast, BroadcastSchedule, Confirm, DeliveryError, EnqueueError, Entry,
    Frame, HostRoute, MAX_DEPTH, NwkSecurityMode, PROTOCOL_VERSION, RouteDirective, SendHandle,
    SendId, SendMode, SendSlot, TxPolicy, TxPriority, Unicast, ZigbeeNotification, ZigbeeStack,
};

/// The outcome of resolving a unicast's MAC next hop without blocking (see
/// [`ZigbeeStack::resolve_next_hop`]).
pub(super) enum NextHop {
    /// Transmit to this next hop now.
    Resolved(Nwk),
    /// No route known; the frame must wait for route discovery.
    NeedDiscovery,
    /// No route known and the frame's `discover_route` flag forbids discovering one.
    Discard,
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
            && (CoreInstant::from_micros(0) + self.tunables.broadcast_delivery_time() > now)
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
            self.tunables.broadcast_delivery_time(),
        );
        drop(core);

        if duplicate {
            // A duplicate is its sender's passive ack: wake the send timer so it
            // re-evaluates completeness and can settle a now-acknowledged broadcast early
            self.send_timer_wake.notify_one();
        }

        duplicate
    }

    /// Spec 3.6.4.5.1: broadcast a route request `attempts` times, the first after
    /// `initial_delay`, at the retry interval.
    pub(super) fn broadcast_route_request(
        &self,
        nwk_frame: NwkFrame,
        attempts: u8,
        initial_delay: Duration,
    ) {
        let key = (
            nwk_frame.nwk_header.source,
            nwk_frame.nwk_header.sequence_number,
        );

        let admitted = self.admit(
            Frame::nwk(nwk_frame, NwkSecurityMode::NetworkKey),
            TxPolicy {
                priority: TxPriority::UserNormal,
                class: TrafficClass::Critical,
            },
            Confirm::OnHandoff,
            None,
            Entry::Broadcast {
                key,
                schedule: BroadcastSchedule::FixedInterval {
                    interval: self.tunables.rreq_retry_interval(),
                },
                attempts,
                next_attempt: self.core_now() + initial_delay,
                copy_now: false,
            },
        );

        if let Err(err) = admitted {
            tracing::warn!("Dropping route request: {err}");
        }
    }

    /// A random retransmission jitter in `[0, max_broadcast_jitter)` (spec 3.6.6).
    pub(super) fn broadcast_jitter(&self) -> Duration {
        self.tunables
            .max_broadcast_jitter()
            .mul_f32(crate::rng::random_f32())
    }

    /// Whether the broadcast's passive ack quorum has been heard from the audience
    /// members that are still live neighbors.
    pub(super) fn broadcast_passively_acked(&self, key: (Nwk, u8)) -> bool {
        let core = self.core();
        let live_relayers = core.nib.neighbors.expected_broadcast_relayers();

        core.nib.broadcasts.passively_acked(
            key.0,
            key.1,
            &live_relayers,
            self.tunables.broadcast_passive_ack_quorum(),
        )
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
                if CoreInstant::from_micros(0) + self.tunables.broadcast_delivery_time()
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
                    tracing::trace!("Route record command frame received: {cmd:?}");
                    let source = nwk_frame.nwk_header.source;
                    let changed = self
                        .core()
                        .nib
                        .routing
                        .store_route_record(source, cmd.relays.clone());

                    if changed {
                        self.push_notification(ZigbeeNotification::RouteRecord {
                            destination: source,
                            relays: cmd.relays.clone(),
                        });
                    }
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
    pub(super) fn nwk_data_frame(
        &self,
        destination: Nwk,
        payload: Vec<u8>,
    ) -> Result<NwkFrame, EnqueueError> {
        Ok(NwkFrame {
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
                FrameBytes::from_slice(&payload).map_err(|_| EnqueueError::PayloadTooLong)?,
            ),
        })
    }

    /// Send a unicast: assign its NWK sequence number, resolve a next hop, and admit it
    /// to the send table, parked on a route discovery if none is known. `Err` rejects at
    /// admission and no handle is returned.
    pub(super) fn send_unicast(&self, send: Unicast) -> Result<SendHandle, EnqueueError> {
        let slot = Arc::new(SendSlot::default());
        let id = self.admit_unicast(send, Some(slot.clone()))?;
        Ok(SendHandle::new(id, slot))
    }

    /// [`Self::send_unicast`] for a send nobody awaits: a failure is only logged.
    pub(super) fn send_unicast_untracked(&self, send: Unicast) -> Result<(), EnqueueError> {
        self.admit_unicast(send, None).map(|_| ())
    }

    fn admit_unicast(
        &self,
        send: Unicast,
        waiter: Option<Arc<SendSlot>>,
    ) -> Result<SendId, EnqueueError> {
        let Unicast {
            frame: mut nwk_frame,
            security,
            mode,
            policy,
            confirm,
        } = send;
        debug_assert!(
            nwk_frame.nwk_header.destination.as_u16() < BROADCAST_LOW_POWER_ROUTERS.as_u16(),
            "send_unicast is unicast only; got broadcast {:?}",
            nwk_frame.nwk_header.destination
        );

        nwk_frame.nwk_header.sequence_number = self.next_nwk_sequence_number();

        let entry = match self.resolve_next_hop(&mut nwk_frame, &mode) {
            NextHop::Resolved(next_hop) => self.place_unicast(next_hop),
            NextHop::NeedDiscovery => {
                let destination = nwk_frame.nwk_header.destination;
                tracing::debug!("Queuing frame awaiting a route to {destination:?}");
                Entry::AwaitRoute {
                    destination,
                    discovery_time: self.tunables.route_discovery_time(),
                    attempts: self.tunables.pending_route_discovery_attempts(),
                }
            }
            NextHop::Discard => {
                let destination = nwk_frame.nwk_header.destination;
                tracing::debug!(
                    "Dropping frame to {destination:?}: no route and discovery suppressed"
                );
                return Err(EnqueueError::RouteDiscoverySuppressed);
            }
        };

        self.admit(
            Frame::nwk(nwk_frame, security),
            policy,
            confirm,
            waiter,
            entry,
        )
    }

    /// Resolve the MAC next hop for a unicast without ever blocking. A source-routed
    /// result rewrites `nwk_frame`'s header in place (spec 3.6.4.3.1). When no route is
    /// known the frame's `discover_route` flag decides between discovery and discard.
    pub(super) fn resolve_next_hop(&self, nwk_frame: &mut NwkFrame, mode: &SendMode) -> NextHop {
        let destination = nwk_frame.nwk_header.destination;

        let directive = match mode {
            SendMode::Direct => return NextHop::Resolved(destination),
            SendMode::Route(directive) => directive,
        };

        // A forced host route overrides everything, including a known route.
        if let RouteDirective::Force(route) = directive {
            return self.apply_host_route(nwk_frame, route);
        }

        // End device children never route-discover; their parent delivers directly.
        if self.end_device_child_eui64(destination).is_some() {
            return NextHop::Resolved(destination);
        }

        // A stored source route (concentrator behavior) wins over the routing table.
        match self.outbound_route(destination) {
            Some(Route::NextHop(next_hop)) => return NextHop::Resolved(next_hop),
            Some(Route::SourceRouted(relays)) => {
                return self.apply_source_route(nwk_frame, relays);
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

        // No usable route. A host hint stands in for discovery rather than triggering it.
        if let RouteDirective::Hint(route) = directive {
            return self.apply_host_route(nwk_frame, route);
        }

        // Spec 3.6.3.3: only initiate discovery if the frame allows it.
        if nwk_frame.nwk_header.frame_control.discover_route == NwkRouteDiscovery::Suppress {
            NextHop::Discard
        } else {
            NextHop::NeedDiscovery
        }
    }

    /// Apply a host-supplied route to a frame we originate, resolving its MAC next hop.
    fn apply_host_route(&self, nwk_frame: &mut NwkFrame, route: &HostRoute) -> NextHop {
        match route {
            // The next hop routes onward itself, so `discover_route` is left as built:
            // an intermediate hop still needs it to reach the final destination.
            HostRoute::NextHop(next_hop) => NextHop::Resolved(*next_hop),
            HostRoute::SourceRoute(relays) => self.apply_source_route(nwk_frame, relays.clone()),
        }
    }

    /// Rewrite `nwk_frame` to carry a source route.
    fn apply_source_route(&self, nwk_frame: &mut NwkFrame, relays: Vec<Nwk>) -> NextHop {
        let next_hop = *relays.last().unwrap();
        nwk_frame.nwk_header.frame_control.source_route = true;
        nwk_frame.nwk_header.frame_control.discover_route = NwkRouteDiscovery::Suppress;
        nwk_frame.nwk_header.source_route = Some(NwkSourceRoute {
            relay_index: relays.len() as u8 - 1,
            relays,
        });
        NextHop::Resolved(next_hop)
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
            .route_to(destination, self.tunables.max_source_route())
    }

    /// Wrap an encrypted NWK payload in a unicast 802.15.4 data frame. The sequence
    /// number is assigned at transmit time. `frame_pending` tells a polling device that
    /// more frames await it (802.15.4 spec 6.7.3).
    fn build_unicast_802154_data_frame<Payload>(
        &self,
        next_hop_address: Nwk,
        payload: Payload,
        frame_pending: bool,
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
                    frame_pending,
                    ack_request: true,
                    pan_id_compression: true,
                    reserved1: false,
                    sequence_number_suppression: false,
                    information_elements_present: false,
                    dest_addr_mode: Ieee802154AddressingMode::Short,
                    frame_version: Ieee802154FrameVersion::Ieee2003,
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

    /// One transmit attempt for a unicast: assign the frame counter, encrypt, and send
    /// once. The send table decides what a failure means (a retry, or the verdict).
    pub(super) async fn transmit_unicast(
        &self,
        mut nwk_frame: NwkFrame,
        next_hop_address: Nwk,
        security: NwkSecurityMode,
        frame_pending: bool,
    ) -> Result<(), DeliveryError> {
        self.apply_nwk_aux_header(&mut nwk_frame, security);
        let encrypted_nwk_frame = self.encrypt_nwk_frame(&mut nwk_frame, security);
        let ieee802154_frame = self.build_unicast_802154_data_frame(
            next_hop_address,
            encrypted_nwk_frame,
            frame_pending,
        );

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

        let result = self.send_802154_frame(ieee802154_frame).await;

        if let Err(e) = &result {
            // Spec Table 3-75: an unacknowledged unicast is a transmit failure recorded
            // against the next hop. Counted per MCPS-DATA.request, like `nwkTxTotal`
            // above, so the two stay on the same denominator.
            if let DeliveryError::NwkNoAck { .. } = e {
                let mut core = self.core();
                if let Some(next_hop_eui64) = core.nib.address_map.eui64_for(next_hop_address) {
                    core.nib.neighbors.record_transmit_failure(next_hop_eui64);
                }
            }

            tracing::warn!("Failed to send unicast frame: {e}");
        }

        result
    }

    /// A unicast exhausted its retries at the sender. The next hop is dead: invalidate
    /// routes through it. A frame we originated also drops any stored source route and
    /// pushes the MTORR scheduler; a frame we were relaying reports the failure back
    /// to its originator (spec 3.6.4.8.1).
    pub(super) fn handle_unicast_send_failure(&self, nwk_frame: &NwkFrame, next_hop: Nwk) {
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
    /// every 0xFFFF broadcast to each of them as a MAC unicast, since a sleeping radio
    /// never hears the broadcast itself. The NWK source is skipped (it already has the
    /// frame). Each copy awaits its child's poll, or expires.
    fn maybe_fan_out_broadcast_to_sleepy_children(
        &self,
        nwk_frame: &NwkFrame,
        security: NwkSecurityMode,
        class: TrafficClass,
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
            // Each per-child copy is its own charge: under pressure copies are skipped
            // (the child misses one broadcast) instead of exhausting the heap.
            let admitted = self.admit(
                Frame::nwk(nwk_frame.clone(), security),
                TxPolicy {
                    priority: TxPriority::UserNormal,
                    class,
                },
                Confirm::OnHandoff,
                None,
                Entry::Indirect {
                    address: Ieee802154Address::Eui64(child_eui64),
                    next_hop: child_nwk,
                    persistence_time: self.tunables.transaction_persistence_time(),
                },
            );

            if let Err(err) = admitted {
                tracing::warn!("Skipping broadcast copy to sleepy child {child_nwk:?}: {err}");
            }
        }
    }

    /// Send a broadcast, retransmitted until its passive-ack quorum is heard or its
    /// attempts run out. `Err` rejects at admission and no handle is returned.
    pub(super) fn send_broadcast(&self, send: Broadcast) -> Result<SendHandle, EnqueueError> {
        let slot = Arc::new(SendSlot::default());
        let id = self.admit_broadcast(send, Some(slot.clone()))?;
        Ok(SendHandle::new(id, slot))
    }

    /// [`Self::send_broadcast`] for a send nobody awaits.
    pub(super) fn send_broadcast_untracked(&self, send: Broadcast) -> Result<(), EnqueueError> {
        self.admit_broadcast(send, None).map(|_| ())
    }

    fn admit_broadcast(
        &self,
        send: Broadcast,
        waiter: Option<Arc<SendSlot>>,
    ) -> Result<SendId, EnqueueError> {
        let Broadcast {
            frame: mut nwk_frame,
            security,
            policy,
        } = send;
        // Stack-critical broadcasts always pass; host- and forwarding-class broadcasts
        // yield to the reserves when the bucket is drained.
        let admission = self.broadcast_budget.lock().take(
            policy.class,
            self.core_now(),
            self.tunables.broadcast_budget_tokens(),
            self.tunables.broadcast_token_refill(),
            self.tunables.broadcast_critical_reserve(),
            self.tunables.broadcast_forwarding_reserve(),
        );

        if let BroadcastAdmission::Defer { retry_in } = admission {
            return Err(EnqueueError::RateLimited { retry_in });
        }

        nwk_frame.nwk_header.sequence_number = self.next_nwk_sequence_number();

        // Sleepy children never hear the over-the-air broadcast; queue a unicast copy
        // for each (spec 3.6.6).
        self.maybe_fan_out_broadcast_to_sleepy_children(&nwk_frame, security, policy.class);

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
                self.core_now(),
                self.tunables.broadcast_delivery_time(),
            );
        }

        // The first copy goes out now: a lost copy is not terminal, the schedule
        // retransmits. The first copy on air is the send's handoff; the quorum is its
        // delivery.
        self.admit(
            Frame::nwk(nwk_frame, security),
            policy,
            Confirm::OnHandoff,
            waiter,
            Entry::Broadcast {
                key,
                schedule: BroadcastSchedule::PassiveAck,
                attempts: self.tunables.max_broadcast_retries(),
                next_attempt: self.core_now()
                    + self.tunables.passive_ack_timeout()
                    + self.broadcast_jitter(),
                copy_now: true,
            },
        )
    }

    /// Send a single-copy broadcast: assign its sequence number and queue one copy for
    /// the sender. The transmit result is the verdict. A budget rejection resolves the
    /// returned handle with `BudgetExhausted`.
    #[allow(clippy::option_if_let_else)]
    pub(super) fn send_oneshot_broadcast(&self, send: Broadcast) -> SendHandle {
        let slot = Arc::new(SendSlot::default());
        match self.admit_oneshot_broadcast(send, Some(slot.clone())) {
            Ok(id) => SendHandle::new(id, slot),
            Err(_) => SendHandle::resolved(Err(DeliveryError::BudgetExhausted)),
        }
    }

    /// [`Self::send_oneshot_broadcast`] for a send nobody awaits.
    pub(super) fn send_oneshot_broadcast_untracked(&self, send: Broadcast) {
        if let Err(err) = self.admit_oneshot_broadcast(send, None) {
            tracing::warn!("Dropping broadcast: {err}");
        }
    }

    fn admit_oneshot_broadcast(
        &self,
        send: Broadcast,
        waiter: Option<Arc<SendSlot>>,
    ) -> Result<SendId, EnqueueError> {
        let Broadcast {
            frame: mut nwk_frame,
            security,
            policy,
        } = send;
        nwk_frame.nwk_header.sequence_number = self.next_nwk_sequence_number();

        self.admit(
            Frame::nwk(nwk_frame, security),
            policy,
            Confirm::OnHandoff,
            waiter,
            Entry::Queue(super::Next::Once),
        )
    }

    /// Encrypt and broadcast a single copy of a frame.
    pub(super) async fn transmit_broadcast(
        &self,
        mut nwk_frame: NwkFrame,
        security: NwkSecurityMode,
    ) -> Result<(), DeliveryError> {
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
                    frame_version: Ieee802154FrameVersion::Ieee2003,
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

        // Spec 3.3.1.1.8: a frame from one of our end device children is relayed with
        // its End Device Initiator bit cleared
        self.core()
            .nib
            .neighbors
            .clear_end_device_initiator_for_relay(&mut nwk_frame.nwk_header);

        let destination = nwk_frame.nwk_header.destination;

        // Spec 3.6.4.5.5: each relay appends its network address to a transiting route
        // record command before forwarding it. Other command types (and frames we could
        // not decode) are relayed verbatim.
        if let NwkPayload::Command(command) = &mut nwk_frame.payload {
            match command {
                NwkCommand::RouteRecord(route_record) => {
                    // Spec 3.6.4.5.5: with no room left for our address the route record
                    // is discarded rather than overflowing the frame.
                    if route_record.relays.len() >= usize::from(self.tunables.max_source_route()) {
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

        // Transit traffic draws from the forwarding tier: under a best-effort flood we
        // keep relaying, and under true exhaustion the drop is the originator's to
        // retry end-to-end. The originator's sequence number is preserved. Any failure
        // handling (route invalidation, the network status back to the originator)
        // follows the send table's verdict; nothing is awaited here.
        let admitted = self.admit(
            Frame::nwk(nwk_frame, NwkSecurityMode::NetworkKey),
            TxPolicy {
                priority: TxPriority::UserNormal,
                class: TrafficClass::Forwarding,
            },
            Confirm::OnHandoff,
            None,
            self.place_unicast(next_hop_address),
        );

        if let Err(err) = admitted {
            tracing::warn!("Dropping relay to {destination:?}: {err}");
        }
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

        let send = Unicast {
            frame: network_status_frame,
            security: NwkSecurityMode::NetworkKey,
            mode: SendMode::Route(RouteDirective::StackDecides),
            policy: TxPolicy::STACK_CRITICAL,
            confirm: Confirm::OnHandoff,
        };
        if let Err(err) = self.send_unicast_untracked(send) {
            tracing::warn!("Failed to send network status report: {err}");
        }
    }

    /// Zigbee spec 3.6.6: re-broadcast a newly seen broadcast frame, preserving the
    /// originator's source address and sequence number. The first relay is jittered to
    /// decorrelate from the originator's wave; the broadcast-retransmit reactor then
    /// retransmits until the passive-ack quorum is heard or attempts run out.
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

        // Spec 3.3.1.1.8: a broadcast from one of our end device children is relayed
        // with its End Device Initiator bit cleared, both over the air and in the
        // copies queued for sleepy children
        self.core()
            .nib
            .neighbors
            .clear_end_device_initiator_for_relay(&mut relayed_frame.nwk_header);

        // Spec 3.6.6: deliver another device's 0xFFFF broadcast to our own sleepy
        // children as MAC unicasts (a no-op for non-0xFFFF destinations).
        self.maybe_fan_out_broadcast_to_sleepy_children(
            &relayed_frame,
            NwkSecurityMode::NetworkKey,
            TrafficClass::Forwarding,
        );

        relayed_frame.nwk_header.radius = relayed_frame.nwk_header.radius.saturating_sub(1);
        if relayed_frame.nwk_header.radius == 0 {
            tracing::debug!("Not relaying broadcast, radius is exhausted");
            return;
        }

        let key = (
            relayed_frame.nwk_header.source,
            relayed_frame.nwk_header.sequence_number,
        );

        // Unlike an originated broadcast, the first relay is also scheduled (after jitter)
        // rather than sent inline, so the attempt count includes it. The passive-ack
        // contract was recorded when we received the frame, so the timer's quorum check
        // already covers relayed broadcasts.
        let admitted = self.admit(
            Frame::nwk(relayed_frame, NwkSecurityMode::NetworkKey),
            TxPolicy {
                priority: TxPriority::UserNormal,
                class: TrafficClass::Forwarding,
            },
            Confirm::OnHandoff,
            None,
            Entry::Broadcast {
                key,
                schedule: BroadcastSchedule::PassiveAck,
                attempts: self.tunables.max_broadcast_retries() + 1,
                next_attempt: self.core_now() + self.broadcast_jitter(),
                copy_now: false,
            },
        );

        if let Err(err) = admitted {
            tracing::warn!("Not relaying broadcast {key:?}: {err}");
        }
    }
}
