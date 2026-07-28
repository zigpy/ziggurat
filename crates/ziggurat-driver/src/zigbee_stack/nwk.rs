use crate::broadcast_budget::BroadcastAdmission;
use crate::frame_token::{self, FrameToken, TrafficClass};
use crate::runtime::{Elapsed, Runtime};
use crate::ziggurat_ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154DataFrame, Ieee802154Frame,
    Ieee802154FrameControl, Ieee802154FrameHeader, Ieee802154FrameType, Ieee802154FrameVersion,
};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering as AtomicOrdering;
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
    AddrConflictSource, Broadcast, BroadcastSchedule, DeliveryError, EnqueueError, HostRoute,
    IndirectFrame, IndirectPayload, MAX_DEPTH, NwkSecurityMode, PROTOCOL_VERSION, PendingBroadcast,
    PendingFrame, PendingRoute, PendingUnicastRetry, RouteDirective, SendKind, SendMode,
    SendRequest, SendSlot, TrackStage, TxOutcome, TxPolicy, TxPriority, Unicast,
    ZigbeeNotification, ZigbeeStack,
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
            // A duplicate is its sender's passive ack: wake the retransmit reactor so it
            // re-evaluates completeness and can drop a now-acknowledged broadcast early
            self.broadcast_retransmit_wake.notify_one();
        }

        duplicate
    }

    /// The broadcast-retransmit reactor: a single long-lived task that owns every
    /// in-flight broadcast's retransmission.
    pub(super) async fn broadcast_retransmit_task(&self) {
        loop {
            match self.earliest_broadcast_retransmit() {
                Some(deadline) => {
                    let _ = self
                        .timeout_at_core(deadline, self.broadcast_retransmit_wake.notified())
                        .await;
                }
                None => self.broadcast_retransmit_wake.notified().await,
            }

            self.drive_broadcast_retransmits();
        }
    }

    /// The soonest retransmit deadline across all pending broadcasts, or `None` when none
    /// are pending (the reactor then sleeps on its wake signal).
    fn earliest_broadcast_retransmit(&self) -> Option<CoreInstant> {
        self.state
            .pending_broadcasts
            .lock()
            .values()
            .map(|pending| pending.next_attempt)
            .min()
    }

    /// One reactor pass: for each pending broadcast, drop it if its quorum is now heard,
    /// otherwise retransmit a copy if it is due (and not out of attempts).
    #[allow(clippy::significant_drop_tightening)]
    fn drive_broadcast_retransmits(&self) {
        let keys: Vec<((Nwk, u8), BroadcastSchedule)> = self
            .state
            .pending_broadcasts
            .lock()
            .iter()
            .map(|(key, broadcast)| (*key, broadcast.schedule))
            .collect();

        let now = self.core_now();

        for (key, schedule) in keys {
            // Route requests have no passive ack; only a data broadcast is retired early.
            if matches!(schedule, BroadcastSchedule::PassiveAck)
                && self.broadcast_passively_acked(key)
            {
                tracing::debug!("Broadcast {key:?} passively acknowledged");
                let removed = self.state.pending_broadcasts.lock().remove(&key);
                if let Some(PendingBroadcast {
                    slot: Some(slot), ..
                }) = removed
                {
                    slot.resolve(TrackStage::Delivery, Ok(()));
                }
                continue;
            }

            let next_attempt = match schedule {
                BroadcastSchedule::PassiveAck => {
                    now + self.tunables.passive_ack_timeout() + self.broadcast_jitter()
                }
                BroadcastSchedule::FixedInterval { interval } => now + interval,
            };

            // A single stack local, matched immediately after the lock is released, so the
            // size-amplification the lint warns about does not apply.
            #[allow(clippy::large_enum_variant)]
            enum Next {
                Idle,
                Retransmit(NwkFrame, NwkSecurityMode, TxPolicy, Option<Arc<SendSlot>>),
                Cancelled(Option<Arc<SendSlot>>),
                Exhausted(Option<Arc<SendSlot>>),
            }

            // Decide under the lock; if a copy is due, extract it to transmit after release.
            let action = {
                let mut pending = self.state.pending_broadcasts.lock();
                let Some(broadcast) = pending.get_mut(&key) else {
                    continue;
                };

                if broadcast
                    .slot
                    .as_ref()
                    .is_some_and(|slot| slot.is_cancelled())
                {
                    Next::Cancelled(pending.remove(&key).unwrap().slot)
                } else if broadcast.next_attempt > now {
                    Next::Idle
                } else if broadcast.attempts_remaining == 0 {
                    Next::Exhausted(pending.remove(&key).unwrap().slot)
                } else {
                    broadcast.attempts_remaining -= 1;
                    broadcast.next_attempt = next_attempt;
                    Next::Retransmit(
                        broadcast.nwk_frame.clone(),
                        broadcast.security,
                        broadcast.policy,
                        broadcast.slot.clone(),
                    )
                }
            };

            match action {
                Next::Idle => {}
                Next::Retransmit(nwk_frame, security, policy, slot) => {
                    tracing::debug!("Retransmitting broadcast {key:?}");
                    // Each on-air copy resolves the send's handoff; write-once means only
                    // the first successful one takes.
                    self.enqueue_send(
                        SendKind::Broadcast {
                            nwk_frame,
                            security,
                        },
                        policy,
                        Self::broadcast_copy_outcome(slot),
                    );
                }
                Next::Cancelled(slot) => {
                    tracing::debug!("Broadcast {key:?} cancelled");
                    if let Some(slot) = slot {
                        slot.resolve(TrackStage::Delivery, Err(DeliveryError::Cancelled));
                    }
                }
                Next::Exhausted(slot) => {
                    tracing::debug!("Broadcast {key:?} out of retransmit attempts");
                    // A fixed-interval broadcast (a route request) completes by running
                    // out of attempts; a data broadcast fails its quorum.
                    if let Some(slot) = slot {
                        let result = match schedule {
                            BroadcastSchedule::PassiveAck => {
                                Err(DeliveryError::BroadcastQuorumNotReached)
                            }
                            BroadcastSchedule::FixedInterval { .. } => Ok(()),
                        };
                        slot.resolve(TrackStage::Delivery, result);
                    }
                }
            }
        }
    }

    /// The outcome for one on-air broadcast copy: a tracked broadcast resolves its
    /// `HandOff` stage (write-once, so only the first successful copy takes), an internal
    /// one is fire-and-forget.
    fn broadcast_copy_outcome(slot: Option<Arc<SendSlot>>) -> TxOutcome {
        slot.map_or(TxOutcome::Discard, |slot| TxOutcome::Track {
            slot,
            stage: TrackStage::HandOff,
        })
    }

    /// Insert a broadcast into the pending-retransmit map and wake the reactor.
    #[allow(clippy::too_many_arguments)]
    fn schedule_broadcast(
        &self,
        key: (Nwk, u8),
        nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        policy: TxPolicy,
        schedule: BroadcastSchedule,
        first_delay: Duration,
        attempts: u8,
        slot: Option<Arc<SendSlot>>,
        // Caller-taken, held by the retained copy for the whole retransmit schedule
        token: FrameToken,
    ) {
        // A tracked broadcast is scheduled even at zero retransmits, so the reactor can
        // resolve its quorum (or fail it); an untracked one with nothing to retransmit is
        // a no-op.
        if attempts == 0 && slot.is_none() {
            return;
        }

        self.state.pending_broadcasts.lock().insert(
            key,
            PendingBroadcast {
                nwk_frame,
                security,
                policy,
                schedule,
                attempts_remaining: attempts,
                next_attempt: self.core_now() + first_delay,
                slot,
                _token: token,
            },
        );
        self.broadcast_retransmit_wake.notify_one();
    }

    pub(super) fn broadcast_route_request(
        &self,
        nwk_frame: NwkFrame,
        attempts: u8,
        initial_delay: Duration,
    ) {
        let Some(token) = frame_token::take(TrafficClass::Critical) else {
            tracing::warn!("Frame budget exhausted; dropping route request retransmissions");
            return;
        };

        let key = (
            nwk_frame.nwk_header.source,
            nwk_frame.nwk_header.sequence_number,
        );

        self.schedule_broadcast(
            key,
            nwk_frame,
            NwkSecurityMode::NetworkKey,
            TxPolicy {
                priority: TxPriority::UserNormal,
                class: TrafficClass::Critical,
            },
            BroadcastSchedule::FixedInterval {
                interval: self.tunables.rreq_retry_interval(),
            },
            initial_delay,
            attempts,
            None,
            token,
        );
    }

    /// A random retransmission jitter in `[0, max_broadcast_jitter)` (spec 3.6.6).
    pub(super) fn broadcast_jitter(&self) -> Duration {
        self.tunables
            .max_broadcast_jitter()
            .mul_f32(crate::rng::random_f32())
    }

    /// Whether the broadcast's passive ack quorum has been heard from the audience
    /// members that are still live neighbors.
    fn broadcast_passively_acked(&self, key: (Nwk, u8)) -> bool {
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

    /// Send a unicast: assign its NWK sequence number, resolve a next hop, and
    /// either enqueue it, queue it awaiting route discovery, or drop it
    /// (discovery suppressed).
    /// `Err` rejects at enqueue without consuming `outcome`; on `Ok` the outcome
    /// resolves with the delivery result.
    pub(super) fn send_unicast(&self, send: Unicast) -> Result<(), EnqueueError> {
        let Unicast {
            frame: mut nwk_frame,
            security,
            mode,
            policy,
            outcome,
        } = send;
        debug_assert!(
            nwk_frame.nwk_header.destination.as_u16() < BROADCAST_LOW_POWER_ROUTERS.as_u16(),
            "send_unicast is unicast only; got broadcast {:?}",
            nwk_frame.nwk_header.destination
        );

        // The token is taken here, at the frame's entry into the stack's ownership, so
        // that route-discovery parking is covered by the budget too. It travels with
        // the frame through every queue until its terminal outcome.
        let Some(token) = frame_token::take(policy.class) else {
            tracing::warn!(
                "Frame budget exhausted ({}/{} tokens); rejecting {:?} unicast",
                frame_token::used(),
                frame_token::total(),
                policy.class,
            );
            return Err(EnqueueError::BudgetExhausted);
        };

        nwk_frame.nwk_header.sequence_number = self.next_nwk_sequence_number();

        match self.resolve_next_hop(&mut nwk_frame, &mode) {
            NextHop::Resolved(next_hop) => {
                self.enqueue_unicast(
                    nwk_frame,
                    next_hop,
                    security,
                    policy.priority,
                    outcome,
                    token,
                );
                Ok(())
            }
            NextHop::NeedDiscovery => {
                self.enqueue_awaiting_route(nwk_frame, security, policy.priority, outcome, token);
                Ok(())
            }
            NextHop::Discard => {
                let destination = nwk_frame.nwk_header.destination;
                tracing::debug!(
                    "Dropping frame to {destination:?}: no route and discovery suppressed"
                );
                Err(EnqueueError::RouteDiscoverySuppressed)
            }
        }
    }

    /// Resolve the MAC next hop for a unicast without ever blocking. A source-routed
    /// result rewrites `nwk_frame`'s header in place (spec 3.6.4.3.1). When no route is
    /// known the frame's `discover_route` flag decides between discovery and discard.
    fn resolve_next_hop(&self, nwk_frame: &mut NwkFrame, mode: &SendMode) -> NextHop {
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

    /// Enqueue a send into the priority queue and wake the sender task, taking a frame
    /// token from the policy's budget tier. A refused token resolves the outcome with
    /// an error instead.
    pub(super) fn enqueue_send(&self, kind: SendKind, policy: TxPolicy, outcome: TxOutcome) {
        let Some(token) = frame_token::take(policy.class) else {
            tracing::warn!(
                "Frame budget exhausted ({}/{} tokens); rejecting {:?} frame",
                frame_token::used(),
                frame_token::total(),
                policy.class,
            );
            self.resolve_outcome(outcome, Err(DeliveryError::BudgetExhausted));
            return;
        };

        self.enqueue_send_with_token(kind, policy.priority, outcome, token);
    }

    /// Enqueue a send whose frame already holds a budget token (a retry, or a frame
    /// released from route-discovery parking).
    fn enqueue_send_with_token(
        &self,
        kind: SendKind,
        priority: TxPriority,
        outcome: TxOutcome,
        token: FrameToken,
    ) {
        let seq = self.send_seq.fetch_add(1, AtomicOrdering::Relaxed);

        self.send_queue.lock().push(SendRequest {
            seq,
            priority,
            kind: Box::new(kind),
            outcome,
            token,
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
        outcome: TxOutcome,
        token: FrameToken,
    ) {
        if let Some(child_eui64) = self.sleepy_child_eui64(next_hop) {
            // The frame is left as plaintext and finished (encrypted, counter assigned)
            // only when the child polls. See `IndirectFrame`. The NWK sequence number
            // is already assigned.
            let frame = IndirectFrame {
                poll_address: Ieee802154Address::Eui64(child_eui64),
                payload: IndirectPayload::Deferred {
                    nwk_frame,
                    next_hop,
                    security,
                },
                token,
            };
            self.increment_tx_total();

            self.enqueue_indirect_frame(frame, outcome);
            return;
        }

        self.enqueue_send_with_token(
            SendKind::Unicast {
                nwk_frame,
                next_hop,
                security,
                attempts_remaining: self.tunables.unicast_retries(),
            },
            priority,
            outcome,
            token,
        );
    }

    /// Enqueue a unicast awaiting a route and start discovery if necessary.
    fn enqueue_awaiting_route(
        &self,
        nwk_frame: NwkFrame,
        security: NwkSecurityMode,
        priority: TxPriority,
        outcome: TxOutcome,
        token: FrameToken,
    ) {
        let destination = nwk_frame.nwk_header.destination;

        let start_discovery = {
            let mut pending = self.state.pending_routes.lock();
            let is_new = !pending.contains_key(&destination);
            pending
                .entry(destination)
                .or_insert_with(|| PendingRoute {
                    frames: Vec::new(),
                    attempts_remaining: self.tunables.pending_route_discovery_attempts(),
                })
                .frames
                .push(PendingFrame {
                    nwk_frame,
                    security,
                    priority,
                    outcome,
                    token,
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
        let destinations: Vec<Nwk> = self.state.pending_routes.lock().keys().copied().collect();

        let now = self.core_now();
        let core = self.core();
        destinations
            .iter()
            .filter_map(|destination| core.nib.routing.discovery_deadline(*destination, now))
            .min()
    }

    /// One reactor pass: classify each queued destination and act on it.
    fn drive_pending_routes(&self) {
        let destinations: Vec<Nwk> = self.state.pending_routes.lock().keys().copied().collect();

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
        let bucket = self.state.pending_routes.lock().remove(&destination);

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
                outcome,
                token,
            } = queued;

            match self.resolve_next_hop(
                &mut nwk_frame,
                &SendMode::Route(RouteDirective::StackDecides),
            ) {
                NextHop::Resolved(next_hop) => {
                    self.enqueue_unicast(nwk_frame, next_hop, security, priority, outcome, token);
                }
                NextHop::NeedDiscovery | NextHop::Discard => {
                    self.resolve_outcome(outcome, Err(DeliveryError::RouteInactiveAfterDiscovery));
                }
            }
        }
    }

    /// A discovery window lapsed: retry the discovery if the destination has attempts
    /// left, otherwise mark it failed and discard every frame waiting on it.
    fn retry_or_fail_discovery(&self, destination: Nwk) {
        let discarded = {
            let mut pending = self.state.pending_routes.lock();

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
                for PendingFrame { outcome, .. } in frames {
                    self.resolve_outcome(
                        outcome,
                        Err(DeliveryError::RouteDiscoveryTimeout(Elapsed)),
                    );
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
                let request = self.send_queue.lock().pop();

                let Some(request) = request else {
                    break;
                };

                // The budget token stays charged for the duration of the transmit and
                // follows a failed unicast into the retry reactor.
                let SendRequest {
                    priority,
                    kind,
                    outcome,
                    token,
                    ..
                } = request;

                // A send cancelled while queued never reaches the air; its token frees
                // as `token` drops here.
                if Self::outcome_cancelled(&outcome) {
                    self.resolve_outcome(outcome, Err(DeliveryError::Cancelled));
                    continue;
                }

                match *kind {
                    SendKind::Unicast {
                        nwk_frame,
                        next_hop,
                        security,
                        attempts_remaining,
                    } => {
                        // Owns the outcome: reports it on success or terminal failure, or
                        // hands it to the retry reactor.
                        self.attempt_unicast_send(
                            nwk_frame,
                            next_hop,
                            security,
                            priority,
                            attempts_remaining,
                            outcome,
                            token,
                        )
                        .await;
                    }
                    SendKind::Broadcast {
                        nwk_frame,
                        security,
                    } => {
                        let result = self.process_broadcast_send(nwk_frame, security).await;
                        self.resolve_outcome(outcome, result);
                    }
                    SendKind::Raw { frame } => {
                        let result = self.send_802154_frame(frame).await;
                        self.resolve_outcome(outcome, result);
                    }
                }
            }

            self.send_wake.notified().await;
        }
    }

    /// Deliver a transmit's terminal outcome to wherever it is owed: log a dropped
    /// background failure, wake an awaiting caller, or confirm an application send.
    pub(super) fn resolve_outcome(&self, outcome: TxOutcome, result: Result<(), DeliveryError>) {
        match outcome {
            TxOutcome::Discard => {
                if let Err(err) = result {
                    tracing::warn!("Background send failed: {err}");
                }
            }
            TxOutcome::Track { slot, stage } => slot.resolve(stage, result),
            TxOutcome::IndirectDelivery {
                destination,
                transaction,
            } => match result {
                // 802.15.4 spec 6.7.3: a transaction is only extracted once
                // acknowledged, so a failed transmit goes back to the head of the
                // queue for the next poll
                Err(err) if self.core_now() < transaction.expires_at => {
                    tracing::warn!(
                        "Indirect transmit to {destination:?} failed ({err}), requeueing"
                    );
                    self.core()
                        .mac
                        .indirect_queue
                        .requeue(destination, *transaction);
                }
                _ => {
                    let transaction = *transaction;
                    self.resolve_outcome(transaction.completion, result);
                    self.remove_indirect_queue_if_empty(destination);
                }
            },
        }
    }

    /// One transmit attempt for a dequeued unicast: assign the frame counter, encrypt,
    /// and send once. On success (or terminal failure) the completion resolves here;
    /// on a failed attempt with retries left, the plaintext frame is parked with the
    /// unicast-retry reactor instead of being slept on, so the sender stays free.
    #[allow(clippy::too_many_arguments)]
    async fn attempt_unicast_send(
        &self,
        mut nwk_frame: NwkFrame,
        next_hop_address: Nwk,
        security: NwkSecurityMode,
        priority: TxPriority,
        attempts_remaining: u8,
        outcome: TxOutcome,
        token: FrameToken,
    ) {
        self.apply_nwk_aux_header(&mut nwk_frame, security);
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

        let Err(e) = self.send_802154_frame(ieee802154_frame).await else {
            self.resolve_outcome(outcome, Ok(()));
            return;
        };

        // Spec Table 3-75: an unacknowledged unicast is a transmit failure recorded
        // against the next hop. Counted per MCPS-DATA.request, like `nwkTxTotal` above,
        // so the two stay on the same denominator.
        if let DeliveryError::NwkNoAck { .. } = e {
            let mut core = self.core();
            if let Some(next_hop_eui64) = core.nib.address_map.eui64_for(next_hop_address) {
                core.nib.neighbors.record_transmit_failure(next_hop_eui64);
            }
        }

        tracing::warn!("Failed to send unicast frame: {e}");

        if attempts_remaining == 0 {
            tracing::error!("Failed to send unicast frame after all attempts");
            self.handle_unicast_send_failure(&nwk_frame, next_hop_address);
            self.resolve_outcome(outcome, Err(e));
            return;
        }

        // Park the frame for re-transmission after the retry delay. The plaintext frame
        // is re-enqueued (not the ciphertext), so the next attempt earns a fresh counter
        // at dequeue and on-air order stays equal to counter order.
        tracing::debug!("Scheduling unicast retry, {attempts_remaining} attempt(s) remaining");
        self.schedule_unicast_retry(
            nwk_frame,
            next_hop_address,
            security,
            priority,
            attempts_remaining - 1,
            outcome,
            token,
        );
    }

    /// Park a failed unicast for re-enqueue after [`unicast_retry_delay`] and wake the
    /// retry reactor.
    #[allow(clippy::too_many_arguments)]
    fn schedule_unicast_retry(
        &self,
        nwk_frame: NwkFrame,
        next_hop: Nwk,
        security: NwkSecurityMode,
        priority: TxPriority,
        attempts_remaining: u8,
        outcome: TxOutcome,
        token: FrameToken,
    ) {
        let delay = self.tunables.unicast_retry_delay();

        // The frame has a random jitter of up to one retry delay period
        let jitter = delay.mul_f32(crate::rng::random_f32());
        let next_attempt = self.core_now() + delay + jitter;

        self.state
            .pending_unicast_retries
            .lock()
            .push(PendingUnicastRetry {
                nwk_frame,
                next_hop,
                security,
                priority,
                attempts_remaining,
                next_attempt,
                outcome,
                token,
            });
        self.unicast_retry_wake.notify_one();
    }

    /// The unicast-retry reactor: a single long-lived task that re-enqueues failed
    /// unicasts once their retry delay elapses, mirroring the broadcast-retransmit
    /// reactor.
    pub(super) async fn unicast_retry_task(&self) {
        loop {
            match self.earliest_unicast_retry() {
                Some(deadline) => {
                    let _ = self
                        .timeout_at_core(deadline, self.unicast_retry_wake.notified())
                        .await;
                }
                None => self.unicast_retry_wake.notified().await,
            }

            self.drive_unicast_retries();
        }
    }

    /// The soonest re-enqueue deadline across all parked retries, or `None` when none are
    /// parked (the reactor then sleeps on its wake signal).
    fn earliest_unicast_retry(&self) -> Option<CoreInstant> {
        self.state
            .pending_unicast_retries
            .lock()
            .iter()
            .map(|retry| retry.next_attempt)
            .min()
    }

    /// One reactor pass: re-enqueue every parked retry whose delay has elapsed. The
    /// re-enqueued frame competes by its priority and earns a fresh counter at dequeue.
    fn drive_unicast_retries(&self) {
        let now = self.core_now();

        let due: Vec<PendingUnicastRetry> = {
            let mut pending = self.state.pending_unicast_retries.lock();
            let mut due = Vec::new();
            let mut i = 0;
            while i < pending.len() {
                // A retry that is due, or cancelled, is pulled: due ones re-enqueue,
                // cancelled ones resolve below (freeing their token early).
                if pending[i].next_attempt <= now || Self::outcome_cancelled(&pending[i].outcome) {
                    // Order does not matter (the priority queue reorders anyway), so an
                    // O(1) swap-remove is fine.
                    due.push(pending.swap_remove(i));
                } else {
                    i += 1;
                }
            }
            drop(pending);

            due
        };

        for retry in due {
            if Self::outcome_cancelled(&retry.outcome) {
                self.resolve_outcome(retry.outcome, Err(DeliveryError::Cancelled));
                continue;
            }
            self.enqueue_send_with_token(
                SendKind::Unicast {
                    nwk_frame: retry.nwk_frame,
                    next_hop: retry.next_hop,
                    security: retry.security,
                    attempts_remaining: retry.attempts_remaining,
                },
                retry.priority,
                retry.outcome,
                retry.token,
            );
        }
    }

    /// Whether this outcome belongs to a cancelled send. Only a tracked send carries a
    /// slot, and only a tracked send can be cancelled; every reactor checks this before
    /// acting on the entry it holds, dropping it and resolving `Err(Cancelled)` if set.
    fn outcome_cancelled(outcome: &TxOutcome) -> bool {
        matches!(outcome, TxOutcome::Track { slot, .. } if slot.is_cancelled())
    }

    /// Nudge every reactor that parks a cancellable send, so a just-set cancel flag is
    /// acted on this pass rather than at the reactor's next scheduled wake. Called after a
    /// [`SendHandle::cancel`](super::SendHandle::cancel).
    pub fn nudge_cancellation(&self) {
        self.send_wake.notify_one();
        self.unicast_retry_wake.notify_one();
        self.broadcast_retransmit_wake.notify_one();
        self.pending_route_wake.notify_one();
        self.aps_ack_wake.notify_one();
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
            let Some(token) = frame_token::take(class) else {
                tracing::warn!(
                    "Frame budget exhausted; skipping broadcast copy to sleepy child {child_nwk:?}"
                );
                continue;
            };

            // Finished only when the child polls (see `IndirectFrame`).
            let frame = IndirectFrame {
                poll_address: Ieee802154Address::Eui64(child_eui64),
                payload: IndirectPayload::Deferred {
                    nwk_frame: nwk_frame.clone(),
                    next_hop: child_nwk,
                    security,
                },
                token,
            };
            self.increment_tx_total();

            // Fire-and-forget: a broadcast copy has no end-to-end result to await.
            self.enqueue_indirect_frame(frame, TxOutcome::Discard);
        }
    }

    /// Send a broadcast.
    pub(super) fn send_broadcast(&self, send: Broadcast) -> Result<(), EnqueueError> {
        let Broadcast {
            frame: mut nwk_frame,
            security,
            policy,
            slot,
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

        // The retained copy's token, held for the whole retransmit schedule.
        let Some(token) = frame_token::take(policy.class) else {
            tracing::warn!(
                "Frame budget exhausted ({}/{} tokens); rejecting {:?} broadcast",
                frame_token::used(),
                frame_token::total(),
                policy.class,
            );
            return Err(EnqueueError::BudgetExhausted);
        };

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

        // Transmit the first copy immediately: a lost copy is not terminal, the reactor
        // retransmits. The copy resolves the send's handoff (the first on-air copy wins);
        // the reactor holds the slot and resolves the end-to-end quorum result.
        self.enqueue_send(
            SendKind::Broadcast {
                nwk_frame: nwk_frame.clone(),
                security,
            },
            policy,
            Self::broadcast_copy_outcome(slot.clone()),
        );

        self.schedule_broadcast(
            key,
            nwk_frame,
            security,
            policy,
            BroadcastSchedule::PassiveAck,
            self.tunables.passive_ack_timeout() + self.broadcast_jitter(),
            self.tunables.max_broadcast_retries(),
            slot,
            token,
        );
        Ok(())
    }

    /// Send a single-copy broadcast: assign its sequence number and queue one copy
    /// for the sender task.
    pub(super) fn send_oneshot_broadcast(&self, send: Broadcast) {
        let Broadcast {
            frame: mut nwk_frame,
            security,
            policy,
            slot,
        } = send;
        nwk_frame.nwk_header.sequence_number = self.next_nwk_sequence_number();

        #[allow(clippy::option_if_let_else)]
        let outcome = match slot {
            Some(slot) => TxOutcome::Track {
                slot,
                stage: TrackStage::Delivery,
            },
            None => TxOutcome::Discard,
        };

        self.enqueue_send(
            SendKind::Broadcast {
                nwk_frame,
                security,
            },
            policy,
            outcome,
        );
    }

    /// Encrypt and broadcast a single dequeued copy of a frame.
    async fn process_broadcast_send(
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
        // retry end-to-end.
        let Some(token) = frame_token::take(TrafficClass::Forwarding) else {
            tracing::warn!("Frame budget exhausted; dropping relay to {destination:?}");
            return;
        };

        // The originator's sequence number is preserved when relaying. The transmit and
        // any failure handling (route invalidation, the network status back to the
        // originator) happen in the sender; nothing is awaited here.
        self.enqueue_unicast(
            nwk_frame,
            next_hop_address,
            NwkSecurityMode::NetworkKey,
            TxPriority::UserNormal,
            TxOutcome::Discard,
            token,
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

        let send = Unicast {
            frame: network_status_frame,
            security: NwkSecurityMode::NetworkKey,
            mode: SendMode::Route(RouteDirective::StackDecides),
            policy: TxPolicy::STACK_CRITICAL,
            outcome: TxOutcome::Discard,
        };
        if let Err(err) = self.send_unicast(send) {
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

        // Spec 3.6.6: deliver another device's 0xFFFF broadcast to our own sleepy
        // children as MAC unicasts (a no-op for non-0xFFFF destinations).
        self.maybe_fan_out_broadcast_to_sleepy_children(
            nwk_frame,
            NwkSecurityMode::NetworkKey,
            TrafficClass::Forwarding,
        );

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

        let Some(token) = frame_token::take(TrafficClass::Forwarding) else {
            tracing::warn!("Frame budget exhausted; not relaying broadcast {key:?}");
            return;
        };

        // Unlike an originated broadcast, the first relay is also scheduled (after jitter)
        // rather than sent inline, so the attempt count includes it. The passive-ack
        // contract was recorded when we received the frame, so the reactor's quorum check
        // already covers relayed broadcasts.
        self.schedule_broadcast(
            key,
            relayed_frame,
            NwkSecurityMode::NetworkKey,
            TxPolicy {
                priority: TxPriority::UserNormal,
                class: TrafficClass::Forwarding,
            },
            BroadcastSchedule::PassiveAck,
            self.broadcast_jitter(),
            self.tunables.max_broadcast_retries() + 1,
            None,
            token,
        );
    }
}
