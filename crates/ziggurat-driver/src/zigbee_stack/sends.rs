//! The async shell around the send table ([`Sends`]): enqueueing, the sender task that
//! feeds the radio, the timer task that drives everything waiting on time, and the
//! execution of the actions the table returns.
//!
//! The table lives in the core, so one lock covers a mutation and the core facts it
//! reads. The lock is released before the actions are carried out, since resolving a
//! waiter can wake a task that sends again.

use alloc::sync::Arc;
use core::time::Duration;

use ziggurat_ieee_802154::Ieee802154Address;
use ziggurat_ieee_802154::types::Nwk;
use ziggurat_phy::RadioPhy;
use ziggurat_zigbee::Instant as CoreInstant;
use ziggurat_zigbee::nwk::next_hop::{self, NextHop};
use ziggurat_zigbee::sends::{Action, Broadcast as BroadcastRecord, Unicast as UnicastRecord};

use crate::frame_token;
use crate::runtime::Runtime;

use super::routing::Status as RouteStatus;
use super::{
    Confirm, CoreGuard, DeliveryError, EnqueueError, Frame, HeldFrame, Nib, NwkSecurityMode,
    RouteDirective, Schedule, SendActions, SendHandle, SendId, SendMode, SendSlot, Transmit,
    TxPolicy, TxPriority, ZigbeeCore, ZigbeeStack,
};

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    /// Take a frame token from the policy's budget tier and the slot the send's verdicts
    /// go to. A refused token rejects the send.
    pub(super) fn hold_frame(
        &self,
        frame: Frame,
        policy: TxPolicy,
    ) -> Result<(HeldFrame, Arc<SendSlot>), EnqueueError> {
        let token = frame_token::take(policy.class).ok_or_else(|| {
            tracing::warn!(
                "Frame budget exhausted ({}/{} tokens); rejecting {:?} frame",
                frame_token::used(),
                frame_token::total(),
                policy.class,
            );
            EnqueueError::BudgetExhausted
        })?;

        Ok((HeldFrame { frame, token }, Arc::new(SendSlot::default())))
    }

    /// Enqueue a unicast to `next_hop`, held until the device polls under
    /// `poll_address` if it is given. Every send gets a slot: dropping the returned
    /// handle is how a caller detaches from a send it does not await.
    // The guard is moved into `commit_sends`; the lint misreads the `?` return path
    #[allow(clippy::significant_drop_tightening)]
    pub(super) fn enqueue_unicast(
        &self,
        frame: Frame,
        policy: TxPolicy,
        confirm: Confirm,
        next_hop: Nwk,
        poll_address: Option<Ieee802154Address>,
    ) -> Result<SendHandle, EnqueueError> {
        let mut core = self.core();
        let (handle, actions) =
            self.enqueue_unicast_in(&mut core, frame, policy, confirm, next_hop, poll_address)?;
        self.commit_sends(core, actions);
        Ok(handle)
    }

    /// [`Self::enqueue_unicast`] under a core lock the caller holds and commits.
    pub(super) fn enqueue_unicast_in(
        &self,
        core: &mut ZigbeeCore,
        frame: Frame,
        policy: TxPolicy,
        confirm: Confirm,
        next_hop: Nwk,
        poll_address: Option<Ieee802154Address>,
    ) -> Result<(SendHandle, SendActions), EnqueueError> {
        let (frame, slot) = self.hold_frame(frame, policy)?;
        let (id, actions) = core.sends.enqueue_unicast(
            UnicastRecord {
                frame,
                priority: policy.priority,
                waiter: slot.clone(),
                confirm,
                next_hop,
                poll_address,
            },
            self.core_now(),
            &self.tunables,
        );

        Ok((SendHandle::new(id, slot), actions))
    }

    /// Enqueue a broadcast, or any frame transmitted on a schedule.
    // The guard is moved into `commit_sends`; the lint misreads the `?` return path
    #[allow(clippy::significant_drop_tightening)]
    pub(super) fn enqueue_broadcast(
        &self,
        frame: Frame,
        policy: TxPolicy,
        schedule: Schedule,
    ) -> Result<SendHandle, EnqueueError> {
        let mut core = self.core();
        let (handle, actions) = self.enqueue_broadcast_in(&mut core, frame, policy, schedule)?;
        self.commit_sends(core, actions);
        Ok(handle)
    }

    /// [`Self::enqueue_broadcast`] under a core lock the caller holds and commits.
    pub(super) fn enqueue_broadcast_in(
        &self,
        core: &mut ZigbeeCore,
        frame: Frame,
        policy: TxPolicy,
        schedule: Schedule,
    ) -> Result<(SendHandle, SendActions), EnqueueError> {
        let (frame, slot) = self.hold_frame(frame, policy)?;
        Ok(self.enqueue_held_broadcast(core, frame, slot, policy.priority, schedule))
    }

    /// Enqueue a broadcast whose frame is already held, so admission happened before
    /// whatever the caller did between the two.
    pub(super) fn enqueue_held_broadcast(
        &self,
        core: &mut ZigbeeCore,
        frame: HeldFrame,
        slot: Arc<SendSlot>,
        priority: TxPriority,
        schedule: Schedule,
    ) -> (SendHandle, SendActions) {
        let (id, actions) = core.sends.enqueue_broadcast(
            BroadcastRecord {
                frame,
                priority,
                waiter: slot.clone(),
                schedule,
            },
            self.core_now(),
            &self.tunables,
        );

        (SendHandle::new(id, slot), actions)
    }

    /// Finish a mutation of the send table from any task but the timer: carry out the
    /// actions and wake the timer, whose next deadline may have moved.
    pub(super) fn commit_sends(&self, core: CoreGuard<'_>, actions: SendActions) {
        self.run_send_actions(core, actions);
        self.send_timer_wake.notify_one();
    }

    /// Release the core, carry out the actions a mutation returned, and wake the sender
    /// and the source-match sync, which diffs the poll set itself. Taking the guard is
    /// what guarantees the core is unlocked before an action locks it again.
    fn run_send_actions(&self, core: CoreGuard<'_>, actions: SendActions) {
        drop(core);

        for action in actions {
            match action {
                Action::HandedOff(slot) => slot.handed_off(),
                Action::Settled {
                    waiter,
                    result,
                    frame,
                    failed_hop,
                } => {
                    if let Some(next_hop) = failed_hop
                        && let Frame::Nwk { nwk_frame, .. } = &frame.frame
                    {
                        tracing::error!("Failed to send unicast frame after all attempts");
                        self.handle_unicast_send_failure(nwk_frame, next_hop);
                    }

                    waiter.settled(result);

                    // Frees the frame token
                    drop(frame);
                }
            }
        }

        self.send_wake.notify_one();
        self.src_match_sync.notify_one();
    }

    /// Cancel a send. Returns whether it was still pending and is now settled with
    /// `Cancelled`. A send in the radio right now is refused: its own report settles it
    /// within the radio's timeout.
    #[allow(clippy::option_if_let_else)]
    pub fn cancel_send(&self, id: SendId) -> bool {
        let mut core = self.core();
        match core.sends.cancel(id) {
            Some(actions) => {
                self.commit_sends(core, actions);
                true
            }
            None => false,
        }
    }

    /// The stack settings next-hop resolution reads.
    pub(super) fn next_hop_policy(&self) -> next_hop::Policy {
        next_hop::Policy {
            is_concentrator: self.state.is_concentrator,
            force_route_discovery: self.state.hack_force_route_discovery,
            max_source_route: self.tunables.max_source_route(),
        }
    }

    /// The address a next hop polls under, if it is a sleepy child whose frames await
    /// its poll.
    pub(super) fn poll_address(nib: &Nib, next_hop: Nwk) -> Option<Ieee802154Address> {
        nib.neighbors
            .sleepy_child_eui64(next_hop)
            .map(Ieee802154Address::Eui64)
    }

    /// The next hop of an unrouted frame once its route is known, and the address it
    /// polls under if it is a sleepy child. The route can have vanished in the race,
    /// which fails the send.
    fn resolve_routed_unicast(
        &self,
        nib: &Nib,
        frame: &mut Frame,
    ) -> Result<(Nwk, Option<Ieee802154Address>), DeliveryError> {
        let Frame::Nwk { nwk_frame, .. } = frame else {
            unreachable!("only NWK unicasts await a route")
        };

        let resolved = next_hop::resolve(
            &nib.routing,
            &nib.neighbors,
            nwk_frame,
            &SendMode::Route(RouteDirective::StackDecides),
            self.next_hop_policy(),
        );

        match resolved {
            NextHop::Resolved(next_hop) => Ok((next_hop, Self::poll_address(nib, next_hop))),
            NextHop::NeedDiscovery | NextHop::Discard => {
                Err(DeliveryError::RouteInactiveAfterDiscovery)
            }
        }
    }

    /// The single transmit task: takes the highest-priority ready frame, secures it (so
    /// frame-counter order always matches on-air order), transmits it, and reports back
    /// to the table. Serializing all transmits here is what keeps the counter
    /// monotonic.
    pub(super) async fn sender_task(&self) {
        loop {
            loop {
                // The frame leaves the table on loan, so the core is unlocked across the
                // transmit
                let Some(mut in_flight) = self.core().sends.dequeue() else {
                    break;
                };

                let transmit = in_flight.transmit();
                let result = self
                    .transmit(&mut in_flight.frame_mut().frame, transmit)
                    .await;

                let now = self.core_now();
                let retry_delay = self.unicast_retry_delay();
                let mut core = self.core();
                let actions = core.sends.transmitted(in_flight, result, now, retry_delay);
                self.commit_sends(core, actions);
            }

            self.send_wake.notified().await;
        }
    }

    /// Build the 802.15.4 frame for one transmit and hand it to the radio. The frame is
    /// finished in place (aux header, frame-pending bit) and keeps that state between
    /// attempts; every attempt overwrites it.
    async fn transmit(&self, frame: &mut Frame, transmit: Transmit) -> Result<(), DeliveryError> {
        match (transmit, frame) {
            (
                Transmit::Unicast {
                    next_hop,
                    frame_pending,
                },
                Frame::Nwk {
                    nwk_frame,
                    security,
                },
            ) => {
                self.transmit_unicast(nwk_frame, next_hop, *security, frame_pending)
                    .await
            }
            (Transmit::Unicast { frame_pending, .. }, Frame::Raw(raw)) => {
                raw.header_mut().frame_control.frame_pending = frame_pending;
                self.send_802154_frame(raw).await
            }
            (
                Transmit::Broadcast,
                Frame::Nwk {
                    nwk_frame,
                    security,
                },
            ) => self.transmit_broadcast(nwk_frame, *security).await,
            (Transmit::Broadcast, Frame::Raw(raw)) => self.send_802154_frame(raw).await,
        }
    }

    /// The NWK retry delay with a random jitter of up to one delay period.
    fn unicast_retry_delay(&self) -> Duration {
        let delay = self.tunables.unicast_retry_delay();
        delay + delay.mul_f32(crate::rng::random_f32())
    }

    /// The timer task: runs the table's timed transitions whenever its next deadline is
    /// due, or when a mutation may have moved that deadline.
    pub(super) async fn send_timer_task(&self) {
        loop {
            match self.drive_sends() {
                Some(deadline) => {
                    let _ = self
                        .timeout_at_core(deadline, self.send_timer_wake.notified())
                        .await;
                }
                None => self.send_timer_wake.notified().await,
            }
        }
    }

    /// One timer pass: settle the broadcasts whose passive-ack quorum was heard, route
    /// the sends whose route became active, restart or fail the discoveries that
    /// lapsed, then run the table's timed transitions. Returns when the next pass is
    /// due: the table's next deadline, or that of a route discovery unrouted sends wait
    /// on, which lives in the routing table.
    fn drive_sends(&self) -> Option<CoreInstant> {
        let now = self.core_now();
        let passive_ack_interval = self.tunables.passive_ack_timeout() + self.broadcast_jitter();

        let mut guard = self.core();
        // A plain `&mut ZigbeeCore`, so the closure below borrows `nib` beside `sends`
        let core = &mut *guard;
        let mut actions = SendActions::new();

        for key in core.sends.broadcasts_awaiting_quorum() {
            if self.passive_ack_quorum_heard(&core.nib, key) {
                actions.extend(core.sends.broadcast_delivered(key));
            }
        }

        for destination in core.sends.unrouted_destinations() {
            if core.nib.routing.route_status(destination) == Some(RouteStatus::Active) {
                actions.extend(core.sends.route_unicasts(
                    destination,
                    now,
                    &self.tunables,
                    |send| self.resolve_routed_unicast(&core.nib, &mut send.frame),
                ));
            } else if core
                .nib
                .routing
                .discovery_deadline(destination, now)
                .is_none()
            {
                if core.sends.retry_discovery(destination) {
                    actions.extend(self.start_route_discovery(core, destination));
                } else {
                    core.nib.routing.mark_discovery_failed(destination);
                    actions.extend(core.sends.fail_unrouted(destination));
                }
            }
        }

        actions.extend(core.sends.tick(now, passive_ack_interval));

        let discoveries = core
            .sends
            .unrouted_destinations()
            .into_iter()
            .filter_map(|destination| core.nib.routing.discovery_deadline(destination, now));
        let next_wake = core.sends.next_wake().into_iter().chain(discoveries).min();

        // This pass is the timer task's own: waking the timer here would make it spin
        self.run_send_actions(guard, actions);
        next_wake
    }
}

/// Convenience for building a plain NWK frame entry.
impl Frame {
    pub const fn nwk(
        nwk_frame: ziggurat_zigbee::nwk::frame::NwkFrame,
        security: NwkSecurityMode,
    ) -> Self {
        Self::Nwk {
            nwk_frame,
            security,
        }
    }
}
