//! The async shell around the send table ([`Sends`]): enqueueing, the sender task that
//! feeds the radio, the timer task that drives everything waiting on time, and the
//! execution of the actions the table queues.
//!
//! The table lives in the core, so one lock covers a mutation and the core facts it
//! reads. The actions are carried out before the lock is released, so waiters learn
//! their verdicts in the order the table reached them. Resolving a waiter only marks
//! its task ready: it runs once the lock is released.

use core::time::Duration;

use ziggurat_ieee_802154::Ieee802154Address;
use ziggurat_ieee_802154::types::Nwk;
use ziggurat_phy::RadioPhy;
use ziggurat_zigbee::Instant as CoreInstant;
use ziggurat_zigbee::nwk::next_hop::{self, NextHop};
use ziggurat_zigbee::sends::{Action, Broadcast as BroadcastRecord, Unicast as UnicastRecord};

use crate::runtime::Runtime;

use super::{
    Confirm, CoreGuard, DeliveryError, Frame, Nib, NwkSecurityMode, RouteDirective, Schedule,
    SendHandle, SendId, SendMode, Transmit, TxPolicy, ZigbeeCore, ZigbeeStack,
};

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    /// Enqueue a unicast to `next_hop`, held until the device polls under
    /// `poll_address` if it is given. Every send gets a handle: dropping the returned
    /// handle is how a caller detaches from a send it does not await.
    pub(super) fn enqueue_unicast(
        &self,
        frame: Frame,
        policy: TxPolicy,
        confirm: Confirm,
        next_hop: Nwk,
        poll_address: Option<Ieee802154Address>,
    ) -> SendHandle {
        let mut core = self.core();
        let handle =
            self.enqueue_unicast_in(&mut core, frame, policy, confirm, next_hop, poll_address);
        self.commit_sends(core);
        handle
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
    ) -> SendHandle {
        let id = core.sends.enqueue_unicast(
            UnicastRecord {
                frame,
                priority: policy.priority,
                confirm,
                next_hop,
                poll_address,
            },
            self.core_now(),
            &self.tunables,
        );

        SendHandle::new(id, &self.send_watches)
    }

    /// Enqueue a broadcast, or any frame transmitted on a schedule.
    pub(super) fn enqueue_broadcast(
        &self,
        frame: Frame,
        policy: TxPolicy,
        schedule: Schedule,
    ) -> SendHandle {
        let mut core = self.core();
        let handle = self.enqueue_broadcast_in(&mut core, frame, policy, schedule);
        self.commit_sends(core);
        handle
    }

    /// [`Self::enqueue_broadcast`] under a core lock the caller holds and commits.
    pub(super) fn enqueue_broadcast_in(
        &self,
        core: &mut ZigbeeCore,
        frame: Frame,
        policy: TxPolicy,
        schedule: Schedule,
    ) -> SendHandle {
        let id = core.sends.enqueue_broadcast(
            BroadcastRecord {
                frame,
                priority: policy.priority,
                schedule,
            },
            self.core_now(),
            &self.tunables,
        );

        SendHandle::new(id, &self.send_watches)
    }

    /// Finish a mutation of the send table from any task but the timer: carry out its
    /// actions and wake the timer, whose next deadline may have moved.
    pub(super) fn commit_sends(&self, core: CoreGuard<'_>) {
        self.run_send_actions(core);
        self.send_timer_wake.notify_one();
    }

    /// Carry out the actions the table queued, release the core, and wake the sender
    /// and the source-match sync, which diffs the poll set itself. Every mutation is
    /// followed by this under the same lock, so no action waits for a later mutation.
    ///
    /// A unicast that failed at its next hop is handled once the core is released,
    /// since that locks the core again; its waiter learns its verdict after. Taking the
    /// guard is what guarantees the core is unlocked by then.
    pub(super) fn run_send_actions(&self, mut core: CoreGuard<'_>) {
        let mut failed_unicast = None;

        while let Some(action) = core.sends.next_action() {
            match action {
                Action::HandedOff(id) => self.send_watches.handed_off(id),
                Action::Settled {
                    id,
                    result,
                    failed_hop: Some((next_hop, Some(failed))),
                } => {
                    // Only a transmit report fails a unicast at its next hop, one at a time
                    assert!(failed_unicast.is_none());
                    failed_unicast = Some((failed, next_hop, id, result));
                }
                Action::Settled { id, result, .. } => self.send_watches.settled(id, result),
            }
        }

        drop(core);

        if let Some((failed, next_hop, id, result)) = failed_unicast {
            tracing::error!("Failed to send unicast frame after all attempts");
            self.handle_unicast_send_failure(failed, next_hop);
            self.send_watches.settled(id, result);
        }

        self.send_wake.notify_one();
        self.src_match_sync.notify_one();
    }

    /// Cancel a send. Returns whether it was still pending and is now settled with
    /// `Cancelled`. A send in the radio right now is refused: its own report settles it
    /// within the radio's timeout.
    pub fn cancel_send(&self, id: SendId) -> bool {
        let mut core = self.core();
        if !core.sends.cancel(id) {
            return false;
        }

        self.commit_sends(core);
        true
    }

    /// The stack settings next-hop resolution reads.
    pub(super) fn next_hop_policy(&self) -> next_hop::Policy {
        next_hop::Policy {
            is_concentrator: self.state.is_concentrator,
            force_route_discovery: self.state.hack_force_route_discovery,
            max_source_route: self.tunables.max_source_route(),
            new_router_child_window: 2 * self.tunables.link_status_period(),
        }
    }

    /// The address a next hop polls under, if it is a sleepy child whose frames await
    /// its poll.
    pub(super) fn poll_address(nib: &Nib, next_hop: Nwk) -> Option<Ieee802154Address> {
        nib.neighbors
            .sleepy_child_eui64(next_hop)
            .map(Ieee802154Address::Eui64)
    }

    /// Resolve the route of an unrouted frame again: its next hop and the address it
    /// polls under if it is a sleepy child. `None` means no route yet.
    fn resolve_unrouted_unicast(
        &self,
        nib: &Nib,
        frame: &mut Frame,
        now: CoreInstant,
    ) -> Option<(Nwk, Option<Ieee802154Address>)> {
        let Frame::Nwk { nwk_frame, .. } = frame else {
            unreachable!("only NWK unicasts await a route")
        };

        // A forced discovery holds the frame only while it is underway. Once it is
        // answered or has lapsed, the frame takes any route like every other frame
        let mut policy = self.next_hop_policy();
        policy.force_route_discovery &= nib.routing.own_discovery_underway(
            self.state.network_address,
            nwk_frame.nwk_header.destination,
            now,
        );

        let resolved = next_hop::resolve(
            &nib.routing,
            &nib.neighbors,
            nwk_frame,
            &SendMode::Route(RouteDirective::StackDecides),
            policy,
            now,
        );

        match resolved {
            NextHop::Resolved(next_hop) => Some((next_hop, Self::poll_address(nib, next_hop))),
            NextHop::NeedDiscovery => None,
            NextHop::Discard => {
                unreachable!("a frame is only held for a route if it allows discovery")
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
                let now = self.core_now();
                let Some(mut in_flight) = self.core().sends.dequeue(now) else {
                    break;
                };

                let transmit = in_flight.transmit();
                let result = self.transmit(in_flight.frame_mut(), transmit).await;

                let now = self.core_now();
                let retry_delay = self.unicast_retry_delay();
                let passive_ack_interval =
                    self.tunables.passive_ack_timeout() + self.broadcast_jitter();
                let mut core = self.core();
                core.sends
                    .transmitted(in_flight, result, now, retry_delay, passive_ack_interval);
                self.commit_sends(core);
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
        delay + delay.mul_f32(crate::rng::random_f32::<R>())
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

    /// One timer pass: settle the broadcasts whose passive-ack quorum was heard, run
    /// the send tables' pass against the routing and neighbor tables, then let the
    /// routing table start a discovery for, or give up on, each destination a send
    /// still waits on with none underway. Returns when the next pass is due.
    fn drive_sends(&self) -> Option<CoreInstant> {
        let now = self.core_now();

        let mut guard = self.core();
        // A plain `&mut ZigbeeCore`, so the closures below borrow `nib` beside `sends`
        let core = &mut *guard;

        core.sends
            .deliver_broadcasts(|key| self.passive_ack_quorum_heard(&core.nib, key));

        core.sends.tick(now, &self.tunables, |frame| {
            self.resolve_unrouted_unicast(&core.nib, frame, now)
        });

        let discoveries = core.nib.routing.tick_discoveries(
            self.state.network_address,
            now,
            self.tunables.route_discovery_time(),
            |destination| core.sends.has_unrouted(destination),
        );

        for (destination, route_request_identifier) in discoveries.restarted {
            self.broadcast_discovery_request(core, destination, route_request_identifier);
        }

        for destination in discoveries.unreachable {
            core.sends.fail_unrouted(destination);
        }

        let next_wake = [
            core.sends.next_wake(),
            core.nib
                .routing
                .next_discovery_lapse(self.state.network_address, now),
        ]
        .into_iter()
        .flatten()
        .min();

        // This pass is the timer task's own: waking the timer here would make it spin
        self.run_send_actions(guard);
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
