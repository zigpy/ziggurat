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
use ziggurat_zigbee::nwk::next_hop::{self, NextHop};
use ziggurat_zigbee::sends::{Action, Broadcast as BroadcastRecord, Unicast as UnicastRecord};

use crate::frame_token::{self, FrameToken};
use crate::runtime::Runtime;

use super::routing::Status as RouteStatus;
use super::{
    Confirm, CoreGuard, Delivery, DeliveryError, EnqueueError, Frame, HeldFrame, Nib,
    NwkSecurityMode, Placement, RouteDirective, Schedule, SendActions, SendHandle, SendId,
    SendMode, SendSlot, Transmit, TxPolicy, ZigbeeCore, ZigbeeStack,
};

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    /// Take a frame token from the policy's budget tier. A refused token rejects the
    /// send at admission.
    pub(super) fn take_token(&self, policy: TxPolicy) -> Result<FrameToken, EnqueueError> {
        frame_token::take(policy.class).ok_or_else(|| {
            tracing::warn!(
                "Frame budget exhausted ({}/{} tokens); rejecting {:?} frame",
                frame_token::used(),
                frame_token::total(),
                policy.class,
            );
            EnqueueError::BudgetExhausted
        })
    }

    /// Enqueue a unicast with a known next hop. Every send gets a slot: dropping the
    /// returned handle is how a caller detaches from a send it does not await.
    // The guard is moved into `commit_sends`; the lint misreads the `?` return path
    #[allow(clippy::significant_drop_tightening)]
    pub(super) fn enqueue_unicast(
        &self,
        frame: Frame,
        policy: TxPolicy,
        confirm: Confirm,
        placement: Placement,
    ) -> Result<SendHandle, EnqueueError> {
        let mut core = self.core();
        let (handle, actions) =
            self.enqueue_unicast_in(&mut core, frame, policy, confirm, placement)?;
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
        placement: Placement,
    ) -> Result<(SendHandle, SendActions), EnqueueError> {
        let token = self.take_token(policy)?;
        let slot = Arc::new(SendSlot::default());

        let (id, actions) = core.sends.enqueue_unicast(UnicastRecord {
            frame: HeldFrame { frame, token },
            priority: policy.priority,
            waiter: slot.clone(),
            confirm,
            delivery: placement.delivery,
            deadline: placement.deadline,
        });

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
        let token = self.take_token(policy)?;
        let slot = Arc::new(SendSlot::default());

        let (id, actions) = core.sends.enqueue_broadcast(BroadcastRecord {
            frame: HeldFrame { frame, token },
            priority: policy.priority,
            waiter: slot.clone(),
            schedule,
            deadline: self.core_now() + self.tunables.handoff_timeout(),
        });

        Ok((SendHandle::new(id, slot), actions))
    }

    /// Finish a mutation of the send table: release the core, carry out the actions
    /// the mutation returned, and wake the tasks whose next step may have changed: the
    /// sender, the timer, and the source-match sync, which diffs the poll set itself.
    /// Taking the guard is what guarantees the core is unlocked before an action locks
    /// it again.
    pub(super) fn commit_sends(&self, core: CoreGuard<'_>, actions: SendActions) {
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
        self.send_timer_wake.notify_one();
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

    /// Where a unicast with a resolved next hop goes: a sleepy child's frame awaits its
    /// poll, everything else is queued for the sender.
    #[allow(clippy::option_if_let_else)]
    pub(super) fn place_unicast(&self, nib: &Nib, next_hop: Nwk) -> Placement {
        match nib.neighbors.sleepy_child_eui64(next_hop) {
            Some(child_eui64) => {
                self.place_indirect_unicast(Ieee802154Address::Eui64(child_eui64), next_hop)
            }
            None => Placement {
                delivery: Delivery::Direct {
                    next_hop,
                    attempts_remaining: self.tunables.unicast_retries(),
                },
                deadline: self.core_now() + self.tunables.handoff_timeout(),
            },
        }
    }

    /// A frame held for a sleepy device until it polls under `address`, then transmitted
    /// to `next_hop`. It expires after the transaction persistence time.
    pub(super) fn place_indirect_unicast(
        &self,
        address: Ieee802154Address,
        next_hop: Nwk,
    ) -> Placement {
        Placement {
            delivery: Delivery::Indirect { address, next_hop },
            deadline: self.core_now() + self.tunables.transaction_persistence_time(),
        }
    }

    /// Where an unrouted frame goes once its route is known. The route can have
    /// vanished in the race, which fails the send.
    fn place_routed_unicast(
        &self,
        nib: &Nib,
        frame: &mut Frame,
    ) -> Result<Placement, DeliveryError> {
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
            NextHop::Resolved(next_hop) => Ok(self.place_unicast(nib, next_hop)),
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
                // The frame is cloned out so the core is unlocked across the transmit
                let dequeued = self.core().sends.dequeue().map(|dequeued| {
                    (
                        dequeued.in_flight,
                        dequeued.frame.frame.clone(),
                        dequeued.transmit,
                    )
                });

                let Some((in_flight, frame, transmit)) = dequeued else {
                    break;
                };

                let result = self.transmit(frame, transmit).await;

                let now = self.core_now();
                let retry_delay = self.unicast_retry_delay();
                let mut core = self.core();
                let actions = core.sends.transmitted(in_flight, result, now, retry_delay);
                self.commit_sends(core, actions);
            }

            self.send_wake.notified().await;
        }
    }

    /// Build the 802.15.4 frame for one transmit and hand it to the radio.
    async fn transmit(&self, frame: Frame, transmit: Transmit) -> Result<(), DeliveryError> {
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
                self.transmit_unicast(nwk_frame, next_hop, security, frame_pending)
                    .await
            }
            (Transmit::Unicast { frame_pending, .. }, Frame::Raw(mut raw)) => {
                raw.header_mut().frame_control.frame_pending = frame_pending;
                self.send_802154_frame(raw).await
            }
            (
                Transmit::Broadcast,
                Frame::Nwk {
                    nwk_frame,
                    security,
                },
            ) => self.transmit_broadcast(nwk_frame, security).await,
            (Transmit::Broadcast, Frame::Raw(raw)) => self.send_802154_frame(raw).await,
        }
    }

    /// The NWK retry delay with a random jitter of up to one delay period.
    fn unicast_retry_delay(&self) -> Duration {
        let delay = self.tunables.unicast_retry_delay();
        delay + delay.mul_f32(crate::rng::random_f32())
    }

    /// The timer task: runs the table's timed transitions whenever its next deadline is
    /// due, or when a mutation may have moved that deadline. The route discoveries
    /// unrouted sends wait on keep their deadlines in the routing table, so those count
    /// too.
    pub(super) async fn send_timer_task(&self) {
        loop {
            self.drive_sends();

            let next_wake = {
                let now = self.core_now();
                let core = self.core();
                let discoveries =
                    core.sends
                        .unrouted_destinations()
                        .into_iter()
                        .filter_map(|destination| {
                            core.nib.routing.discovery_deadline(destination, now)
                        });
                core.sends.next_wake().into_iter().chain(discoveries).min()
            };

            match next_wake {
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
    /// lapsed, then run the table's timed transitions.
    fn drive_sends(&self) {
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
                actions.extend(core.sends.route_unicasts(destination, |send| {
                    self.place_routed_unicast(&core.nib, &mut send.frame)
                }));
            } else if core.nib.routing.discovery_lapsed(destination, now) {
                if core.sends.retry_discovery(destination) {
                    actions.extend(self.start_route_discovery(core, destination));
                } else {
                    core.nib.routing.mark_discovery_failed(destination);
                    actions.extend(core.sends.fail_unrouted(destination));
                }
            }
        }

        actions.extend(core.sends.tick(now, passive_ack_interval));
        self.commit_sends(guard, actions);
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
