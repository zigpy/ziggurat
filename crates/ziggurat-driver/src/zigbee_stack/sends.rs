//! The async shell around the send table ([`Sends`]): admission, the sender task that
//! feeds the radio, the timer task that drives everything waiting on time, and the
//! execution of the actions the table returns.
//!
//! The table is locked briefly for every mutation and released before its actions are
//! carried out, since an action (starting a route discovery) can admit a new send.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_ieee_802154::Ieee802154Address;
use ziggurat_ieee_802154::types::Nwk;
use ziggurat_phy::RadioPhy;
use ziggurat_zigbee::sends::{Action, Admission};

use crate::frame_token;
use crate::runtime::Runtime;

use super::routing::Status as RouteStatus;
use super::{
    Confirm, DeliveryError, EnqueueError, Entry, Frame, Held, Next, NwkSecurityMode,
    RouteDirective, SendAction, SendHandle, SendId, SendMode, SendSlot, SendTable, TrackStage,
    Transmit, TxPolicy, ZigbeeStack,
};

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    /// Admit a frame into the send table, taking its frame token from the policy's
    /// budget tier. A refused token rejects the send at admission.
    pub(super) fn admit(
        &self,
        frame: Frame,
        policy: TxPolicy,
        confirm: Confirm,
        waiter: Option<Arc<SendSlot>>,
        entry: Entry,
    ) -> Result<SendId, EnqueueError> {
        let Some(token) = frame_token::take(policy.class) else {
            tracing::warn!(
                "Frame budget exhausted ({}/{} tokens); rejecting {:?} frame",
                frame_token::used(),
                frame_token::total(),
                policy.class,
            );
            return Err(EnqueueError::BudgetExhausted);
        };

        let now = self.core_now();
        let handoff_timeout = self.tunables.handoff_timeout();

        let id = self.mutate_sends(|sends| {
            sends.admit(
                Admission {
                    frame: Held { frame, token },
                    priority: policy.priority,
                    confirm,
                    waiter,
                },
                entry,
                now,
                handoff_timeout,
            )
        });

        Ok(id)
    }

    /// Admit a tracked send: the returned handle awaits its stages.
    pub(super) fn admit_tracked(
        &self,
        frame: Frame,
        policy: TxPolicy,
        confirm: Confirm,
        entry: Entry,
    ) -> Result<SendHandle, EnqueueError> {
        let slot = Arc::new(SendSlot::default());
        let id = self.admit(frame, policy, confirm, Some(slot.clone()), entry)?;
        Ok(SendHandle::new(id, slot))
    }

    /// Run one mutation of the send table, then carry out the actions it returned and
    /// wake the sender and timer tasks, whose next step may have changed.
    pub(super) fn mutate_sends<T>(
        &self,
        mutate: impl FnOnce(&mut SendTable) -> (T, Vec<SendAction>),
    ) -> T {
        let (value, actions) = mutate(&mut self.sends.lock());
        self.execute(actions);
        self.send_wake.notify_one();
        self.send_timer_wake.notify_one();
        value
    }

    /// Carry out what the send table decided. Called with the table unlocked.
    fn execute(&self, actions: Vec<SendAction>) {
        for action in actions {
            match action {
                Action::HandedOff(slot) => slot.resolve(TrackStage::HandOff, Ok(())),
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

                    match waiter {
                        Some(slot) => slot.resolve(TrackStage::Delivery, result),
                        None => {
                            if let Err(err) = result {
                                tracing::warn!("Background send failed: {err}");
                            }
                        }
                    }

                    // Frees the frame token
                    drop(frame);
                }
                Action::StartDiscovery(destination) => self.send_route_discovery(destination),
                Action::DiscoveryFailed(destination) => {
                    self.core().nib.routing.mark_discovery_failed(destination);
                }
                Action::PollAddressesChanged => self.src_match_sync.notify_one(),
            }
        }
    }

    /// Cancel a send. Returns whether it was still pending and is now settled with
    /// `Cancelled`. A send in the radio right now is refused: its own report settles it
    /// within the radio's timeout.
    #[allow(clippy::option_if_let_else)]
    pub fn cancel_send(&self, id: SendId) -> bool {
        self.mutate_sends(|sends| match sends.cancel(id) {
            Some(actions) => (true, actions),
            None => (false, Vec::new()),
        })
    }

    /// Where a unicast with a resolved next hop goes: a sleepy child's frame awaits its
    /// poll, everything else is queued for the sender.
    #[allow(clippy::option_if_let_else)]
    pub(super) fn place_unicast(&self, next_hop: Nwk) -> Entry {
        match self.sleepy_child_eui64(next_hop) {
            Some(child_eui64) => Entry::Indirect {
                address: Ieee802154Address::Eui64(child_eui64),
                next_hop,
                persistence_time: self.tunables.transaction_persistence_time(),
            },
            None => Entry::Queue(Next::Unicast {
                next_hop,
                attempts_remaining: self.tunables.unicast_retries(),
            }),
        }
    }

    /// Re-place a frame whose route discovery resolved. The route can have vanished in
    /// the race, which fails the send.
    fn place_released(&self, held: &mut Held) -> Result<Entry, DeliveryError> {
        let Frame::Nwk { nwk_frame, .. } = &mut held.frame else {
            unreachable!("only NWK unicasts await a route")
        };

        match self.resolve_next_hop(nwk_frame, &SendMode::Route(RouteDirective::StackDecides)) {
            super::nwk::NextHop::Resolved(next_hop) => Ok(self.place_unicast(next_hop)),
            super::nwk::NextHop::NeedDiscovery | super::nwk::NextHop::Discard => {
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
                let dequeued = {
                    let mut sends = self.sends.lock();
                    sends.dequeue().map(|dequeued| {
                        (dequeued.id, dequeued.frame.frame.clone(), dequeued.transmit)
                    })
                };

                let Some((id, frame, transmit)) = dequeued else {
                    break;
                };

                let result = self.transmit(frame, transmit).await;

                let now = self.core_now();
                let retry_delay = self.unicast_retry_delay();
                self.mutate_sends(|sends| ((), sends.transmitted(id, result, now, retry_delay)));
            }

            self.send_wake.notified().await;
        }
    }

    /// Build the 802.15.4 frame for one transmit and hand it to the radio.
    async fn transmit(&self, frame: Frame, transmit: Transmit) -> Result<(), DeliveryError> {
        match (transmit, frame) {
            (
                Transmit::Unicast { next_hop },
                Frame::Nwk {
                    nwk_frame,
                    security,
                },
            ) => {
                self.transmit_unicast(nwk_frame, next_hop, security, false)
                    .await
            }
            (
                Transmit::Indirect {
                    next_hop,
                    more_pending,
                    ..
                },
                Frame::Nwk {
                    nwk_frame,
                    security,
                },
            ) => {
                self.transmit_unicast(nwk_frame, next_hop, security, more_pending)
                    .await
            }
            (Transmit::Indirect { more_pending, .. }, Frame::Raw(mut raw)) => {
                raw.header_mut().frame_control.frame_pending = more_pending;
                self.send_802154_frame(raw).await
            }
            (
                Transmit::Once | Transmit::BroadcastCopy,
                Frame::Nwk {
                    nwk_frame,
                    security,
                },
            ) => self.transmit_broadcast(nwk_frame, security).await,
            (Transmit::Once, Frame::Raw(raw)) => self.send_802154_frame(raw).await,
            (Transmit::Unicast { .. } | Transmit::BroadcastCopy, Frame::Raw(_)) => {
                unreachable!("a raw frame is never a unicast or a broadcast")
            }
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
            self.drive_sends();

            let next_wake = self.sends.lock().next_wake();
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

    /// One timer pass. The checks that need the core's tables (a broadcast's passive-ack
    /// quorum, a route becoming active) are made first, then fed to the table with its
    /// own timed transitions.
    fn drive_sends(&self) {
        let now = self.core_now();

        let keys = self.sends.lock().passive_ack_keys();
        let acked: Vec<(Nwk, u8)> = keys
            .into_iter()
            .filter(|key| self.broadcast_passively_acked(*key))
            .collect();

        let destinations = self.sends.lock().awaiting_route_destinations();
        let active: Vec<Nwk> = {
            let core = self.core();
            destinations
                .into_iter()
                .filter(|destination| {
                    core.nib.routing.route_status(*destination) == Some(RouteStatus::Active)
                })
                .collect()
        };

        let retransmit_interval = self.tunables.passive_ack_timeout() + self.broadcast_jitter();

        self.mutate_sends(|sends| {
            let mut actions = Vec::new();
            for key in acked {
                tracing::debug!("Broadcast {key:?} passively acknowledged");
                actions.extend(sends.broadcast_acked(key));
            }
            for destination in active {
                actions.extend(
                    sends.route_resolved(destination, now, |held| self.place_released(held)),
                );
            }
            actions.extend(sends.tick(now, retransmit_interval));
            ((), actions)
        });
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
