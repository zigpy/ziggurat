//! Unicasts with a known next hop: delivered directly with NWK retries, or to a sleepy
//! child when it polls (802.15.4 spec 6.7.3).

use alloc::vec::Vec;
use core::marker::PhantomData;
use core::time::Duration;

use ziggurat_ieee_802154::Ieee802154Address;
use ziggurat_ieee_802154::types::{Eui64, Nwk};

use crate::Instant;
use crate::flat_map::FlatMap;

use super::{
    Action, Actions, ApsAckData, Confirm, DequeuedSend, InFlight, SendFailure, SendId,
    SrcMatchTable, Transmit, TxPriority,
};

/// How a unicast reaches its next hop. Fixed at admission.
#[derive(Debug, Clone, Copy)]
pub enum Delivery {
    /// Transmitted to `next_hop` now, retried `attempts_remaining` more times on failure.
    Direct {
        next_hop: Nwk,
        attempts_remaining: u8,
    },
    /// HeldFrame until the device polls under `address`, then transmitted to `next_hop`. A
    /// failed transmit waits for the next poll until the frame expires.
    Indirect {
        address: Ieee802154Address,
        next_hop: Nwk,
    },
}

/// Where a unicast goes once its next hop is known, with the deadline that fits.
#[derive(Debug, Clone, Copy)]
pub struct Placement {
    pub delivery: Delivery,
    pub deadline: Instant,
}

/// What a unicast is enqueued with.
#[derive(Debug)]
pub struct Unicast<F, W> {
    pub frame: F,
    pub priority: TxPriority,
    pub waiter: W,
    pub confirm: Confirm,
    pub delivery: Delivery,
    /// When the send fails if still not handed off (for an indirect delivery, if still
    /// not polled for).
    pub deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Ready for the sender.
    Queued,
    /// The sender holds an encrypted copy and is waiting on the radio. A record in this
    /// stage is never settled from outside: `transmitted` always finds it. `acked`
    /// records an end-to-end APS ack that arrived meanwhile.
    Transmitting { acked: bool },
    /// A failed direct unicast waiting out its retry delay.
    Retrying { at: Instant },
    /// An indirect unicast waiting for its device to poll.
    AwaitingPoll,
    /// Handed off; waiting for the end-to-end APS ack.
    AwaitingApsAck,
}

#[derive(Debug)]
struct Record<F, W> {
    frame: F,
    priority: TxPriority,
    waiter: W,
    confirm: Confirm,
    delivery: Delivery,
    stage: Stage,
    deadline: Instant,
}

impl<F, W> Record<F, W> {
    /// The address this send keeps a frame-pending bit set for, if any.
    const fn poll_address(&self) -> Option<Ieee802154Address> {
        match (self.delivery, self.stage) {
            (
                Delivery::Indirect { address, .. },
                Stage::AwaitingPoll | Stage::Queued | Stage::Transmitting { .. },
            ) => Some(address),
            _ => None,
        }
    }

    /// The failure a lapsed deadline means in this stage. `None` while transmitting:
    /// the radio's own timeout bounds that stage.
    const fn deadline_failure(&self) -> Option<SendFailure> {
        match self.stage {
            Stage::Transmitting { .. } => None,
            Stage::AwaitingApsAck => Some(SendFailure::ApsAckTimeout),
            Stage::Queued | Stage::Retrying { .. } | Stage::AwaitingPoll => match self.delivery {
                Delivery::Direct { .. } => Some(SendFailure::HandoffTimeout),
                Delivery::Indirect { address, .. } => Some(SendFailure::IndirectExpired {
                    destination: address,
                }),
            },
        }
    }

    fn next_wake(&self) -> Option<Instant> {
        match self.stage {
            Stage::Transmitting { .. } => None,
            Stage::Retrying { at } => Some(at.min(self.deadline)),
            Stage::Queued | Stage::AwaitingPoll | Stage::AwaitingApsAck => Some(self.deadline),
        }
    }
}

#[derive(Debug)]
pub(super) struct Unicasts<F, W, E> {
    records: FlatMap<SendId, Record<F, W>>,
    _error: PhantomData<fn() -> E>,
}

impl<F, W, E> Default for Unicasts<F, W, E> {
    fn default() -> Self {
        Self {
            records: FlatMap::new(),
            _error: PhantomData,
        }
    }
}

impl<F, W: Clone, E: From<SendFailure>> Unicasts<F, W, E> {
    pub(super) const RECORD_BYTES: usize = core::mem::size_of::<(SendId, Record<F, W>)>();

    pub(super) fn contains(&self, id: SendId) -> bool {
        self.records.contains_key(&id)
    }

    pub(super) fn enqueue(&mut self, id: SendId, unicast: Unicast<F, W>) {
        let stage = match unicast.delivery {
            Delivery::Direct { .. } => Stage::Queued,
            Delivery::Indirect { .. } => Stage::AwaitingPoll,
        };

        self.records.insert(
            id,
            Record {
                frame: unicast.frame,
                priority: unicast.priority,
                waiter: unicast.waiter,
                confirm: unicast.confirm,
                delivery: unicast.delivery,
                stage,
                deadline: unicast.deadline,
            },
        );
    }

    /// The highest-priority queued send, oldest first within a priority.
    pub(super) fn best_queued(&self) -> Option<(SendId, TxPriority)> {
        let mut best: Option<(SendId, TxPriority)> = None;

        for (id, record) in self.records.iter() {
            if record.stage == Stage::Queued
                && best.is_none_or(|(_, priority)| record.priority > priority)
            {
                best = Some((*id, record.priority));
            }
        }

        best
    }

    pub(super) fn dequeue(&mut self, id: SendId) -> DequeuedSend<'_, F> {
        let (next_hop, frame_pending) = match self.records.get(&id).unwrap().delivery {
            Delivery::Direct { next_hop, .. } => (next_hop, false),
            // More frames await the same device: it keeps polling
            Delivery::Indirect { address, next_hop } => {
                let more_pending = self
                    .records
                    .iter()
                    .any(|(other, record)| *other != id && record.poll_address() == Some(address));
                (next_hop, more_pending)
            }
        };

        let record = self.records.get_mut(&id).unwrap();
        debug_assert_eq!(record.stage, Stage::Queued);
        record.stage = Stage::Transmitting { acked: false };

        DequeuedSend {
            in_flight: InFlight(id),
            frame: &record.frame,
            transmit: Transmit::Unicast {
                next_hop,
                frame_pending,
            },
        }
    }

    pub(super) fn transmitted(
        &mut self,
        id: SendId,
        result: Result<(), E>,
        now: Instant,
        retry_delay: Duration,
    ) -> Actions<F, W, E> {
        let mut actions = Actions::new();

        let record = self
            .records
            .get_mut(&id)
            .expect("a transmitting send is never settled from outside");
        let Stage::Transmitting { acked } = record.stage else {
            unreachable!("only a transmitting send is reported on")
        };

        match result {
            Ok(()) => self.handed_off(id, now, acked, &mut actions),
            // The destination acked end to end while the radio reported a failure: the
            // frame got through
            Err(_) if acked => self.handed_off(id, now, acked, &mut actions),
            Err(err) => match record.delivery {
                Delivery::Direct {
                    next_hop,
                    attempts_remaining: 0,
                } => self.settle(id, Err(err), Some(next_hop), &mut actions),
                Delivery::Direct {
                    next_hop,
                    attempts_remaining,
                } => {
                    record.delivery = Delivery::Direct {
                        next_hop,
                        attempts_remaining: attempts_remaining - 1,
                    };
                    record.stage = Stage::Retrying {
                        at: now + retry_delay,
                    };
                }
                // 802.15.4 spec 6.7.3: a transaction is only extracted once acknowledged,
                // so a failed transmit awaits the device's next poll, keeping its deadline
                Delivery::Indirect { .. } if now < record.deadline => {
                    record.stage = Stage::AwaitingPoll;
                }
                Delivery::Indirect { .. } => self.settle(id, Err(err), None, &mut actions),
            },
        }

        actions
    }

    /// The frame reached its next hop: settle the send, or start waiting for its ack
    /// unless `acked` says it already arrived.
    fn handed_off(
        &mut self,
        id: SendId,
        now: Instant,
        acked: bool,
        actions: &mut Actions<F, W, E>,
    ) {
        let record = self.records.get_mut(&id).unwrap();

        let wait = match record.confirm {
            Confirm::OnHandoff => None,
            Confirm::ApsAck { wait, .. } => (!acked).then_some(wait),
        };

        let Some(wait) = wait else {
            self.settle(id, Ok(()), None, actions);
            return;
        };

        record.stage = Stage::AwaitingApsAck;
        record.deadline = now + wait;

        actions.push(Action::HandedOff(record.waiter.clone()));
    }

    /// Remove a record and report its verdict. The only way a record leaves the table.
    fn settle(
        &mut self,
        id: SendId,
        result: Result<(), E>,
        failed_hop: Option<Nwk>,
        actions: &mut Actions<F, W, E>,
    ) {
        let record = self.records.remove(&id).unwrap();

        actions.push(Action::Settled {
            waiter: record.waiter,
            result,
            frame: record.frame,
            failed_hop,
        });
    }

    /// A MAC Data Request from a device: queue the oldest frame awaiting it under either
    /// of its addresses. Frames past their deadline are left for `tick` to fail.
    pub(super) fn poll(&mut self, eui64: Option<Eui64>, nwk: Option<Nwk>, now: Instant) -> bool {
        let matches = |address: Ieee802154Address| match address {
            Ieee802154Address::Eui64(e) => eui64 == Some(e),
            Ieee802154Address::Nwk(n) => nwk == Some(n),
        };

        let oldest =
            self.records
                .iter()
                .find_map(|(id, record)| match (record.delivery, record.stage) {
                    (Delivery::Indirect { address, .. }, Stage::AwaitingPoll)
                        if matches(address) && now < record.deadline =>
                    {
                        Some(*id)
                    }
                    _ => None,
                });

        let Some(id) = oldest else {
            return false;
        };

        let record = self.records.get_mut(&id).unwrap();
        // The poll is answered within `macResponseWaitTime`: ahead of everything else
        record.priority = TxPriority::StackCritical;
        record.stage = Stage::Queued;

        true
    }

    /// An end-to-end APS ack arrived. It settles the oldest send waiting for it; the
    /// ack carries no way to tell two frames sharing a key apart.
    pub(super) fn ack_received(&mut self, ack: &ApsAckData) -> Actions<F, W, E> {
        let mut actions = Actions::new();

        let matched = self.records.iter().find_map(|(id, record)| {
            let expected = match &record.confirm {
                Confirm::ApsAck { ack: expected, .. } => expected,
                Confirm::OnHandoff => return None,
            };
            if expected != ack {
                return None;
            }
            match record.stage {
                Stage::AwaitingApsAck => Some((*id, true)),
                Stage::Transmitting { .. } => Some((*id, false)),
                _ => None,
            }
        });

        match matched {
            Some((id, true)) => self.settle(id, Ok(()), None, &mut actions),
            // Faster than the radio's own report: `transmitted` settles it
            Some((id, false)) => {
                self.records.get_mut(&id).unwrap().stage = Stage::Transmitting { acked: true };
            }
            None => {}
        }

        actions
    }

    /// Fail every frame awaiting a device's poll: it is no longer a child.
    pub(super) fn drop_indirect(&mut self, eui64: Option<Eui64>, nwk: Nwk) -> Actions<F, W, E> {
        let mut actions = Actions::new();

        let dropped: Vec<(SendId, Ieee802154Address)> = self
            .records
            .iter()
            .filter_map(|(id, record)| match (record.delivery, record.stage) {
                (Delivery::Indirect { address, .. }, Stage::AwaitingPoll)
                    if address == Ieee802154Address::Nwk(nwk)
                        || eui64.is_some_and(|e| address == Ieee802154Address::Eui64(e)) =>
                {
                    Some((*id, address))
                }
                _ => None,
            })
            .collect();

        for (id, destination) in dropped {
            self.settle(
                id,
                Err(SendFailure::IndirectExpired { destination }.into()),
                None,
                &mut actions,
            );
        }

        actions
    }

    /// `None` if the send is in the radio right now, or unknown.
    pub(super) fn cancel(&mut self, id: SendId) -> Option<Actions<F, W, E>> {
        let record = self.records.get(&id)?;
        if matches!(record.stage, Stage::Transmitting { .. }) {
            return None;
        }

        let mut actions = Actions::new();
        self.settle(id, Err(SendFailure::Cancelled.into()), None, &mut actions);
        Some(actions)
    }

    /// Re-queue retries that are due and fail records past their deadline.
    pub(super) fn tick(&mut self, now: Instant) -> Actions<F, W, E> {
        let mut actions = Actions::new();
        let mut lapsed: Vec<(SendId, SendFailure)> = Vec::new();

        for (id, record) in self.records.iter_mut() {
            if let Stage::Retrying { at } = record.stage
                && at <= now
            {
                record.stage = Stage::Queued;
            }

            if record.deadline <= now
                && let Some(failure) = record.deadline_failure()
            {
                lapsed.push((*id, failure));
            }
        }

        for (id, failure) in lapsed {
            self.settle(id, Err(failure.into()), None, &mut actions);
        }

        actions
    }

    pub(super) fn next_wake(&self) -> Option<Instant> {
        self.records.values().filter_map(Record::next_wake).min()
    }

    pub(super) fn poll_addresses(&self, address_map: &FlatMap<Eui64, Nwk>) -> SrcMatchTable {
        let mut table = SrcMatchTable::default();

        for address in self.records.values().filter_map(Record::poll_address) {
            match address {
                Ieee802154Address::Eui64(eui64) => {
                    table.extended_addresses.insert(eui64);

                    if let Some(nwk) = address_map.get(&eui64) {
                        table.short_addresses.insert(*nwk);
                    }
                }
                Ieee802154Address::Nwk(nwk) => {
                    table.short_addresses.insert(nwk);
                }
            }
        }

        table
    }

    pub(super) fn has_awaiting_poll(&self, address: Ieee802154Address) -> bool {
        self.records
            .values()
            .any(|record| record.poll_address() == Some(address))
    }
}
