//! Unicasts with a known next hop: delivered directly with NWK retries, or to a sleepy
//! child when it polls (802.15.4 spec 6.7.3).

use alloc::vec::Vec;
use core::cmp::Reverse;
use core::marker::PhantomData;
use core::time::Duration;

use ziggurat_ieee_802154::Ieee802154Address;
use ziggurat_ieee_802154::types::{Eui64, Nwk};

use crate::Instant;
use crate::constants::Tunables;
use crate::flat_map::FlatMap;

use super::{
    Action, Actions, ApsAckData, Confirm, InFlight, SendFailure, SendId, SrcMatchTable, Transmit,
    TxPriority,
};

/// What a unicast is enqueued with.
#[derive(Debug)]
pub struct Unicast<F, W> {
    pub frame: F,
    pub priority: TxPriority,
    pub waiter: W,
    pub confirm: Confirm,
    pub next_hop: Nwk,
    /// The address the device polls under, for a frame held until it polls (802.15.4
    /// spec 6.7.3). `None`: transmitted as soon as it is dequeued, with NWK retries.
    pub poll_address: Option<Ieee802154Address>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Ready for the sender.
    Queued,
    /// The sender holds an encrypted copy and is waiting on the radio. A record in this
    /// stage is never settled from outside: `transmitted` always finds it. `acked`
    /// records an end-to-end APS ack that arrived meanwhile.
    Transmitting { acked: bool },
    /// A failed transmit waiting out its retry delay.
    Retrying { at: Instant },
    /// A held frame waiting for its device to poll.
    AwaitingPoll,
    /// Handed off; waiting for the end-to-end APS ack.
    AwaitingApsAck,
}

#[derive(Debug)]
struct Record<F, W> {
    /// `None` exactly while the frame is on loan to the radio (`Stage::Transmitting`).
    frame: Option<F>,
    priority: TxPriority,
    waiter: W,
    confirm: Confirm,
    next_hop: Nwk,
    poll_address: Option<Ieee802154Address>,
    /// Transmit attempts left after the current one. A failed transmit of a held frame
    /// waits for the next poll instead, until the frame expires.
    attempts_remaining: u8,
    stage: Stage,
    deadline: Instant,
}

impl<F, W> Record<F, W> {
    /// The address this send keeps a frame-pending bit set for, if any.
    const fn pending_for(&self) -> Option<Ieee802154Address> {
        match (self.poll_address, self.stage) {
            (Some(address), Stage::AwaitingPoll | Stage::Queued | Stage::Transmitting { .. }) => {
                Some(address)
            }
            _ => None,
        }
    }

    /// The failure a lapsed deadline means in this stage. `None` while transmitting:
    /// the radio's own timeout bounds that stage.
    const fn deadline_failure(&self) -> Option<SendFailure> {
        match self.stage {
            Stage::Transmitting { .. } => None,
            Stage::AwaitingApsAck => Some(SendFailure::ApsAckTimeout),
            Stage::Queued | Stage::Retrying { .. } | Stage::AwaitingPoll => {
                match self.poll_address {
                    None => Some(SendFailure::HandoffTimeout),
                    Some(destination) => Some(SendFailure::IndirectExpired { destination }),
                }
            }
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

    /// A unicast fails if not handed off within the handoff timeout; a held frame if
    /// not polled for within the transaction persistence time.
    pub(super) fn enqueue(
        &mut self,
        id: SendId,
        unicast: Unicast<F, W>,
        now: Instant,
        tunables: &Tunables,
    ) {
        let (stage, deadline) = match unicast.poll_address {
            None => (Stage::Queued, now + tunables.handoff_timeout()),
            Some(_) => (
                Stage::AwaitingPoll,
                now + tunables.transaction_persistence_time(),
            ),
        };

        self.records.insert(
            id,
            Record {
                frame: Some(unicast.frame),
                priority: unicast.priority,
                waiter: unicast.waiter,
                confirm: unicast.confirm,
                next_hop: unicast.next_hop,
                poll_address: unicast.poll_address,
                attempts_remaining: tunables.unicast_retries(),
                stage,
                deadline,
            },
        );
    }

    /// The highest-priority queued send, oldest first within a priority.
    pub(super) fn best_queued(&self) -> Option<(SendId, TxPriority)> {
        self.records
            .iter()
            .filter(|(_, record)| record.stage == Stage::Queued)
            .max_by_key(|(id, record)| (record.priority, Reverse(**id)))
            .map(|(id, record)| (*id, record.priority))
    }

    pub(super) fn dequeue(&mut self, id: SendId) -> InFlight<F> {
        // More frames await the same device: it keeps polling
        let frame_pending = self
            .records
            .get(&id)
            .unwrap()
            .poll_address
            .is_some_and(|address| {
                self.records
                    .iter()
                    .any(|(other, record)| *other != id && record.pending_for() == Some(address))
            });

        let record = self.records.get_mut(&id).unwrap();
        debug_assert_eq!(record.stage, Stage::Queued);
        record.stage = Stage::Transmitting { acked: false };

        InFlight {
            id,
            frame: record.frame.take().unwrap(),
            transmit: Transmit::Unicast {
                next_hop: record.next_hop,
                frame_pending,
            },
        }
    }

    pub(super) fn transmitted(
        &mut self,
        id: SendId,
        frame: F,
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
        record.frame = Some(frame);

        match result {
            Ok(()) => self.handed_off(id, now, acked, &mut actions),
            // The destination acked end to end while the radio reported a failure: the
            // frame got through
            Err(_) if acked => self.handed_off(id, now, acked, &mut actions),
            Err(err) => match record.poll_address {
                // 802.15.4 spec 6.7.3: a transaction is only extracted once acknowledged,
                // so a failed transmit awaits the device's next poll, keeping its deadline
                Some(_) if now < record.deadline => record.stage = Stage::AwaitingPoll,
                Some(_) => self.settle(id, Err(err), None, &mut actions),
                None if record.attempts_remaining == 0 => {
                    let next_hop = record.next_hop;
                    self.settle(id, Err(err), Some(next_hop), &mut actions);
                }
                None => {
                    record.attempts_remaining -= 1;
                    record.stage = Stage::Retrying {
                        at: now + retry_delay,
                    };
                }
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
            frame: record
                .frame
                .expect("a transmitting send is never settled from outside"),
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

        let oldest = self.records.iter().find_map(|(id, record)| {
            match (record.poll_address, record.stage) {
                (Some(address), Stage::AwaitingPoll)
                    if matches(address) && now < record.deadline =>
                {
                    Some(*id)
                }
                _ => None,
            }
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

        let matched = self
            .records
            .iter()
            .find_map(|(id, record)| match &record.confirm {
                Confirm::ApsAck { ack: expected, .. } if expected == ack => Some(*id),
                _ => None,
            });

        let Some(id) = matched else {
            return actions;
        };

        let record = self.records.get_mut(&id).unwrap();
        if matches!(record.stage, Stage::Transmitting { .. }) {
            // Faster than the radio's own report: `transmitted` settles it
            record.stage = Stage::Transmitting { acked: true };
        } else {
            self.settle(id, Ok(()), None, &mut actions);
        }

        actions
    }

    /// Fail every frame awaiting a device's poll: it is no longer a child.
    pub(super) fn drop_indirect(&mut self, eui64: Option<Eui64>, nwk: Nwk) -> Actions<F, W, E> {
        let mut actions = Actions::new();

        let dropped: Vec<(SendId, Ieee802154Address)> = self
            .records
            .iter()
            .filter_map(|(id, record)| match (record.poll_address, record.stage) {
                (Some(address), Stage::AwaitingPoll)
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

    /// Drop every record and return its waiter: the stack is shutting down and no
    /// frame, in the radio or not, is ever reported on again.
    pub(super) fn abandon(&mut self) -> Vec<W> {
        let mut waiters = Vec::new();
        while let Some((_, record)) = self.records.pop_first() {
            waiters.push(record.waiter);
        }
        waiters
    }

    /// `None` if the send is in the radio right now, or unknown.
    pub(super) fn cancel(&mut self, id: SendId) -> Option<Actions<F, W, E>> {
        let record = self.records.get(&id)?;
        if matches!(record.stage, Stage::Transmitting { .. }) {
            return None;
        }

        let mut actions = Actions::new();
        // The handoff's own action may still be on its way to the waiter: repeat it, so
        // the cancel does not back-fill a handoff that happened as failed
        if record.stage == Stage::AwaitingApsAck {
            actions.push(Action::HandedOff(record.waiter.clone()));
        }
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

        for address in self.records.values().filter_map(Record::pending_for) {
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
            .any(|record| record.pending_for() == Some(address))
    }
}
