//! Broadcasts: a frame sent once, or rebroadcast on a schedule (spec 3.6.6).
//!
//! The record's frame is the only copy: a retransmission queues the record itself, so
//! settling the record drops every copy still to come, and at most one copy is ever
//! outstanding. Every copy, the first included, is queued by the tick its schedule
//! makes it due on; only a `Once` schedule queues its copy at admission.

use alloc::vec::Vec;
use core::marker::PhantomData;
use core::time::Duration;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::flat_map::FlatMap;

use super::{Action, Dequeued, SendFailure, SendId, Transmit, TxPriority};

/// How a broadcast is retransmitted and when it is done.
#[derive(Debug, Clone, Copy)]
pub enum Schedule {
    /// One copy; its transmit result is the verdict.
    Once,
    /// Spec 3.6.6: rebroadcast until the passive-ack quorum for `key` is heard, or
    /// `copies_remaining` run out, which fails the send.
    PassiveAck {
        key: (Nwk, u8),
        copies_remaining: u8,
        next_attempt: Instant,
    },
    /// `copies_remaining` copies at `interval` (a route request); running out completes
    /// the send.
    FixedInterval {
        interval: Duration,
        copies_remaining: u8,
        next_attempt: Instant,
    },
}

/// What a broadcast is admitted with.
#[derive(Debug)]
pub struct Broadcast<F, W> {
    pub frame: F,
    pub priority: TxPriority,
    pub waiter: W,
    pub schedule: Schedule,
    /// When the send fails if still not over.
    pub deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Copy {
    Idle,
    Queued,
    /// The sender holds an encrypted copy and is waiting on the radio. A record in this
    /// state is never settled from outside: `transmitted` always finds it.
    Transmitting,
}

#[derive(Debug)]
struct Record<F, W> {
    frame: F,
    priority: TxPriority,
    waiter: W,
    schedule: Schedule,
    copy: Copy,
    handed_off: bool,
    /// The quorum was heard while a copy was in the radio; that copy's report settles
    /// the send.
    quorum_heard: bool,
    deadline: Instant,
}

impl<F, W> Record<F, W> {
    const fn next_attempt(&self) -> Option<Instant> {
        match self.schedule {
            Schedule::Once => None,
            Schedule::PassiveAck { next_attempt, .. }
            | Schedule::FixedInterval { next_attempt, .. } => Some(next_attempt),
        }
    }

    fn next_wake(&self) -> Option<Instant> {
        match self.copy {
            Copy::Transmitting => None,
            Copy::Queued => Some(self.deadline),
            Copy::Idle => {
                let next_attempt = self.next_attempt().unwrap_or(self.deadline);
                Some(next_attempt.min(self.deadline))
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct Broadcasts<F, W, E> {
    records: FlatMap<SendId, Record<F, W>>,
    _error: PhantomData<fn() -> E>,
}

impl<F, W, E> Default for Broadcasts<F, W, E> {
    fn default() -> Self {
        Self {
            records: FlatMap::new(),
            _error: PhantomData,
        }
    }
}

impl<F, W: Clone, E: From<SendFailure>> Broadcasts<F, W, E> {
    pub(super) const RECORD_BYTES: usize = core::mem::size_of::<(SendId, Record<F, W>)>();

    pub(super) fn admit(&mut self, id: SendId, broadcast: Broadcast<F, W>) {
        self.records.insert(
            id,
            Record {
                frame: broadcast.frame,
                priority: broadcast.priority,
                waiter: broadcast.waiter,
                schedule: broadcast.schedule,
                copy: match broadcast.schedule {
                    Schedule::Once => Copy::Queued,
                    Schedule::PassiveAck { .. } | Schedule::FixedInterval { .. } => Copy::Idle,
                },
                handed_off: false,
                quorum_heard: false,
                deadline: broadcast.deadline,
            },
        );
    }

    /// The highest-priority queued copy, oldest first within a priority.
    pub(super) fn best_queued(&self) -> Option<(SendId, TxPriority)> {
        let mut best: Option<(SendId, TxPriority)> = None;

        for (id, record) in self.records.iter() {
            if record.copy == Copy::Queued
                && best.is_none_or(|(_, priority)| record.priority > priority)
            {
                best = Some((*id, record.priority));
            }
        }

        best
    }

    pub(super) fn dequeue(&mut self, id: SendId) -> Dequeued<'_, F> {
        let record = self.records.get_mut(&id).unwrap();
        debug_assert_eq!(record.copy, Copy::Queued);
        record.copy = Copy::Transmitting;

        Dequeued {
            id,
            frame: &record.frame,
            transmit: Transmit::Broadcast,
        }
    }

    pub(super) fn transmitted(
        &mut self,
        id: SendId,
        result: Result<(), E>,
        actions: &mut Vec<Action<F, W, E>>,
    ) {
        let record = self
            .records
            .get_mut(&id)
            .expect("a transmitting send is never settled from outside");
        debug_assert_eq!(record.copy, Copy::Transmitting);
        record.copy = Copy::Idle;

        if matches!(record.schedule, Schedule::Once) {
            self.settle(id, result, actions);
            return;
        }

        // A lost copy is not terminal: the schedule retransmits. The first copy on air
        // is the handoff.
        if result.is_ok() && !record.handed_off {
            record.handed_off = true;
            actions.push(Action::HandedOff(record.waiter.clone()));
        }

        if record.quorum_heard {
            self.settle(id, Ok(()), actions);
        }
    }

    /// Remove a record and report its verdict. The only way a record leaves the table.
    fn settle(&mut self, id: SendId, result: Result<(), E>, actions: &mut Vec<Action<F, W, E>>) {
        let record = self.records.remove(&id).unwrap();

        actions.push(Action::Settled {
            waiter: record.waiter,
            result,
            frame: record.frame,
            failed_hop: None,
        });
    }

    pub(super) fn passive_ack_keys(&self) -> Vec<(Nwk, u8)> {
        self.records
            .values()
            .filter_map(|record| match record.schedule {
                Schedule::PassiveAck { key, .. } => Some(key),
                _ => None,
            })
            .collect()
    }

    /// The passive-ack quorum for a broadcast was heard: it is delivered. A copy in the
    /// radio right now settles it on its report instead.
    pub(super) fn acked(&mut self, key: (Nwk, u8), actions: &mut Vec<Action<F, W, E>>) {
        let found = self
            .records
            .iter()
            .find_map(|(id, record)| match record.schedule {
                Schedule::PassiveAck { key: k, .. } if k == key => Some(*id),
                _ => None,
            });

        let Some(id) = found else {
            return;
        };

        let record = self.records.get_mut(&id).unwrap();
        if record.copy == Copy::Transmitting {
            record.quorum_heard = true;
        } else {
            self.settle(id, Ok(()), actions);
        }
    }

    /// `false` if a copy is in the radio right now, or the send is unknown.
    pub(super) fn cancel(&mut self, id: SendId, actions: &mut Vec<Action<F, W, E>>) -> bool {
        match self.records.get(&id) {
            Some(record) if record.copy != Copy::Transmitting => {
                self.settle(id, Err(SendFailure::Cancelled.into()), actions);
                true
            }
            _ => false,
        }
    }

    /// Queue copies that are due, complete or fail schedules that ran out, and fail
    /// records past their deadline. `passive_ack_interval` spaces passive-ack copies.
    pub(super) fn tick(
        &mut self,
        now: Instant,
        passive_ack_interval: Duration,
        actions: &mut Vec<Action<F, W, E>>,
    ) {
        let mut settle: Vec<(SendId, Result<(), E>)> = Vec::new();

        for (id, record) in self.records.iter_mut() {
            if record.copy == Copy::Transmitting {
                continue;
            }

            if record.copy == Copy::Idle
                && let Some(result) =
                    Self::schedule_due(&mut record.schedule, now, passive_ack_interval)
            {
                match result {
                    Ok(()) => record.copy = Copy::Queued,
                    Err(verdict) => {
                        settle.push((*id, verdict));
                        continue;
                    }
                }
            }

            if record.deadline <= now {
                let failure = if record.handed_off {
                    SendFailure::BroadcastQuorumNotReached
                } else {
                    SendFailure::HandoffTimeout
                };
                settle.push((*id, Err(failure.into())));
            }
        }

        for (id, result) in settle {
            self.settle(id, result, actions);
        }
    }

    /// Advance a schedule whose next copy is due: `Some(Ok)` queues a copy, `Some(Err)`
    /// carries the verdict of a schedule that ran out, `None` means nothing is due.
    fn schedule_due(
        schedule: &mut Schedule,
        now: Instant,
        passive_ack_interval: Duration,
    ) -> Option<Result<(), Result<(), E>>> {
        match schedule {
            Schedule::Once => None,
            Schedule::PassiveAck {
                copies_remaining,
                next_attempt,
                ..
            } => {
                if *next_attempt > now {
                    return None;
                }
                if *copies_remaining == 0 {
                    return Some(Err(Err(SendFailure::BroadcastQuorumNotReached.into())));
                }
                *copies_remaining -= 1;
                *next_attempt = now + passive_ack_interval;
                Some(Ok(()))
            }
            Schedule::FixedInterval {
                interval,
                copies_remaining,
                next_attempt,
            } => {
                if *next_attempt > now {
                    return None;
                }
                // A fixed-interval broadcast completes by running out of copies
                if *copies_remaining == 0 {
                    return Some(Err(Ok(())));
                }
                *copies_remaining -= 1;
                *next_attempt = now + *interval;
                Some(Ok(()))
            }
        }
    }

    pub(super) fn next_wake(&self) -> Option<Instant> {
        self.records.values().filter_map(Record::next_wake).min()
    }
}
