//! Broadcasts: a frame sent once, or rebroadcast on a schedule (spec 3.6.6).
//!
//! The record's frame is the only copy: a retransmission queues the record itself, so
//! settling the record drops every copy still to come, and at most one copy is ever
//! outstanding. Every copy, the first included, is queued by the tick its schedule
//! makes it due on; only a `Once` schedule queues its copy at admission.

use core::cmp::Reverse;
use core::marker::PhantomData;
use core::time::Duration;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::constants::Tunables;
use crate::flat_map::FlatMap;

use super::{
    Action, InFlight, Outbox, SendFailure, SendFrame, SendId, Transmit, TransmitError, TxPriority,
};

/// How a broadcast is retransmitted and when it is done.
///
/// `next_attempt` is when the next copy is due. It is re-armed when a copy's transmit
/// completes, so the interval between copies is measured on the air, not from when the
/// copy was queued.
#[derive(Debug, Clone, Copy)]
pub enum Schedule {
    /// One copy; its transmit result is the verdict.
    Once,
    /// Spec 3.6.6: rebroadcast until the passive-ack quorum for `key` is heard, or
    /// `copies_remaining` run out.
    PassiveAck {
        key: (Nwk, u8),
        copies_remaining: u8,
        next_attempt: Instant,
    },
    /// `copies_remaining` copies at `interval` (a route request).
    FixedInterval {
        interval: Duration,
        copies_remaining: u8,
        next_attempt: Instant,
    },
}

/// What a broadcast is enqueued with.
#[derive(Debug)]
pub struct Broadcast<F> {
    pub frame: F,
    pub priority: TxPriority,
    pub schedule: Schedule,
}

/// What a tick finds a schedule's next copy to be.
enum Due {
    /// A copy is due: queue it.
    Copy,
    /// The schedule ran out.
    Over,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CopyState {
    Idle,
    Queued,
    /// The sender holds an encrypted copy and is waiting on the radio. A record in this
    /// state is never settled from outside: `transmitted` always finds it.
    Transmitting,
}

#[derive(Debug)]
struct Record<F, E> {
    /// `None` exactly while a copy is on loan to the radio (`CopyState::Transmitting`).
    frame: Option<F>,
    priority: TxPriority,
    schedule: Schedule,
    copy: CopyState,
    handed_off: bool,
    /// The quorum was heard before a copy was handed off: the neighbors relayed while
    /// the copy was in the radio. The first handoff settles
    /// the send; a broadcast is never delivered without reaching the air once.
    quorum_heard: bool,
    /// The last copy's radio failure: the verdict if the copies run out before one is
    /// handed off.
    last_error: Option<E>,
    deadline: Instant,
}

impl<F, E> Record<F, E> {
    const fn next_attempt(&self) -> Option<Instant> {
        match self.schedule {
            Schedule::Once => None,
            Schedule::PassiveAck { next_attempt, .. }
            | Schedule::FixedInterval { next_attempt, .. } => Some(next_attempt),
        }
    }

    fn next_wake(&self) -> Option<Instant> {
        match self.copy {
            CopyState::Transmitting => None,
            CopyState::Queued => Some(self.deadline),
            CopyState::Idle => {
                let next_attempt = self.next_attempt().unwrap_or(self.deadline);
                Some(next_attempt.min(self.deadline))
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct Broadcasts<F, E> {
    records: FlatMap<SendId, Record<F, E>>,
    _error: PhantomData<fn() -> E>,
}

impl<F, E> Default for Broadcasts<F, E> {
    fn default() -> Self {
        Self {
            records: FlatMap::new(),
            _error: PhantomData,
        }
    }
}

impl<F: SendFrame, E: From<SendFailure>> Broadcasts<F, E> {
    /// The send fails if still not over within the handoff timeout.
    pub(super) fn enqueue(
        &mut self,
        id: SendId,
        broadcast: Broadcast<F>,
        now: Instant,
        tunables: &Tunables,
    ) {
        self.records.insert(
            id,
            Record {
                frame: Some(broadcast.frame),
                priority: broadcast.priority,
                schedule: broadcast.schedule,
                copy: match broadcast.schedule {
                    Schedule::Once => CopyState::Queued,
                    Schedule::PassiveAck { .. } | Schedule::FixedInterval { .. } => CopyState::Idle,
                },
                handed_off: false,
                quorum_heard: false,
                last_error: None,
                deadline: now + tunables.handoff_timeout(),
            },
        );
    }

    /// The highest-priority queued copy, oldest first within a priority. A send past its
    /// deadline is left for `tick` to fail.
    pub(super) fn best_queued(&self, now: Instant) -> Option<(SendId, TxPriority)> {
        self.records
            .iter()
            .filter(|(_, record)| record.copy == CopyState::Queued && now < record.deadline)
            .max_by_key(|(id, record)| (record.priority, Reverse(**id)))
            .map(|(id, record)| (*id, record.priority))
    }

    pub(super) fn dequeue(&mut self, id: SendId) -> InFlight<F> {
        let record = self.records.get_mut(&id).unwrap();
        debug_assert_eq!(record.copy, CopyState::Queued);
        record.copy = CopyState::Transmitting;

        InFlight {
            id,
            frame: record.frame.take().unwrap(),
            transmit: Transmit::Broadcast,
        }
    }

    /// `passive_ack_interval` spaces the next passive-ack copy from this one.
    pub(super) fn transmitted(
        &mut self,
        id: SendId,
        frame: F,
        result: Result<(), TransmitError<E>>,
        now: Instant,
        passive_ack_interval: Duration,
        outbox: &mut Outbox<F, E>,
    ) {
        let record = self
            .records
            .get_mut(&id)
            .expect("a transmitting send is never settled from outside");
        debug_assert_eq!(record.copy, CopyState::Transmitting);
        record.copy = CopyState::Idle;
        record.frame = Some(frame);

        let result = match result {
            Ok(()) => Ok(()),
            Err(TransmitError::Failed(err)) => Err(err),
            // No later copy can succeed either
            Err(TransmitError::Rejected(err)) => {
                self.settle(id, Err(err), outbox);
                return;
            }
        };

        match &mut record.schedule {
            Schedule::Once => {
                self.settle(id, result, outbox);
                return;
            }
            Schedule::PassiveAck { next_attempt, .. } => {
                *next_attempt = now + passive_ack_interval;
            }
            Schedule::FixedInterval {
                interval,
                next_attempt,
                ..
            } => {
                *next_attempt = now + *interval;
            }
        }

        // A lost copy is not terminal: the schedule retransmits. The first copy on air
        // is the handoff.
        let first_handoff = result.is_ok() && !record.handed_off;
        match result {
            Ok(()) => record.handed_off = true,
            Err(err) => record.last_error = Some(err),
        }

        let delivered = record.quorum_heard && record.handed_off;
        if first_handoff {
            outbox.push_back(Action::HandedOff(id));
        }
        if delivered {
            self.settle(id, Ok(()), outbox);
        }
    }

    /// Remove a record and report its verdict.
    fn settle(&mut self, id: SendId, result: Result<(), E>, outbox: &mut Outbox<F, E>) {
        let record = self.records.remove(&id).unwrap();
        Self::settled(id, record, result, outbox);
    }

    /// Report the verdict of a record removed from the table.
    fn settled(id: SendId, record: Record<F, E>, result: Result<(), E>, outbox: &mut Outbox<F, E>) {
        drop(
            record
                .frame
                .expect("a transmitting send is never settled from outside"),
        );

        outbox.push_back(Action::Settled {
            id,
            result,
            failed_hop: None,
        });
    }

    /// Deliver every broadcast whose passive-ack quorum `heard` says was heard: the send
    /// is delivered once a copy was handed off. Until then (no copy handed off yet, or
    /// one in the radio right now) the first successful report settles it instead.
    pub(super) fn deliver(
        &mut self,
        mut heard: impl FnMut((Nwk, u8)) -> bool,
        outbox: &mut Outbox<F, E>,
    ) {
        let delivered = self.records.extract_if(|_, record| {
            let Schedule::PassiveAck { key, .. } = record.schedule else {
                return false;
            };
            if record.quorum_heard || !heard(key) {
                return false;
            }

            if record.copy == CopyState::Transmitting || !record.handed_off {
                record.quorum_heard = true;
                return false;
            }
            true
        });

        for (id, record) in delivered {
            Self::settled(id, record, Ok(()), outbox);
        }
    }

    /// Settle every record as cancelled: the stack is shutting down and no copy, in the
    /// radio or not, is ever reported on again.
    pub(super) fn abandon(&mut self, outbox: &mut Outbox<F, E>) {
        while let Some((id, _)) = self.records.pop_first() {
            outbox.push_back(Action::Settled {
                id,
                result: Err(SendFailure::Cancelled.into()),
                failed_hop: None,
            });
        }
    }

    pub(super) fn contains(&self, id: SendId) -> bool {
        self.records.contains_key(&id)
    }

    /// Whether the send was cancelled: not if a copy is in the radio right now, or the
    /// send is unknown.
    pub(super) fn cancel(&mut self, id: SendId, outbox: &mut Outbox<F, E>) -> bool {
        let Some(record) = self.records.get(&id) else {
            return false;
        };
        if record.copy == CopyState::Transmitting {
            return false;
        }
        self.settle(id, Err(SendFailure::Cancelled.into()), outbox);
        true
    }

    /// Send no further copies of a broadcast nobody waits on any more. A copy in the
    /// radio right now cannot be recalled: its schedule is emptied instead, so the
    /// record settles when it next comes due (a `Once` schedule settles on the copy's
    /// own report).
    pub(super) fn stop(&mut self, id: SendId, outbox: &mut Outbox<F, E>) {
        let Some(record) = self.records.get_mut(&id) else {
            return;
        };

        if record.copy == CopyState::Transmitting {
            match &mut record.schedule {
                Schedule::Once => {}
                Schedule::PassiveAck {
                    copies_remaining, ..
                }
                | Schedule::FixedInterval {
                    copies_remaining, ..
                } => *copies_remaining = 0,
            }
        } else {
            self.settle(id, Err(SendFailure::Cancelled.into()), outbox);
        }
    }

    /// Queue copies that are due, complete or fail schedules that ran out, and fail
    /// records past their deadline.
    pub(super) fn tick(&mut self, now: Instant, outbox: &mut Outbox<F, E>) {
        let over = self.records.extract_map(|_, record| {
            if record.copy == CopyState::Transmitting {
                return None;
            }

            if record.copy == CopyState::Idle
                && let Some(due) = Self::schedule_due(&mut record.schedule, now)
            {
                match due {
                    Due::Copy => record.copy = CopyState::Queued,
                    Due::Over => {
                        return Some(if record.handed_off {
                            Ok(())
                        } else {
                            Err(record.last_error.take().unwrap())
                        });
                    }
                }
            }

            if record.deadline <= now {
                return Some(if record.handed_off {
                    Ok(())
                } else {
                    Err(SendFailure::HandoffTimeout.into())
                });
            }

            None
        });

        for (id, record, result) in over {
            Self::settled(id, record, result, outbox);
        }
    }

    /// Consume a schedule's next copy if it is due. `None` means nothing is due.
    fn schedule_due(schedule: &mut Schedule, now: Instant) -> Option<Due> {
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
                    return Some(Due::Over);
                }
                *copies_remaining -= 1;
                Some(Due::Copy)
            }
            Schedule::FixedInterval {
                copies_remaining,
                next_attempt,
                ..
            } => {
                if *next_attempt > now {
                    return None;
                }
                if *copies_remaining == 0 {
                    return Some(Due::Over);
                }
                *copies_remaining -= 1;
                Some(Due::Copy)
            }
        }
    }

    pub(super) fn next_wake(&self) -> Option<Instant> {
        self.records.values().filter_map(Record::next_wake).min()
    }
}
