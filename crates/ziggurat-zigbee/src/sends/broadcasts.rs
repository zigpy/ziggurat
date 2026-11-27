//! Broadcasts: a frame sent once, or rebroadcast on a schedule (spec 3.6.6).
//!
//! A broadcast goes out on a set of PHYs, each through its own lane: a copy of the
//! frame with its own schedule, so that a slow PHY never holds up the others. The
//! radio's lane is done once its passive-ack quorum is heard, a secondary PHY's once
//! the PHY confirms a copy, and any lane once its schedule runs out. The send is over
//! when every lane is done.
//!
//! A lane's frame is its only copy: a retransmission queues the lane itself, so
//! settling the record drops every copy still to come, and a lane has at most one copy
//! outstanding. Every copy, the first included, is queued by the tick its schedule
//! makes it due on; only a `Once` schedule queues its copy at admission.

use alloc::vec::Vec;
use core::cmp::Reverse;
use core::marker::PhantomData;
use core::time::Duration;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::constants::Tunables;
use crate::flat_map::FlatMap;
use crate::phy::{PhyIndex, PhySet};

use super::{
    Action, Delivery, InFlight, Outbox, SendFailure, SendFrame, SendId, Transmit, TransmitError,
    TxPriority,
};

/// How a broadcast is retransmitted on each of its PHYs and when it is done.
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

impl Schedule {
    const fn next_attempt(&self) -> Option<Instant> {
        match self {
            Self::Once => None,
            Self::PassiveAck { next_attempt, .. } | Self::FixedInterval { next_attempt, .. } => {
                Some(*next_attempt)
            }
        }
    }

    /// Send no copy after the one in flight.
    const fn stop(&mut self) {
        match self {
            Self::Once => {}
            Self::PassiveAck {
                copies_remaining, ..
            }
            | Self::FixedInterval {
                copies_remaining, ..
            } => *copies_remaining = 0,
        }
    }

    /// Consume the next copy if it is due. `None` means nothing is due.
    fn due(&mut self, now: Instant) -> Option<Due> {
        match self {
            Self::Once => None,
            Self::PassiveAck {
                copies_remaining,
                next_attempt,
                ..
            }
            | Self::FixedInterval {
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
}

/// What a broadcast is enqueued with.
#[derive(Debug)]
pub struct Broadcast<F> {
    pub frame: F,
    pub priority: TxPriority,
    pub schedule: Schedule,
    /// The PHYs the broadcast goes out on, each with the whole schedule
    pub phys: PhySet,
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
    /// The PHY's sender holds a secured copy and is waiting on the PHY. A lane in this
    /// state is never settled from outside: `transmitted` always finds it.
    Transmitting,
}

/// A broadcast's copies on one PHY.
#[derive(Debug)]
struct Lane<F> {
    phy: PhyIndex,
    /// `None` exactly while a copy is on loan to the PHY (`CopyState::Transmitting`).
    frame: Option<F>,
    schedule: Schedule,
    copy: CopyState,
    /// A copy went out on this PHY.
    handed_off: bool,
    /// The radio's passive-ack quorum was heard. It confirms the lane once a copy went
    /// out: a broadcast is never delivered without reaching the air once.
    quorum_heard: bool,
    /// The PHY has the broadcast: no copy follows.
    confirmed: bool,
    /// The schedule has no copy left.
    exhausted: bool,
}

impl<F> Lane<F> {
    /// Whether the lane sends no further copy.
    const fn done(&self) -> bool {
        self.confirmed || self.exhausted
    }

    /// Whether the lane is done and has no copy left to report.
    fn over(&self) -> bool {
        self.done() && self.copy != CopyState::Transmitting
    }

    fn next_wake(&self, deadline: Instant) -> Option<Instant> {
        if self.done() {
            return None;
        }

        match self.copy {
            CopyState::Transmitting => None,
            CopyState::Queued => Some(deadline),
            CopyState::Idle => Some(
                self.schedule
                    .next_attempt()
                    .unwrap_or(deadline)
                    .min(deadline),
            ),
        }
    }

    /// No copy follows: a queued one is dropped, one in flight still reports.
    fn finish(&mut self) {
        self.exhausted = true;
        if self.copy == CopyState::Queued {
            self.copy = CopyState::Idle;
        }
    }
}

#[derive(Debug)]
struct Record<F, E> {
    lanes: Vec<Lane<F>>,
    priority: TxPriority,
    /// A copy went out on some PHY.
    handed_off: bool,
    /// The last copy's failure: the verdict if the copies run out before one is
    /// handed off. `None` then means no copy was ever sent, a handoff timeout.
    last_error: Option<E>,
    /// A copy can never be transmitted: the verdict once no copy is in flight.
    rejected: Option<E>,
    deadline: Instant,
}

impl<F, E: From<SendFailure>> Record<F, E> {
    fn lane_mut(&mut self, phy: PhyIndex) -> &mut Lane<F> {
        self.lanes
            .iter_mut()
            .find(|lane| lane.phy == phy)
            .expect("a copy only comes from one of the broadcast's PHYs")
    }

    fn transmitting(&self) -> bool {
        self.lanes
            .iter()
            .any(|lane| lane.copy == CopyState::Transmitting)
    }

    fn over(&self) -> bool {
        self.lanes.iter().all(Lane::over)
    }

    /// The verdict of a record that is over.
    fn verdict(&mut self) -> Result<(), E> {
        if let Some(err) = self.rejected.take() {
            Err(err)
        } else if self.handed_off {
            Ok(())
        } else {
            // A schedule that started with no copies has no failure to report: no copy
            // ever reached a PHY
            Err(self
                .last_error
                .take()
                .unwrap_or_else(|| SendFailure::HandoffTimeout.into()))
        }
    }

    fn next_wake(&self) -> Option<Instant> {
        self.lanes
            .iter()
            .filter_map(|lane| lane.next_wake(self.deadline))
            .min()
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
    ) where
        F: Clone,
    {
        let copy = match broadcast.schedule {
            Schedule::Once => CopyState::Queued,
            Schedule::PassiveAck { .. } | Schedule::FixedInterval { .. } => CopyState::Idle,
        };

        let lanes = broadcast
            .phys
            .iter()
            .map(|phy| Lane {
                phy,
                frame: Some(broadcast.frame.clone()),
                schedule: broadcast.schedule,
                copy,
                handed_off: false,
                quorum_heard: false,
                confirmed: false,
                exhausted: false,
            })
            .collect();

        self.records.insert(
            id,
            Record {
                lanes,
                priority: broadcast.priority,
                handed_off: false,
                last_error: None,
                rejected: None,
                deadline: now + tunables.handoff_timeout(),
            },
        );
    }

    /// The highest-priority copy queued for `phy`, oldest first within a priority. A
    /// send past its deadline is left for `tick` to fail.
    pub(super) fn best_queued(&self, now: Instant, phy: PhyIndex) -> Option<(SendId, TxPriority)> {
        self.records
            .iter()
            .filter(|(_, record)| {
                now < record.deadline
                    && record
                        .lanes
                        .iter()
                        .any(|lane| lane.phy == phy && lane.copy == CopyState::Queued)
            })
            .max_by_key(|(id, record)| (record.priority, Reverse(**id)))
            .map(|(id, record)| (*id, record.priority))
    }

    pub(super) fn dequeue(&mut self, id: SendId, phy: PhyIndex) -> InFlight<F> {
        let lane = self.records.get_mut(&id).unwrap().lane_mut(phy);
        debug_assert_eq!(lane.copy, CopyState::Queued);
        lane.copy = CopyState::Transmitting;

        InFlight {
            id,
            frame: lane.frame.take().unwrap(),
            transmit: Transmit::Broadcast,
            phy,
        }
    }

    /// `passive_ack_interval` spaces the next passive-ack copy from this one.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn transmitted(
        &mut self,
        id: SendId,
        phy: PhyIndex,
        frame: F,
        result: Result<Delivery, TransmitError<E>>,
        now: Instant,
        passive_ack_interval: Duration,
        outbox: &mut Outbox<F, E>,
    ) {
        let record = self
            .records
            .get_mut(&id)
            .expect("a transmitting send is never settled from outside");

        let lane = record.lane_mut(phy);
        debug_assert_eq!(lane.copy, CopyState::Transmitting);
        lane.copy = CopyState::Idle;
        lane.frame = Some(frame);

        match &mut lane.schedule {
            Schedule::Once => lane.exhausted = true,
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

        // A lost copy is not terminal: the schedule retransmits
        match result {
            Ok(delivery) => {
                lane.handed_off = true;

                // Only a secondary PHY confirms what it delivered; on the radio, the
                // passive-ack quorum does
                if (phy != PhyIndex::Radio && delivery == Delivery::Confirmed) || lane.quorum_heard
                {
                    lane.confirmed = true;
                }

                // The first copy on air is the handoff
                if !record.handed_off {
                    record.handed_off = true;
                    outbox.push_back(Action::HandedOff(id));
                }
            }
            Err(TransmitError::Failed(err)) => record.last_error = Some(err),
            // No later copy can succeed either, on any PHY
            Err(TransmitError::Rejected(err)) => {
                record.rejected = Some(err);
                record.lanes.iter_mut().for_each(Lane::finish);
            }
        }

        if record.over() {
            self.settle(id, outbox);
        }
    }

    /// Remove a record that is over and report its verdict.
    fn settle(&mut self, id: SendId, outbox: &mut Outbox<F, E>) {
        let mut record = self.records.remove(&id).unwrap();
        let result = record.verdict();
        Self::settled(id, result, outbox);
    }

    /// Report the verdict of a record removed from the table.
    fn settled(id: SendId, result: Result<(), E>, outbox: &mut Outbox<F, E>) {
        outbox.push_back(Action::Settled {
            id,
            result,
            failed_hop: None,
        });
    }

    /// Confirm the radio's copies of every broadcast whose passive-ack quorum `heard`
    /// says was heard. The send is delivered once every PHY is done. A quorum heard
    /// before the radio's first copy went out confirms the radio when it does.
    pub(super) fn deliver(
        &mut self,
        mut heard: impl FnMut((Nwk, u8)) -> bool,
        outbox: &mut Outbox<F, E>,
    ) {
        for record in self.records.values_mut() {
            let Some(lane) = record
                .lanes
                .iter_mut()
                .find(|lane| lane.phy == PhyIndex::Radio)
            else {
                continue;
            };
            let Schedule::PassiveAck { key, .. } = lane.schedule else {
                continue;
            };
            if lane.quorum_heard || !heard(key) {
                continue;
            }

            lane.quorum_heard = true;
            if lane.handed_off {
                lane.confirmed = true;
                if lane.copy == CopyState::Queued {
                    lane.copy = CopyState::Idle;
                }
            }
        }

        let delivered = self.records.extract_if(|_, record| record.over());
        for (id, mut record) in delivered {
            Self::settled(id, record.verdict(), outbox);
        }
    }

    /// Settle every record as cancelled: the stack is shutting down and no copy, in a
    /// PHY or not, is ever reported on again.
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

    /// Whether the send was cancelled: not if a copy is in a PHY right now, or the
    /// send is unknown.
    pub(super) fn cancel(&mut self, id: SendId, outbox: &mut Outbox<F, E>) -> bool {
        let Some(record) = self.records.get(&id) else {
            return false;
        };
        if record.transmitting() {
            return false;
        }

        self.records.remove(&id);
        Self::settled(id, Err(SendFailure::Cancelled.into()), outbox);
        true
    }

    /// Send no further copies of a broadcast nobody waits on any more. A copy in a PHY
    /// right now cannot be recalled: the schedules are emptied instead, so the record
    /// settles when they next come due (a `Once` schedule settles on the copy's own
    /// report).
    pub(super) fn stop(&mut self, id: SendId, outbox: &mut Outbox<F, E>) {
        let Some(record) = self.records.get_mut(&id) else {
            return;
        };

        if record.transmitting() {
            for lane in &mut record.lanes {
                lane.schedule.stop();
                if lane.copy == CopyState::Queued {
                    lane.copy = CopyState::Idle;
                }
            }
        } else {
            self.records.remove(&id);
            Self::settled(id, Err(SendFailure::Cancelled.into()), outbox);
        }
    }

    /// Queue copies that are due, complete or fail schedules that ran out, and fail
    /// records past their deadline.
    pub(super) fn tick(&mut self, now: Instant, outbox: &mut Outbox<F, E>) {
        let over = self.records.extract_map(|_, record| {
            for lane in &mut record.lanes {
                if lane.done() || lane.copy != CopyState::Idle {
                    continue;
                }

                match lane.schedule.due(now) {
                    Some(Due::Copy) => lane.copy = CopyState::Queued,
                    Some(Due::Over) => lane.exhausted = true,
                    None => {}
                }
            }

            if record.over() {
                return Some(record.verdict());
            }

            if record.deadline <= now && !record.transmitting() {
                return Some(if record.handed_off {
                    Ok(())
                } else {
                    Err(SendFailure::HandoffTimeout.into())
                });
            }

            None
        });

        for (id, _, result) in over {
            Self::settled(id, result, outbox);
        }
    }

    pub(super) fn next_wake(&self) -> Option<Instant> {
        self.records.values().filter_map(Record::next_wake).min()
    }
}
