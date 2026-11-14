//! GPDFs held until their GPD listens. A GPD receives only for a moment after it sends a
//! GPDF with RxAfterTx set, so a send waits for one of those, then goes out 20-25 ms
//! after it began (GP A.1.5.2.1). A GPD has at most one GPDF waiting: a new one replaces
//! it.

use core::marker::PhantomData;
use core::time::Duration;

use crate::Instant;
use crate::flat_map::FlatMap;
use crate::gp::GpdfTarget;

use super::{
    Action, InFlight, Outbox, SendFailure, SendFrame, SendId, Transmit, TransmitError, TxPriority,
};

/// What a GPDF is enqueued with.
#[derive(Debug)]
pub struct Gpdf<F> {
    pub frame: F,
    pub target: GpdfTarget,
    /// How long it waits for its GPD to listen
    pub lifetime: Duration,
}

/// The GPDF after which the GPD listens: it lets a held GPDF go out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpdfTrigger {
    /// When the trigger was received, on the radio clock: the reply is timed from it
    pub rx_timestamp_us: u64,
    /// Past this, a reply handed to the radio misses the GPD's receive window
    pub send_by: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    AwaitingTrigger,
    /// Ready for the sender while the window is open.
    Queued(GpdfTrigger),
    /// A record in this stage is never settled from outside: `transmitted` always finds
    /// it.
    Transmitting,
}

#[derive(Debug)]
struct Record<F> {
    /// `None` exactly while the frame is on loan to the radio (`Stage::Transmitting`).
    frame: Option<F>,
    target: GpdfTarget,
    stage: Stage,
    deadline: Instant,
}

#[derive(Debug)]
pub(super) struct Gpdfs<F, E> {
    records: FlatMap<SendId, Record<F>>,
    _error: PhantomData<fn() -> E>,
}

impl<F, E> Default for Gpdfs<F, E> {
    fn default() -> Self {
        Self {
            records: FlatMap::new(),
            _error: PhantomData,
        }
    }
}

impl<F: SendFrame, E: From<SendFailure>> Gpdfs<F, E> {
    pub(super) fn contains(&self, id: SendId) -> bool {
        self.records.contains_key(&id)
    }

    /// The record of `target` that is not yet in the radio. A record in the radio
    /// finishes on its own, beside a newer one for the same target.
    fn waiting_for(&self, target: GpdfTarget) -> Option<SendId> {
        self.records
            .iter()
            .find(|(_, record)| record.target == target && record.stage != Stage::Transmitting)
            .map(|(id, _)| *id)
    }

    /// Hold a GPDF for its GPD, replacing the one still held for it.
    pub(super) fn enqueue(
        &mut self,
        id: SendId,
        gpdf: Gpdf<F>,
        now: Instant,
        outbox: &mut Outbox<F, E>,
    ) {
        if let Some(replaced) = self.waiting_for(gpdf.target) {
            self.settle(replaced, Err(SendFailure::GpdfReplaced.into()), outbox);
        }

        self.records.insert(
            id,
            Record {
                frame: Some(gpdf.frame),
                target: gpdf.target,
                stage: Stage::AwaitingTrigger,
                deadline: now + gpdf.lifetime,
            },
        );
    }

    /// A GPDF after which `target` listens. `accept` decides on the held frame: `Ok(true)`
    /// queues it, `Ok(false)` ignores the trigger, and an error fails the send.
    pub(super) fn triggered(
        &mut self,
        target: GpdfTarget,
        trigger: GpdfTrigger,
        now: Instant,
        accept: impl FnOnce(&F) -> Result<bool, E>,
        outbox: &mut Outbox<F, E>,
    ) {
        let Some(id) = self.waiting_for(target) else {
            return;
        };

        let record = self.records.get_mut(&id).unwrap();
        // A repetition of a trigger already answered, or a send left for `tick` to fail
        if record.stage != Stage::AwaitingTrigger || record.deadline <= now {
            return;
        }

        match accept(record.frame.as_ref().unwrap()) {
            Ok(true) => record.stage = Stage::Queued(trigger),
            Ok(false) => (),
            Err(err) => self.settle(id, Err(err), outbox),
        }
    }

    /// The oldest GPDF whose window is still open. They all go ahead of everything else.
    pub(super) fn best_queued(&self, now: Instant) -> Option<(SendId, TxPriority)> {
        self.records
            .iter()
            .find(|(_, record)| {
                matches!(record.stage, Stage::Queued(trigger) if now < trigger.send_by)
            })
            .map(|(id, _)| (*id, TxPriority::Realtime))
    }

    pub(super) fn dequeue(&mut self, id: SendId) -> InFlight<F> {
        let record = self.records.get_mut(&id).unwrap();
        let Stage::Queued(trigger) = record.stage else {
            unreachable!("only a queued GPDF is dequeued")
        };
        record.stage = Stage::Transmitting;

        InFlight {
            id,
            frame: record.frame.take().unwrap(),
            transmit: Transmit::Gpdf(trigger),
        }
    }

    /// A GPDF is sent once. A failed transmit waits for the next trigger instead, until
    /// the GPDF expires or a newer GPDF for its GPD replaces it.
    pub(super) fn transmitted(
        &mut self,
        id: SendId,
        frame: F,
        result: Result<(), TransmitError<E>>,
        now: Instant,
        outbox: &mut Outbox<F, E>,
    ) {
        let record = self
            .records
            .get_mut(&id)
            .expect("a transmitting send is never settled from outside");
        debug_assert_eq!(record.stage, Stage::Transmitting);
        record.frame = Some(frame);
        let target = record.target;
        let deadline = record.deadline;

        match result {
            // A newer GPDF was enqueued while this one was in the radio
            Err(TransmitError::Failed(_))
                if now < deadline && self.waiting_for(target).is_some() =>
            {
                self.settle(id, Err(SendFailure::GpdfReplaced.into()), outbox);
            }
            Err(TransmitError::Failed(_)) if now < deadline => {
                self.records.get_mut(&id).unwrap().stage = Stage::AwaitingTrigger;
            }
            Ok(()) => self.settle(id, Ok(()), outbox),
            Err(TransmitError::Failed(err) | TransmitError::Rejected(err)) => {
                self.settle(id, Err(err), outbox);
            }
        }
    }

    /// Remove a record and report its verdict. The only way a record leaves the table.
    fn settle(&mut self, id: SendId, result: Result<(), E>, outbox: &mut Outbox<F, E>) {
        let record = self.records.remove(&id).unwrap();
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

    /// Settle every record as cancelled: the stack is shutting down and no frame, in the
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

    /// Whether the send was cancelled: not if it is in the radio right now, or unknown.
    pub(super) fn cancel(&mut self, id: SendId, outbox: &mut Outbox<F, E>) -> bool {
        let Some(record) = self.records.get(&id) else {
            return false;
        };
        if record.stage == Stage::Transmitting {
            return false;
        }

        self.settle(id, Err(SendFailure::Cancelled.into()), outbox);
        true
    }

    /// Put back the GPDFs whose window closed before the sender took them, and fail the
    /// ones past their deadline.
    pub(super) fn tick(&mut self, now: Instant, outbox: &mut Outbox<F, E>) {
        for record in self.records.values_mut() {
            if let Stage::Queued(trigger) = record.stage
                && trigger.send_by <= now
            {
                record.stage = Stage::AwaitingTrigger;
            }
        }

        let lapsed = self.records.extract_if(|_, record| {
            record.stage == Stage::AwaitingTrigger && record.deadline <= now
        });

        for (id, record) in lapsed {
            drop(record.frame);
            outbox.push_back(Action::Settled {
                id,
                result: Err(SendFailure::GpdfExpired.into()),
                failed_hop: None,
            });
        }
    }

    pub(super) fn next_wake(&self) -> Option<Instant> {
        self.records
            .values()
            .filter_map(|record| match record.stage {
                Stage::AwaitingTrigger => Some(record.deadline),
                Stage::Queued(trigger) => Some(trigger.send_by),
                Stage::Transmitting => None,
            })
            .min()
    }
}
