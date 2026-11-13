//! Unicasts with a known next hop: delivered directly with NWK retries, or to a sleepy
//! child when it polls (802.15.4 spec 6.7.3).

use core::cmp::Reverse;
use core::marker::PhantomData;
use core::time::Duration;

use ziggurat_ieee_802154::Ieee802154Address;
use ziggurat_ieee_802154::types::{Eui64, Nwk};

use crate::Instant;
use crate::constants::Tunables;
use crate::flat_map::FlatMap;

use super::{
    Action, ApsAckData, Confirm, InFlight, Outbox, SendFailure, SendFrame, SendId, SrcMatchTable,
    Transmit, TransmitError, TxPriority,
};

/// What a unicast is enqueued with.
#[derive(Debug)]
pub struct Unicast<F> {
    pub frame: F,
    pub priority: TxPriority,
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
struct Record<F> {
    /// `None` exactly while the frame is on loan to the radio (`Stage::Transmitting`).
    frame: Option<F>,
    priority: TxPriority,
    confirm: Confirm,
    next_hop: Nwk,
    poll_address: Option<Ieee802154Address>,
    /// Transmit attempts left after the current one. A failed transmit of a held frame
    /// waits for the next poll instead, until the frame expires.
    attempts_remaining: u8,
    stage: Stage,
    deadline: Instant,
    /// The broadcast this frame copies to a sleepy child.
    copy_of: Option<SendId>,
}

impl<F> Record<F> {
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
pub(super) struct Unicasts<F, E> {
    records: FlatMap<SendId, Record<F>>,
    _error: PhantomData<fn() -> E>,
}

impl<F, E> Default for Unicasts<F, E> {
    fn default() -> Self {
        Self {
            records: FlatMap::new(),
            _error: PhantomData,
        }
    }
}

impl<F: SendFrame, E: From<SendFailure>> Unicasts<F, E> {
    pub(super) fn contains(&self, id: SendId) -> bool {
        self.records.contains_key(&id)
    }

    /// A unicast fails if not handed off within the handoff timeout; a held frame if
    /// not polled for within the transaction persistence time. A send admitted earlier
    /// passes the deadline it was admitted with: it replaces the handoff timeout and
    /// caps the persistence time.
    pub(super) fn enqueue(
        &mut self,
        id: SendId,
        unicast: Unicast<F>,
        now: Instant,
        admitted_deadline: Option<Instant>,
        copy_of: Option<SendId>,
        tunables: &Tunables,
    ) {
        let persistence_deadline = now + tunables.transaction_persistence_time();
        let (stage, deadline) = match (unicast.poll_address, admitted_deadline) {
            (None, None) => (Stage::Queued, now + tunables.handoff_timeout()),
            (None, Some(deadline)) => (Stage::Queued, deadline),
            (Some(_), None) => (Stage::AwaitingPoll, persistence_deadline),
            (Some(_), Some(deadline)) => (Stage::AwaitingPoll, persistence_deadline.min(deadline)),
        };

        self.records.insert(
            id,
            Record {
                frame: Some(unicast.frame),
                priority: unicast.priority,
                confirm: unicast.confirm,
                next_hop: unicast.next_hop,
                poll_address: unicast.poll_address,
                attempts_remaining: tunables.unicast_retries(),
                stage,
                deadline,
                copy_of,
            },
        );
    }

    /// The highest-priority queued send, oldest first within a priority. A send past its
    /// deadline is left for `tick` to fail.
    pub(super) fn best_queued(&self, now: Instant) -> Option<(SendId, TxPriority)> {
        self.records
            .iter()
            .filter(|(_, record)| record.stage == Stage::Queued && now < record.deadline)
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
        result: Result<(), TransmitError<E>>,
        now: Instant,
        retry_delay: Duration,
        outbox: &mut Outbox<F, E>,
    ) {
        let record = self
            .records
            .get_mut(&id)
            .expect("a transmitting send is never settled from outside");
        let Stage::Transmitting { acked } = record.stage else {
            unreachable!("only a transmitting send is reported on")
        };
        record.frame = Some(frame);

        match result {
            Ok(()) => self.handed_off(id, now, acked, outbox),
            // The destination acked end to end while the radio reported a failure: the
            // frame got through
            // TODO: the ack can only be for an earlier attempt, but it overrides any
            // error from this one, `Rejected` included
            Err(_) if acked => self.handed_off(id, now, acked, outbox),
            // Nothing reached the air, so the next hop is not to blame
            Err(TransmitError::Rejected(err)) => self.settle(id, Err(err), None, outbox),
            Err(TransmitError::Failed(err)) => match record.poll_address {
                // 802.15.4 spec 6.7.3: a transaction is only extracted once acknowledged,
                // so a failed transmit awaits the device's next poll, keeping its deadline
                Some(_) if now < record.deadline => record.stage = Stage::AwaitingPoll,
                Some(_) => self.settle(id, Err(err), None, outbox),
                None if record.attempts_remaining == 0 => {
                    let next_hop = record.next_hop;
                    self.settle(id, Err(err), Some(next_hop), outbox);
                }
                None => {
                    record.attempts_remaining -= 1;
                    record.stage = Stage::Retrying {
                        at: now + retry_delay,
                    };
                }
            },
        }
    }

    /// The frame reached its next hop: settle the send, or start waiting for its ack
    /// unless `acked` says it already arrived.
    fn handed_off(&mut self, id: SendId, now: Instant, acked: bool, outbox: &mut Outbox<F, E>) {
        let record = self.records.get_mut(&id).unwrap();

        let wait = match record.confirm {
            Confirm::OnHandoff => None,
            Confirm::ApsAck { wait, .. } => (!acked).then_some(wait),
        };

        let Some(wait) = wait else {
            self.settle(id, Ok(()), None, outbox);
            return;
        };

        record.stage = Stage::AwaitingApsAck;
        record.deadline = now + wait;

        outbox.push_back(Action::HandedOff(id));
    }

    /// Remove a record and report its verdict.
    fn settle(
        &mut self,
        id: SendId,
        result: Result<(), E>,
        failed_hop: Option<Nwk>,
        outbox: &mut Outbox<F, E>,
    ) {
        let record = self.records.remove(&id).unwrap();
        Self::settled(id, record, result, failed_hop, outbox);
    }

    /// Report the verdict of a record removed from the table.
    fn settled(
        id: SendId,
        record: Record<F>,
        result: Result<(), E>,
        failed_hop: Option<Nwk>,
        outbox: &mut Outbox<F, E>,
    ) {
        let frame = record
            .frame
            .expect("a transmitting send is never settled from outside");

        outbox.push_back(Action::Settled {
            id,
            result,
            failed_hop: failed_hop.map(|next_hop| (next_hop, frame.failure())),
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
    pub(super) fn ack_received(&mut self, ack: &ApsAckData, outbox: &mut Outbox<F, E>) {
        let matched = self
            .records
            .iter()
            .find_map(|(id, record)| match &record.confirm {
                Confirm::ApsAck { ack: expected, .. } if expected == ack => Some(*id),
                _ => None,
            });

        let Some(id) = matched else {
            return;
        };

        let record = self.records.get_mut(&id).unwrap();
        if matches!(record.stage, Stage::Transmitting { .. }) {
            // Faster than the radio's own report: `transmitted` settles it
            record.stage = Stage::Transmitting { acked: true };
        } else {
            self.settle(id, Ok(()), None, outbox);
        }
    }

    /// Fail every frame awaiting a device's poll: it is no longer a child.
    pub(super) fn drop_indirect(
        &mut self,
        eui64: Option<Eui64>,
        nwk: Nwk,
        outbox: &mut Outbox<F, E>,
    ) {
        let dropped =
            self.records
                .extract_map(|_, record| match (record.poll_address, record.stage) {
                    (Some(address), Stage::AwaitingPoll)
                        if address == Ieee802154Address::Nwk(nwk)
                            || eui64.is_some_and(|e| address == Ieee802154Address::Eui64(e)) =>
                    {
                        Some(address)
                    }
                    _ => None,
                });

        for (id, record, destination) in dropped {
            Self::settled(
                id,
                record,
                Err(SendFailure::IndirectExpired { destination }.into()),
                None,
                outbox,
            );
        }
    }

    /// Settle every record as cancelled: the stack is shutting down and no frame, in
    /// the radio or not, is ever reported on again.
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
        if matches!(record.stage, Stage::Transmitting { .. }) {
            return false;
        }
        self.settle(id, Err(SendFailure::Cancelled.into()), None, outbox);
        true
    }

    /// Whether a copy of a broadcast to one of its sleepy children is in the radio.
    pub(super) fn copy_transmitting(&self, broadcast: SendId) -> bool {
        self.records.values().any(|record| {
            record.copy_of == Some(broadcast) && matches!(record.stage, Stage::Transmitting { .. })
        })
    }

    /// Cancel the copies of a broadcast to its sleepy children. None may be in the radio.
    pub(super) fn cancel_copies(&mut self, broadcast: SendId, outbox: &mut Outbox<F, E>) {
        let copies = self
            .records
            .extract_if(|_, record| record.copy_of == Some(broadcast));

        for (id, record) in copies {
            assert!(!matches!(record.stage, Stage::Transmitting { .. }));
            Self::settled(id, record, Err(SendFailure::Cancelled.into()), None, outbox);
        }
    }

    /// Re-queue retries that are due and fail records past their deadline.
    pub(super) fn tick(&mut self, now: Instant, outbox: &mut Outbox<F, E>) {
        let lapsed = self.records.extract_map(|_, record| {
            if let Stage::Retrying { at } = record.stage
                && at <= now
            {
                record.stage = Stage::Queued;
            }

            if record.deadline <= now {
                record.deadline_failure()
            } else {
                None
            }
        });

        for (id, record, failure) in lapsed {
            Self::settled(id, record, Err(failure.into()), None, outbox);
        }
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
