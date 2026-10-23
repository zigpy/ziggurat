//! The send table: every outgoing frame the stack holds, from admission to its verdict.
//!
//! A send is one [`Record`], owned here and nowhere else. The frame lives only in its
//! record, so once the record is settled (removed) there is nothing left to transmit.
//! The record's [`Stage`] says where the send is in its life; every queue the driver used
//! to keep (the sender's priority queue, the frames parked on a route discovery, the
//! unicast retries, the indirect transactions awaiting a poll, the broadcasts awaiting
//! retransmission, the sends awaiting an APS ack) is a query over this one table.
//!
//! The table never reads a clock and never notifies anyone: `now` is passed in, and every
//! mutation returns the [`Action`]s the driver must carry out, such as resolving a
//! waiter or starting a route discovery. It is generic over the frame type `F`, the
//! waiter type `W` and the driver's error type `E`, which it only ever needs to build
//! from a [`SendFailure`].
//!
//! A record always carries a deadline, so no send can be stranded: a record past its
//! deadline fails with the error its stage implies.

use alloc::vec::Vec;
use core::marker::PhantomData;
use core::time::Duration;

use ziggurat_ieee_802154::Ieee802154Address;
use ziggurat_ieee_802154::types::{Eui64, Nwk};

use crate::Instant;
use crate::aps::frame::ApsAckFrame;
use crate::flat_map::{FlatMap, FlatSet};

/// Identifies a send for its whole life. Allocated in admission order and never reused,
/// so a lower id is always an older send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SendId(u32);

impl SendId {
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Transmit scheduling priority. Higher transmits first when the radio is contended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxPriority {
    Background,
    UserLow,
    UserNormal,
    UserHigh,
    UserCritical,
    StackCritical,
}

impl TxPriority {
    /// Map a host-supplied wire priority (an `i8`, 0 = normal) to a level, clamped
    /// below [`Self::StackCritical`]: the host cannot preempt the stack's own
    /// machinery.
    pub const fn from_host(value: i8) -> Self {
        match value {
            i8::MIN..=-2 => Self::Background,
            -1 => Self::UserLow,
            0 => Self::UserNormal,
            1 => Self::UserHigh,
            _ => Self::UserCritical,
        }
    }
}

/// What an end-to-end APS ack is matched on.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApsAckData {
    pub src: Nwk,
    pub destination_endpoint: Option<u8>,
    pub cluster_id: Option<u16>,
    pub profile_id: Option<u16>,
    pub source_endpoint: Option<u8>,
    pub counter: u8,
}

impl ApsAckData {
    pub const fn from_aps_ack(src: Nwk, ack: &ApsAckFrame) -> Self {
        Self {
            src,
            destination_endpoint: ack.destination_endpoint,
            cluster_id: ack.cluster_id,
            profile_id: ack.profile_id,
            source_endpoint: ack.source_endpoint,
            counter: ack.counter,
        }
    }
}

/// A failure the table decides on its own. The driver's error type is built from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFailure {
    /// The send was never handed to the mesh before its deadline.
    HandoffTimeout,
    ApsAckTimeout,
    /// The device never polled for the frame before it expired.
    IndirectExpired {
        destination: Ieee802154Address,
    },
    RouteDiscoveryTimeout,
    BroadcastQuorumNotReached,
    Cancelled,
}

/// What settles a unicast send's `delivered` verdict.
#[derive(Debug)]
pub enum Confirm {
    /// Next-hop acceptance is the whole verdict.
    OnHandoff,
    /// The end-to-end APS ack matching `ack`, waited for `wait` after handoff. `acked`
    /// records an ack that arrived while the frame was still in the radio.
    ApsAck {
        ack: ApsAckData,
        wait: Duration,
        acked: bool,
    },
}

/// How a queued frame is transmitted and what happens after.
#[derive(Debug, Clone, Copy)]
pub enum Next {
    /// Transmit once; the result is the verdict (a single-copy broadcast, a raw frame).
    Once,
    /// A unicast to `next_hop`, retried `attempts_remaining` more times on failure.
    Unicast {
        next_hop: Nwk,
        attempts_remaining: u8,
    },
    /// A frame a polling device extracted, transmitted to it as a unicast. On failure
    /// it returns to awaiting the device's next poll until it expires.
    Indirect {
        address: Ieee802154Address,
        next_hop: Nwk,
    },
}

/// How a broadcast is retransmitted and when it is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastSchedule {
    /// Spec 3.6.6: rebroadcast until the passive-ack quorum is heard or attempts run
    /// out, which fails the send.
    PassiveAck,
    /// Send a fixed number of copies at this interval (a route request); running out of
    /// attempts completes the send.
    FixedInterval { interval: Duration },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CopyState {
    Idle,
    Queued,
    Transmitting,
}

/// A broadcast's retransmission state. The record's frame is the only copy: a
/// retransmission queues the record itself, so settling the record drops every copy
/// still to come.
#[derive(Debug)]
pub struct Broadcasting {
    key: (Nwk, u8),
    schedule: BroadcastSchedule,
    attempts_remaining: u8,
    next_attempt: Instant,
    copy: CopyState,
    handed_off: bool,
    /// The quorum was heard while a copy was in the radio; that copy's report settles
    /// the send.
    quorum_heard: bool,
}

/// Where a send is in its life.
#[derive(Debug)]
pub enum Stage {
    /// Parked until the destination's route discovery resolves.
    AwaitingRoute {
        destination: Nwk,
    },
    /// Ready for the sender.
    Queued(Next),
    /// The sender holds an encrypted copy and is waiting on the radio. A record in this
    /// stage is never settled from outside: `transmitted` always finds it.
    Transmitting(Next),
    /// A failed unicast waiting out its retry delay.
    Retrying {
        next_hop: Nwk,
        attempts_remaining: u8,
        at: Instant,
    },
    /// Queued for a sleepy device, which extracts it by polling (802.15.4 spec 6.7.3).
    AwaitingPoll {
        address: Ieee802154Address,
        next_hop: Nwk,
    },
    Broadcasting(Broadcasting),
    /// Handed off; waiting for the end-to-end APS ack.
    AwaitingApsAck,
}

/// How a send enters the table, or re-enters it once its route resolves.
#[derive(Debug)]
pub enum Entry {
    Queue(Next),
    AwaitRoute {
        destination: Nwk,
        discovery_time: Duration,
        attempts: u8,
    },
    Indirect {
        address: Ieee802154Address,
        next_hop: Nwk,
        persistence_time: Duration,
    },
    Broadcast {
        key: (Nwk, u8),
        schedule: BroadcastSchedule,
        /// Copies the schedule sends, besides the one sent now if `copy_now`.
        attempts: u8,
        next_attempt: Instant,
        /// Queue the first copy now, instead of at `next_attempt`.
        copy_now: bool,
    },
}

/// What the sender dequeued and how to transmit it.
#[derive(Debug, Clone, Copy)]
pub enum Transmit {
    Once,
    Unicast {
        next_hop: Nwk,
    },
    Indirect {
        address: Ieee802154Address,
        next_hop: Nwk,
        /// More frames await the same device's polls: the delivered frame's pending bit
        /// is set so the device keeps polling (802.15.4 spec 6.7.3).
        more_pending: bool,
    },
    BroadcastCopy,
}

#[derive(Debug)]
pub struct Dequeued<'a, F> {
    pub id: SendId,
    pub frame: &'a F,
    pub transmit: Transmit,
}

/// What the driver must do after a mutation.
#[must_use = "actions resolve waiters and start discoveries; dropping them loses sends"]
#[derive(Debug)]
pub enum Action<F, W, E> {
    /// The mesh accepted the send's frame; its waiter learns so.
    HandedOff(W),
    /// The send is over. The frame is handed back so the driver drops it (and whatever
    /// budget it holds). `failed_hop` names the next hop a unicast exhausted its
    /// attempts at.
    Settled {
        waiter: Option<W>,
        result: Result<(), E>,
        frame: F,
        failed_hop: Option<Nwk>,
    },
    StartDiscovery(Nwk),
    DiscoveryFailed(Nwk),
    /// The set of devices with frames awaiting their poll changed.
    PollAddressesChanged,
}

/// What a send is admitted with: everything about it that never changes.
#[derive(Debug)]
pub struct Admission<F, W> {
    pub frame: F,
    pub priority: TxPriority,
    pub confirm: Confirm,
    pub waiter: Option<W>,
}

#[derive(Debug)]
struct Record<F, W> {
    frame: F,
    priority: TxPriority,
    waiter: Option<W>,
    confirm: Confirm,
    stage: Stage,
    deadline: Instant,
}

impl<F, W> Record<F, W> {
    /// Whether the send counts toward its device's frame-pending bit.
    const fn awaits_poll(&self) -> bool {
        self.poll_address().is_some()
    }

    const fn poll_address(&self) -> Option<Ieee802154Address> {
        match self.stage {
            Stage::AwaitingPoll { address, .. }
            | Stage::Queued(Next::Indirect { address, .. })
            | Stage::Transmitting(Next::Indirect { address, .. }) => Some(address),
            _ => None,
        }
    }

    /// Whether the sender holds a copy of the frame right now.
    const fn transmitting(&self) -> bool {
        matches!(
            self.stage,
            Stage::Transmitting(_)
                | Stage::Broadcasting(Broadcasting {
                    copy: CopyState::Transmitting,
                    ..
                })
        )
    }

    /// The failure a lapsed deadline means in this stage. `None` while transmitting:
    /// the radio's own timeout bounds that stage.
    const fn deadline_failure(&self) -> Option<SendFailure> {
        match &self.stage {
            Stage::Transmitting(_) => None,
            Stage::AwaitingRoute { .. }
            | Stage::Queued(Next::Once | Next::Unicast { .. })
            | Stage::Retrying { .. } => Some(SendFailure::HandoffTimeout),
            Stage::AwaitingPoll { address, .. } | Stage::Queued(Next::Indirect { address, .. }) => {
                Some(SendFailure::IndirectExpired {
                    destination: *address,
                })
            }
            Stage::AwaitingApsAck => Some(SendFailure::ApsAckTimeout),
            Stage::Broadcasting(broadcasting) => match broadcasting.copy {
                CopyState::Transmitting => None,
                CopyState::Idle | CopyState::Queued => {
                    if broadcasting.handed_off {
                        Some(SendFailure::BroadcastQuorumNotReached)
                    } else {
                        Some(SendFailure::HandoffTimeout)
                    }
                }
            },
        }
    }

    /// When the timer must next look at this record.
    fn next_wake(&self) -> Option<Instant> {
        match &self.stage {
            Stage::Transmitting(_) => None,
            Stage::Retrying { at, .. } => Some((*at).min(self.deadline)),
            Stage::Broadcasting(broadcasting) => match broadcasting.copy {
                CopyState::Transmitting => None,
                CopyState::Idle => Some(broadcasting.next_attempt.min(self.deadline)),
                CopyState::Queued => Some(self.deadline),
            },
            Stage::AwaitingRoute { .. }
            | Stage::Queued(_)
            | Stage::AwaitingPoll { .. }
            | Stage::AwaitingApsAck => Some(self.deadline),
        }
    }
}

/// One destination's route discovery, shared by every send parked on it.
#[derive(Debug)]
struct Discovery {
    attempts_remaining: u8,
    discovery_time: Duration,
    deadline: Instant,
}

/// The source address match table the radio should hold: every device with a frame
/// awaiting its poll, under both its address forms (the device may poll with either).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SrcMatchTable {
    pub short_addresses: FlatSet<Nwk>,
    pub extended_addresses: FlatSet<Eui64>,
}

impl SrcMatchTable {
    pub fn contains(&self, address: Ieee802154Address) -> bool {
        match address {
            Ieee802154Address::Nwk(nwk) => self.short_addresses.contains(&nwk),
            Ieee802154Address::Eui64(eui64) => self.extended_addresses.contains(&eui64),
        }
    }
}

#[derive(Debug)]
pub struct Sends<F, W, E> {
    records: FlatMap<SendId, Record<F, W>>,
    discoveries: FlatMap<Nwk, Discovery>,
    next_id: u32,
    _error: PhantomData<fn() -> E>,
}

impl<F, W, E> Default for Sends<F, W, E> {
    fn default() -> Self {
        Self {
            records: FlatMap::new(),
            discoveries: FlatMap::new(),
            next_id: 0,
            _error: PhantomData,
        }
    }
}

/// What `transmitted` decided for a record, applied once the record borrow ends.
enum AfterTransmit<E> {
    HandedOff,
    Settle(Result<(), E>, Option<Nwk>),
    Retry {
        next_hop: Nwk,
        attempts_remaining: u8,
    },
    AwaitPoll {
        address: Ieee802154Address,
        next_hop: Nwk,
    },
    CopyDone {
        on_air: bool,
    },
}

impl<F, W: Clone, E: From<SendFailure>> Sends<F, W, E> {
    /// What one record costs in the table, for pricing the frame budget.
    pub const RECORD_BYTES: usize = core::mem::size_of::<(SendId, Record<F, W>)>();

    /// Admit a send. `handoff_timeout` bounds how long it may wait to reach the mesh.
    pub fn admit(
        &mut self,
        admission: Admission<F, W>,
        entry: Entry,
        now: Instant,
        handoff_timeout: Duration,
    ) -> (SendId, Vec<Action<F, W, E>>) {
        let id = SendId(self.next_id);
        self.next_id += 1;

        self.records.insert(
            id,
            Record {
                frame: admission.frame,
                priority: admission.priority,
                waiter: admission.waiter,
                confirm: admission.confirm,
                // Overwritten by `enter`
                stage: Stage::Queued(Next::Once),
                deadline: now + handoff_timeout,
            },
        );

        let mut actions = Vec::new();
        self.enter(id, entry, now, &mut actions);
        (id, actions)
    }

    /// Put a record into the stage its entry names.
    fn enter(
        &mut self,
        id: SendId,
        entry: Entry,
        now: Instant,
        actions: &mut Vec<Action<F, W, E>>,
    ) {
        let record = self.records.get_mut(&id).unwrap();

        match entry {
            Entry::Queue(next) => record.stage = Stage::Queued(next),
            Entry::AwaitRoute {
                destination,
                discovery_time,
                attempts,
            } => {
                record.stage = Stage::AwaitingRoute { destination };

                // One discovery per destination: later sends ride the one in flight
                if !self.discoveries.contains_key(&destination) {
                    self.discoveries.insert(
                        destination,
                        Discovery {
                            attempts_remaining: attempts,
                            discovery_time,
                            deadline: now + discovery_time,
                        },
                    );
                    actions.push(Action::StartDiscovery(destination));
                }
            }
            Entry::Indirect {
                address,
                next_hop,
                persistence_time,
            } => {
                record.stage = Stage::AwaitingPoll { address, next_hop };
                record.deadline = now + persistence_time;
                actions.push(Action::PollAddressesChanged);
            }
            Entry::Broadcast {
                key,
                schedule,
                attempts,
                next_attempt,
                copy_now,
            } => {
                record.stage = Stage::Broadcasting(Broadcasting {
                    key,
                    schedule,
                    attempts_remaining: attempts,
                    next_attempt,
                    copy: if copy_now {
                        CopyState::Queued
                    } else {
                        CopyState::Idle
                    },
                    handed_off: false,
                    quorum_heard: false,
                });
            }
        }
    }

    /// Hand the highest-priority queued frame (oldest first within a priority) to the
    /// sender, which must report back through `transmitted`.
    pub fn dequeue(&mut self) -> Option<Dequeued<'_, F>> {
        let mut best: Option<(SendId, TxPriority)> = None;

        for (id, record) in self.records.iter() {
            let queued = matches!(
                record.stage,
                Stage::Queued(_)
                    | Stage::Broadcasting(Broadcasting {
                        copy: CopyState::Queued,
                        ..
                    })
            );

            if queued && best.is_none_or(|(_, priority)| record.priority > priority) {
                best = Some((*id, record.priority));
            }
        }

        let (id, _) = best?;

        let more_pending = match self.records.get(&id).unwrap().stage {
            Stage::Queued(Next::Indirect { address, .. }) => self
                .records
                .iter()
                .any(|(other, record)| *other != id && record.poll_address() == Some(address)),
            _ => false,
        };

        let record = self.records.get_mut(&id).unwrap();

        let transmit = match &mut record.stage {
            Stage::Queued(next) => {
                let next = *next;
                record.stage = Stage::Transmitting(next);
                match next {
                    Next::Once => Transmit::Once,
                    Next::Unicast { next_hop, .. } => Transmit::Unicast { next_hop },
                    Next::Indirect { address, next_hop } => Transmit::Indirect {
                        address,
                        next_hop,
                        more_pending,
                    },
                }
            }
            Stage::Broadcasting(broadcasting) => {
                broadcasting.copy = CopyState::Transmitting;
                Transmit::BroadcastCopy
            }
            _ => unreachable!("only queued records are dequeued"),
        };

        Some(Dequeued {
            id,
            frame: &record.frame,
            transmit,
        })
    }

    /// The sender's report for a dequeued frame. `retry_delay` is how long a failed
    /// unicast waits before its next attempt.
    pub fn transmitted(
        &mut self,
        id: SendId,
        result: Result<(), E>,
        now: Instant,
        retry_delay: Duration,
    ) -> Vec<Action<F, W, E>> {
        let mut actions = Vec::new();

        let record = self
            .records
            .get(&id)
            .expect("a transmitting send is never settled from outside");

        let acked = matches!(record.confirm, Confirm::ApsAck { acked: true, .. });

        let after = match record.stage {
            Stage::Transmitting(Next::Once) => AfterTransmit::Settle(result, None),
            Stage::Transmitting(Next::Unicast {
                next_hop,
                attempts_remaining,
            }) => match result {
                Ok(()) => AfterTransmit::HandedOff,
                // The destination acked end to end while the radio reported a failure:
                // the frame got through
                Err(_) if acked => AfterTransmit::HandedOff,
                Err(err) if attempts_remaining == 0 => {
                    AfterTransmit::Settle(Err(err), Some(next_hop))
                }
                Err(_) => AfterTransmit::Retry {
                    next_hop,
                    attempts_remaining: attempts_remaining - 1,
                },
            },
            Stage::Transmitting(Next::Indirect { address, next_hop }) => match result {
                Ok(()) => AfterTransmit::HandedOff,
                Err(_) if acked => AfterTransmit::HandedOff,
                // 802.15.4 spec 6.7.3: a transaction is only extracted once acknowledged,
                // so a failed transmit awaits the device's next poll, keeping its deadline
                Err(_) if now < record.deadline => AfterTransmit::AwaitPoll { address, next_hop },
                Err(err) => AfterTransmit::Settle(Err(err), None),
            },
            Stage::Broadcasting(Broadcasting {
                copy: CopyState::Transmitting,
                ..
            }) => AfterTransmit::CopyDone {
                on_air: result.is_ok(),
            },
            _ => unreachable!("transmitted called for a send that was not dequeued"),
        };

        match after {
            AfterTransmit::HandedOff => self.handed_off(id, now, &mut actions),
            AfterTransmit::Settle(result, failed_hop) => {
                self.settle(id, result, failed_hop, &mut actions);
            }
            AfterTransmit::Retry {
                next_hop,
                attempts_remaining,
            } => {
                self.records.get_mut(&id).unwrap().stage = Stage::Retrying {
                    next_hop,
                    attempts_remaining,
                    at: now + retry_delay,
                };
            }
            AfterTransmit::AwaitPoll { address, next_hop } => {
                self.records.get_mut(&id).unwrap().stage =
                    Stage::AwaitingPoll { address, next_hop };
            }
            AfterTransmit::CopyDone { on_air } => {
                let record = self.records.get_mut(&id).unwrap();
                let Stage::Broadcasting(broadcasting) = &mut record.stage else {
                    unreachable!()
                };
                broadcasting.copy = CopyState::Idle;

                // A lost copy is not terminal: the schedule retransmits. The first copy
                // on air is the handoff.
                if on_air && !broadcasting.handed_off {
                    broadcasting.handed_off = true;
                    if let Some(waiter) = &record.waiter {
                        actions.push(Action::HandedOff(waiter.clone()));
                    }
                }

                if broadcasting.quorum_heard {
                    self.settle(id, Ok(()), None, &mut actions);
                }
            }
        }

        actions
    }

    /// A unicast's frame reached its next hop: settle it, or start waiting for its ack.
    fn handed_off(&mut self, id: SendId, now: Instant, actions: &mut Vec<Action<F, W, E>>) {
        let record = self.records.get_mut(&id).unwrap();

        let wait = match record.confirm {
            Confirm::OnHandoff | Confirm::ApsAck { acked: true, .. } => None,
            Confirm::ApsAck { wait, .. } => Some(wait),
        };

        let Some(wait) = wait else {
            self.settle(id, Ok(()), None, actions);
            return;
        };

        let left_poll_set = record.awaits_poll();
        record.stage = Stage::AwaitingApsAck;
        record.deadline = now + wait;

        if let Some(waiter) = &record.waiter {
            actions.push(Action::HandedOff(waiter.clone()));
        }
        if left_poll_set {
            actions.push(Action::PollAddressesChanged);
        }
    }

    /// Remove a record and report its verdict. The only way a record leaves the table.
    fn settle(
        &mut self,
        id: SendId,
        result: Result<(), E>,
        failed_hop: Option<Nwk>,
        actions: &mut Vec<Action<F, W, E>>,
    ) {
        let record = self.records.remove(&id).unwrap();

        if record.awaits_poll() {
            actions.push(Action::PollAddressesChanged);
        }

        actions.push(Action::Settled {
            waiter: record.waiter,
            result,
            frame: record.frame,
            failed_hop,
        });
    }

    /// 802.15.4 spec 6.7.3: a MAC Data Request extracts the oldest frame awaiting the
    /// polling device, under either of its addresses. Returns whether one was queued
    /// for the sender. Frames past their deadline are left for `tick` to fail.
    pub fn poll(&mut self, eui64: Option<Eui64>, nwk: Option<Nwk>, now: Instant) -> bool {
        let matches = |address: Ieee802154Address| match address {
            Ieee802154Address::Eui64(e) => eui64 == Some(e),
            Ieee802154Address::Nwk(n) => nwk == Some(n),
        };

        let oldest = self
            .records
            .iter()
            .find_map(|(id, record)| match record.stage {
                Stage::AwaitingPoll { address, .. }
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
        let Stage::AwaitingPoll { address, next_hop } = record.stage else {
            unreachable!()
        };

        // The poll is answered within `macResponseWaitTime`: ahead of everything else
        record.priority = TxPriority::StackCritical;
        record.stage = Stage::Queued(Next::Indirect { address, next_hop });

        true
    }

    /// An end-to-end APS ack arrived. It settles the oldest send waiting for it; the
    /// ack carries no way to tell two frames sharing a key apart.
    pub fn ack_received(&mut self, ack: &ApsAckData) -> Vec<Action<F, W, E>> {
        let mut actions = Vec::new();

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
                Stage::Transmitting(_) => Some((*id, false)),
                _ => None,
            }
        });

        match matched {
            Some((id, true)) => self.settle(id, Ok(()), None, &mut actions),
            // Faster than the radio's own report: `transmitted` settles it
            Some((id, false)) => {
                if let Confirm::ApsAck { acked, .. } =
                    &mut self.records.get_mut(&id).unwrap().confirm
                {
                    *acked = true;
                }
            }
            None => {}
        }

        actions
    }

    /// Every destination with sends parked on its route discovery.
    pub fn awaiting_route_destinations(&self) -> Vec<Nwk> {
        self.discoveries.keys().copied().collect()
    }

    /// A route to `destination` is active: re-enter every send parked on it. `place`
    /// resolves each frame's next hop (rewriting the frame for a source route), or fails
    /// the send.
    pub fn route_resolved(
        &mut self,
        destination: Nwk,
        now: Instant,
        mut place: impl FnMut(&mut F) -> Result<Entry, E>,
    ) -> Vec<Action<F, W, E>> {
        let mut actions = Vec::new();

        if self.discoveries.remove(&destination).is_none() {
            return actions;
        }

        let parked: Vec<SendId> = self
            .records
            .iter()
            .filter_map(|(id, record)| match record.stage {
                Stage::AwaitingRoute { destination: d } if d == destination => Some(*id),
                _ => None,
            })
            .collect();

        for id in parked {
            let placed = place(&mut self.records.get_mut(&id).unwrap().frame);
            match placed {
                Ok(entry) => self.enter(id, entry, now, &mut actions),
                Err(err) => self.settle(id, Err(err), None, &mut actions),
            }
        }

        actions
    }

    /// The keys of every broadcast awaiting its passive-ack quorum.
    pub fn passive_ack_keys(&self) -> Vec<(Nwk, u8)> {
        self.records
            .values()
            .filter_map(|record| match &record.stage {
                Stage::Broadcasting(Broadcasting {
                    key,
                    schedule: BroadcastSchedule::PassiveAck,
                    ..
                }) => Some(*key),
                _ => None,
            })
            .collect()
    }

    /// The passive-ack quorum for a broadcast was heard: it is delivered. A copy in the
    /// radio right now settles it on its report instead.
    pub fn broadcast_acked(&mut self, key: (Nwk, u8)) -> Vec<Action<F, W, E>> {
        let mut actions = Vec::new();

        let found = self
            .records
            .iter_mut()
            .find_map(|(id, record)| match &mut record.stage {
                Stage::Broadcasting(broadcasting) if broadcasting.key == key => {
                    Some((*id, broadcasting))
                }
                _ => None,
            });

        let Some((id, broadcasting)) = found else {
            return actions;
        };

        if broadcasting.copy == CopyState::Transmitting {
            broadcasting.quorum_heard = true;
        } else {
            self.settle(id, Ok(()), None, &mut actions);
        }

        actions
    }

    /// Fail every frame awaiting a device's poll: it is no longer a child.
    pub fn drop_indirect(&mut self, eui64: Option<Eui64>, nwk: Nwk) -> Vec<Action<F, W, E>> {
        let mut actions = Vec::new();

        let dropped: Vec<(SendId, Ieee802154Address)> = self
            .records
            .iter()
            .filter_map(|(id, record)| match record.stage {
                Stage::AwaitingPoll { address, .. }
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

    /// Cancel a send. `None` if it is unknown, already over, or in the radio right now
    /// (its own report settles it within the radio's timeout).
    pub fn cancel(&mut self, id: SendId) -> Option<Vec<Action<F, W, E>>> {
        let record = self.records.get(&id)?;
        if record.transmitting() {
            return None;
        }

        let mut actions = Vec::new();
        self.settle(id, Err(SendFailure::Cancelled.into()), None, &mut actions);
        Some(actions)
    }

    /// The timer pass: re-queue retries and broadcast copies that are due, fail records
    /// past their deadline, and retry or fail lapsed route discoveries.
    /// `broadcast_retransmit_interval` spaces passive-ack broadcast copies.
    pub fn tick(
        &mut self,
        now: Instant,
        broadcast_retransmit_interval: Duration,
    ) -> Vec<Action<F, W, E>> {
        let mut actions = Vec::new();
        let mut settle: Vec<(SendId, Result<(), E>)> = Vec::new();

        for (id, record) in self.records.iter_mut() {
            match record.stage {
                Stage::Retrying {
                    next_hop,
                    attempts_remaining,
                    at,
                } if at <= now => {
                    record.stage = Stage::Queued(Next::Unicast {
                        next_hop,
                        attempts_remaining,
                    });
                }
                Stage::Broadcasting(ref mut broadcasting)
                    if broadcasting.copy == CopyState::Idle && broadcasting.next_attempt <= now =>
                {
                    if broadcasting.attempts_remaining == 0 {
                        // A fixed-interval broadcast completes by running out of
                        // attempts; a data broadcast fails its quorum
                        let result = match broadcasting.schedule {
                            BroadcastSchedule::PassiveAck => {
                                Err(SendFailure::BroadcastQuorumNotReached.into())
                            }
                            BroadcastSchedule::FixedInterval { .. } => Ok(()),
                        };
                        settle.push((*id, result));
                        continue;
                    }

                    broadcasting.attempts_remaining -= 1;
                    broadcasting.copy = CopyState::Queued;
                    broadcasting.next_attempt = now
                        + match broadcasting.schedule {
                            BroadcastSchedule::PassiveAck => broadcast_retransmit_interval,
                            BroadcastSchedule::FixedInterval { interval } => interval,
                        };
                }
                _ => {}
            }

            if record.deadline <= now
                && let Some(failure) = record.deadline_failure()
            {
                settle.push((*id, Err(failure.into())));
            }
        }

        for (id, result) in settle {
            self.settle(id, result, None, &mut actions);
        }

        self.tick_discoveries(now, &mut actions);

        actions
    }

    fn tick_discoveries(&mut self, now: Instant, actions: &mut Vec<Action<F, W, E>>) {
        let lapsed: Vec<Nwk> = self
            .discoveries
            .iter()
            .filter(|(_, discovery)| discovery.deadline <= now)
            .map(|(destination, _)| *destination)
            .collect();

        for destination in lapsed {
            let parked: Vec<SendId> = self
                .records
                .iter()
                .filter_map(|(id, record)| match record.stage {
                    Stage::AwaitingRoute { destination: d } if d == destination => Some(*id),
                    _ => None,
                })
                .collect();

            let discovery = self.discoveries.get_mut(&destination).unwrap();
            discovery.attempts_remaining = discovery.attempts_remaining.saturating_sub(1);

            // A discovery nothing waits on any more is not retried
            if discovery.attempts_remaining > 0 && !parked.is_empty() {
                discovery.deadline = now + discovery.discovery_time;
                actions.push(Action::StartDiscovery(destination));
                continue;
            }

            self.discoveries.remove(&destination);
            actions.push(Action::DiscoveryFailed(destination));
            for id in parked {
                self.settle(
                    id,
                    Err(SendFailure::RouteDiscoveryTimeout.into()),
                    None,
                    actions,
                );
            }
        }
    }

    /// When the timer must next run, or `None` when nothing is waiting on time.
    pub fn next_wake(&self) -> Option<Instant> {
        let records = self.records.values().filter_map(Record::next_wake);
        let discoveries = self
            .discoveries
            .values()
            .map(|discovery| discovery.deadline);

        records.chain(discoveries).min()
    }

    /// The source address match table the radio should hold.
    pub fn poll_addresses(&self, address_map: &FlatMap<Eui64, Nwk>) -> SrcMatchTable {
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

    /// Whether a device has a frame awaiting its poll under this exact address.
    pub fn has_awaiting_poll(&self, address: Ieee802154Address) -> bool {
        self.records
            .values()
            .any(|record| record.poll_address() == Some(address))
    }
}
