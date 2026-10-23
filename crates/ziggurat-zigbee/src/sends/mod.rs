//! The send tables: every outgoing frame the stack holds, from admission to its verdict.
//!
//! A send is one record in exactly one of three tables, and its frame lives only in
//! that record. Once the record is settled (removed) there is nothing left to transmit.
//!
//! - [`Unicasts`](unicasts::Unicasts): a frame with a known next hop, delivered directly
//!   (with retries) or to a sleepy child when it polls.
//! - [`Parked`](parked::Parked): a unicast with no route yet, waiting on its
//!   destination's route discovery. It moves to the unicasts once the route resolves.
//! - [`Broadcasts`](broadcasts::Broadcasts): a frame sent once, or rebroadcast on a
//!   schedule until its passive-ack quorum is heard.
//!
//! [`Sends`] fronts the three with one id space: the sender dequeues the highest
//! priority ready frame across them, and a cancel or a transmit report is routed to the
//! table holding the id.
//!
//! The tables never read a clock and never notify anyone: `now` is passed in, and every
//! mutation appends the [`Action`]s the driver must carry out to the `actions` it is
//! given. They are generic over the frame type `F`, the waiter type `W` and the driver's
//! error type `E`, which they only ever need to build from a [`SendFailure`].
//!
//! Every record carries a deadline, so no send can be stranded: a record past its
//! deadline fails with the error its state implies.

mod broadcasts;
mod parked;
mod unicasts;

use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_ieee_802154::Ieee802154Address;
use ziggurat_ieee_802154::types::{Eui64, Nwk};

use crate::Instant;
use crate::aps::frame::ApsAckFrame;
use crate::flat_map::{FlatMap, FlatSet};

pub use broadcasts::{Broadcast, Schedule};
pub use parked::ParkedSend;
pub use unicasts::{Delivery, Placement, Unicast};

use broadcasts::Broadcasts;
use parked::Parked;
use unicasts::Unicasts;

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

/// A failure a table decides on its own. The driver's error type is built from it.
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

/// How the sender transmits a dequeued frame.
#[derive(Debug, Clone, Copy)]
pub enum Transmit {
    /// A MAC unicast to `next_hop`. `frame_pending` tells a polling device that more
    /// frames await it (802.15.4 spec 6.7.3).
    Unicast {
        next_hop: Nwk,
        frame_pending: bool,
    },
    Broadcast,
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
        waiter: W,
        result: Result<(), E>,
        frame: F,
        failed_hop: Option<Nwk>,
    },
    StartDiscovery(Nwk),
    DiscoveryFailed(Nwk),
    /// The set of devices with frames awaiting their poll changed.
    PollAddressesChanged,
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

/// The three send tables behind one id space.
#[derive(Debug)]
pub struct Sends<F, W, E> {
    next_id: u32,
    unicasts: Unicasts<F, W, E>,
    parked: Parked<F, W, E>,
    broadcasts: Broadcasts<F, W, E>,
}

impl<F, W, E> Default for Sends<F, W, E> {
    fn default() -> Self {
        Self {
            next_id: 0,
            unicasts: Unicasts::default(),
            parked: Parked::default(),
            broadcasts: Broadcasts::default(),
        }
    }
}

const fn max3(a: usize, b: usize, c: usize) -> usize {
    let ab = if a > b { a } else { b };
    if ab > c { ab } else { c }
}

impl<F, W: Clone, E: From<SendFailure>> Sends<F, W, E> {
    /// What the fattest record costs, for pricing the frame budget.
    pub const RECORD_BYTES: usize = max3(
        Unicasts::<F, W, E>::RECORD_BYTES,
        Parked::<F, W, E>::RECORD_BYTES,
        Broadcasts::<F, W, E>::RECORD_BYTES,
    );

    const fn next_id(&mut self) -> SendId {
        let id = SendId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Admit a unicast with a known next hop.
    pub fn admit_unicast(
        &mut self,
        unicast: Unicast<F, W>,
        actions: &mut Vec<Action<F, W, E>>,
    ) -> SendId {
        let id = self.next_id();
        self.unicasts.admit(id, unicast, actions);
        id
    }

    /// Admit a unicast with no route yet, parked on its destination's discovery. One
    /// discovery runs per destination; `attempts` bounds how often it is restarted.
    pub fn admit_parked(
        &mut self,
        send: ParkedSend<F, W>,
        now: Instant,
        discovery_time: Duration,
        attempts: u8,
        actions: &mut Vec<Action<F, W, E>>,
    ) -> SendId {
        let id = self.next_id();
        self.parked
            .admit(id, send, now, discovery_time, attempts, actions);
        id
    }

    /// Admit a broadcast. Its first copy goes out on the next tick its schedule says
    /// it is due (a `Once` schedule queues it right away).
    pub fn admit_broadcast(&mut self, broadcast: Broadcast<F, W>) -> SendId {
        let id = self.next_id();
        self.broadcasts.admit(id, broadcast);
        id
    }

    /// Hand the highest-priority queued frame (oldest first within a priority) to the
    /// sender, which must report back through `transmitted`.
    pub fn dequeue(&mut self) -> Option<Dequeued<'_, F>> {
        let unicast = self.unicasts.best_queued();
        let broadcast = self.broadcasts.best_queued();

        let (id, from_unicasts) = match (unicast, broadcast) {
            (None, None) => return None,
            (Some((id, _)), None) => (id, true),
            (None, Some((id, _))) => (id, false),
            (Some((u, up)), Some((b, bp))) => {
                if (up, b) > (bp, u) {
                    (u, true)
                } else {
                    (b, false)
                }
            }
        };

        Some(if from_unicasts {
            self.unicasts.dequeue(id)
        } else {
            self.broadcasts.dequeue(id)
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
        actions: &mut Vec<Action<F, W, E>>,
    ) {
        if self.unicasts.contains(id) {
            self.unicasts
                .transmitted(id, result, now, retry_delay, actions);
        } else {
            self.broadcasts.transmitted(id, result, actions);
        }
    }

    /// 802.15.4 spec 6.7.3: a MAC Data Request extracts the oldest frame awaiting the
    /// polling device. Returns whether one was queued for the sender.
    pub fn poll(&mut self, eui64: Option<Eui64>, nwk: Option<Nwk>, now: Instant) -> bool {
        self.unicasts.poll(eui64, nwk, now)
    }

    /// An end-to-end APS ack arrived.
    pub fn ack_received(&mut self, ack: &ApsAckData, actions: &mut Vec<Action<F, W, E>>) {
        self.unicasts.ack_received(ack, actions);
    }

    /// Every destination with sends parked on its route discovery.
    pub fn awaiting_route_destinations(&self) -> Vec<Nwk> {
        self.parked.destinations()
    }

    /// A route to `destination` is active: move every send parked on it to the unicasts.
    /// `place` resolves each frame's next hop (rewriting the frame for a source route),
    /// or fails the send.
    pub fn route_resolved(
        &mut self,
        destination: Nwk,
        mut place: impl FnMut(&mut F) -> Result<Placement, E>,
        actions: &mut Vec<Action<F, W, E>>,
    ) {
        for (id, mut parked) in self.parked.resolved(destination) {
            match place(&mut parked.frame) {
                Ok(placement) => self.unicasts.admit(
                    id,
                    Unicast {
                        frame: parked.frame,
                        priority: parked.priority,
                        waiter: parked.waiter,
                        confirm: parked.confirm,
                        delivery: placement.delivery,
                        deadline: placement.deadline,
                    },
                    actions,
                ),
                Err(err) => actions.push(Action::Settled {
                    waiter: parked.waiter,
                    result: Err(err),
                    frame: parked.frame,
                    failed_hop: None,
                }),
            }
        }
    }

    /// The keys of every broadcast awaiting its passive-ack quorum.
    pub fn passive_ack_keys(&self) -> Vec<(Nwk, u8)> {
        self.broadcasts.passive_ack_keys()
    }

    /// The passive-ack quorum for a broadcast was heard: it is delivered.
    pub fn broadcast_acked(&mut self, key: (Nwk, u8), actions: &mut Vec<Action<F, W, E>>) {
        self.broadcasts.acked(key, actions);
    }

    /// Fail every frame awaiting a device's poll: it is no longer a child.
    pub fn drop_indirect(
        &mut self,
        eui64: Option<Eui64>,
        nwk: Nwk,
        actions: &mut Vec<Action<F, W, E>>,
    ) {
        self.unicasts.drop_indirect(eui64, nwk, actions);
    }

    /// Cancel a send. `false` if it is unknown, already over, or in the radio right now
    /// (its own report settles it within the radio's timeout).
    pub fn cancel(&mut self, id: SendId, actions: &mut Vec<Action<F, W, E>>) -> bool {
        if self.unicasts.contains(id) {
            self.unicasts.cancel(id, actions)
        } else if self.parked.contains(id) {
            self.parked.cancel(id, actions);
            true
        } else {
            self.broadcasts.cancel(id, actions)
        }
    }

    /// The timer pass: re-queue what is due, fail what is past its deadline, and retry
    /// or fail lapsed route discoveries. `passive_ack_interval` spaces passive-ack
    /// broadcast copies.
    pub fn tick(
        &mut self,
        now: Instant,
        passive_ack_interval: Duration,
        actions: &mut Vec<Action<F, W, E>>,
    ) {
        self.unicasts.tick(now, actions);
        self.parked.tick(now, actions);
        self.broadcasts.tick(now, passive_ack_interval, actions);
    }

    /// When the timer must next run, or `None` when nothing is waiting on time.
    pub fn next_wake(&self) -> Option<Instant> {
        [
            self.unicasts.next_wake(),
            self.parked.next_wake(),
            self.broadcasts.next_wake(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// The source address match table the radio should hold.
    pub fn poll_addresses(&self, address_map: &FlatMap<Eui64, Nwk>) -> SrcMatchTable {
        self.unicasts.poll_addresses(address_map)
    }

    /// Whether a device has a frame awaiting its poll under this exact address.
    pub fn has_awaiting_poll(&self, address: Ieee802154Address) -> bool {
        self.unicasts.has_awaiting_poll(address)
    }
}
