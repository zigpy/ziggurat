//! The send tables: every outgoing frame the stack holds, from admission to its verdict.
//!
//! A send is one record in exactly one of three tables, and its frame lives only in
//! that record. Once the record is settled (removed) there is nothing left to transmit.
//!
//! - [`Unicasts`](unicasts::Unicasts): a frame with a known next hop, delivered directly
//!   (with retries) or to a sleepy child when it polls.
//! - [`UnroutedUnicasts`](unrouted::UnroutedUnicasts): a unicast with no route yet, held
//!   until its destination's route discovery ends. The driver runs the discovery against its
//!   routing table and reports when the route is known or the discovery lapsed; the
//!   send then moves to the unicasts or fails.
//! - [`Broadcasts`](broadcasts::Broadcasts): a frame sent once, or rebroadcast on a
//!   schedule until its passive-ack quorum is heard.
//!
//! [`Sends`] fronts the three with one id space: the sender dequeues the highest
//! priority ready frame across them, and a cancel or a transmit report is routed to the
//! table holding the id.
//!
//! The tables never read a clock and never notify anyone: `now` is passed in, and every
//! mutation returns the [`Action`]s the driver must carry out. They are generic over the
//! frame type `F`, the waiter type `W` and the driver's error type `E`, which they only
//! ever need to build from a [`SendFailure`].
//!
//! Every record carries a deadline, so no send can be stranded: a record past its
//! deadline fails with the error its state implies.

mod broadcasts;
mod unicasts;
mod unrouted;

use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_ieee_802154::Ieee802154Address;
use ziggurat_ieee_802154::types::{Eui64, Nwk};

use crate::Instant;
use crate::aps::frame::ApsAckFrame;
use crate::flat_map::{FlatMap, FlatSet};

pub use broadcasts::{Broadcast, Schedule};
pub use unicasts::{Delivery, Placement, Unicast};
pub use unrouted::UnroutedUnicast;

use broadcasts::Broadcasts;
use unicasts::Unicasts;
use unrouted::UnroutedUnicasts;

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
    /// The end-to-end APS ack matching `ack`, waited for `wait` after handoff.
    ApsAck { ack: ApsAckData, wait: Duration },
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
pub struct DequeuedSend<'a, F> {
    pub id: SendId,
    pub frame: &'a F,
    pub transmit: Transmit,
}

/// What the driver must do after a mutation.
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
}

/// What the driver must do after a mutation, in order. Every mutating verb returns one,
/// so a mutation whose consequences are dropped is a compile-time warning.
#[must_use = "actions resolve waiters; dropping them loses sends"]
#[derive(Debug)]
pub struct Actions<F, W, E>(Vec<Action<F, W, E>>);

impl<F, W, E> Default for Actions<F, W, E> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<F, W, E> Actions<F, W, E> {
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, action: Action<F, W, E>) {
        self.0.push(action);
    }
}

impl<F, W, E> Extend<Action<F, W, E>> for Actions<F, W, E> {
    fn extend<I: IntoIterator<Item = Action<F, W, E>>>(&mut self, actions: I) {
        self.0.extend(actions);
    }
}

impl<F, W, E> FromIterator<Action<F, W, E>> for Actions<F, W, E> {
    fn from_iter<I: IntoIterator<Item = Action<F, W, E>>>(actions: I) -> Self {
        Self(actions.into_iter().collect())
    }
}

impl<F, W, E> IntoIterator for Actions<F, W, E> {
    type Item = Action<F, W, E>;
    type IntoIter = alloc::vec::IntoIter<Action<F, W, E>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
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
    unrouted_unicasts: UnroutedUnicasts<F, W, E>,
    broadcasts: Broadcasts<F, W, E>,
}

impl<F, W, E> Default for Sends<F, W, E> {
    fn default() -> Self {
        Self {
            next_id: 0,
            unicasts: Unicasts::default(),
            unrouted_unicasts: UnroutedUnicasts::default(),
            broadcasts: Broadcasts::default(),
        }
    }
}

impl<F, W: Clone, E: From<SendFailure>> Sends<F, W, E> {
    /// What the fattest record, a unicast's, costs, for pricing the frame budget.
    pub const RECORD_BYTES: usize = {
        assert!(Unicasts::<F, W, E>::RECORD_BYTES >= UnroutedUnicasts::<F, W, E>::RECORD_BYTES);
        assert!(Unicasts::<F, W, E>::RECORD_BYTES >= Broadcasts::<F, W, E>::RECORD_BYTES);
        Unicasts::<F, W, E>::RECORD_BYTES
    };

    const fn next_id(&mut self) -> SendId {
        let id = SendId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Enqueue a unicast with a known next hop.
    pub fn enqueue_unicast(&mut self, unicast: Unicast<F, W>) -> (SendId, Actions<F, W, E>) {
        let id = self.next_id();
        self.unicasts.enqueue(id, unicast);
        (id, Actions::new())
    }

    /// Enqueue a unicast with no route yet, held until its destination's discovery
    /// ends. The caller starts that discovery if the destination was not already
    /// awaited; the first unrouted send to a destination fixes `retries`, how often it
    /// is restarted.
    pub fn enqueue_unrouted_unicast(
        &mut self,
        send: UnroutedUnicast<F, W>,
        retries: u8,
    ) -> (SendId, Actions<F, W, E>) {
        let id = self.next_id();
        self.unrouted_unicasts.enqueue(id, send, retries);
        (id, Actions::new())
    }

    /// Enqueue a broadcast. Its first copy goes out on the next tick its schedule says
    /// it is due (a `Once` schedule queues it right away).
    pub fn enqueue_broadcast(&mut self, broadcast: Broadcast<F, W>) -> (SendId, Actions<F, W, E>) {
        let id = self.next_id();
        self.broadcasts.enqueue(id, broadcast);
        (id, Actions::new())
    }

    /// Hand the highest-priority queued frame (oldest first within a priority) to the
    /// sender, which must report back through `transmitted`.
    pub fn dequeue(&mut self) -> Option<DequeuedSend<'_, F>> {
        let unicast = self.unicasts.best_queued();
        let broadcast = self.broadcasts.best_queued();

        let (id, from_unicasts) = match (unicast, broadcast) {
            (None, None) => return None,
            (Some((id, _)), None) => (id, true),
            (None, Some((id, _))) => (id, false),
            // Higher priority first; between equal priorities the older send (lower id)
            (Some((u, up)), Some((b, bp))) => {
                let unicast_first = up > bp || (up == bp && u < b);
                if unicast_first { (u, true) } else { (b, false) }
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
    ) -> Actions<F, W, E> {
        if self.unicasts.contains(id) {
            self.unicasts.transmitted(id, result, now, retry_delay)
        } else {
            self.broadcasts.transmitted(id, result)
        }
    }

    /// 802.15.4 spec 6.7.3: a MAC Data Request extracts the oldest frame awaiting the
    /// polling device. Returns whether one was queued for the sender.
    pub fn poll(
        &mut self,
        eui64: Option<Eui64>,
        nwk: Option<Nwk>,
        now: Instant,
    ) -> (bool, Actions<F, W, E>) {
        (self.unicasts.poll(eui64, nwk, now), Actions::new())
    }

    /// An end-to-end APS ack arrived.
    pub fn aps_ack_received(&mut self, ack: &ApsAckData) -> Actions<F, W, E> {
        self.unicasts.ack_received(ack)
    }

    /// Every destination with unrouted sends.
    pub fn unrouted_destinations(&self) -> Vec<Nwk> {
        self.unrouted_unicasts.destinations()
    }

    /// Whether any unrouted send waits on `destination`'s route discovery.
    pub fn has_unrouted(&self, destination: Nwk) -> bool {
        self.unrouted_unicasts.has_unrouted(destination)
    }

    /// `destination`'s discovery lapsed: consume a restart of it, if one is left and
    /// an unrouted send still waits on it. The caller restarts the discovery.
    pub fn retry_discovery(&mut self, destination: Nwk) -> bool {
        self.unrouted_unicasts.retry_discovery(destination)
    }

    /// Fail every unrouted send to `destination`: its discovery is over without a
    /// route.
    pub fn fail_unrouted(&mut self, destination: Nwk) -> Actions<F, W, E> {
        self.unrouted_unicasts.fail(destination)
    }

    /// A route to `destination` is known: move every unrouted send to it to the unicasts.
    /// `place` resolves each frame's next hop (rewriting the frame for a source route),
    /// or fails the send.
    pub fn route_unicasts(
        &mut self,
        destination: Nwk,
        mut place: impl FnMut(&mut F) -> Result<Placement, E>,
    ) -> Actions<F, W, E> {
        let mut actions = Actions::new();

        for (id, mut unrouted) in self.unrouted_unicasts.route(destination) {
            match place(&mut unrouted.frame) {
                Ok(placement) => self.unicasts.enqueue(
                    id,
                    Unicast {
                        frame: unrouted.frame,
                        priority: unrouted.priority,
                        waiter: unrouted.waiter,
                        confirm: unrouted.confirm,
                        delivery: placement.delivery,
                        deadline: placement.deadline,
                    },
                ),
                Err(err) => actions.push(Action::Settled {
                    waiter: unrouted.waiter,
                    result: Err(err),
                    frame: unrouted.frame,
                    failed_hop: None,
                }),
            }
        }

        actions
    }

    /// The key of every broadcast awaiting its passive-ack quorum.
    pub fn broadcasts_awaiting_quorum(&self) -> Vec<(Nwk, u8)> {
        self.broadcasts.awaiting_quorum()
    }

    /// The passive-ack quorum for a broadcast was heard: the send is delivered.
    pub fn broadcast_delivered(&mut self, key: (Nwk, u8)) -> Actions<F, W, E> {
        self.broadcasts.delivered(key)
    }

    /// Fail every frame awaiting a device's poll: it is no longer a child.
    pub fn drop_indirect_unicasts(&mut self, eui64: Option<Eui64>, nwk: Nwk) -> Actions<F, W, E> {
        self.unicasts.drop_indirect(eui64, nwk)
    }

    /// Cancel a send. `None` if it is unknown, already over, or in the radio right now
    /// (its own report settles it within the radio's timeout).
    pub fn cancel(&mut self, id: SendId) -> Option<Actions<F, W, E>> {
        if self.unicasts.contains(id) {
            self.unicasts.cancel(id)
        } else if self.unrouted_unicasts.contains(id) {
            Some(self.unrouted_unicasts.cancel(id))
        } else {
            self.broadcasts.cancel(id)
        }
    }

    /// The timer pass: re-queue what is due and fail what is past its deadline.
    /// `passive_ack_interval` spaces passive-ack broadcast copies.
    pub fn tick(&mut self, now: Instant, passive_ack_interval: Duration) -> Actions<F, W, E> {
        let mut actions = self.unicasts.tick(now);
        actions.extend(self.unrouted_unicasts.tick(now));
        actions.extend(self.broadcasts.tick(now, passive_ack_interval));
        actions
    }

    /// When the timer must next run, or `None` when nothing is waiting on time.
    pub fn next_wake(&self) -> Option<Instant> {
        [
            self.unicasts.next_wake(),
            self.unrouted_unicasts.next_wake(),
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
    pub fn has_unicast_awaiting_poll(&self, address: Ieee802154Address) -> bool {
        self.unicasts.has_awaiting_poll(address)
    }
}
