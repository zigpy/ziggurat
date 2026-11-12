//! Unicasts with no route yet, held until their destination's route discovery ends.
//!
//! Discovery runs once per destination and the whole bucket moves on together, so ten
//! frames to one device ride a single discovery. The discovery itself lives in the
//! routing table; this table counts the restarts it has left and remembers the
//! broadcast of its route request, to stop it if the discovery is abandoned.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::constants::Tunables;
use crate::flat_map::FlatMap;

use super::{Action, Actions, Confirm, SendFailure, SendId, TxPriority};

/// What an unrouted unicast is enqueued with.
#[derive(Debug)]
pub struct UnroutedUnicast<F, W> {
    pub frame: F,
    pub priority: TxPriority,
    pub waiter: W,
    pub confirm: Confirm,
    pub destination: Nwk,
}

/// A held send: what it carries to the unicasts once its route is known.
#[derive(Debug)]
pub(super) struct Record<F, W> {
    pub(super) frame: F,
    pub(super) priority: TxPriority,
    pub(super) waiter: W,
    pub(super) confirm: Confirm,
    pub(super) destination: Nwk,
    /// When the send fails if still unrouted.
    pub(super) deadline: Instant,
}

/// What this table tracks of a destination's route discovery.
#[derive(Debug)]
struct Discovery {
    /// Restarts left. The first discovery is the driver's, started at admission; these
    /// are the ones after it.
    restarts_left: u8,
    /// The broadcast of the latest route request.
    request: Option<SendId>,
}

#[derive(Debug)]
pub(super) struct UnroutedUnicasts<F, W, E> {
    records: FlatMap<SendId, Record<F, W>>,
    /// One per destination with unrouted sends.
    discoveries: FlatMap<Nwk, Discovery>,
    _error: PhantomData<fn() -> E>,
}

impl<F, W, E> Default for UnroutedUnicasts<F, W, E> {
    fn default() -> Self {
        Self {
            records: FlatMap::new(),
            discoveries: FlatMap::new(),
            _error: PhantomData,
        }
    }
}

impl<F, W, E: From<SendFailure>> UnroutedUnicasts<F, W, E> {
    pub(super) fn contains(&self, id: SendId) -> bool {
        self.records.contains_key(&id)
    }

    pub(super) fn has_unrouted(&self, destination: Nwk) -> bool {
        self.discoveries.contains_key(&destination)
    }

    /// Hold a send. It fails if still unrouted within the handoff timeout. The first
    /// unrouted send to a destination fixes how often its discovery may be restarted.
    pub(super) fn enqueue(
        &mut self,
        id: SendId,
        send: UnroutedUnicast<F, W>,
        now: Instant,
        tunables: &Tunables,
    ) {
        let destination = send.destination;
        self.records.insert(
            id,
            Record {
                frame: send.frame,
                priority: send.priority,
                waiter: send.waiter,
                confirm: send.confirm,
                destination,
                deadline: now + tunables.handoff_timeout(),
            },
        );

        if !self.discoveries.contains_key(&destination) {
            self.discoveries.insert(
                destination,
                Discovery {
                    // The tunable counts discoveries; the first one is not a restart
                    restarts_left: tunables
                        .pending_route_discovery_attempts()
                        .saturating_sub(1),
                    request: None,
                },
            );
        }
    }

    pub(super) fn destinations(&self) -> Vec<Nwk> {
        self.discoveries.keys().copied().collect()
    }

    /// The driver broadcast a route request for `destination`'s discovery. Returns the
    /// broadcast of the request it replaces, for the caller to stop.
    pub(super) fn route_request_sent(
        &mut self,
        destination: Nwk,
        request: SendId,
    ) -> Option<SendId> {
        self.discoveries
            .get_mut(&destination)
            .unwrap()
            .request
            .replace(request)
    }

    /// The id of every send to `destination`, oldest first.
    pub(super) fn sends_to(&self, destination: Nwk) -> Vec<SendId> {
        self.records
            .iter()
            .filter(|(_, send)| send.destination == destination)
            .map(|(id, _)| *id)
            .collect()
    }

    pub(super) fn frame_mut(&mut self, id: SendId) -> &mut F {
        &mut self.records.get_mut(&id).unwrap().frame
    }

    /// Take a held send: it has a route, or it failed.
    pub(super) fn take(&mut self, id: SendId) -> Record<F, W> {
        self.records.remove(&id).unwrap()
    }

    /// A send to `destination` found a route. Its discovery is over once no send waits
    /// on it any more.
    pub(super) fn routed(&mut self, destination: Nwk) {
        if self.sends_to(destination).is_empty() {
            self.discoveries.remove(&destination);
        }
    }

    fn settled(send: Record<F, W>, failure: SendFailure) -> Action<F, W, E> {
        Action::Settled {
            waiter: send.waiter,
            result: Err(failure.into()),
            frame: send.frame,
            failed_hop: None,
        }
    }

    /// Consume a restart of `destination`'s discovery, if one is left and a send still
    /// waits on it.
    pub(super) fn retry_discovery(&mut self, destination: Nwk) -> bool {
        let waiting = self
            .records
            .values()
            .any(|send| send.destination == destination);

        let discovery = self.discoveries.get_mut(&destination).unwrap();
        // A discovery nothing waits on any more is not restarted
        if discovery.restarts_left == 0 || !waiting {
            return false;
        }

        discovery.restarts_left -= 1;
        true
    }

    /// Fail every send to `destination`: its discovery is over without a route. Returns
    /// the broadcast of its route request, for the caller to stop.
    pub(super) fn fail(&mut self, destination: Nwk) -> (Option<SendId>, Actions<F, W, E>) {
        let request = self
            .discoveries
            .remove(&destination)
            .and_then(|discovery| discovery.request);

        let actions = self
            .sends_to(destination)
            .into_iter()
            .map(|id| Self::settled(self.take(id), SendFailure::RouteDiscoveryTimeout))
            .collect();

        (request, actions)
    }

    /// Drop every record and return its waiter: the stack is shutting down.
    pub(super) fn abandon(&mut self) -> Vec<W> {
        self.discoveries.clear();
        let mut waiters = Vec::new();
        while let Some((_, send)) = self.records.pop_first() {
            waiters.push(send.waiter);
        }
        waiters
    }

    /// The destination stays awaited, so a new send to it does not start a second
    /// discovery; it lapses on its own once nothing waits on it.
    pub(super) fn cancel(&mut self, id: SendId) -> Actions<F, W, E> {
        let send = self.records.remove(&id).unwrap();
        let mut actions = Actions::new();
        actions.push(Self::settled(send, SendFailure::Cancelled));
        actions
    }

    /// Fail sends past their deadline.
    pub(super) fn tick(&mut self, now: Instant) -> Actions<F, W, E> {
        let lapsed: Vec<SendId> = self
            .records
            .iter()
            .filter(|(_, send)| send.deadline <= now)
            .map(|(id, _)| *id)
            .collect();

        lapsed
            .into_iter()
            .map(|id| {
                let send = self.records.remove(&id).unwrap();
                Self::settled(send, SendFailure::HandoffTimeout)
            })
            .collect()
    }

    pub(super) fn next_wake(&self) -> Option<Instant> {
        self.records.values().map(|send| send.deadline).min()
    }
}
