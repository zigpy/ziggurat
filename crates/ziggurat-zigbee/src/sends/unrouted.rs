//! Unicasts with no route yet, held until their destination's route discovery ends.
//!
//! Discovery runs once per destination and the whole bucket moves on together, so ten
//! frames to one device ride a single discovery. The discovery itself lives in the
//! routing table; this table only counts the restarts it has left.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::flat_map::FlatMap;

use super::{Action, Confirm, SendFailure, SendId, TxPriority};

/// An unrouted unicast: what it is enqueued with, and what it carries to the unicasts
/// once its route is known.
#[derive(Debug)]
pub struct UnroutedUnicast<F, W> {
    pub frame: F,
    pub priority: TxPriority,
    pub waiter: W,
    pub confirm: Confirm,
    pub destination: Nwk,
    /// When the send fails if still unrouted.
    pub deadline: Instant,
}

#[derive(Debug)]
pub(super) struct UnroutedUnicasts<F, W, E> {
    records: FlatMap<SendId, UnroutedUnicast<F, W>>,
    /// Discovery restarts left, per destination with unrouted sends.
    retries: FlatMap<Nwk, u8>,
    _error: PhantomData<fn() -> E>,
}

impl<F, W, E> Default for UnroutedUnicasts<F, W, E> {
    fn default() -> Self {
        Self {
            records: FlatMap::new(),
            retries: FlatMap::new(),
            _error: PhantomData,
        }
    }
}

impl<F, W, E: From<SendFailure>> UnroutedUnicasts<F, W, E> {
    pub(super) const RECORD_BYTES: usize = core::mem::size_of::<(SendId, UnroutedUnicast<F, W>)>();

    pub(super) fn contains(&self, id: SendId) -> bool {
        self.records.contains_key(&id)
    }

    pub(super) fn has_unrouted(&self, destination: Nwk) -> bool {
        self.retries.contains_key(&destination)
    }

    /// Hold a send. The first unrouted send to a destination fixes how often its
    /// discovery may be restarted.
    pub(super) fn enqueue(&mut self, id: SendId, send: UnroutedUnicast<F, W>, retries: u8) {
        let destination = send.destination;
        self.records.insert(id, send);

        if !self.retries.contains_key(&destination) {
            self.retries.insert(destination, retries);
        }
    }

    pub(super) fn destinations(&self) -> Vec<Nwk> {
        self.retries.keys().copied().collect()
    }

    /// Take every send to `destination`: its route is known.
    pub(super) fn route(&mut self, destination: Nwk) -> Vec<(SendId, UnroutedUnicast<F, W>)> {
        self.retries.remove(&destination);
        self.take(destination)
    }

    fn take(&mut self, destination: Nwk) -> Vec<(SendId, UnroutedUnicast<F, W>)> {
        let ids: Vec<SendId> = self
            .records
            .iter()
            .filter(|(_, send)| send.destination == destination)
            .map(|(id, _)| *id)
            .collect();

        ids.into_iter()
            .map(|id| (id, self.records.remove(&id).unwrap()))
            .collect()
    }

    fn settled(send: UnroutedUnicast<F, W>, failure: SendFailure) -> Action<F, W, E> {
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

        let retries = self.retries.get_mut(&destination).unwrap();
        // A discovery nothing waits on any more is not restarted
        if *retries == 0 || !waiting {
            return false;
        }

        *retries -= 1;
        true
    }

    /// Fail every send to `destination`: its discovery is over without a route.
    pub(super) fn fail(&mut self, destination: Nwk) -> Vec<Action<F, W, E>> {
        self.retries.remove(&destination);
        self.take(destination)
            .into_iter()
            .map(|(_, send)| Self::settled(send, SendFailure::RouteDiscoveryTimeout))
            .collect()
    }

    /// The destination stays awaited, so a new send to it does not start a second
    /// discovery; it lapses on its own once nothing waits on it.
    pub(super) fn cancel(&mut self, id: SendId) -> Action<F, W, E> {
        let send = self.records.remove(&id).unwrap();
        Self::settled(send, SendFailure::Cancelled)
    }

    /// Fail sends past their deadline.
    pub(super) fn tick(&mut self, now: Instant) -> Vec<Action<F, W, E>> {
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
