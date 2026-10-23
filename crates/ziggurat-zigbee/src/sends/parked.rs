//! Unicasts with no route yet, parked on their destination's route discovery.
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

/// A parked unicast: what it is admitted with, and what it carries to the unicasts
/// once its route is known.
#[derive(Debug)]
pub struct ParkedUnicast<F, W> {
    pub frame: F,
    pub priority: TxPriority,
    pub waiter: W,
    pub confirm: Confirm,
    pub destination: Nwk,
    /// When the send fails if still parked.
    pub deadline: Instant,
}

#[derive(Debug)]
pub(super) struct ParkedUnicasts<F, W, E> {
    records: FlatMap<SendId, ParkedUnicast<F, W>>,
    /// Discovery restarts left, per destination with sends parked on it.
    retries: FlatMap<Nwk, u8>,
    _error: PhantomData<fn() -> E>,
}

impl<F, W, E> Default for ParkedUnicasts<F, W, E> {
    fn default() -> Self {
        Self {
            records: FlatMap::new(),
            retries: FlatMap::new(),
            _error: PhantomData,
        }
    }
}

impl<F, W, E: From<SendFailure>> ParkedUnicasts<F, W, E> {
    pub(super) const RECORD_BYTES: usize = core::mem::size_of::<(SendId, ParkedUnicast<F, W>)>();

    pub(super) fn contains(&self, id: SendId) -> bool {
        self.records.contains_key(&id)
    }

    pub(super) fn is_awaiting_route(&self, destination: Nwk) -> bool {
        self.retries.contains_key(&destination)
    }

    /// Park a send. The first send parked on a destination fixes how often its
    /// discovery may be restarted.
    pub(super) fn admit(&mut self, id: SendId, send: ParkedUnicast<F, W>, retries: u8) {
        let destination = send.destination;
        self.records.insert(id, send);

        if !self.retries.contains_key(&destination) {
            self.retries.insert(destination, retries);
        }
    }

    pub(super) fn destinations(&self) -> Vec<Nwk> {
        self.retries.keys().copied().collect()
    }

    /// Take every send parked on `destination`: its route is known.
    pub(super) fn unpark(&mut self, destination: Nwk) -> Vec<(SendId, ParkedUnicast<F, W>)> {
        self.retries.remove(&destination);
        self.take(destination)
    }

    fn take(&mut self, destination: Nwk) -> Vec<(SendId, ParkedUnicast<F, W>)> {
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

    fn settled(send: ParkedUnicast<F, W>, failure: SendFailure) -> Action<F, W, E> {
        Action::Settled {
            waiter: send.waiter,
            result: Err(failure.into()),
            frame: send.frame,
            failed_hop: None,
        }
    }

    /// The discovery toward `destination` lapsed. `true` if a restart is left and a
    /// send still waits on it: the caller restarts the discovery. Otherwise every send
    /// parked on the destination fails.
    pub(super) fn discovery_lapsed(
        &mut self,
        destination: Nwk,
        actions: &mut Vec<Action<F, W, E>>,
    ) -> bool {
        let waiting = self
            .records
            .values()
            .any(|send| send.destination == destination);

        let retries = self.retries.get_mut(&destination).unwrap();
        // A discovery nothing waits on any more is not restarted
        if *retries > 0 && waiting {
            *retries -= 1;
            return true;
        }

        self.retries.remove(&destination);
        for (_, send) in self.take(destination) {
            actions.push(Self::settled(send, SendFailure::RouteDiscoveryTimeout));
        }
        false
    }

    /// The destination stays awaited, so a new send to it does not start a second
    /// discovery; it lapses on its own once nothing is parked on it.
    pub(super) fn cancel(&mut self, id: SendId, actions: &mut Vec<Action<F, W, E>>) {
        let send = self.records.remove(&id).unwrap();
        actions.push(Self::settled(send, SendFailure::Cancelled));
    }

    /// Fail sends past their deadline.
    pub(super) fn tick(&mut self, now: Instant, actions: &mut Vec<Action<F, W, E>>) {
        let lapsed: Vec<SendId> = self
            .records
            .iter()
            .filter(|(_, send)| send.deadline <= now)
            .map(|(id, _)| *id)
            .collect();

        for id in lapsed {
            let send = self.records.remove(&id).unwrap();
            actions.push(Self::settled(send, SendFailure::HandoffTimeout));
        }
    }

    pub(super) fn next_wake(&self) -> Option<Instant> {
        self.records.values().map(|send| send.deadline).min()
    }
}
