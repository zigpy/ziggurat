//! Unicasts with no route yet, parked on their destination's route discovery.
//!
//! Discovery runs once per destination and the whole bucket moves on together, so ten
//! frames to one device ride a single discovery.

use alloc::vec::Vec;
use core::marker::PhantomData;
use core::time::Duration;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::flat_map::FlatMap;

use super::{Action, Confirm, SendFailure, SendId, TxPriority};

/// A parked unicast: what it is admitted with, and what it carries to the unicasts
/// once its route resolves.
#[derive(Debug)]
pub struct ParkedSend<F, W> {
    pub frame: F,
    pub priority: TxPriority,
    pub waiter: W,
    pub confirm: Confirm,
    pub destination: Nwk,
    /// When the send fails if still parked.
    pub deadline: Instant,
}

/// One destination's route discovery, shared by every send parked on it.
#[derive(Debug)]
struct Discovery {
    attempts_remaining: u8,
    discovery_time: Duration,
    deadline: Instant,
}

#[derive(Debug)]
pub(super) struct Parked<F, W, E> {
    records: FlatMap<SendId, ParkedSend<F, W>>,
    discoveries: FlatMap<Nwk, Discovery>,
    _error: PhantomData<fn() -> E>,
}

impl<F, W, E> Default for Parked<F, W, E> {
    fn default() -> Self {
        Self {
            records: FlatMap::new(),
            discoveries: FlatMap::new(),
            _error: PhantomData,
        }
    }
}

impl<F, W, E: From<SendFailure>> Parked<F, W, E> {
    pub(super) const RECORD_BYTES: usize = core::mem::size_of::<(SendId, ParkedSend<F, W>)>();

    pub(super) fn contains(&self, id: SendId) -> bool {
        self.records.contains_key(&id)
    }

    /// Park a send, starting its destination's discovery if none is in flight.
    pub(super) fn admit(
        &mut self,
        id: SendId,
        send: ParkedSend<F, W>,
        now: Instant,
        discovery_time: Duration,
        attempts: u8,
        actions: &mut Vec<Action<F, W, E>>,
    ) {
        let destination = send.destination;

        self.records.insert(id, send);

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

    pub(super) fn destinations(&self) -> Vec<Nwk> {
        self.discoveries.keys().copied().collect()
    }

    /// Take every send parked on `destination`, ending its discovery.
    pub(super) fn resolved(&mut self, destination: Nwk) -> Vec<(SendId, ParkedSend<F, W>)> {
        if self.discoveries.remove(&destination).is_none() {
            return Vec::new();
        }

        self.take(destination)
    }

    fn take(&mut self, destination: Nwk) -> Vec<(SendId, ParkedSend<F, W>)> {
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

    fn settled(send: ParkedSend<F, W>, failure: SendFailure) -> Action<F, W, E> {
        Action::Settled {
            waiter: send.waiter,
            result: Err(failure.into()),
            frame: send.frame,
            failed_hop: None,
        }
    }

    /// The discovery stays, so a new send to the destination does not start a second
    /// one; it lapses on its own once nothing is parked on it.
    pub(super) fn cancel(&mut self, id: SendId, actions: &mut Vec<Action<F, W, E>>) {
        let send = self.records.remove(&id).unwrap();
        actions.push(Self::settled(send, SendFailure::Cancelled));
    }

    /// Fail sends past their deadline, and restart or fail lapsed discoveries.
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

        let lapsed: Vec<Nwk> = self
            .discoveries
            .iter()
            .filter(|(_, discovery)| discovery.deadline <= now)
            .map(|(destination, _)| *destination)
            .collect();
        for destination in lapsed {
            let waiting = self
                .records
                .values()
                .any(|send| send.destination == destination);

            let discovery = self.discoveries.get_mut(&destination).unwrap();
            discovery.attempts_remaining = discovery.attempts_remaining.saturating_sub(1);

            // A discovery nothing waits on any more is not retried
            if discovery.attempts_remaining > 0 && waiting {
                discovery.deadline = now + discovery.discovery_time;
                actions.push(Action::StartDiscovery(destination));
                continue;
            }

            self.discoveries.remove(&destination);
            actions.push(Action::DiscoveryFailed(destination));
            for (_, send) in self.take(destination) {
                actions.push(Self::settled(send, SendFailure::RouteDiscoveryTimeout));
            }
        }
    }

    pub(super) fn next_wake(&self) -> Option<Instant> {
        let sends = self.records.values().map(|send| send.deadline);
        let discoveries = self
            .discoveries
            .values()
            .map(|discovery| discovery.deadline);

        sends.chain(discoveries).min()
    }
}
