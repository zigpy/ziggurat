//! Unicasts with no route yet, held until one is known or their deadline passes.
//!
//! This table knows nothing of route discovery. The routing table decides when one is
//! started, restarted or given up on; a held send only waits for a next hop.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::constants::Tunables;
use crate::flat_map::FlatMap;

use super::{Action, Confirm, Outbox, SendFailure, SendFrame, SendId, TxPriority};

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

#[derive(Debug)]
pub(super) struct UnroutedUnicasts<F, W, E> {
    records: FlatMap<SendId, Record<F, W>>,
    _error: PhantomData<fn() -> E>,
}

impl<F, W, E> Default for UnroutedUnicasts<F, W, E> {
    fn default() -> Self {
        Self {
            records: FlatMap::new(),
            _error: PhantomData,
        }
    }
}

impl<F: SendFrame, W, E: From<SendFailure>> UnroutedUnicasts<F, W, E> {
    pub(super) fn contains(&self, id: SendId) -> bool {
        self.records.contains_key(&id)
    }

    /// Whether any send waits for a route to `destination`.
    pub(super) fn has_sends_to(&self, destination: Nwk) -> bool {
        self.records
            .values()
            .any(|send| send.destination == destination)
    }

    /// Hold a send. It fails if still unrouted within the handoff timeout.
    pub(super) fn enqueue(
        &mut self,
        id: SendId,
        send: UnroutedUnicast<F, W>,
        now: Instant,
        tunables: &Tunables,
    ) {
        self.records.insert(
            id,
            Record {
                frame: send.frame,
                priority: send.priority,
                waiter: send.waiter,
                confirm: send.confirm,
                destination: send.destination,
                deadline: now + tunables.handoff_timeout(),
            },
        );
    }

    /// Take every held send `next_hop` finds a next hop for, oldest first, with that
    /// next hop. `next_hop` may rewrite the frame, for a source route.
    pub(super) fn take_routed<T>(
        &mut self,
        mut next_hop: impl FnMut(&mut F) -> Option<T>,
    ) -> impl Iterator<Item = (SendId, Record<F, W>, T)> {
        self.records
            .extract_map(move |_, send| next_hop(&mut send.frame))
    }

    fn settled(send: Record<F, W>, failure: SendFailure) -> Action<F, W, E> {
        Action::Settled {
            waiter: send.waiter,
            result: Err(failure.into()),
            failed_hop: None,
        }
    }

    /// Fail every send to `destination`: no route to it will be found.
    pub(super) fn fail(&mut self, destination: Nwk, outbox: &mut Outbox<F, W, E>) {
        let failed = self
            .records
            .extract_if(|_, send| send.destination == destination);

        for (_, send) in failed {
            outbox.push_back(Self::settled(send, SendFailure::RouteDiscoveryTimeout));
        }
    }

    /// Drop every record and return its waiter: the stack is shutting down.
    pub(super) fn abandon(&mut self) -> Vec<W> {
        let mut waiters = Vec::new();
        while let Some((_, send)) = self.records.pop_first() {
            waiters.push(send.waiter);
        }
        waiters
    }

    pub(super) fn cancel(&mut self, id: SendId, outbox: &mut Outbox<F, W, E>) {
        let send = self.records.remove(&id).unwrap();
        outbox.push_back(Self::settled(send, SendFailure::Cancelled));
    }

    /// Fail sends past their deadline.
    pub(super) fn tick(&mut self, now: Instant, outbox: &mut Outbox<F, W, E>) {
        let lapsed = self.records.extract_if(|_, send| send.deadline <= now);

        for (_, send) in lapsed {
            outbox.push_back(Self::settled(send, SendFailure::HandoffTimeout));
        }
    }

    pub(super) fn next_wake(&self) -> Option<Instant> {
        self.records.values().map(|send| send.deadline).min()
    }
}
