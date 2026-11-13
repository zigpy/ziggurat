//! Unicasts with no route yet, held until one is known or their deadline passes.
//!
//! This table knows nothing of route discovery. The routing table decides when one is
//! started, restarted or given up on; a held send only waits for a next hop.

use core::marker::PhantomData;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::constants::Tunables;
use crate::flat_map::FlatMap;

use super::{Action, Confirm, Outbox, SendFailure, SendFrame, SendId, TxPriority};

/// What an unrouted unicast is enqueued with.
#[derive(Debug)]
pub struct UnroutedUnicast<F> {
    pub frame: F,
    pub priority: TxPriority,
    pub confirm: Confirm,
    pub destination: Nwk,
}

/// A held send: what it carries to the unicasts once its route is known.
#[derive(Debug)]
pub(super) struct Record<F> {
    pub(super) frame: F,
    pub(super) priority: TxPriority,
    pub(super) confirm: Confirm,
    pub(super) destination: Nwk,
    /// When the send fails if still unrouted.
    pub(super) deadline: Instant,
}

#[derive(Debug)]
pub(super) struct UnroutedUnicasts<F, E> {
    records: FlatMap<SendId, Record<F>>,
    _error: PhantomData<fn() -> E>,
}

impl<F, E> Default for UnroutedUnicasts<F, E> {
    fn default() -> Self {
        Self {
            records: FlatMap::new(),
            _error: PhantomData,
        }
    }
}

impl<F: SendFrame, E: From<SendFailure>> UnroutedUnicasts<F, E> {
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
        send: UnroutedUnicast<F>,
        now: Instant,
        tunables: &Tunables,
    ) {
        self.records.insert(
            id,
            Record {
                frame: send.frame,
                priority: send.priority,
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
    ) -> impl Iterator<Item = (SendId, Record<F>, T)> {
        self.records
            .extract_map(move |_, send| next_hop(&mut send.frame))
    }

    fn settled(id: SendId, failure: SendFailure) -> Action<F, E> {
        Action::Settled {
            id,
            result: Err(failure.into()),
            failed_hop: None,
        }
    }

    /// Fail every send to `destination`: no route to it will be found.
    pub(super) fn fail(&mut self, destination: Nwk, outbox: &mut Outbox<F, E>) {
        let failed = self
            .records
            .extract_if(|_, send| send.destination == destination);

        for (id, _) in failed {
            outbox.push_back(Self::settled(id, SendFailure::RouteDiscoveryTimeout));
        }
    }

    /// Settle every record as cancelled: the stack is shutting down.
    pub(super) fn abandon(&mut self, outbox: &mut Outbox<F, E>) {
        while let Some((id, _)) = self.records.pop_first() {
            outbox.push_back(Self::settled(id, SendFailure::Cancelled));
        }
    }

    pub(super) fn cancel(&mut self, id: SendId, outbox: &mut Outbox<F, E>) {
        self.records.remove(&id).unwrap();
        outbox.push_back(Self::settled(id, SendFailure::Cancelled));
    }

    /// Fail sends past their deadline.
    pub(super) fn tick(&mut self, now: Instant, outbox: &mut Outbox<F, E>) {
        let lapsed = self.records.extract_if(|_, send| send.deadline <= now);

        for (id, _) in lapsed {
            outbox.push_back(Self::settled(id, SendFailure::HandoffTimeout));
        }
    }

    pub(super) fn next_wake(&self) -> Option<Instant> {
        self.records.values().map(|send| send.deadline).min()
    }
}
