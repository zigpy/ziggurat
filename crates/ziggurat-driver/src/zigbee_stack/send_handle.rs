//! An awaitable, staged view over a single send.
//!
//! An outgoing request goes through two send stages: hand off (the frame was actually
//! sent on air, either to a next hop or as an initial broadcast) and delivery
//! (dependent on the request: APS ACK, end of broadcast retransmissions, etc.). A send point can
//! decide what stage to block on (if any).
//!
//! The send table reports verdicts by send id. Only a send someone holds a handle to
//! has a [`Watch`] that keeps its verdicts; the verdicts of every other send are
//! dropped as they are reported.

use alloc::sync::Arc;
use core::future::poll_fn;
use core::task::{Poll, Waker};

use ziggurat_zigbee::flat_map::FlatMap;

use crate::sync::{Mutex, Notify};

use super::{DeliveryError, SendId};

/// What is known about a send someone holds a handle to: its two verdicts, each written
/// once, and who to wake when they are.
#[derive(Debug, Default)]
struct Watch {
    handed_off: Option<Result<(), DeliveryError>>,
    delivered: Option<Result<(), DeliveryError>>,
    /// Each stage has its own waker, so the two stages can be awaited at once (`join!`)
    /// without one stage's awaiter taking the other's wake.
    handed_off_waker: Option<Waker>,
    delivered_waker: Option<Waker>,
    /// Also notified on any stage resolution, so a poller (the wire `SendTracker`) can
    /// sweep without occupying the handle's wakers. Set via
    /// [`SendHandle::set_completion_wake`].
    completion_wake: Option<Arc<Notify>>,
}

/// The watches of every send someone holds a handle to, by send id.
#[derive(Debug, Default)]
pub struct SendWatches {
    watches: Mutex<FlatMap<SendId, Watch>>,
}

impl SendWatches {
    /// Run `f` on the watch of `id` under the lock. `None` if nobody watches the send.
    fn with_watch<T>(&self, id: SendId, f: impl FnOnce(&mut Watch) -> T) -> Option<T> {
        self.watches.lock().get_mut(&id).map(f)
    }

    /// The mesh accepted the frame: the next-hop MAC ack, or the first broadcast copy
    /// on air.
    pub(crate) fn handed_off(&self, id: SendId) {
        let wakes = self.with_watch(id, |watch| {
            if watch.handed_off.is_some() {
                return (None, None);
            }
            watch.handed_off = Some(Ok(()));
            (watch.handed_off_waker.take(), watch.completion_wake.clone())
        });
        let Some((waker, completion)) = wakes else {
            return;
        };

        if let Some(waker) = waker {
            waker.wake();
        }
        if let Some(completion) = completion {
            completion.notify_one();
        }
    }

    /// The send's final verdict. It also back-fills a still-unset `handed_off` with the
    /// same result, so `handed_off().await` can never outlive the send.
    pub(crate) fn settled(&self, id: SendId, result: Result<(), DeliveryError>) {
        let wakes = self.with_watch(id, |watch| {
            if watch.handed_off.is_none() {
                watch.handed_off = Some(result.clone());
            }
            watch.delivered = Some(result);
            (
                watch.handed_off_waker.take(),
                watch.delivered_waker.take(),
                watch.completion_wake.clone(),
            )
        });
        let Some((handed_off_waker, delivered_waker, completion)) = wakes else {
            return;
        };

        for waker in [handed_off_waker, delivered_waker].into_iter().flatten() {
            waker.wake();
        }
        if let Some(completion) = completion {
            completion.notify_one();
        }
    }
}

/// A non-blocking snapshot of a send's two verdicts, taken by the wire tracker's sweep.
#[derive(Debug, Clone)]
pub struct SendProgress {
    pub handed_off: Option<Result<(), DeliveryError>>,
    pub delivered: Option<Result<(), DeliveryError>>,
}

/// An awaitable, detachable view over one send.
///
/// Cloning it is deliberately not offered: each stage has a single waker, so a stage is
/// awaited by one task. Dropping the handle detaches: its watch is removed and the
/// send's verdicts are dropped as they are reported. Nothing is cancelled
/// (fire-and-forget is "drop the handle").
#[derive(Debug)]
pub struct SendHandle {
    watches: Arc<SendWatches>,
    /// The send's id in the table, for cancellation.
    id: SendId,
}

impl SendHandle {
    /// A handle over the send `id`. Created under the core lock with the send, before
    /// the table can report on it.
    pub(crate) fn new(id: SendId, watches: &Arc<SendWatches>) -> Self {
        watches.watches.lock().insert(id, Watch::default());

        Self {
            watches: watches.clone(),
            id,
        }
    }

    /// The send's id, to cancel it through `ZigbeeStack::cancel_send`.
    pub const fn id(&self) -> SendId {
        self.id
    }

    /// Await the mesh accepting the (first) frame: the next-hop MAC ack of a unicast, or
    /// the first broadcast copy reaching the air. Resolves early with the terminal error
    /// if the send fails before it is ever accepted.
    pub async fn handed_off(&self) -> Result<(), DeliveryError> {
        poll_fn(|cx| {
            self.watches
                .with_watch(self.id, |watch| match &watch.handed_off {
                    Some(result) => Poll::Ready(result.clone()),
                    None => {
                        watch.handed_off_waker = Some(cx.waker().clone());
                        Poll::Pending
                    }
                })
                .unwrap()
        })
        .await
    }

    /// Await the send's final verdict: the end-to-end APS ack for an ack unicast, the
    /// next-hop acceptance for a no-ack unicast, or the end of retransmissions for a
    /// broadcast/groupcast.
    pub async fn delivered(&self) -> Result<(), DeliveryError> {
        poll_fn(|cx| {
            self.watches
                .with_watch(self.id, |watch| match &watch.delivered {
                    Some(result) => Poll::Ready(result.clone()),
                    None => {
                        watch.delivered_waker = Some(cx.waker().clone());
                        Poll::Pending
                    }
                })
                .unwrap()
        })
        .await
    }

    /// A non-blocking snapshot of both stages, what the wire tracker sweeps with. Never
    /// occupies the wakers.
    pub fn status(&self) -> SendProgress {
        self.watches
            .with_watch(self.id, |watch| SendProgress {
                handed_off: watch.handed_off.clone(),
                delivered: watch.delivered.clone(),
            })
            .unwrap()
    }

    /// Register the tracker's aggregate wake, notified on any stage resolution in
    /// addition to the per-stage wakers. Set once, by the tracker, after the send
    /// returns; the send may already be resolved, so the tracker self-notifies once
    /// after registration and re-checks.
    pub fn set_completion_wake(&self, wake: Arc<Notify>) {
        self.watches
            .with_watch(self.id, |watch| watch.completion_wake = Some(wake))
            .unwrap();
    }
}

impl Drop for SendHandle {
    fn drop(&mut self) {
        self.watches.watches.lock().remove(&self.id);
    }
}
