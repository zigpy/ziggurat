//! An awaitable, staged view over a single send.
//!
//! The driver stays reified: a send is a table entry (or a queued frame) whose terminal
//! outcome is *resolved* as a value, not awaited. [`SendSlot`] is the seam where a
//! caller that owns a suspendable context re-enters that model: the producer keeps its
//! `Arc<SendSlot>` and resolves into it, while the [`SendHandle`] hands out linear
//! `.await`s over the two verdicts a send earns — `handed_off` (the mesh accepted the
//! frame) and `delivered` (the end-to-end verdict).
//!
//! A send has two write-once stages. The [`SendSlot::resolve`] write rules keep every
//! resolution site unambiguous and hang-free (see the method).
//!
//! ## Single awaiter per stage
//! Each stage's wake is a single-slot signal (embassy `Signal` / tokio `Notify`): a
//! second concurrent waiter on the *same* stage silently overwrites the first's waker.
//! Each of [`SendHandle::handed_off`] / [`SendHandle::delivered`] may therefore be
//! awaited by at most one task at a time. The wire tracker never awaits — it polls
//! [`SendHandle::status`] — so a wire-tracked send leaves both waiters free for a local
//! caller.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::{Mutex, Notify};

use super::DeliveryError;

/// Which of a send's two verdicts a resolution supplies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackStage {
    /// The mesh accepted the frame (next-hop MAC ack, or the first broadcast copy on
    /// air).
    HandOff,
    /// The send's final verdict. Delivery subsumes acceptance, so it also back-fills a
    /// still-unset `handed_off` with the same result.
    Delivery,
}

/// The two write-once verdicts of a send, plus the tracker's aggregate wake.
#[derive(Debug, Default)]
struct Progress {
    handed_off: Option<Result<(), DeliveryError>>,
    delivered: Option<Result<(), DeliveryError>>,
    /// Also notified on any stage resolution, so a poller (the wire `SendTracker`) can
    /// sweep without occupying either per-stage waiter. Set via
    /// [`SendHandle::set_completion_wake`].
    completion_wake: Option<Arc<Notify>>,
}

/// The reified substrate a send resolves into.
///
/// Two write-once verdicts, a per-stage wake each (so the stages can be awaited
/// independently), and a cancellation flag the reactors honour. The producer and every
/// awaiter/poller share one via `Arc`.
#[derive(Debug)]
pub struct SendSlot {
    progress: Mutex<Progress>,
    handed_off_wake: Notify,
    delivered_wake: Notify,
    cancelled: AtomicBool,
}

/// A non-blocking snapshot of a slot's two verdicts, taken by the wire tracker's sweep.
#[derive(Debug, Clone)]
pub struct SendProgress {
    pub handed_off: Option<Result<(), DeliveryError>>,
    pub delivered: Option<Result<(), DeliveryError>>,
}

impl SendSlot {
    fn new() -> Self {
        Self {
            progress: Mutex::new(Progress::default()),
            handed_off_wake: Notify::new(),
            delivered_wake: Notify::new(),
            cancelled: AtomicBool::new(false),
        }
    }

    /// Whether the send has been cancelled. Checked by each reactor before it acts on the
    /// entry holding this slot.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Resolve one of the send's stages, applying the write rules:
    ///
    /// 1. **First write wins** — both fields are write-once; a later write is ignored.
    /// 2. **`Ok` writes its own stage** — a `HandOff` `Ok` leaves `delivered` unset.
    /// 3. **`Err` at either stage writes both** — a failed handoff is a failed delivery.
    /// 4. **A `Delivery` write back-fills `handed_off`** if unset, with the same result,
    ///    so `handed_off().await` can never outlive the send.
    ///
    /// Rules 1, 3 and 4 collapse to: any resolution establishes `handed_off` if still
    /// unset; `delivered` is written by a `Delivery` resolution or by any failure.
    pub(crate) fn resolve(&self, stage: TrackStage, result: Result<(), DeliveryError>) {
        let (woke_handed_off, woke_delivered, completion) = {
            let mut progress = self.progress.lock();

            let woke_handed_off = progress.handed_off.is_none();
            if woke_handed_off {
                progress.handed_off = Some(result.clone());
            }

            let woke_delivered = progress.delivered.is_none()
                && (matches!(stage, TrackStage::Delivery) || result.is_err());
            if woke_delivered {
                progress.delivered = Some(result);
            }

            (
                woke_handed_off,
                woke_delivered,
                progress.completion_wake.clone(),
            )
        };

        if woke_handed_off {
            self.handed_off_wake.notify_one();
        }
        if woke_delivered {
            self.delivered_wake.notify_one();
        }
        if (woke_handed_off || woke_delivered)
            && let Some(completion) = completion
        {
            completion.notify_one();
        }
    }
}

/// An awaitable, detachable view over one send.
///
/// Cloning it is deliberately not offered: each stage has a single-waiter wake (see the
/// module docs), so a send is awaited by one task. Dropping the handle detaches — the
/// producer keeps its own `Arc` and resolves harmlessly into the slot; nothing is
/// cancelled (fire-and-forget is "drop the handle").
#[derive(Debug)]
pub struct SendHandle {
    slot: Arc<SendSlot>,
}

impl SendHandle {
    /// Create a fresh slot and a handle over it. The caller passes the returned
    /// `Arc<SendSlot>` into the send's [`TxOutcome::Track`](super::TxOutcome::Track) so
    /// the producer and this handle share it.
    pub(crate) fn new() -> (Self, Arc<SendSlot>) {
        let slot = Arc::new(SendSlot::new());
        (Self { slot: slot.clone() }, slot)
    }

    /// Await the mesh accepting the (first) frame: the next-hop MAC ack of a unicast, or
    /// the first broadcast copy reaching the air. Resolves early with the terminal error
    /// if the send fails before it is ever accepted.
    pub async fn handed_off(&self) -> Result<(), DeliveryError> {
        loop {
            // Arm the wake before checking, so a resolution between the check and the
            // await is not lost. Bind the snapshot to a local so the guard drops before
            // the await.
            let wait = self.slot.handed_off_wake.notified();
            let resolved = self.slot.progress.lock().handed_off.clone();
            if let Some(result) = resolved {
                return result;
            }
            wait.await;
        }
    }

    /// Await the send's final verdict: the end-to-end APS ack for an ack unicast, the
    /// next-hop acceptance for a no-ack unicast, or the passive-ack quorum for a
    /// broadcast/groupcast.
    pub async fn delivered(&self) -> Result<(), DeliveryError> {
        loop {
            let wait = self.slot.delivered_wake.notified();
            let resolved = self.slot.progress.lock().delivered.clone();
            if let Some(result) = resolved {
                return result;
            }
            wait.await;
        }
    }

    /// A non-blocking snapshot of both stages, what the wire tracker sweeps with. Never
    /// occupies either per-stage waiter.
    pub fn status(&self) -> SendProgress {
        let progress = self.slot.progress.lock();
        SendProgress {
            handed_off: progress.handed_off.clone(),
            delivered: progress.delivered.clone(),
        }
    }

    /// Request cancellation. Sets the flag every in-flight reactor checks before acting;
    /// the reactor that next touches this send drops its entry and resolves both stages
    /// `Err(Cancelled)`. Cleanup is lazy (the next reactor pass) unless the caller also
    /// nudges the reactor wakes.
    pub fn cancel(&self) {
        self.slot.cancelled.store(true, Ordering::Relaxed);
    }

    /// Register the tracker's aggregate wake, notified on any stage resolution in
    /// addition to the per-stage wakes. Set once, by the tracker, after the send returns;
    /// the slot may already be resolved, so the tracker self-notifies once after
    /// registration and re-checks.
    pub fn set_completion_wake(&self, wake: Arc<Notify>) {
        self.slot.progress.lock().completion_wake = Some(wake);
    }
}
