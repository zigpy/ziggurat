//! An awaitable, staged view over a single send.
//!
//! An outgoing request goes through two send stages: hand off (the frame was actually
//! sent on air, either to a next hop or as an initial broadcast) and delivery
//! (dependent on the request: APS ACK, broadcast relay quorum, etc.). A send point can
//! decide what stage to block on (if any).

use alloc::sync::Arc;

use crate::sync::{Mutex, Notify};

use super::{DeliveryError, SendId};

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
    /// sweep without occupying the handle's waiter. Set via
    /// [`SendHandle::set_completion_wake`].
    completion_wake: Option<Arc<Notify>>,
}

/// The slot a send's verdicts are written into: the send table's waiter.
///
/// Two write-once verdicts and one wake: the handle's awaiter re-checks the verdict it
/// wants after every wake. The send table's record and every awaiter/poller share one
/// via `Arc`. The table writes each verdict exactly once; the write-once rule here only
/// back-fills `handed_off` from a delivery verdict.
#[derive(Debug, Default)]
pub struct SendSlot {
    progress: Mutex<Progress>,
    wake: Notify,
}

/// A non-blocking snapshot of a slot's two verdicts, taken by the wire tracker's sweep.
#[derive(Debug, Clone)]
pub struct SendProgress {
    pub handed_off: Option<Result<(), DeliveryError>>,
    pub delivered: Option<Result<(), DeliveryError>>,
}

impl SendSlot {
    /// Resolve one of the send's stages, applying the write rules:
    ///
    /// 1. **First write wins** — both fields are write-once; a later write is ignored.
    /// 2. **`Ok` writes its own stage** — a `HandOff` `Ok` leaves `delivered` unset.
    /// 3. **`Err` at either stage writes both** — a failed handoff is a failed delivery.
    /// 4. **A `Delivery` write back-fills `handed_off`** if unset, with the same result,
    ///    so `handed_off().await` can never outlive the send.
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

        if woke_handed_off || woke_delivered {
            self.wake.notify_one();
            if let Some(completion) = completion {
                completion.notify_one();
            }
        }
    }
}

/// An awaitable, detachable view over one send.
///
/// Cloning it is deliberately not offered: the slot has a single-waiter wake, so a send
/// is awaited by one task. Dropping the handle detaches — the send table keeps its own
/// `Arc` and resolves harmlessly into the slot; nothing is cancelled (fire-and-forget
/// is "drop the handle").
#[derive(Debug)]
pub struct SendHandle {
    slot: Arc<SendSlot>,
    /// The send's id in the table, for cancellation.
    id: SendId,
}

impl SendHandle {
    /// A handle over the slot the send table holds as the waiter of `id`.
    pub(crate) const fn new(id: SendId, slot: Arc<SendSlot>) -> Self {
        Self { slot, id }
    }

    /// The send's id, to cancel it through `ZigbeeStack::cancel_send`.
    pub const fn id(&self) -> SendId {
        self.id
    }

    /// Await the mesh accepting the (first) frame: the next-hop MAC ack of a unicast, or
    /// the first broadcast copy reaching the air. Resolves early with the terminal error
    /// if the send fails before it is ever accepted.
    pub async fn handed_off(&self) -> Result<(), DeliveryError> {
        loop {
            // Arm the wake before checking, so a resolution between the check and the
            // await is not lost. Bind the snapshot to a local so the guard drops before
            // the await.
            let wait = self.slot.wake.notified();
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
            let wait = self.slot.wake.notified();
            let resolved = self.slot.progress.lock().delivered.clone();
            if let Some(result) = resolved {
                return result;
            }
            wait.await;
        }
    }

    /// A non-blocking snapshot of both stages, what the wire tracker sweeps with. Never
    /// occupies the waiter.
    pub fn status(&self) -> SendProgress {
        let progress = self.slot.progress.lock();
        SendProgress {
            handed_off: progress.handed_off.clone(),
            delivered: progress.delivered.clone(),
        }
    }

    /// Register the tracker's aggregate wake, notified on any stage resolution in
    /// addition to the per-stage wakes. Set once, by the tracker, after the send returns;
    /// the slot may already be resolved, so the tracker self-notifies once after
    /// registration and re-checks.
    pub fn set_completion_wake(&self, wake: Arc<Notify>) {
        self.slot.progress.lock().completion_wake = Some(wake);
    }
}
