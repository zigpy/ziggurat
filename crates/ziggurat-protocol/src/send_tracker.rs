//! The wire projection of tracked sends: an `id -> SendHandle` map plus a sweep.
//!
//! Once `request_id` leaves the driver, this map must exist at the protocol layer
//! regardless — cancellation needs it. It is sans-io and shared verbatim by the host
//! server and the NCP firmware, so the two transports project a send onto the wire
//! identically and cannot drift.
//!
//! The tracker only ever calls [`SendHandle::status`] — it never awaits — so both of a
//! handle's per-stage waiters stay free for a local caller. The async shell around it is
//! one wake-and-sweep reactor per transport: it waits on the shared wake, sweeps the
//! whole table, and emits the frames the sweep returns.

use alloc::sync::Arc;
use alloc::vec::Vec;

use ziggurat_driver::sync::Notify;
use ziggurat_driver::zigbee_stack::SendHandle;
use ziggurat_zigbee::flat_map::FlatMap;

use crate::bridge::send_status;
use crate::wire::{ApsAckConfirmPayload, Notification, RequestId, SendConfirmPayload};

/// Which confirm frames a tracked send owes, stated once per send from its kind. Frame
/// names stay truthful: `SendConfirm` = the mesh accepted a unicast; `ApsAckConfirm` =
/// the end-to-end APS ack verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireProjection {
    /// `SendConfirm` at `delivered` (which equals `handed_off` for a no-ack unicast).
    UnicastNoAck,
    /// `SendConfirm` at `handed_off`, then `ApsAckConfirm` at `delivered`.
    UnicastApsAck,
    /// `SendConfirm` at `delivered` (the passive-ack quorum verdict); groupcast too. The
    /// broadcast `handed_off` checkpoint stays local-only and is not projected.
    Broadcast,
}

struct TrackedSend {
    handle: SendHandle,
    projection: WireProjection,
    /// Whether the first frame a two-frame projection owes has been emitted.
    emitted_send_confirm: bool,
}

/// The per-transport map of in-flight tracked sends. Entries resolve as their slots do
/// and are removed by [`sweep`](Self::sweep) once every frame they owe has been emitted.
pub struct SendTracker {
    entries: FlatMap<RequestId, TrackedSend>,
    wake: Arc<Notify>,
}

impl SendTracker {
    /// Create a tracker whose entries share `wake`: every handle inserted is given it as
    /// its completion wake, so any stage resolution nudges the shell to sweep.
    pub const fn new(wake: Arc<Notify>) -> Self {
        Self {
            entries: FlatMap::new(),
            wake,
        }
    }

    /// The shared wake handed to every tracked send. A shell notifies it after an insert
    /// to close the registration race, and its reactor awaits it to drive the sweep.
    pub fn wake(&self) -> Arc<Notify> {
        self.wake.clone()
    }

    /// Begin tracking a send under its wire `request_id`. Registers the shared wake on
    /// the handle; the slot may already be resolved, so the shell must self-notify once
    /// after inserting (the sweep re-checks everything, closing the race).
    pub fn insert(&mut self, id: RequestId, handle: SendHandle, projection: WireProjection) {
        handle.set_completion_wake(self.wake.clone());
        self.entries.insert(
            id,
            TrackedSend {
                handle,
                projection,
                emitted_send_confirm: false,
            },
        );
    }

    /// Cancel the send tracked under `id`. Returns whether an entry was present and still
    /// unresolved (its terminal frame not yet owed). The caller must also nudge the
    /// driver's reactors so the cancellation is acted on promptly.
    pub fn cancel(&mut self, id: RequestId) -> bool {
        self.entries.get(&id).is_some_and(|entry| {
            let unresolved = entry.handle.status().delivered.is_none();
            entry.handle.cancel();
            unresolved
        })
    }

    /// One reactor pass: emit every confirm frame now owed and drop entries that have
    /// emitted their last. Per-entry `emitted_send_confirm` flags keep two-frame
    /// projections exactly-once and ordered even though a coalesced wake sweeps the whole
    /// table.
    pub fn sweep(&mut self) -> Vec<Notification> {
        let mut out = Vec::new();
        let mut done: Vec<RequestId> = Vec::new();

        for (id, entry) in self.entries.iter_mut() {
            let progress = entry.handle.status();

            match entry.projection {
                WireProjection::UnicastNoAck | WireProjection::Broadcast => {
                    if let Some(delivered) = &progress.delivered {
                        out.push(Notification::SendConfirm(
                            *id,
                            SendConfirmPayload {
                                status: send_status(delivered),
                            },
                        ));
                        done.push(*id);
                    }
                }
                WireProjection::UnicastApsAck => {
                    if !entry.emitted_send_confirm {
                        if let Some(handed_off) = &progress.handed_off {
                            out.push(Notification::SendConfirm(
                                *id,
                                SendConfirmPayload {
                                    status: send_status(handed_off),
                                },
                            ));
                            entry.emitted_send_confirm = true;

                            // A failed handoff is terminal: no end-to-end ack will follow,
                            // so the `ApsAckConfirm` is never owed.
                            if handed_off.is_err() {
                                done.push(*id);
                                continue;
                            }
                        }
                    }

                    // Reached only once the handoff succeeded (its failure was retired
                    // above), so `delivered` here is the end-to-end ack verdict.
                    if entry.emitted_send_confirm {
                        if let Some(delivered) = &progress.delivered {
                            out.push(Notification::ApsAckConfirm(
                                *id,
                                ApsAckConfirmPayload {
                                    status: send_status(delivered),
                                },
                            ));
                            done.push(*id);
                        }
                    }
                }
            }
        }

        for id in done {
            self.entries.remove(&id);
        }

        out
    }
}
