//! Turns tracked sends into their wire confirm frames: an `id -> SendHandle` map that
//! hands out the frames it owes one at a time.
//!
//! Once `request_id` leaves the driver, this map must exist at the protocol layer
//! regardless — cancellation needs it. It is sans-io and shared verbatim by the host
//! server and the NCP firmware, so the two transports emit the same confirm frames for
//! a send and cannot drift.
//!
//! The tracker only ever calls [`SendHandle::status`] (it never awaits) so both of a
//! handle's per-stage waiters stay free for a local caller. The async shell around it
//! is one reactor per transport: it waits on the shared wake, then takes and emits
//! [`SendTracker::next_confirm`] until none is owed. It holds the tracker's lock for one
//! call at a time, so it can encode and send each frame without it.

use alloc::sync::Arc;

use ziggurat_driver::sync::Notify;
use ziggurat_driver::zigbee_stack::{SendHandle, SendId};
use ziggurat_zigbee::flat_map::FlatMap;

use crate::bridge::send_status;
use crate::wire::{
    ApsAckConfirmPayload, BroadcastConfirmPayload, Notification, RequestId, SendConfirmPayload,
};

/// Which confirm frames a tracked send owes, fixed when the send is started.
///
/// Frame names stay truthful: `SendConfirm` = the mesh accepted a unicast; `ApsAckConfirm`
/// = the end-to-end APS ack verdict; `BroadcastConfirm` = the broadcast's retransmissions ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmKind {
    /// `SendConfirm` at `delivered` (which equals `handed_off` for a no-ack unicast).
    UnicastNoAck,
    /// `SendConfirm` at `handed_off`, then `ApsAckConfirm` at `delivered`.
    UnicastApsAck,
    /// `BroadcastConfirm` at `delivered` (the retransmissions ended); groupcast
    /// too. The broadcast `handed_off` checkpoint stays local-only, never a wire
    /// frame.
    Broadcast,
}

struct TrackedSend {
    handle: SendHandle,
    confirm_kind: ConfirmKind,
    emitted_send_confirm: bool,
}

/// The per-transport map of in-flight tracked sends. Entries resolve as their sends do
/// and are removed by [`next_confirm`](Self::next_confirm) once every frame they owe has
/// been handed out.
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
    /// the handle; the send may already be resolved, so the shell must self-notify once
    /// after inserting (the sweep re-checks everything, closing the race).
    pub fn insert(&mut self, id: RequestId, handle: SendHandle, confirm_kind: ConfirmKind) {
        handle.set_completion_wake(self.wake.clone());
        self.entries.insert(
            id,
            TrackedSend {
                handle,
                confirm_kind,
                emitted_send_confirm: false,
            },
        );
    }

    /// The driver's id of the send tracked under `id`, to cancel it with
    /// `ZigbeeStack::cancel_send`. `None` if nothing is tracked under `id`.
    pub fn send_id(&self, id: RequestId) -> Option<SendId> {
        self.entries.get(&id).map(|entry| entry.handle.id())
    }

    /// The next confirm frame owed, oldest request first, or `None` when none is. An
    /// entry is dropped with the last frame it owes. The per-entry `emitted_send_confirm`
    /// flag keeps the two-frame kind exactly-once and ordered.
    pub fn next_confirm(&mut self) -> Option<Notification> {
        let (id, notification, done) = self
            .entries
            .iter_mut()
            .find_map(|(&id, entry)| Self::owed(id, entry).map(|(n, done)| (id, n, done)))?;

        if done {
            self.entries.remove(&id);
        }

        Some(notification)
    }

    /// The frame an entry owes now, and whether it is the last.
    fn owed(id: RequestId, entry: &mut TrackedSend) -> Option<(Notification, bool)> {
        let progress = entry.handle.status();

        match entry.confirm_kind {
            ConfirmKind::UnicastNoAck => {
                let delivered = progress.delivered?;
                let status = send_status(&delivered);
                Some((
                    Notification::SendConfirm(id, SendConfirmPayload { status }),
                    true,
                ))
            }
            ConfirmKind::Broadcast => {
                let delivered = progress.delivered?;
                let status = send_status(&delivered);
                Some((
                    Notification::BroadcastConfirm(id, BroadcastConfirmPayload { status }),
                    true,
                ))
            }
            ConfirmKind::UnicastApsAck if !entry.emitted_send_confirm => {
                let handed_off = progress.handed_off?;
                entry.emitted_send_confirm = true;

                // A failed handoff is terminal: no end-to-end ack will follow, so the
                // `ApsAckConfirm` is never owed
                let status = send_status(&handed_off);
                Some((
                    Notification::SendConfirm(id, SendConfirmPayload { status }),
                    handed_off.is_err(),
                ))
            }
            // Reached only once the handoff succeeded (its failure was retired above), so
            // `delivered` here is the end-to-end ack verdict
            ConfirmKind::UnicastApsAck => {
                let delivered = progress.delivered?;
                let status = send_status(&delivered);
                Some((
                    Notification::ApsAckConfirm(id, ApsAckConfirmPayload { status }),
                    true,
                ))
            }
        }
    }
}
