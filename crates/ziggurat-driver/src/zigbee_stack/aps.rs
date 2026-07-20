use crate::runtime::Runtime;
use ziggurat_ieee_802154::FrameBytes;
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_zigbee::aps::frame::{
    ApsAckFrame, ApsAckFrameControl, ApsDataFrame, ApsDeliveryMode, ApsFrameControl, ApsFrameType,
    EncryptedApsAckFrame, EncryptedApsDataFrame,
};
use ziggurat_zigbee::nwk::frame::{BROADCAST_RX_ON_WHEN_IDLE, NwkFrame, NwkRouteDiscovery};

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp;
use core::time::Duration;
use ziggurat_phy::RadioPhy;
use ziggurat_zigbee::Instant as CoreInstant;
use ziggurat_zigbee::flat_map::Entry;

use super::{
    ApsAck, ApsAckData, DeliveryError, EnqueueError, NwkSecurityMode, PendingApsAck,
    RouteDirective, SendHandle, SendMode, SendSlot, TrackStage, TxOutcome, TxPolicy, TxPriority,
    ZigbeeStack,
};
use crate::frame_token::TrafficClass;

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    /// The EUI64 an inbound secured APS frame was encrypted by: the auxiliary header's
    /// extended source when present, otherwise resolved from the NWK frame (spec
    /// 4.4.1.2 step 2).
    fn aps_frame_source(
        &self,
        nwk_frame: &NwkFrame,
        extended_source: Option<Eui64>,
    ) -> Option<Eui64> {
        if let Some(eui64) = extended_source.or(nwk_frame.nwk_header.source_ieee) {
            return Some(eui64);
        }

        let nwk_source = nwk_frame.nwk_header.source;
        let eui64 = self.core().nib.address_map.eui64_for(nwk_source);

        if eui64.is_none() {
            tracing::warn!("Cannot resolve the EUI64 of {nwk_source:?} to decrypt an APS frame");
        }

        eui64
    }

    /// Decrypt an inbound APS-secured data frame, returning it along with the
    /// originator's EUI64.
    pub(super) fn decrypt_aps_data_frame(
        &self,
        nwk_frame: &NwkFrame,
        frame: &EncryptedApsDataFrame,
    ) -> Option<(ApsDataFrame, Eui64)> {
        let source = self.aps_frame_source(nwk_frame, frame.aux_header.extended_source)?;

        let mut core = self.core();
        let network_key = core.nib.nwk_security.network_key();

        core.aib
            .aps_security
            .decrypt_data(source, frame, &network_key)
            .map(|data| (data, source))
    }

    /// Decrypt an inbound APS-secured acknowledgement.
    pub(super) fn decrypt_aps_ack_frame(
        &self,
        nwk_frame: &NwkFrame,
        frame: &EncryptedApsAckFrame,
    ) -> Option<ApsAckFrame> {
        let source = self.aps_frame_source(nwk_frame, frame.aux_header.extended_source)?;

        let mut core = self.core();
        let network_key = core.nib.nwk_security.network_key();

        core.aib
            .aps_security
            .decrypt_ack(source, frame, &network_key)
    }

    /// Resolve an inbound APS ACK against the pending transmissions waiting for it: wake an
    /// awaiting caller, or push the delivery outcome for a fire-and-forget send.
    pub(super) fn handle_aps_ack(&self, nwk_frame: &NwkFrame, ack: &ApsAckFrame) {
        let ack_data = ApsAckData::from_aps_ack(nwk_frame.nwk_header.source, ack);
        tracing::trace!("Received APS ack: {ack_data:?}");

        let pending = self.state.pending_aps_acks.lock().remove(&ack_data);
        if let Some(PendingApsAck { slot, .. }) = pending {
            slot.resolve(TrackStage::Delivery, Ok(()));
        }
    }

    /// Spec 2.2.8.4.2: record an inbound APS data frame and report whether it duplicates
    /// one seen within the rejection window. Duplicates are still ACKed so the sender
    /// stops retransmitting, but must not reach the application twice. Expired entries
    /// are swept on each call.
    pub(super) fn is_duplicate_aps_frame(&self, source: Nwk, counter: u8) -> bool {
        let now = self.core_now();
        let timeout = self.tunables.aps_duplicate_rejection_timeout();

        let mut table = self.state.aps_duplicates.lock();
        table.retain(|_, seen| now.saturating_duration_since(*seen) < timeout);

        match table.entry((source, counter)) {
            Entry::Occupied(mut slot) => {
                slot.insert(now);
                true
            }
            Entry::Vacant(slot) => {
                slot.insert(now);
                false
            }
        }
    }

    pub(super) fn handle_aps_ack_request(
        &self,
        aps_frame: &ApsDataFrame,
        nwk_frame: &NwkFrame,
        source_eui64: Option<Eui64>,
    ) {
        tracing::debug!("Sending back an APS ACK");

        // An ACK mirrors the security of the frame it acknowledges
        let secured = aps_frame.frame_control.security;

        let ack_frame = ApsAckFrame {
            frame_control: ApsAckFrameControl {
                frame_type: ApsFrameType::Ack,
                delivery_mode: ApsDeliveryMode::Unicast,
                ack_format: false,
                security: secured,
                ack_request: false,
                extended_header: false,
            },
            destination_endpoint: Some(aps_frame.source_endpoint),
            cluster_id: Some(aps_frame.cluster_id),
            profile_id: Some(aps_frame.profile_id),
            source_endpoint: aps_frame.destination_endpoint,
            counter: aps_frame.counter,
        };

        let payload = if secured {
            let Some(source_eui64) = source_eui64 else {
                tracing::warn!("Cannot send a secured APS ACK without the originator's EUI64");
                return;
            };

            let encrypted = self
                .core()
                .aib
                .aps_security
                .encrypt_ack(source_eui64, &ack_frame);

            let Some(encrypted) = encrypted else {
                tracing::warn!("No usable link key to secure an APS ACK for {source_eui64:?}");
                return;
            };

            self.maybe_notify_aps_frame_counter();
            encrypted.to_bytes()
        } else {
            ack_frame.to_bytes()
        };

        // Send our ACK back to the sender
        let aps_ack_frame = self
            .nwk_data_frame(nwk_frame.nwk_header.source, payload)
            .with_discover_route(NwkRouteDiscovery::Enable);

        if let Err(err) = self.originate_unicast(
            aps_ack_frame,
            NwkSecurityMode::NetworkKey,
            SendMode::Route(RouteDirective::StackDecides),
            TxPolicy::STACK_CRITICAL,
            TxOutcome::Discard,
        ) {
            tracing::warn!("Failed to send APS ack: {err}");
        }
    }

    /// Wrap a fully-built APS data frame in its NWK data frame: encrypt the ASDU with the
    /// pairwise link key when `aps_security` is set (unicast only), otherwise send it in
    /// the clear, then apply the route-discovery flag and radius. The mechanical tail
    /// shared by the send entry points below; the frame itself, and its per-mode fields,
    /// stays constructed inline at each origination site.
    pub(super) fn wrap_aps_frame(
        &self,
        aps_frame: &ApsDataFrame,
        nwk_destination: Nwk,
        radius: u8,
        aps_security: Option<Eui64>,
    ) -> Result<NwkFrame, EnqueueError> {
        tracing::trace!("Prepared APS frame: {aps_frame:?}");

        let aps_payload = if let Some(destination_eui64) = aps_security {
            let encrypted = self
                .core()
                .aib
                .aps_security
                .encrypt_data(destination_eui64, aps_frame);
            match encrypted {
                Some(encrypted) => {
                    self.maybe_notify_aps_frame_counter();
                    encrypted.to_bytes()
                }
                None => return Err(EnqueueError::SecurityUnavailable),
            }
        } else {
            aps_frame.to_bytes()
        };

        Ok(self
            .nwk_data_frame(nwk_destination, aps_payload)
            .with_discover_route(NwkRouteDiscovery::Enable)
            .with_radius(cmp::max(radius, 1)))
    }

    /// How long to wait for a device's APS ack: longer for a sleepy destination, which
    /// only sees (and acks) the frame after polling.
    fn aps_ack_timeout(&self, destination: Nwk, sleepy_destination: bool) -> Duration {
        if sleepy_destination || self.sleepy_child_eui64(destination).is_some() {
            self.tunables.aps_ack_timeout_indirect()
        } else {
            self.tunables.aps_ack_timeout()
        }
    }

    /// The traffic policy for a host-originated send. The class is fixed here, not
    /// host-chosen: a host send can never draw from the forwarding or critical budget
    /// tiers, whatever its priority.
    const fn host_policy(priority: TxPriority) -> TxPolicy {
        TxPolicy {
            priority,
            class: TrafficClass::Host,
        }
    }

    /// Send a unicast APS data frame, returning a [`SendHandle`] over its two stages.
    /// `Err` rejects at admission (malformed, rate limited, frame budget) and no handle is
    /// returned. On `Ok`, `handed_off` resolves on next-hop acceptance and `delivered` on
    /// the end-to-end APS ack (for an ack send) or on that same acceptance (rule 4, for a
    /// no-ack send).
    ///
    /// `aps_security` requests APS encryption of the ASDU with the link key shared with
    /// that device (link keys are pairwise, so this is unicast-only).
    #[allow(clippy::too_many_arguments)]
    pub fn send_aps_unicast(
        &self,
        destination: Nwk,
        profile_id: u16,
        cluster_id: u16,
        src_ep: u8,
        dst_ep: u8,
        aps_ack: ApsAck,
        radius: u8,
        aps_seq: u8,
        data: Vec<u8>,
        aps_security: Option<Eui64>,
        sleepy_destination: bool,
        priority: TxPriority,
        route: RouteDirective,
    ) -> Result<SendHandle, EnqueueError> {
        let asdu = FrameBytes::from_slice(&data).map_err(|_| EnqueueError::PayloadTooLong)?;

        let aps_frame = ApsDataFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Data,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved1: 0b0,
                security: aps_security.is_some(),
                ack_request: aps_ack == ApsAck::Request,
                extended_header: false,
            },
            group_id: None,
            destination_endpoint: Some(dst_ep),
            cluster_id,
            profile_id,
            source_endpoint: src_ep,
            counter: aps_seq,
            asdu,
        };

        let nwk_frame = self.wrap_aps_frame(&aps_frame, destination, radius, aps_security)?;

        // The end-to-end ack correlates on the swapped endpoints (our destination is the
        // acker's source, and vice-versa).
        let ack_data = (aps_ack == ApsAck::Request).then_some(ApsAckData {
            src: destination,
            destination_endpoint: Some(src_ep),
            cluster_id: Some(cluster_id),
            profile_id: Some(profile_id),
            source_endpoint: Some(dst_ep),
            counter: aps_seq,
        });

        let (handle, slot) = SendHandle::new();

        // With an APS ack, the sender resolves only `handed_off` (next-hop acceptance);
        // the ack arrival/timeout resolves `delivered` through the slot held here. Without
        // one, next-hop acceptance is the whole verdict, so the sender resolves
        // `Delivery` directly (rule 4 back-fills `handed_off`).
        let stage = if ack_data.is_some() {
            TrackStage::HandOff
        } else {
            TrackStage::Delivery
        };

        // An APS-ack send registers its pending ack (with the deadline the timeout
        // reactor uses) before enqueueing so a fast reply is caught.
        if let Some(ack_data) = &ack_data {
            let deadline = self.core_now() + self.aps_ack_timeout(destination, sleepy_destination);
            self.state.pending_aps_acks.lock().insert(
                ack_data.clone(),
                PendingApsAck {
                    slot: slot.clone(),
                    deadline,
                },
            );
            self.aps_ack_wake.notify_one();
        }

        let accepted = self.originate_unicast(
            nwk_frame,
            NwkSecurityMode::NetworkKey,
            SendMode::Route(route),
            Self::host_policy(priority),
            TxOutcome::Track { slot, stage },
        );

        // A rejected frame gets no confirmation: unregister its pending ack and drop the
        // handle by returning the admission error.
        if let Err(err) = accepted {
            if let Some(ack_data) = ack_data {
                self.state.pending_aps_acks.lock().remove(&ack_data);
            }
            return Err(err);
        }

        Ok(handle)
    }

    /// Send a broadcast APS data frame to a broadcast sink, returning a [`SendHandle`].
    /// `Err` rejects at admission; on `Ok`, `handed_off` resolves when the first copy
    /// reaches the air and `delivered` on the passive-ack quorum result. A broadcast is
    /// never APS-secured nor end-to-end acked: the quorum is its confirmation.
    #[allow(clippy::too_many_arguments)]
    pub fn send_aps_broadcast(
        &self,
        destination: Nwk,
        profile_id: u16,
        cluster_id: u16,
        src_ep: u8,
        dst_ep: u8,
        radius: u8,
        aps_seq: u8,
        data: Vec<u8>,
        priority: TxPriority,
    ) -> Result<SendHandle, EnqueueError> {
        let asdu = FrameBytes::from_slice(&data).map_err(|_| EnqueueError::PayloadTooLong)?;

        let aps_frame = ApsDataFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Data,
                delivery_mode: ApsDeliveryMode::Broadcast,
                reserved1: 0b0,
                security: false,
                ack_request: false,
                extended_header: false,
            },
            group_id: None,
            destination_endpoint: Some(dst_ep),
            cluster_id,
            profile_id,
            source_endpoint: src_ep,
            counter: aps_seq,
            asdu,
        };

        let nwk_frame = self.wrap_aps_frame(&aps_frame, destination, radius, None)?;

        let (handle, slot) = SendHandle::new();
        self.originate_broadcast(
            nwk_frame,
            NwkSecurityMode::NetworkKey,
            Self::host_policy(priority),
            Some(slot),
        )?;
        Ok(handle)
    }

    /// Send a groupcast (APS multicast) data frame, returning a [`SendHandle`]. The group
    /// lives only in the APS header; the NWK frame is broadcast to all rx-on-when-idle
    /// devices (spec 2.2.4.1.1.1), so it rides the broadcast machinery and, like a
    /// broadcast, its confirmation is the passive-ack quorum result and it is never
    /// APS-secured or acked.
    #[allow(clippy::too_many_arguments)]
    pub fn send_aps_groupcast(
        &self,
        group_id: u16,
        profile_id: u16,
        cluster_id: u16,
        src_ep: u8,
        radius: u8,
        aps_seq: u8,
        data: Vec<u8>,
        priority: TxPriority,
    ) -> Result<SendHandle, EnqueueError> {
        let asdu = FrameBytes::from_slice(&data).map_err(|_| EnqueueError::PayloadTooLong)?;

        let aps_frame = ApsDataFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Data,
                delivery_mode: ApsDeliveryMode::Multicast,
                reserved1: 0b0,
                security: false,
                ack_request: false,
                extended_header: false,
            },
            group_id: Some(group_id),
            destination_endpoint: None,
            cluster_id,
            profile_id,
            source_endpoint: src_ep,
            counter: aps_seq,
            asdu,
        };

        let nwk_frame = self.wrap_aps_frame(&aps_frame, BROADCAST_RX_ON_WHEN_IDLE, radius, None)?;

        let (handle, slot) = SendHandle::new();
        self.originate_broadcast(
            nwk_frame,
            NwkSecurityMode::NetworkKey,
            Self::host_policy(priority),
            Some(slot),
        )?;
        Ok(handle)
    }

    /// The APS-ack timeout reactor: sleeps to the earliest pending send's deadline, then
    /// fails any whose ack never arrived.
    pub(super) async fn aps_ack_timeout_task(&self) {
        loop {
            match self.earliest_aps_ack_deadline() {
                Some(deadline) => {
                    let _ = self
                        .timeout_at_core(deadline, self.aps_ack_wake.notified())
                        .await;
                }
                None => self.aps_ack_wake.notified().await,
            }

            self.expire_aps_acks();
        }
    }

    fn earliest_aps_ack_deadline(&self) -> Option<CoreInstant> {
        self.state
            .pending_aps_acks
            .lock()
            .values()
            .map(|pending| pending.deadline)
            .min()
    }

    /// Expire pending APS acks: an entry past its deadline resolves `delivered` with a
    /// timeout, and a cancelled entry with `Cancelled`. A stale entry whose send already
    /// failed at handoff still expires here; its slot is already resolved, so the late
    /// write is ignored (write-once, rule 1).
    fn expire_aps_acks(&self) {
        let now = self.core_now();

        let due: Vec<(Arc<SendSlot>, bool)> = {
            let mut pending = self.state.pending_aps_acks.lock();
            let due: Vec<(ApsAckData, Arc<SendSlot>, bool)> = pending
                .iter()
                .filter(|(_, p)| p.deadline <= now || p.slot.is_cancelled())
                .map(|(key, p)| (key.clone(), p.slot.clone(), p.slot.is_cancelled()))
                .collect();
            for (key, _, _) in &due {
                pending.remove(key);
            }
            drop(pending);
            due.into_iter()
                .map(|(_, slot, cancelled)| (slot, cancelled))
                .collect()
        };

        for (slot, cancelled) in due {
            let result = if cancelled {
                Err(DeliveryError::Cancelled)
            } else {
                Err(DeliveryError::ApsAckTimeout)
            };
            slot.resolve(TrackStage::Delivery, result);
        }
    }
}
