use crate::runtime::Runtime;
use ziggurat_ieee_802154::FrameBytes;
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_zigbee::aps::frame::{
    ApsAckFrame, ApsAckFrameControl, ApsDataFrame, ApsDeliveryMode, ApsFrameControl, ApsFrameType,
    EncryptedApsAckFrame, EncryptedApsDataFrame,
};
use ziggurat_zigbee::nwk::frame::{
    BROADCAST_LOW_POWER_ROUTERS, BROADCAST_RX_ON_WHEN_IDLE, NwkFrame, NwkRouteDiscovery,
};

use alloc::collections::btree_map::Entry;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::cmp;
use core::time::Duration;
use ziggurat_phy::RadioPhy;
use ziggurat_zigbee::Instant as CoreInstant;

use super::{
    ApsAck, ApsAckData, ConfirmTrigger, NwkSecurityMode, PendingApsAck, SendMode, SendResult,
    TxOutcome, TxPriority, ZigbeeNotification, ZigbeeStack, ZigbeeStackError,
};

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
        if let Some(PendingApsAck { token, .. }) = pending {
            self.push_notification(ZigbeeNotification::SendConfirm {
                token,
                result: SendResult::Confirmed {
                    via: ConfirmTrigger::ApsAck,
                },
            });
        }
    }

    /// Spec 2.2.8.4.2: record an inbound APS data frame and report whether it duplicates
    /// one seen within the rejection window. Duplicates are still ACKed so the sender
    /// stops retransmitting, but must not reach the application twice. Expired entries
    /// are swept on each call.
    pub(super) fn is_duplicate_aps_frame(&self, source: Nwk, counter: u8) -> bool {
        let now = self.core_now();
        let timeout = self.tunables.aps_duplicate_rejection_timeout;

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

            encrypted.to_bytes()
        } else {
            ack_frame.to_bytes()
        };

        // Send our ACK back to the sender
        let aps_ack_frame = self
            .nwk_data_frame(nwk_frame.nwk_header.source, payload)
            .with_discover_route(NwkRouteDiscovery::Enable);

        self.background_send_nwk_frame(aps_ack_frame, NwkSecurityMode::NetworkKey, SendMode::Route);
    }

    /// Build the NWK frame carrying an APS data frame, plus the ack-correlation data when
    /// an end-to-end ack was requested. Shared by the awaiting [`Self::send_aps_command`]
    /// and the fire-and-forget [`Self::send_aps`].
    ///
    /// `aps_security` requests APS encryption of the ASDU with the link key shared
    /// with that device (unicast only: link keys are pairwise).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_aps_send(
        &self,
        delivery_mode: ApsDeliveryMode,
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
    ) -> Result<(NwkFrame, Option<ApsAckData>), ZigbeeStackError> {
        let asdu = FrameBytes::from_slice(&data).map_err(|_| ZigbeeStackError::PayloadTooLong)?;

        let aps_frame = match delivery_mode {
            ApsDeliveryMode::Unicast => ApsDataFrame {
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
            },
            ApsDeliveryMode::Broadcast => ApsDataFrame {
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
            },
            ApsDeliveryMode::Multicast => ApsDataFrame {
                frame_control: ApsFrameControl {
                    frame_type: ApsFrameType::Data,
                    delivery_mode: ApsDeliveryMode::Multicast,
                    reserved1: 0b0,
                    security: false,
                    ack_request: false,
                    extended_header: false,
                },
                group_id: Some(destination.as_u16()),
                destination_endpoint: None,
                cluster_id,
                profile_id,
                source_endpoint: src_ep,
                counter: aps_seq,
                asdu,
            },
        };

        tracing::trace!("Prepared APS frame: {aps_frame:?}");

        let aps_payload = if let Some(destination_eui64) = aps_security {
            let encrypted = self
                .core()
                .aib
                .aps_security
                .encrypt_data(destination_eui64, &aps_frame);
            match encrypted {
                Some(encrypted) => encrypted.to_bytes(),
                None => return Err(ZigbeeStackError::ApsSecurityFailed),
            }
        } else {
            aps_frame.to_bytes()
        };

        // Zigbee 3.0 groupcast: the group lives only in the APS header; the NWK frame
        // is broadcast to all rx-on-when-idle devices (spec 2.2.4.1.1.1)
        let nwk_destination = if delivery_mode == ApsDeliveryMode::Multicast {
            BROADCAST_RX_ON_WHEN_IDLE
        } else {
            destination
        };

        let nwk_frame = self
            .nwk_data_frame(nwk_destination, aps_payload)
            .with_discover_route(NwkRouteDiscovery::Enable)
            .with_radius(cmp::max(radius, 1));

        let ack_data = (aps_ack == ApsAck::Request).then_some(ApsAckData {
            src: destination,
            destination_endpoint: Some(src_ep), // These are swapped
            cluster_id: Some(cluster_id),
            profile_id: Some(profile_id),
            source_endpoint: Some(dst_ep), // These are swapped
            counter: aps_seq,
        });

        Ok((nwk_frame, ack_data))
    }

    /// How long to wait for a device's APS ack: longer for a sleepy child, which only
    /// sees (and acks) the frame after polling.
    fn aps_ack_timeout(&self, destination: Nwk) -> Duration {
        if self.sleepy_child_eui64(destination).is_some() {
            self.tunables.aps_ack_timeout_indirect
        } else {
            self.tunables.aps_ack_timeout
        }
    }

    /// Build and enqueue the frame, then return an accept or reject. Delivery is
    /// confirmed later as a [`ZigbeeNotification::SendConfirm`] carrying `token`,
    /// triggered by the frame type: passive-ack quorum for a broadcast, next-hop
    /// acceptance for a no-ack unicast, or the APS ack for an ack unicast.
    #[allow(clippy::too_many_arguments)]
    pub fn send_aps(
        &self,
        delivery_mode: ApsDeliveryMode,
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
        priority: TxPriority,
        token: u64,
    ) -> Result<(), ZigbeeStackError> {
        let (nwk_frame, ack_data) = self.prepare_aps_send(
            delivery_mode,
            destination,
            profile_id,
            cluster_id,
            src_ep,
            dst_ep,
            aps_ack,
            radius,
            aps_seq,
            data,
            aps_security,
        )?;

        // An APS-ack send is confirmed by the end-to-end ack: register it (with the
        // deadline the timeout reactor uses) before enqueueing so a fast reply is caught.
        if let Some(ack_data) = &ack_data {
            let deadline = self.core_now() + self.aps_ack_timeout(destination);
            self.state
                .pending_aps_acks
                .lock()
                .insert(ack_data.clone(), PendingApsAck { token, deadline });
            self.aps_ack_wake.notify_one();
        }

        self.enqueue_aps_frame(
            nwk_frame,
            priority,
            TxOutcome::Confirm {
                token,
                aps_ack: ack_data,
            },
        );
        Ok(())
    }

    /// Enqueue a built APS/NWK frame fire-and-forget, routing broadcasts and unicasts like
    /// [`send_nwk_frame`](Self::send_nwk_frame). The `outcome` rides the unicast path (the
    /// sender confirms next-hop acceptance / failure); a broadcast is confirmed by the
    /// retransmit reactor on quorum, so only its `token` is carried over.
    pub(super) fn enqueue_aps_frame(
        &self,
        nwk_frame: NwkFrame,
        priority: TxPriority,
        outcome: TxOutcome,
    ) {
        if nwk_frame.nwk_header.destination.as_u16() >= BROADCAST_LOW_POWER_ROUTERS.as_u16() {
            let token = match outcome {
                TxOutcome::Confirm { token, .. } => Some(token),
                TxOutcome::Discard | TxOutcome::Signal(_) => None,
            };
            self.send_broadcast_nwk_frame(nwk_frame, NwkSecurityMode::NetworkKey, priority, token);
        } else {
            self.originate_unicast(
                nwk_frame,
                NwkSecurityMode::NetworkKey,
                SendMode::Route,
                priority,
                outcome,
            );
        }
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

    fn expire_aps_acks(&self) {
        let now = self.core_now();

        let expired: Vec<u64> = {
            let mut pending = self.state.pending_aps_acks.lock();
            let due: Vec<(ApsAckData, u64)> = pending
                .iter()
                .filter(|(_, p)| p.deadline <= now)
                .map(|(key, p)| (key.clone(), p.token))
                .collect();
            for (key, _) in &due {
                pending.remove(key);
            }
            drop(pending);
            due.into_iter().map(|(_, token)| token).collect()
        };

        for token in expired {
            tracing::warn!("APS ack timed out for send {token}");
            self.push_notification(ZigbeeNotification::SendConfirm {
                token,
                result: SendResult::Failed {
                    reason: "APS ack timed out".to_string(),
                },
            });
        }
    }
}
