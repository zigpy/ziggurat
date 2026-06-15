use ieee_802154::FrameBytes;
use ieee_802154::types::{Eui64, Nwk};
use zigbee::aps::frame::{
    ApsAckFrame, ApsAckFrameControl, ApsDataFrame, ApsDeliveryMode, ApsFrameControl, ApsFrameType,
    EncryptedApsAckFrame, EncryptedApsDataFrame,
};
use zigbee::nwk::frame::{BROADCAST_RX_ON_WHEN_IDLE, NwkFrame, NwkRouteDiscovery};

use spinel::client::TxPriority;
use std::cmp;
use tokio::sync::oneshot;

use super::{
    ApsAck, ApsAckData, ApsAckWaiter, LOCK_ACQUIRE_TIMEOUT, NwkSecurityMode, SendMode, ZigbeeStack,
    ZigbeeStackError,
};

impl ZigbeeStack {
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

    /// Resolve an inbound APS ACK against the pending transmissions waiting for it.
    pub(super) fn handle_aps_ack(&self, nwk_frame: &NwkFrame, ack: &ApsAckFrame) {
        let ack_data = ApsAckData::from_aps_ack(nwk_frame.nwk_header.source, ack);
        tracing::debug!("Received APS ack: {ack_data:?}");

        let tx = self
            .state
            .pending_aps_acks
            .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
            .unwrap()
            .remove(&ack_data);
        if let Some(tx) = tx {
            let _ = tx.send(());
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

    /// Send an APS data frame, returning once it has been transmitted (including
    /// route discovery and the NWK retry loop; for sleepy children, once the frame is
    /// extracted from the indirect queue). When an APS ack was requested, the
    /// returned waiter resolves the end-to-end delivery via
    /// [`ZigbeeStack::wait_aps_ack`].
    ///
    /// `aps_security` requests APS encryption of the ASDU with the link key shared
    /// with that device (unicast only: link keys are pairwise).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_aps_command(
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
    ) -> Result<Option<ApsAckWaiter>, ZigbeeStackError> {
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
                asdu: asdu.clone(),
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
                asdu: asdu.clone(),
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
                asdu: asdu.clone(),
            },
        };

        tracing::debug!("Prepared APS frame: {aps_frame:?}");

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

        if aps_ack == ApsAck::None {
            self.send_nwk_frame(
                nwk_frame,
                NwkSecurityMode::NetworkKey,
                SendMode::Route,
                priority,
            )
            .await?;
            return Ok(None);
        }

        let ack_data = ApsAckData {
            src: destination,
            destination_endpoint: Some(src_ep), // These are swapped
            cluster_id: Some(cluster_id),
            profile_id: Some(profile_id),
            source_endpoint: Some(dst_ep), // These are swapped
            counter: aps_seq,
        };

        let (ack_tx, ack_rx) = oneshot::channel();

        tracing::debug!("APS ACK requested, waiting for {ack_data:?}");
        {
            self.state
                .pending_aps_acks
                .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
                .unwrap()
                .insert(ack_data.clone(), ack_tx);
        }

        if let Err(err) = self
            .send_nwk_frame(
                nwk_frame,
                NwkSecurityMode::NetworkKey,
                SendMode::Route,
                priority,
            )
            .await
        {
            self.state
                .pending_aps_acks
                .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
                .unwrap()
                .remove(&ack_data);
            return Err(err);
        }

        // A sleepy child only sees the frame (and acks it) after polling
        let timeout = if self.sleepy_child_eui64(destination).is_some() {
            self.tunables.aps_ack_timeout_indirect
        } else {
            self.tunables.aps_ack_timeout
        };

        Ok(Some(ApsAckWaiter {
            receiver: ack_rx,
            timeout,
            ack_data,
        }))
    }

    /// Wait for the end-to-end APS ack of a previously transmitted frame.
    pub async fn wait_aps_ack(&self, waiter: ApsAckWaiter) -> Result<(), ZigbeeStackError> {
        match tokio::time::timeout(waiter.timeout, waiter.receiver).await {
            Ok(Ok(())) => {
                tracing::debug!("APS ACK received");
                Ok(())
            }
            Ok(Err(_)) | Err(_) => {
                tracing::warn!("APS ACK timed out for {:?}", waiter.ack_data);
                self.state
                    .pending_aps_acks
                    .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
                    .unwrap()
                    .remove(&waiter.ack_data);
                Err(ZigbeeStackError::ApsAckTimeout)
            }
        }
    }
}
