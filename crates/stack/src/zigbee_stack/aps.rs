use crate::zigbee_aps::{
    ApsAckFrame, ApsAckFrameControl, ApsDataFrame, ApsDeliveryMode, ApsFrameControl, ApsFrameType,
};
use crate::zigbee_nwk::{BROADCAST_RX_ON_WHEN_IDLE, NwkFrame, NwkRouteDiscovery};
use ieee_802154::types::Nwk;

use std::cmp;
use tokio::sync::oneshot;

use super::{
    APS_ACK_TIMEOUT, APS_ACK_TIMEOUT_INDIRECT, ApsAckData, ApsAckWaiter, MAX_LOCK_DURATION,
    NwkSecurityMode, ZigbeeStack, ZigbeeStackError,
};

impl ZigbeeStack {
    pub(super) fn handle_aps_ack_request(&self, aps_frame: &ApsDataFrame, nwk_frame: &NwkFrame) {
        log::debug!("Sending back an APS ACK");

        // Send our ACK back to the sender
        let aps_ack_frame = self
            .nwk_data_frame(
                nwk_frame.nwk_header.source,
                ApsAckFrame {
                    frame_control: ApsAckFrameControl {
                        frame_type: ApsFrameType::Ack,
                        delivery_mode: ApsDeliveryMode::Unicast,
                        ack_format: false,
                        security: false,
                        ack_request: false,
                        extended_header: false,
                    },
                    destination_endpoint: Some(aps_frame.source_endpoint),
                    cluster_id: Some(aps_frame.cluster_id),
                    profile_id: Some(aps_frame.profile_id),
                    source_endpoint: aps_frame.destination_endpoint,
                    counter: aps_frame.counter,
                }
                .to_bytes(),
            )
            .with_discover_route(NwkRouteDiscovery::Enable);

        self.background_send_nwk_frame(aps_ack_frame, NwkSecurityMode::NetworkKey, false);
    }

    /// Send an APS data frame, returning once it has been transmitted (including
    /// route discovery and the NWK retry loop; for sleepy children, once the frame is
    /// extracted from the indirect queue). When an APS ack was requested, the
    /// returned waiter resolves the end-to-end delivery via
    /// [`ZigbeeStack::wait_aps_ack`].
    #[allow(clippy::too_many_arguments)]
    pub async fn send_aps_command(
        &self,
        delivery_mode: ApsDeliveryMode,
        destination: Nwk,
        profile_id: u16,
        cluster_id: u16,
        src_ep: u8,
        dst_ep: u8,
        aps_ack: bool,
        radius: u8,
        aps_seq: u8,
        data: Vec<u8>,
    ) -> Result<Option<ApsAckWaiter>, ZigbeeStackError> {
        let aps_frame = match delivery_mode {
            ApsDeliveryMode::Unicast => ApsDataFrame {
                frame_control: ApsFrameControl {
                    frame_type: ApsFrameType::Data,
                    delivery_mode: ApsDeliveryMode::Unicast,
                    reserved1: 0b0,
                    security: false,
                    ack_request: aps_ack,
                    extended_header: false,
                },
                group_id: None,
                destination_endpoint: Some(dst_ep),
                cluster_id,
                profile_id,
                source_endpoint: src_ep,
                counter: aps_seq,
                asdu: data.to_vec(),
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
                asdu: data.to_vec(),
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
                asdu: data.to_vec(),
            },
        };

        log::debug!("Prepared APS frame: {aps_frame:#?}");

        // Zigbee 3.0 groupcast: the group lives only in the APS header; the NWK frame
        // is broadcast to all rx-on-when-idle devices (spec 2.2.4.1.1.1)
        let nwk_destination = if delivery_mode == ApsDeliveryMode::Multicast {
            BROADCAST_RX_ON_WHEN_IDLE
        } else {
            destination
        };

        let nwk_frame = self
            .nwk_data_frame(nwk_destination, aps_frame.to_bytes())
            .with_discover_route(NwkRouteDiscovery::Enable)
            .with_radius(cmp::max(radius, 1));

        log::debug!("Prepared NWK frame: {nwk_frame:#?}");

        if !aps_ack {
            self.send_nwk_frame(nwk_frame, NwkSecurityMode::NetworkKey, false)
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

        log::debug!("APS ACK requested, waiting for {ack_data:?}");
        {
            self.state
                .pending_aps_acks
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .insert(ack_data.clone(), ack_tx);
        }

        if let Err(err) = self
            .send_nwk_frame(nwk_frame, NwkSecurityMode::NetworkKey, false)
            .await
        {
            self.state
                .pending_aps_acks
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .remove(&ack_data);
            return Err(err);
        }

        // A sleepy child only sees the frame (and acks it) after polling
        let timeout = if self.sleepy_child_eui64(destination).is_some() {
            APS_ACK_TIMEOUT_INDIRECT
        } else {
            APS_ACK_TIMEOUT
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
                log::info!("APS ACK received");
                Ok(())
            }
            Ok(Err(_)) | Err(_) => {
                log::warn!("APS ACK timed out for {:?}", waiter.ack_data);
                self.state
                    .pending_aps_acks
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .remove(&waiter.ack_data);
                Err(ZigbeeStackError::ApsAckTimeout)
            }
        }
    }
}
