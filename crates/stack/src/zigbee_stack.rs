use crate::ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154Frame, Ieee802154FrameControl,
    Ieee802154FrameType,
};
use crate::spinel::{SpinelFramePropValueIs, SpinelPropertyId, SpinelStatus};
use crate::spinel_client::{SpinelClient, SpinelError, SpinelRxFrame, SpinelTxFrame};
use crate::zigbee_aps::{
    ApsAckFrame, ApsAckFrameControl, ApsDataFrame, ApsDeliveryMode, ApsFrame, ApsFrameControl,
    ApsFrameType, parse_aps_frame,
};
use crate::zigbee_nwk::{
    BROADCAST_ALL_ROUTERS_AND_COORDINATOR, BROADCAST_LOW_POWER_ROUTERS, EncryptedNwkFrame,
    NwkAuxHeader, NwkFrame, NwkFrameControl, NwkFrameType, NwkHeader, NwkRouteDiscovery,
    NwkSecurityHeaderControlField, NwkSecurityHeaderKeyId, NwkSecurityLevel,
};
use ieee_802154::types::{Eui64, Key, Nwk, PanId};

use thiserror::Error;
use tokio::time::error::Elapsed;
use tokio::time::timeout;
use zigbee_parts::Command;
use zigbee_parts::commands::{
    NwkCommandId, NwkLinkStatus, NwkLinkStatusCommand, NwkRouteRecordCommand, NwkRouteReplyCommand,
    NwkRouteRequestCommand, NwkRouteRequestManyToOne,
};

use parking_lot::Mutex;
use std::cmp;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Weak};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::spawn_local;
use tokio::time::{Duration, Instant};

mod neighbor;
mod route;

// TODO: remove this once all long locks have been found
const MAX_LOCK_DURATION: Duration = Duration::from_millis(10);
const APS_ACK_TIMEOUT: Duration = Duration::from_millis(5000);

// The number of the most recent samples taken into consideration SHOULD be n = 3, which
// eliminates single outliers maintains a fast response to real changes in link quality,
// and keeps memory requirements to a minimum.
const LINK_QUALITY_SAMPLES: usize = 3;

/// Compute the link cost (1-7) based on the LQI (0-255).
const fn lqi_to_link_cost(lqi: u8) -> u8 {
    match lqi {
        0..=16 => 7,
        17..=32 => 6,
        33..=64 => 5,
        65..=96 => 4,
        97..=128 => 3,
        129..=192 => 2,
        193..=255 => 1,
        // 0 corresponds to "unknown LQI"
    }
}

#[derive(Error, Debug)]
pub enum ZigbeeStackError {
    #[error("route discovery timed out")]
    RouteDiscoveryTimeout(#[from] Elapsed),
    #[error("route discovery unexpectedly failed: {0}")]
    RouteDiscoveryFailure(String),
    #[error("next hop {next_hop:?} did not ACK")]
    NwkNoAck { next_hop: Nwk },
    #[error("transmit rejected due to CCA failure")]
    CcaFailure,
    #[error("unexpected transmit failure: {0:?}")]
    SpinelTransmitFailure(SpinelStatus),
    #[error("aps ack timeout")]
    ApsAckTimeout,
    #[error("spinel error: {0}")]
    SpinelError(#[from] SpinelError),
}

#[derive(Debug)]
pub enum NwkCapabilityInformationDeviceType {
    EndDevice = 0,
    Router = 1,
}

#[derive(Debug)]
pub enum NwkCapabilityInformationPowerSource {
    MainsPower = 0,
    Battery = 1,
}

#[derive(Debug)]
pub enum NetworkKeyType {
    Standard = 1,
}

#[derive(Debug)]
pub enum NwkSecurityCapability {
    NotCapable = 0,
    Capable = 1,
}

#[derive(Debug)]
pub struct NwkCapabilityInformation {
    pub alternate_pan_coordinator: bool,
    pub device_type: NwkCapabilityInformationDeviceType,
    pub power_source: NwkCapabilityInformationPowerSource,
    pub receiver_on_when_idle: bool,
    pub reserved1: bool,
    pub reserved2: bool,
    pub security_capability: NwkSecurityCapability,
    pub allocate_address: bool, // = 1
}

#[derive(Debug)]
pub struct NwkSecurityDescriptor {
    pub key_seq_number: u8,
    pub outgoing_frame_counter: u32,
    pub incoming_frame_counter_set: HashMap<Eui64, u32>,
    pub key: Key,
    pub network_key_type: NetworkKeyType,
}

#[derive(Debug)]
pub struct NwkBroadcastTransaction {
    pub source_nwk: Nwk,
    pub sequence_number: u8,
    pub expiration_time: Instant,
    // The spec does not describe how this is supposed to be implemented so we just do
    // it naively
    // pub relayed_neighbors: HashMap<Eui64, Instant>,
}

#[derive(Debug)]
pub enum NwkDeviceType {
    Coordinator = 0x00,
    Router = 0x01,
    EndDevice = 0x02,
}

#[derive(Debug)]
pub struct Constants {
    pub concentrator_radius: u8,
    pub concentrator_discovery_time: Duration,
    pub stack_profile: u8,
    pub transaction_persistence_time: Duration,
    pub max_source_route: u8,
    pub max_children: u8,

    pub passive_ack_timeout: Duration,

    /// The maximum number of retries allowed after a broadcast transmission failure.
    pub max_broadcast_retries: u8,

    /// The minimum time, in seconds, between two consecutive concentrator route
    /// discoveries. If set to 0x00, there is no minimum separation. This only applies
    /// when the device is operating as a Concentrator.
    pub concentrator_discovery_separation_time: Duration,

    /// The time between link status command frames.
    pub link_status_period: Duration,

    /// The number of missed link status command frames before resetting the link costs
    /// to zero.
    pub router_age_limit: u8,

    pub protocol_version: u8,
    pub route_discovery_time: Duration,
    pub max_broadcast_jitter: Duration,
    pub initial_rreq_retries: u8,
    pub rreq_retries: u8,
    pub rreq_retry_interval: Duration,
    pub min_rreq_jitter: Duration,
    pub max_rreq_jitter: Duration,
    pub max_depth: u8,
    pub unicast_retries: u8,
    pub unicast_retry_delay: Duration,
    pub min_router_bootstrap_jitter: Duration,
    pub max_router_bootstrap_jitter: Duration,
    pub broadcast_delivery_time: Duration,

    /// This is an index into Table 3-54. It indicates the default timeout in minutes for
    /// any end device that does not negotiate a different timeout value.
    pub end_device_timeout_default: u8,
}

impl Default for Constants {
    fn default() -> Self {
        Self::new()
    }
}

impl Constants {
    pub const fn new() -> Self {
        Self {
            passive_ack_timeout: Duration::from_millis(500),
            max_broadcast_retries: 2,
            max_children: 32,
            max_depth: 15,
            max_source_route: 12,
            transaction_persistence_time: Duration::from_millis(7680),
            stack_profile: 2,
            concentrator_radius: 10,
            concentrator_discovery_time: Duration::from_secs(0),
            concentrator_discovery_separation_time: Duration::from_secs(0),
            link_status_period: Duration::from_secs(15),
            router_age_limit: 3,
            protocol_version: 2,
            route_discovery_time: Duration::from_millis(10000),
            max_broadcast_jitter: Duration::from_millis(64),
            initial_rreq_retries: 3,
            rreq_retries: 2,
            rreq_retry_interval: Duration::from_millis(254),
            min_rreq_jitter: Duration::from_millis(2),
            max_rreq_jitter: Duration::from_millis(128),
            unicast_retries: 3,
            unicast_retry_delay: Duration::from_millis(50),
            min_router_bootstrap_jitter: Duration::from_millis(500),
            max_router_bootstrap_jitter: Duration::from_millis(1000),
            broadcast_delivery_time: Duration::from_millis(9000),
            end_device_timeout_default: 0,
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct ApsAckData {
    pub src: Nwk,
    pub destination_endpoint: Option<u8>,
    pub cluster_id: Option<u16>,
    pub profile_id: Option<u16>,
    pub source_endpoint: Option<u8>,
    pub counter: u8,
}

impl ApsAckData {
    pub const fn from_aps_ack(src: Nwk, ack: &ApsAckFrame) -> Self {
        Self {
            src,
            destination_endpoint: ack.destination_endpoint,
            cluster_id: ack.cluster_id,
            profile_id: ack.profile_id,
            source_endpoint: ack.source_endpoint,
            counter: ack.counter,
        }
    }
}

#[derive(Debug)]
pub struct State {
    pub channel: Mutex<u8>,
    pub ieee802154_sequence_number: Mutex<u8>,

    pub pending_aps_acks: Mutex<HashMap<ApsAckData, oneshot::Sender<()>>>,
    pub pending_route_notifications: Mutex<HashMap<Nwk, broadcast::Sender<()>>>,
    pub start_time: Instant,

    // We intentionally violate the spec with these options
    //
    /// The spec mandates that broadcasts be deduplicated only after the stack has been
    /// running for at least 10s, to avoid having our own broadcasts be received. This
    /// slows down development so we will allow it to be disabled.
    pub hack_ignore_broadcast_startup_wait_period: bool,
    /// To allow testing deserialization logic with real networks, allow running the
    /// stack without TX abilities. Note that this will still permit the firmware to
    /// auto-ACK, but this is generally innocuous and won't collide with a second
    /// coordinator running at the same time.
    pub hack_disable_tx: bool,
    /// Instead of caching route information, always perform route discovery. This is
    /// much slower but ensures that routing logic is always followed.
    pub hack_force_route_discovery: bool,

    // NIB
    pub sequence_number: Mutex<u8>,

    pub neighbor_table: Mutex<HashMap<Eui64, neighbor::TableEntry>>,
    pub route_table: Mutex<HashMap<Nwk, route::TableEntry>>,
    pub route_discovery_table: Mutex<HashMap<(Nwk, route::RequestId), route::DiscoveryEntry>>,
    pub broadcast_transaction_table: Mutex<HashMap<(Nwk, u8), NwkBroadcastTransaction>>,
    pub route_record_table: Mutex<HashMap<Nwk, Vec<Nwk>>>,

    pub capability_information: NwkCapabilityInformation,
    pub nwk_manager_addr: Nwk,

    pub ieee_address: Eui64,
    pub update_id: Mutex<u8>,
    pub pan_id: Mutex<PanId>,
    pub network_address: Nwk,
    pub extended_pan_id: Eui64,
    pub security_material_primary: Mutex<NwkSecurityDescriptor>,
    pub security_material_alternate: Mutex<NwkSecurityDescriptor>,
    pub active_key_seq_number: u8,

    pub is_concentrator: bool,
    pub security_level: u8,

    /// Indicates whether incoming NWK frames SHALL be all checked for freshness when
    /// the memory for incoming frame counts is exceeded.
    pub all_fresh: bool,
    pub address_map: Mutex<HashMap<Eui64, Nwk>>,

    /// A flag that determines if a timestamp indication is provided on incoming and
    /// outgoing packets.
    pub time_stamp: bool,

    /// A count of Unicast transmissions made by the NNK layer on this device.
    /// Each time the NWK layer transmits a Unicast frame, by invoking the
    /// MCPS-state.request primitive of the MAC sub-layer, it SHALL increment
    /// this counter. When either the NHL performs an NLME-SET.request on this
    /// attribute or if the value of `tx_total` rolls over past 0xffff the
    /// NWK layer SHALL reset to 0x00 each Transmit Failure field contained in
    /// the neighbor table.
    pub tx_total: Mutex<u16>,

    /// This policy determines whether or not a remote NWK leave request command frame
    /// received by the local device is accepted.
    pub leave_request_allowed: bool,

    pub parent_information: u8,

    /// This policy determines whether a NWK leave request is accepted when the Rejoin
    /// bit in the message is set to FALSE
    pub leave_request_without_rejoin_allowed: bool,

    // A strictly increasing sequence number included in all route request and route
    // reply command frames to allow other routers to determine the chronological order
    // of such route discovery messages.
    // pub nwk_routing_sequence_number: u16,  // Only needed for R23 TLVs
    //
    /// Implied from the spec: "notice that this 8-bit identifier is distinct from the
    /// 16-bit Routing Sequence Number. The former is used to discern route requests
    /// originating in a particular router; the latter is used to identify stale routing
    /// information."
    pub routing_request_sequence_number: Mutex<u8>,

    /// This indicates whether the router has Hub Connectivity as defined by a higher
    /// level application. The higher level application sets this value and the stack
    /// advertises it.
    pub hub_connectivity: bool,
}

impl State {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel: u8,
        update_id: u8,
        pan_id: PanId,
        extended_pan_id: Eui64,
        network_address: Nwk,
        ieee_address: Eui64,
        key: Key,
        key_seq_number: u8,
        outgoing_frame_counter: u32,
    ) -> Self {
        Self {
            channel: Mutex::new(channel),
            ieee802154_sequence_number: Mutex::new(0),
            pending_aps_acks: Mutex::new(HashMap::new()),
            pending_route_notifications: Mutex::new(HashMap::new()),
            start_time: Instant::now(),

            hack_ignore_broadcast_startup_wait_period: true,
            hack_disable_tx: false,
            hack_force_route_discovery: false,

            sequence_number: Mutex::new(0),
            neighbor_table: Mutex::new(HashMap::new()),
            route_table: Mutex::new(HashMap::new()),
            route_discovery_table: Mutex::new(HashMap::new()),
            capability_information: NwkCapabilityInformation {
                alternate_pan_coordinator: false,
                device_type: NwkCapabilityInformationDeviceType::EndDevice,
                power_source: NwkCapabilityInformationPowerSource::MainsPower,
                receiver_on_when_idle: true,
                reserved1: false,
                reserved2: false,
                security_capability: NwkSecurityCapability::Capable,
                allocate_address: true,
            },
            nwk_manager_addr: Nwk(0x0000),
            update_id: Mutex::new(update_id),
            network_address,
            broadcast_transaction_table: Mutex::new(HashMap::new()),
            extended_pan_id,
            route_record_table: Mutex::new(HashMap::new()),
            is_concentrator: true,
            security_level: 5,
            security_material_primary: Mutex::new(NwkSecurityDescriptor {
                key_seq_number,
                outgoing_frame_counter,
                incoming_frame_counter_set: HashMap::new(),
                key,
                network_key_type: NetworkKeyType::Standard,
            }),
            security_material_alternate: Mutex::new(NwkSecurityDescriptor {
                key_seq_number: 0,
                outgoing_frame_counter: 0,
                incoming_frame_counter_set: HashMap::new(),
                key: Key::from_hex("00000000000000000000000000000000"),
                network_key_type: NetworkKeyType::Standard,
            }),
            active_key_seq_number: 0,
            all_fresh: false,
            address_map: Mutex::new(HashMap::new()),
            time_stamp: false,
            pan_id: Mutex::new(pan_id),
            tx_total: Mutex::new(0),
            leave_request_allowed: false,
            parent_information: 0,
            leave_request_without_rejoin_allowed: false,
            ieee_address,
            // TODO: The 16-bit routing sequence number is expected to be
            // strictly-increasing, it should be persisted to disk
            // nwk_routing_sequence_number: 0x0000,
            routing_request_sequence_number: Mutex::new(0x00),
            hub_connectivity: true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ZigbeeNotification {
    ReceivedApsCommand {
        source: Nwk,
        profile_id: u16,
        cluster_id: u16,
        src_ep: u8,
        dst_ep: u8,
        lqi: u8,
        rssi: i8,
        data: Vec<u8>,
    },
}

#[derive(Debug)]
pub struct ZigbeeStack {
    self_weak: Weak<ZigbeeStack>,

    pub state: State,
    pub constants: Constants,
    pub spinel: SpinelClient,
    pub notification_tx: broadcast::Sender<ZigbeeNotification>,
    pub raw_frame_rx: Mutex<mpsc::Receiver<SpinelFramePropValueIs>>,
}

impl ZigbeeStack {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        spinel: SpinelClient,
        channel: u8,
        update_id: u8,
        pan_id: PanId,
        extended_pan_id: Eui64,
        network_address: Nwk,
        ieee_address: Eui64,
        key: Key,
        key_seq_number: u8,
        outgoing_frame_counter: u32,
    ) -> (Arc<Self>, broadcast::Receiver<ZigbeeNotification>) {
        let (notification_tx, notification_rx) = broadcast::channel::<ZigbeeNotification>(32);
        let (raw_frame_tx, raw_frame_rx) = mpsc::channel::<SpinelFramePropValueIs>(32);
        spinel.set_property_update_receiver(SpinelPropertyId::StreamRaw, raw_frame_tx);

        let arc_stack = Arc::new_cyclic(|weak_self| Self {
            self_weak: weak_self.clone(),
            state: State::new(
                channel,
                update_id,
                pan_id,
                extended_pan_id,
                network_address,
                ieee_address,
                key,
                key_seq_number,
                outgoing_frame_counter,
            ),
            constants: Constants::new(),
            spinel,
            notification_tx,
            raw_frame_rx: Mutex::new(raw_frame_rx),
        });

        (arc_stack, notification_rx)
    }

    // This function intentionally holds locks across await points to maintain
    // exclusive access to shared state during frame processing.
    #[allow(clippy::future_not_send)]
    pub async fn run(&self) {
        self.start_network().await.expect("Failed to start network");

        loop {
            let (packet, ieee802154_frame) = self.recv_frame().await;

            if let Some(nwk_frame) =
                self.process_802154_frame(&ieee802154_frame, packet.lqi, packet.rssi)
            {
                if nwk_frame.nwk_header.frame_control.frame_type != NwkFrameType::Data {
                    continue;
                }

                let aps_frame = match parse_aps_frame(&nwk_frame.payload) {
                    Ok(ApsFrame::Data(data)) => data,
                    Ok(ApsFrame::Ack(ack)) => {
                        let ack_data = ApsAckData::from_aps_ack(nwk_frame.nwk_header.source, &ack);
                        log::debug!("Received APS ack: {ack_data:?}");

                        let tx = self
                            .state
                            .pending_aps_acks
                            .try_lock_for(MAX_LOCK_DURATION)
                            .unwrap()
                            .remove(&ack_data);
                        if let Some(tx) = tx {
                            let _ = tx.send(());
                        }

                        continue;
                    }
                    Err(e) => {
                        log::warn!("Error parsing APS frame: {e:?}");
                        continue;
                    }
                };

                log::debug!("Received APS data frame: {aps_frame:#?}");

                if aps_frame.frame_control.ack_request {
                    self.handle_aps_ack_request(&aps_frame, &nwk_frame);
                }

                let notification = ZigbeeNotification::ReceivedApsCommand {
                    source: nwk_frame.nwk_header.source,
                    profile_id: aps_frame.profile_id,
                    cluster_id: aps_frame.cluster_id,
                    src_ep: aps_frame.source_endpoint,
                    dst_ep: aps_frame.destination_endpoint.unwrap_or(0),
                    lqi: packet.lqi,
                    rssi: packet.rssi,
                    data: aps_frame.asdu,
                };
                let _ = self.notification_tx.send(notification);
            }
        }
    }

    // We intentionally hold the receiver lock for the entire duration of this function
    // to ensure exclusive access to the raw frame receiver.
    #[allow(
        clippy::await_holding_lock,
        clippy::significant_drop_tightening,
        clippy::future_not_send
    )]
    async fn recv_frame(&self) -> (SpinelRxFrame, Ieee802154Frame) {
        let mut receiver = self
            .raw_frame_rx
            .try_lock_for(MAX_LOCK_DURATION)
            .expect("No thread should panic");

        loop {
            let Some(spinel_frame) = receiver.recv().await else {
                log::warn!("Frame sender hung up");
                continue;
            };

            let packet = match SpinelRxFrame::from_bytes(&spinel_frame.value) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("Error parsing spinel frame: {e:?}");
                    continue;
                }
            };

            if packet.psdu.len() < 2 {
                log::warn!("Packet too short to contain FCS");
                continue;
            }

            let frame_data = &packet.psdu[..packet.psdu.len() - 2];

            match Ieee802154Frame::from_bytes_without_fcs(frame_data) {
                Ok(frame) => {
                    log::debug!("Received 802.15.4 frame: {frame:?}");
                    return (packet, frame);
                }
                Err(e) => {
                    log::warn!("Error parsing IEEE 802.15.4 frame: {e:?}");
                    continue;
                }
            };
        }
    }

    pub async fn start_network(&self) -> Result<(), ZigbeeStackError> {
        // Update the hardware with new settings.
        self.spinel
            .prop_value_set(SpinelPropertyId::PhyEnabled, vec![true as u8])
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        let channel = *self.state.channel.try_lock_for(MAX_LOCK_DURATION).unwrap();
        self.spinel
            .prop_value_set(SpinelPropertyId::PhyChan, vec![channel])
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        self.spinel
            .prop_value_set(SpinelPropertyId::PhyTxPower, vec![8])
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        /*
        self.spinel
            .prop_value_set(
                SpinelPropertyId::MacPromiscuousMode,
                vec![SpinelMacPromiscuousMode::Full as u8],
            )
            .await
            .map_err(ZigbeeStackError::SpinelError)?;
        */

        self.spinel
            .prop_value_set(
                SpinelPropertyId::Mac154Laddr,
                self.state.ieee_address.to_bytes().to_vec(),
            )
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        self.spinel
            .prop_value_set(
                SpinelPropertyId::Mac154Saddr,
                self.state.network_address.to_bytes().to_vec(),
            )
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        let pan_id = *self.state.pan_id.try_lock_for(MAX_LOCK_DURATION).unwrap();
        self.spinel
            .prop_value_set(SpinelPropertyId::Mac154Panid, pan_id.to_bytes().to_vec())
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        self.spinel
            .prop_value_set(SpinelPropertyId::MacRxOnWhenIdleMode, vec![true as u8])
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        self.spinel
            .prop_value_set(SpinelPropertyId::MacRawStreamEnabled, vec![true as u8])
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        // To kick things off, send a link status broadcast. Silicon Labs routers will
        // "respond" to empty link status broadcasts proactively, independent of the
        // link status period
        log::info!("Sending initial link status broadcast");
        self.send_link_status_broadcast(true).await;

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        // Start the background link status broadcaster task
        spawn_local(async move {
            arc_self.periodic_link_status_broadcast_task().await;
        });

        Ok(())
    }

    // This function handles complex 802.15.4 frame processing with multiple
    // validation steps and protocol handling paths.
    #[allow(clippy::cognitive_complexity)]
    pub fn process_802154_frame(
        &self,
        frame: &Ieee802154Frame,
        lqi: u8,
        rssi: i8,
    ) -> Option<NwkFrame> {
        // 802.15.4 encrypted frames can't be Zigbee NWK
        if frame.frame_control.security_enabled {
            log::debug!("Ignoring frame, 802.15.4 security bit is enabled");
            return None;
        }

        match frame.frame_control.frame_type {
            Ieee802154FrameType::Ack => {
                // Ignored, OpenThread RCP takes care of it
                return None;
            }
            Ieee802154FrameType::Data => (),
            _ => {
                log::debug!("Ignoring frame, not a data frame");
                return None;
            }
        }

        // Only process packets destined for our PAN ID
        let pan_id = *self.state.pan_id.try_lock_for(MAX_LOCK_DURATION).unwrap();

        match frame.dest_pan_id {
            None => {
                log::debug!("Ignoring frame, destination PAN ID is not present");
                return None;
            }
            Some(dest_pan_id) if dest_pan_id != pan_id => {
                log::debug!("Ignoring frame, PAN ID does not match {dest_pan_id:?} != {pan_id:?}");
                return None;
            }
            Some(_) => (),
        }

        // Next, try to parse the NWK frame
        let nwk_frame = match EncryptedNwkFrame::from_bytes(&frame.payload) {
            Ok(nwk_frame) => nwk_frame,
            Err(_) => {
                log::debug!("Ignoring frame, not a NWK frame");
                return None;
            }
        };

        // Ignore frames that aren't destined for us
        if nwk_frame.nwk_header.destination != self.state.network_address
            && nwk_frame.nwk_header.destination.as_u16()
                < BROADCAST_ALL_ROUTERS_AND_COORDINATOR.as_u16()
        {
            log::debug!("Ignoring frame, destination is not us");
            return None;
        }

        // Ignore unencrypted frames
        if !nwk_frame.nwk_header.frame_control.security {
            log::debug!("Ignoring frame, it is not encrypted");
            return None;
        }

        let aux_header = match nwk_frame.aux_header {
            None => {
                log::debug!("Ignoring frame, auxiliary header is missing");
                return None;
            }
            Some(ref header) => header,
        };

        // The frame security level is fixed for a given network and transmitted frames will use "0"
        if aux_header.security_control.security_level != NwkSecurityLevel::NoSecurity {
            log::debug!("Ignoring frame, security level is not 0");
            return None;
        }

        // Only the network key is supported for now
        if aux_header.security_control.key_id != NwkSecurityHeaderKeyId::NetworkKey {
            log::debug!("Ignoring frame, key ID is not NetworkKey");
            return None;
        }

        // Validate the network key sequence number
        if aux_header.key_sequence_number != self.state.active_key_seq_number {
            log::debug!("Ignoring frame, key sequence number is unknown");
            return None;
        }

        // Validate the security header frame counter for the relaying EUI64
        let src_eui64 = match aux_header.extended_source {
            None => {
                log::debug!("Ignoring frame, extended source is missing");
                return None;
            }
            Some(eui64) => eui64,
        };

        match self
            .state
            .security_material_primary
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .incoming_frame_counter_set
            .get(&src_eui64)
        {
            None => {
                log::warn!("Unknown sender, not validating frame counter");
            }
            Some(last_stored_frame_counter) => {
                if aux_header.frame_counter <= *last_stored_frame_counter {
                    log::debug!(
                        "Ignoring frame, frame counter has rolled backward from {last_stored_frame_counter} to {}",
                        aux_header.frame_counter
                    );
                    return None;
                }
            }
        };

        log::debug!(
            "Attempting to decrypt {:?} with {:?}",
            nwk_frame,
            self.state.security_material_primary
        );

        // Finally, attempt decryption
        let key = &self
            .state
            .security_material_primary
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .key;
        let decrypted_nwk_frame = match nwk_frame.decrypt(key) {
            Ok(decrypted_frame) => decrypted_frame,
            Err(err) => {
                log::warn!("Ignoring frame, decryption failed: {err:?}");
                return None;
            }
        };

        log::info!("Decrypted frame: {decrypted_nwk_frame:#?}");

        // TODO: all 802.15.4 frames should be coming in with 16 bit addressing, right?
        let source_nwk = match frame.src_address {
            Some(Ieee802154Address::Nwk(nwk)) => Some(nwk),
            _ => None,
        }
        .unwrap();

        self.handle_decrypted_frame(&decrypted_nwk_frame, source_nwk, lqi, rssi);

        Some(decrypted_nwk_frame)
    }

    pub fn update_nwk_eui64_mapping(&self, nwk: Nwk, eui64: Eui64) {
        let old_nwk = self
            .state
            .address_map
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .insert(eui64, nwk);
        match old_nwk {
            None => {
                log::debug!("Added new address mapping: {eui64:?} -> {nwk:?}")
            }
            Some(old_nwk) => {
                log::warn!("Updated address mapping: {eui64:?} -> {nwk:?} (was {old_nwk:?})",)
            }
        }
    }

    /// Filter broadcast frames based on the NWK broadcast transaction table
    pub fn filter_broadcast(&self, nwk_frame: &NwkFrame) -> bool {
        let now = Instant::now();

        // We cannot handle broadcasts until the network has been running for at least
        // the time it takes to deliver one broadcast
        if !self.state.hack_ignore_broadcast_startup_wait_period
            && (self.state.start_time + self.constants.broadcast_delivery_time > now)
        {
            log::debug!("Filtering broadcast, network started too recently.");
            return true;
        }

        let key = (
            nwk_frame.nwk_header.source,
            nwk_frame.nwk_header.sequence_number,
        );

        // Clean a stale entry first, if one exists.
        let mut broadcast_transaction_table = self
            .state
            .broadcast_transaction_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();

        if let Some(entry) = broadcast_transaction_table.get(&key)
            && entry.expiration_time > now
        {
            return true;
        }

        broadcast_transaction_table.insert(
            key,
            NwkBroadcastTransaction {
                source_nwk: nwk_frame.nwk_header.source,
                sequence_number: nwk_frame.nwk_header.sequence_number,
                expiration_time: now + self.constants.broadcast_delivery_time,
            },
        );

        false
    }

    pub fn handle_decrypted_frame(&self, nwk_frame: &NwkFrame, sender_nwk: Nwk, lqi: u8, rssi: i8) {
        // Update the frame counter for the relaying device
        if let Some(aux_header) = &nwk_frame.aux_header
            && let Some(relaying_eui64) = aux_header.extended_source
        {
            self.state
                .security_material_primary
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .incoming_frame_counter_set
                .insert(relaying_eui64, aux_header.frame_counter);

            log::debug!(
                "Incremented frame counter for {relaying_eui64:?} to {}",
                aux_header.frame_counter
            );
        }

        // Update the address cache
        if let Some(src_eui64) = nwk_frame.nwk_header.source_ieee {
            self.update_nwk_eui64_mapping(nwk_frame.nwk_header.source, src_eui64);
        }

        // Handle LQA calculation
        self.maybe_age_neighbors();
        self.maybe_recompute_lqa(nwk_frame, lqi, rssi);

        // Ignore frames that aren't destined for us
        if nwk_frame.nwk_header.destination.as_u16()
            >= BROADCAST_ALL_ROUTERS_AND_COORDINATOR.as_u16()
            && self.filter_broadcast(nwk_frame)
        {
            log::debug!("Filtering broadcast, stopping further processing");
            return;
        }

        // Handle NWK commands
        if nwk_frame.nwk_header.frame_control.frame_type == NwkFrameType::Command {
            match NwkCommandId::try_from(nwk_frame.payload[0]) {
                Ok(NwkCommandId::LinkStatus) => {
                    // TODO: Error handling for decoding?
                    log::info!("Link status command frame received");
                    self.handle_link_status(nwk_frame, lqi);
                }
                Ok(NwkCommandId::RouteReply) => {
                    // TODO: Error handling for decoding?
                    log::info!("Route reply command frame received");
                    self.handle_route_reply(nwk_frame);
                }
                Ok(NwkCommandId::RouteRecord) => {
                    // TODO: Error handling for decoding?
                    let route_record_cmd =
                        NwkRouteRecordCommand::deserialize(&nwk_frame.payload).unwrap();
                    log::info!("Route record command frame received: {route_record_cmd:#?}");
                    self.state
                        .route_record_table
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap()
                        .insert(nwk_frame.nwk_header.source, route_record_cmd.relays);
                }
                Ok(NwkCommandId::RouteRequest) => {
                    log::info!("Route request command frame received");
                    self.handle_route_request(nwk_frame, sender_nwk);
                }
                Err(_) => {
                    log::warn!("Unknown NWK command: {}", nwk_frame.payload[0]);
                }
                _ => {
                    log::warn!("Unhandled NWK command: {:?}", nwk_frame.payload[0]);
                }
            }
        }
    }

    fn maybe_recompute_lqa(&self, nwk_frame: &NwkFrame, lqi: u8, _rssi: i8) {
        // Find the source node via its EUI64 address (preferred) or its NWK address
        let mut neighbor_table = self
            .state
            .neighbor_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();

        match if nwk_frame.nwk_header.source_ieee.is_some() {
            neighbor_table.get_mut(&nwk_frame.nwk_header.source_ieee.unwrap())
        } else {
            neighbor_table
                .values_mut()
                .find(|e| e.network_address == nwk_frame.nwk_header.source)
        } {
            None => {}
            Some(entry) => {
                entry.lqas.push_back(lqi);

                if entry.lqas.len() > LINK_QUALITY_SAMPLES {
                    entry.lqas.pop_front();
                }
            }
        }
    }

    fn maybe_age_neighbors(&self) {
        // TODO: this function should be replaced by real timers
        let now = Instant::now();
        let max_neighbor_age =
            (self.constants.router_age_limit as u32) * self.constants.link_status_period;

        for neighbor in self
            .state
            .neighbor_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .values_mut()
        {
            if neighbor.outgoing_cost > 0
                && neighbor.last_link_status_timestamp >= now + max_neighbor_age
            {
                neighbor.lqas.truncate(0);
                neighbor.outgoing_cost = 0;

                log::warn!("Neighbor {neighbor:?} has ceased communicating, resetting link costs")
            }
        }
    }

    #[allow(clippy::significant_drop_tightening)]
    fn handle_link_status(&self, nwk_frame: &NwkFrame, lqi: u8) {
        let link_status_cmd = match NwkLinkStatusCommand::deserialize(&nwk_frame.payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                log::warn!("Error parsing link status command: {e:?}");
                return;
            }
        };

        log::info!("Link status command frame: {link_status_cmd:#?}");

        // We collect a list of neighbors with non-zero outgoing cost up here, before
        // mutating the state
        self.maybe_age_neighbors();

        let Some(source_ieee) = nwk_frame.nwk_header.source_ieee else {
            log::warn!("Link status command source EUI64 is missing");
            return;
        };

        let neighbors_with_nonzero_outgoing_cost = self
            .state
            .neighbor_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .iter()
            .filter_map(|(_, neighbor_entry)| {
                if neighbor_entry.outgoing_cost > 0 {
                    Some(neighbor_entry.network_address)
                } else {
                    None
                }
            })
            .collect::<HashSet<Nwk>>();

        let mut neighbor_table = self
            .state
            .neighbor_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();

        let neighbor_entry = neighbor_table.entry(source_ieee).or_insert_with(|| {
            // Create one
            log::info!("Creating new neighbor entry for {source_ieee:?}");

            let mut entry = neighbor::TableEntry {
                extended_address: source_ieee,
                network_address: nwk_frame.nwk_header.source,
                device_type: NwkDeviceType::Router,
                rx_on_when_idle: true,
                end_device_configuration: 0x0000,
                timeout_at: Instant::now() + Duration::from_secs(0xFFFFFFFF),
                device_timeout_at: Instant::now() + Duration::from_secs(0xFFFFFFFF),
                relationship: neighbor::Relationship::Sibling,
                transmit_failure: 0,
                lqas: VecDeque::new(),
                outgoing_cost: 0,
                last_link_status_timestamp: Instant::now(),
                incoming_beacon_timestamp: 0,
                beacon_transmission_time_offset: 0,
                keepalive_received: true,
                mac_unicast_bytes_transmitted: 0,
                mac_unicast_bytes_received: 0,
                router_added_timestamp: Instant::now(),
                router_connectivity: 0,
                router_neighbor_set_diversity: 0,
                router_outbound_activity: 0,
                router_inbound_activity: 0,
                security_timer: 0,
            };

            // Update the neighbor's LQI deque here, since we did not do so earlier
            // when receiving the packet (since the entry was missing)
            entry.lqas.push_back(lqi);

            entry
        });

        neighbor_entry.last_link_status_timestamp = Instant::now();

        if link_status_cmd.is_first_frame {
            neighbor_entry.router_connectivity = 0;
            neighbor_entry.router_neighbor_set_diversity = 0;
            neighbor_entry.outgoing_cost = 0; // If we do not find it in the list, it is 0
        }

        for link_status in link_status_cmd.link_statuses.iter() {
            if link_status.outgoing_cost > 0 {
                let connectivity =
                    7 - cmp::max(link_status.incoming_cost, link_status.outgoing_cost);

                neighbor_entry.router_connectivity = neighbor_entry
                    .router_connectivity
                    .saturating_add(connectivity);

                if !neighbors_with_nonzero_outgoing_cost.contains(&link_status.address) {
                    neighbor_entry.router_neighbor_set_diversity = neighbor_entry
                        .router_neighbor_set_diversity
                        .saturating_add(connectivity);
                }
            }

            if link_status.address == self.state.network_address {
                neighbor_entry.outgoing_cost = link_status.incoming_cost;
            }
        }

        if link_status_cmd.link_statuses.is_empty() {
            // TODO: Initiate a gratuitous link status broadcast, jittered by
            // nwkcMinRouterBootstrapJitter < nwkcMaxRouterBootstrapJitter
        }

        log::debug!("Updated neighbor table entry: {neighbor_entry:#?}");
    }

    fn notify_routing_change(&self, nwk: &Nwk) {
        let tx = {
            let pending_route_notifications = self
                .state
                .pending_route_notifications
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            if !pending_route_notifications.contains_key(nwk) {
                return;
            }

            pending_route_notifications.get(nwk).unwrap().clone()
        };
        let _ = tx.send(());
    }

    #[allow(clippy::significant_drop_tightening)]
    fn handle_route_reply(&self, nwk_frame: &NwkFrame) {
        let route_reply_cmd = match NwkRouteReplyCommand::deserialize(&nwk_frame.payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                log::warn!("Error parsing route reply command: {e:?}");
                return;
            }
        };

        log::info!("Route reply command frame: {route_reply_cmd:#?}");

        // Both `responder_eui64` and `originator_eui64` SHALL be set according to the
        // R23 spec but real devices do not do this

        let our_nwk_address = self.state.network_address;

        let neighbor_table = self
            .state
            .neighbor_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();
        let neighbor = {
            match neighbor_table
                .values()
                .find(|&entry| entry.network_address == nwk_frame.nwk_header.source)
            {
                Some(neighbor) => neighbor,
                None => {
                    log::debug!("Ignoring route reply from unknown neighbor");
                    return;
                }
            }
        };

        if neighbor.outgoing_cost == 0 {
            log::debug!("Ignoring route reply from neighbor with zero outgoing cost");
            return;
        }

        let updated_path_cost = route_reply_cmd
            .path_cost
            .saturating_add(neighbor.outgoing_cost);

        let route_discovery_table_key = (
            route_reply_cmd.originator_nwk,
            route_reply_cmd.route_request_identifier,
        );

        let next_hop_nwk;

        // Hold mutable references to `route_table` and `route_discovery_table` for as
        // little time as possible.
        {
            let mut route_discovery_table = self
                .state
                .route_discovery_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            let Some(discovery_entry) = route_discovery_table.get_mut(&route_discovery_table_key)
            else {
                log::debug!("Route reply for unknown route discovery, ignoring");
                return;
            };

            let mut route_table = self
                .state
                .route_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            let Some(routing_entry) = route_table.get_mut(&route_reply_cmd.responder_nwk) else {
                log::debug!("Route reply with unknown responder, ignoring");
                return;
            };

            // If we are the originator, handling is simplified
            if route_reply_cmd.originator_nwk == our_nwk_address {
                match routing_entry.status {
                    route::Status::Inactive
                    | route::Status::DiscoveryFailed  // Is this correct to have?
                    | route::Status::DiscoveryUnderway => {
                        log::debug!("Setting routing entry for NWK {:?} to active, with next hop {:?} (residual cost {})", 
                            route_reply_cmd.responder_nwk,
                            nwk_frame.nwk_header.source,
                            updated_path_cost);

                        // Mutate the routing entry
                        routing_entry.status = route::Status::Active;
                        routing_entry.next_hop_address = nwk_frame.nwk_header.source;

                        // Mutate the discovery entry
                        discovery_entry.residual_cost = updated_path_cost;

                        self.notify_routing_change(&route_reply_cmd.responder_nwk);
                    },
                    route::Status::Active => {
                        if updated_path_cost >= discovery_entry.residual_cost {
                            log::debug!("Ignoring route reply for us with higher cost ({} > {})", updated_path_cost, discovery_entry.residual_cost);
                            return;
                        }


                        log::debug!("Updating routing entry for NWK {:?} from next hop {:?} (residual cost {}) to next hop {:?} (residual cost {})",
                            route_reply_cmd.responder_nwk,
                            routing_entry.next_hop_address,
                            discovery_entry.residual_cost,
                            nwk_frame.nwk_header.source,
                            updated_path_cost);

                        // Mutate the routing entry
                        routing_entry.next_hop_address = nwk_frame.nwk_header.source;

                        // Mutate the discovery entry
                        discovery_entry.residual_cost = updated_path_cost;

                        self.notify_routing_change(&route_reply_cmd.responder_nwk);
                    },
                }

                return;
            }

            // Otherwise, we need to decide if we need to update our own routes and possibly
            // relay the frame
            if updated_path_cost >= discovery_entry.residual_cost {
                log::debug!(
                    "Ignoring unsolicited route reply with higher cost ({} > {})",
                    updated_path_cost,
                    discovery_entry.residual_cost
                );
                return;
            }

            // Mutate the routing entry
            routing_entry.next_hop_address = nwk_frame.nwk_header.source;

            // Mutate the discovery entry
            discovery_entry.residual_cost = updated_path_cost;

            // Find the next hop to the destination
            next_hop_nwk = discovery_entry.sender_address;
        }

        self.notify_routing_change(&route_reply_cmd.responder_nwk);

        let Some(next_hop_neighbor) = neighbor_table
            .values()
            .find(|&entry| entry.network_address == next_hop_nwk)
        else {
            log::warn!("Next hop neighbor not found in neighbor table");
            return;
        };

        let relayed_route_reply_frame = NwkFrame {
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Command,
                    protocol_version: self.constants.protocol_version,
                    discover_route: NwkRouteDiscovery::Suppress,
                    multicast: false,
                    security: true,
                    source_route: false,
                    destination: true,
                    extended_source: true,
                    end_device_initiator: false,
                },
                destination: next_hop_nwk,
                source: self.state.network_address,
                radius: 2 * self.constants.max_depth,
                sequence_number: *self
                    .state
                    .sequence_number
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap(),
                destination_ieee: nwk_frame.nwk_header.source_ieee,
                source_ieee: Some(self.state.ieee_address),
                multicast_control: None,
                source_route: None,
            },
            aux_header: None,
            payload: NwkRouteReplyCommand {
                route_request_identifier: route_reply_cmd.route_request_identifier,
                originator_nwk: route_reply_cmd.originator_nwk,
                responder_nwk: route_reply_cmd.responder_nwk,
                // We increment the path cost
                path_cost: updated_path_cost.saturating_add(next_hop_neighbor.incoming_link_cost()),
                originator_eui64: route_reply_cmd.originator_eui64,
                responder_eui64: route_reply_cmd.responder_eui64,
            }
            .serialize()
            .unwrap(),
        };

        self.background_send_nwk_frame(relayed_route_reply_frame);
    }

    /// Clean expired entries from the route discovery table. Their lifetime is ~10s.
    ///
    /// TODO: This table is going to be quite small so there is little benefit from
    /// making this a non-linear search. That being said, changing to a HashMap
    /// implementation that orders by expiration time while maintaining fast lookups
    /// would not hurt.
    ///
    /// TODO: Alternatively, we can look into a way to tie timers to these entries and
    /// expire them directly from the event loop.
    fn clean_route_discovery_table(&self) {
        let now = Instant::now();

        self.state
            .route_discovery_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .retain(|_, entry| {
                if entry.expiration_time <= now {
                    log::debug!("Removing expired route discovery entry: {entry:#?}");
                    false
                } else {
                    true
                }
            });
    }

    #[allow(clippy::significant_drop_tightening)]
    fn handle_route_request(&self, nwk_frame: &NwkFrame, sender_nwk: Nwk) {
        let route_request_cmd = match NwkRouteRequestCommand::deserialize(&nwk_frame.payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                log::warn!("Error parsing route request command: {e:?}");
                return;
            }
        };

        log::info!("Route request command frame (sender {sender_nwk:#?}): {route_request_cmd:#?}");

        let network_address = self.state.network_address;

        // Extract needed values from neighbor table and drop the lock early
        let (outgoing_cost, incoming_cost) = {
            let neighbor_table = self
                .state
                .neighbor_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            // We need to know who sent the frame
            let Some(sender_neighbor) = neighbor_table
                .values()
                .find(|&entry| entry.network_address == sender_nwk)
            else {
                // Can we do anything here? Broadcast an unsolicited link status?
                log::warn!("Route request relayer not found in neighbor table");
                return;
            };

            if sender_neighbor.outgoing_cost == 0 {
                log::warn!("Path cost to neighbor is 0, not sending route reply");
                return;
            }

            (
                sender_neighbor.outgoing_cost,
                sender_neighbor.incoming_link_cost(),
            )
        };

        // The maximum of the incoming and outgoing costs is used for computations to
        // deprioritize asymmetric routes
        let contributing_path_cost = cmp::max(outgoing_cost, incoming_cost);
        let updated_path_cost = route_request_cmd
            .path_cost
            .saturating_add(contributing_path_cost);

        // A route request contains enough information to build a provisional route
        // table entry via the relaying device. This is free routing information and
        // should be used.
        {
            let mut route_table = self
                .state
                .route_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            route_table
                .entry(route_request_cmd.destination_address)
                .and_modify(|entry| {
                    if entry.status != route::Status::Active {
                        entry.status = route::Status::Active;
                        entry.next_hop_address = sender_nwk;
                    }
                })
                .or_insert_with(|| {
                    route::TableEntry {
                        destination: route_request_cmd.destination_address,
                        status: route::Status::DiscoveryUnderway,
                        no_route_cache: false,
                        many_to_one: false,
                        route_record_required: false,
                        expired: false,
                        sequence_number_valid: false,
                        next_hop_address: Nwk(0xFFFF), // Unknown
                        sequence_number: 0,
                        total_usage_count: 0,
                        recent_activity: 0,
                    }
                });
        }

        self.notify_routing_change(&route_request_cmd.destination_address);

        // Create a routing table entry that assigns the node that last-relayed the
        // route request command to be the next-hop for the original sender
        {
            let mut route_table = self
                .state
                .route_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            route_table
                .entry(nwk_frame.nwk_header.source)
                .and_modify(|entry| {
                    if entry.status != route::Status::Active {
                        entry.status = route::Status::Active;
                        entry.next_hop_address = sender_nwk;
                    }
                })
                .or_insert_with(|| route::TableEntry {
                    destination: nwk_frame.nwk_header.source,
                    status: route::Status::Active,
                    no_route_cache: false,
                    many_to_one: false,
                    route_record_required: false,
                    expired: false,
                    sequence_number_valid: false,
                    next_hop_address: sender_nwk,
                    sequence_number: 0,
                    total_usage_count: 0,
                    recent_activity: 0,
                });
        }

        self.notify_routing_change(&nwk_frame.nwk_header.source);

        // TODO: what do we do if one of these values doesn't match? This would be
        // an error, some device on the network is storing invalid information about
        // either us or a child.
        let is_for_self_or_child = route_request_cmd.destination_address == network_address
            || route_request_cmd.destination_eui64 == Some(self.state.ieee_address)
            /* || destination_is_child */;

        // Check for a route discovery table entry. If one already exists and the
        // forward cost is better than what this route request advertises, we can drop
        // this frame.
        let route_discovery_table_key = (
            nwk_frame.nwk_header.source,
            route_request_cmd.route_request_identifier,
        );

        if !is_for_self_or_child {
            self.clean_route_discovery_table();

            // Check if we should ignore this route request due to higher cost
            let mut route_discovery_table = self
                .state
                .route_discovery_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            let route_discovery_entry = route_discovery_table
                .entry(route_discovery_table_key)
                .or_insert_with(|| route::DiscoveryEntry {
                    route_request_id: route_request_cmd.route_request_identifier,
                    source_address: nwk_frame.nwk_header.source,
                    sender_address: sender_nwk,
                    forward_cost: updated_path_cost,
                    residual_cost: 0,
                    expiration_time: Instant::now() + self.constants.route_discovery_time,
                    destination_address: route_request_cmd.destination_address,
                });

            log::debug!(
                "Route discovery entry: [{route_discovery_table_key:?}] = {route_discovery_entry:#?}"
            );

            if route_discovery_entry.forward_cost < updated_path_cost {
                log::debug!("Ignoring route request with higher cost");
                return;
            }

            // Create an entry in the routing table as well
            self.state
                .route_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .entry(route_request_cmd.destination_address)
                .or_insert_with(|| route::TableEntry {
                    destination: route_request_cmd.destination_address,
                    status: route::Status::DiscoveryUnderway,
                    no_route_cache: false,
                    many_to_one: false,
                    route_record_required: false,
                    expired: false,
                    sequence_number_valid: false,
                    next_hop_address: Nwk(0xFFFF),
                    sequence_number: 0,
                    total_usage_count: 0,
                    recent_activity: 0,
                });

            // If we get here, we have a reason to relay
            let rebroadcast_radius = nwk_frame.nwk_header.radius.saturating_sub(1);

            if rebroadcast_radius == 0 {
                log::debug!("Not relaying route request, re-broadcast radius is 0");
                return;
            }

            let relayed_route_request_cmd = NwkFrame {
                nwk_header: NwkHeader {
                    frame_control: NwkFrameControl {
                        frame_type: NwkFrameType::Command,
                        protocol_version: self.constants.protocol_version,
                        discover_route: NwkRouteDiscovery::Suppress,
                        multicast: false,
                        security: true,
                        source_route: false,
                        destination: true,
                        extended_source: true,
                        end_device_initiator: false,
                    },
                    destination: nwk_frame.nwk_header.destination,
                    source: nwk_frame.nwk_header.source,
                    radius: rebroadcast_radius,
                    // TODO: do we change this?
                    sequence_number: *self
                        .state
                        .sequence_number
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap(),
                    destination_ieee: nwk_frame.nwk_header.source_ieee,
                    source_ieee: nwk_frame.nwk_header.source_ieee,
                    multicast_control: None,
                    source_route: None,
                },
                aux_header: None, // will be replaced
                payload: NwkRouteRequestCommand {
                    many_to_one: route_request_cmd.many_to_one,
                    route_request_identifier: route_request_cmd.route_request_identifier,
                    destination_address: route_request_cmd.destination_address,
                    path_cost: updated_path_cost, // We update only the path cost
                    destination_eui64: route_request_cmd.destination_eui64,
                }
                .serialize()
                .unwrap(),
            };

            self.background_send_nwk_frame(relayed_route_request_cmd);
        } else {
            let route_reply_frame = NwkFrame {
                nwk_header: NwkHeader {
                    frame_control: NwkFrameControl {
                        frame_type: NwkFrameType::Command,
                        protocol_version: self.constants.protocol_version,
                        discover_route: NwkRouteDiscovery::Suppress,
                        multicast: false,
                        security: true,
                        source_route: false,
                        destination: true,
                        extended_source: true,
                        end_device_initiator: false,
                    },
                    destination: nwk_frame.nwk_header.source,
                    source: self.state.network_address,
                    radius: 2 * self.constants.max_depth,
                    sequence_number: *self
                        .state
                        .sequence_number
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap(),
                    destination_ieee: nwk_frame.nwk_header.source_ieee,
                    source_ieee: Some(self.state.ieee_address),
                    multicast_control: None,
                    source_route: None,
                },
                aux_header: None,
                payload: NwkRouteReplyCommand {
                    route_request_identifier: route_request_cmd.route_request_identifier,
                    originator_nwk: nwk_frame.nwk_header.source,
                    responder_nwk: self.state.network_address,
                    path_cost: updated_path_cost,
                    originator_eui64: nwk_frame.nwk_header.source_ieee,
                    responder_eui64: Some(self.state.ieee_address),
                }
                .serialize()
                .unwrap(),
            };

            self.background_send_nwk_frame(route_reply_frame);
        }
    }

    fn handle_aps_ack_request(&self, aps_frame: &ApsDataFrame, nwk_frame: &NwkFrame) {
        log::debug!("Sending back an APS ACK");

        let aps_ack_frame = NwkFrame {
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Data,
                    protocol_version: self.constants.protocol_version,
                    discover_route: NwkRouteDiscovery::Enable,
                    multicast: false,
                    security: true,
                    source_route: false,
                    destination: false,
                    extended_source: false,
                    end_device_initiator: false,
                },
                // Send our ACK back to the sender
                destination: nwk_frame.nwk_header.source,
                source: self.state.network_address,
                radius: 2 * self.constants.max_depth,
                sequence_number: *self
                    .state
                    .sequence_number
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap(),
                destination_ieee: None,
                source_ieee: None,
                multicast_control: None,
                source_route: None,
            },
            aux_header: None, // will be replaced
            payload: ApsAckFrame {
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
        };

        self.background_send_nwk_frame(aps_ack_frame);
    }

    async fn send_802154_frame(&self, mut frame: Ieee802154Frame) -> Result<(), ZigbeeStackError> {
        // Increment the 802.15.4 sequence number
        if !frame.frame_control.sequence_number_suppression {
            let mut ieee802154_sequence_number = self
                .state
                .ieee802154_sequence_number
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            *ieee802154_sequence_number = ieee802154_sequence_number.wrapping_add(1);

            frame.sequence_number = Some(*ieee802154_sequence_number);
        }

        log::info!("Sending 802.15.4 frame: {frame:#?}");
        log::info!("Sending 802.15.4 frame bytes: {:02X?}", frame.to_bytes());

        if self.state.hack_disable_tx {
            log::debug!("Not transmitting the frame, TX is disabled");
            return Ok(());
        }

        let status = self
            .spinel
            .transmit_frame(&SpinelTxFrame {
                psdu: frame.to_bytes(),
                channel: { Some(*self.state.channel.try_lock_for(MAX_LOCK_DURATION).unwrap()) },
                max_csma_backoffs: Some(1),
                max_frame_retries: Some(5),
                enable_csma_ca: Some(true),
                is_header_updated: Some(true),
                is_a_retransmit: Some(false),
                is_security_processed: Some(true),
                // Omit subsequent fields to reduce serial traffic
                tx_delay: None,            // Some(0 as u32),
                tx_delay_base_time: None,  // Some(0 as u32),
                rx_channel_after_tx: None, // Some(channel),
                tx_power: None,            // Some(8),
            })
            .await
            .expect("Failed to transmit frame");

        if status == SpinelStatus::Ok {
            Ok(())
        } else if status == SpinelStatus::NoAck {
            let next_hop = match frame.dest_address.unwrap() {
                Ieee802154Address::Nwk(nwk) => Some(nwk),
                _ => None,
            }
            .expect("Next 802.15.4. hop must have NWK addressing");

            return Err(ZigbeeStackError::NwkNoAck { next_hop });
        } else if status == SpinelStatus::CcaFailure {
            return Err(ZigbeeStackError::CcaFailure);
        } else {
            return Err(ZigbeeStackError::SpinelTransmitFailure(status));
        }
    }

    pub fn background_send_nwk_frame(&self, nwk_frame: NwkFrame) {
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        spawn_local(async move {
            arc_self
                .send_nwk_frame(nwk_frame)
                .await
                .unwrap_or_else(|err| {
                    log::error!("Failed to send NWK frame: {err}");
                });
        });
    }

    pub async fn send_nwk_frame(&self, nwk_frame: NwkFrame) -> Result<(), ZigbeeStackError> {
        if nwk_frame.nwk_header.destination.as_u16() >= BROADCAST_LOW_POWER_ROUTERS.as_u16() {
            self.send_broadcast_nwk_frame(nwk_frame).await
        } else {
            self.send_unicast_nwk_frame(nwk_frame).await
        }
    }

    pub fn next_nwk_frame_counter(&self) -> u32 {
        let mut security_material_primary = self
            .state
            .security_material_primary
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();
        security_material_primary.outgoing_frame_counter = security_material_primary
            .outgoing_frame_counter
            .wrapping_add(1);

        security_material_primary.outgoing_frame_counter
    }

    pub async fn send_unicast_nwk_frame(
        &self,
        mut nwk_frame: NwkFrame,
    ) -> Result<(), ZigbeeStackError> {
        // Compute a next-hop address
        let next_hop_address = self
            .discover_route(nwk_frame.nwk_header.destination)
            .await?;

        nwk_frame.nwk_header.sequence_number = {
            let mut sequence_number = self
                .state
                .sequence_number
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            *sequence_number = sequence_number.wrapping_add(1);
            *sequence_number
        };

        nwk_frame.aux_header = Some(NwkAuxHeader {
            security_control: NwkSecurityHeaderControlField {
                security_level: NwkSecurityLevel::NoSecurity,
                key_id: NwkSecurityHeaderKeyId::NetworkKey,
                extended_nonce: true,
                require_verified_frame_counter: false,
            },
            frame_counter: 0, // This field is rewritten and is always up-to-date
            extended_source: Some(self.state.ieee_address),
            key_sequence_number: self.state.active_key_seq_number,
        });

        for attempt in 0..=self.constants.unicast_retries {
            // The encryption frame counter always increments
            nwk_frame.aux_header.as_mut().unwrap().frame_counter = self.next_nwk_frame_counter();

            let encrypted_nwk_frame = nwk_frame.encrypt(
                &self
                    .state
                    .security_material_primary
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .key,
            );

            let ieee802154_frame = Ieee802154Frame {
                frame_control: Ieee802154FrameControl {
                    frame_type: Ieee802154FrameType::Data,
                    security_enabled: false,
                    frame_pending: false,
                    ack_request: true,
                    pan_id_compression: true,
                    reserved1: false,
                    sequence_number_suppression: false,
                    information_elements_present: false,
                    dest_addr_mode: Ieee802154AddressingMode::Short,
                    frame_version: 0,
                    src_addr_mode: Ieee802154AddressingMode::Short,
                },
                sequence_number: Some(
                    *self
                        .state
                        .ieee802154_sequence_number
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap(),
                ),
                dest_pan_id: Some(*self.state.pan_id.try_lock_for(MAX_LOCK_DURATION).unwrap()),
                dest_address: Some(Ieee802154Address::Nwk(next_hop_address)),
                src_pan_id: None,
                src_address: Some(Ieee802154Address::Nwk(self.state.network_address)),
                payload: encrypted_nwk_frame.to_bytes(),
                fcs: 0x0000, // It'll be replaced
            };

            // When forwarding packets to another node, update the counters for the neighbor
            // TODO: maybe wrap the send state into some sort of struct to avoid
            // needing to do this?
            if let Some(relaying_ieee) = self
                .state
                .address_map
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .iter()
                .find_map(|(&eui64, &nwk)| {
                    if nwk == next_hop_address {
                        Some(eui64)
                    } else {
                        None
                    }
                })
                && let Some(neighbor_entry) = self
                    .state
                    .neighbor_table
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .get_mut(&relaying_ieee)
            {
                // Update the neighbor table counters
                neighbor_entry.router_outbound_activity =
                    neighbor_entry.router_outbound_activity.saturating_add(1);
            }

            // And the routing table counters
            if let Some(route_entry) = self
                .state
                .route_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .get_mut(&nwk_frame.nwk_header.destination)
            {
                route_entry.recent_activity = route_entry.recent_activity.saturating_add(1);
                route_entry.total_usage_count = route_entry.total_usage_count.saturating_add(1);
            }

            // Increment counters before sending
            let tx_total = {
                let mut tx_total = self.state.tx_total.try_lock_for(MAX_LOCK_DURATION).unwrap();
                *tx_total = tx_total.wrapping_add(1);
                *tx_total
            };

            // Handle `tx_total` wrapping
            if tx_total == 0x0000 {
                for (_, neighbor) in self
                    .state
                    .neighbor_table
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .iter_mut()
                {
                    neighbor.transmit_failure = 0;
                }
            }

            match self.send_802154_frame(ieee802154_frame).await {
                Ok(_) => {
                    break;
                }
                Err(e) => {
                    log::warn!("Failed to send unicast frame: {e}");

                    if attempt + 1 > self.constants.unicast_retries {
                        log::error!("Failed to send unicast frame after {attempt} attempts");
                        return Err(e);
                    }
                    log::debug!(
                        "Retrying unicast frame send, attempt {} of {}",
                        attempt,
                        self.constants.unicast_retries
                    );

                    tokio::time::sleep(self.constants.unicast_retry_delay).await;
                }
            }
        }

        Ok(())
    }

    pub async fn send_broadcast_nwk_frame(
        &self,
        mut nwk_frame: NwkFrame,
    ) -> Result<(), ZigbeeStackError> {
        nwk_frame.nwk_header.sequence_number = {
            let mut sequence_number = self
                .state
                .sequence_number
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            *sequence_number = sequence_number.wrapping_add(1);
            *sequence_number
        };

        nwk_frame.aux_header = Some(NwkAuxHeader {
            security_control: NwkSecurityHeaderControlField {
                security_level: NwkSecurityLevel::NoSecurity,
                key_id: NwkSecurityHeaderKeyId::NetworkKey,
                extended_nonce: true,
                require_verified_frame_counter: false,
            },
            frame_counter: 0, // This field is rewritten and is always up-to-date
            extended_source: Some(self.state.ieee_address),
            key_sequence_number: self.state.active_key_seq_number,
        });

        for attempt in 0..=self.constants.max_broadcast_retries {
            // The encryption frame counter always increments
            nwk_frame.aux_header.as_mut().unwrap().frame_counter = self.next_nwk_frame_counter();

            let encrypted_nwk_frame = nwk_frame.encrypt(
                &self
                    .state
                    .security_material_primary
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .key,
            );

            let ieee802154_frame = Ieee802154Frame {
                frame_control: Ieee802154FrameControl {
                    frame_type: Ieee802154FrameType::Data,
                    security_enabled: false,
                    frame_pending: false,
                    ack_request: false,
                    pan_id_compression: true,
                    reserved1: false,
                    sequence_number_suppression: false,
                    information_elements_present: false,
                    dest_addr_mode: Ieee802154AddressingMode::Short,
                    frame_version: 0,
                    src_addr_mode: Ieee802154AddressingMode::Short,
                },
                sequence_number: Some(
                    *self
                        .state
                        .ieee802154_sequence_number
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap(),
                ),
                dest_pan_id: Some(*self.state.pan_id.try_lock_for(MAX_LOCK_DURATION).unwrap()),
                // All broadcasts are sent to the 802.15.4 broadcast address, since the
                // distinction between Zigbee groups and broadcasts is at a higher layer
                dest_address: Some(Ieee802154Address::Nwk(Nwk(0xFFFF))),
                src_pan_id: None,
                src_address: Some(Ieee802154Address::Nwk(self.state.network_address)),
                payload: encrypted_nwk_frame.to_bytes(),
                fcs: 0x0000, // It'll be replaced
            };

            // Increment counters before sending
            let tx_total = {
                let mut tx_total = self.state.tx_total.try_lock_for(MAX_LOCK_DURATION).unwrap();
                *tx_total = tx_total.wrapping_add(1);
                *tx_total
            };

            // Handle `tx_total` wrapping
            if tx_total == 0x0000 {
                for (_, neighbor) in self
                    .state
                    .neighbor_table
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .iter_mut()
                {
                    neighbor.transmit_failure = 0;
                }
            }

            // TODO: implement logic to detect when broadcasts have been successfully
            // sent. This is done by keeping track of which neighbor routers have been
            // "heard" relaying it. For now, we just retry a few times.
            let _ = self.send_802154_frame(ieee802154_frame).await;

            let sleep_time = self
                .constants
                .max_broadcast_jitter
                .mul_f32(rand::random::<f32>());
            log::debug!(
                "Retrying broadcast frame send, attempt {} of {} in {:?}",
                attempt,
                self.constants.max_broadcast_retries,
                sleep_time,
            );

            tokio::time::sleep(sleep_time).await;
        }

        Ok(())
    }

    #[allow(clippy::significant_drop_tightening)]
    pub async fn discover_route(&self, destination: Nwk) -> Result<Nwk, ZigbeeStackError> {
        if self.state.hack_force_route_discovery
            || !{
                self.state
                    .route_table
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .contains_key(&destination)
            }
        {
            log::debug!("Starting route discovery for NWK {destination:?}");
            self.send_route_discovery(destination).await;
        }

        let (route_entry_status, route_entry_next_hop_address) = {
            let route_table = self
                .state
                .route_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            let entry = route_table.get(&destination).unwrap();

            (entry.status, entry.next_hop_address)
        };

        log::debug!("Routing table status for {destination:?}: {route_entry_status:?}");

        // A route table entry will now exist
        match route_entry_status {
            route::Status::Active => {
                assert!(route_entry_next_hop_address != Nwk(0xFFFF));
                log::debug!(
                    "Using existing next hop for NWK {destination:?}: {route_entry_next_hop_address:?}"
                );
                return Ok(route_entry_next_hop_address);
            }
            route::Status::DiscoveryUnderway => {
                // Do nothing
            }
            route::Status::DiscoveryFailed | route::Status::Inactive => {
                self.send_route_discovery(destination).await;
            }
        }

        // Create a pending route notification
        let mut rx = {
            let mut pending_route_notifications = self
                .state
                .pending_route_notifications
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            let tx = pending_route_notifications
                .entry(destination)
                .or_insert_with(|| {
                    let (tx, _) = broadcast::channel(1);
                    tx
                });

            tx.subscribe()
        };

        // Pull the current route discovery entry for the device to determine the timeout
        let discovery_timeout = {
            let now = Instant::now();
            let route_discovery_table = self
                .state
                .route_discovery_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            // One should exist
            let route_discovery_entry =
                match route_discovery_table.iter().find_map(|(&(_, _), entry)| {
                    if entry.expiration_time >= now && entry.destination_address == destination {
                        Some(entry)
                    } else {
                        None
                    }
                }) {
                    Some(entry) => entry,
                    None => {
                        log::warn!("No route discovery entry found for {destination:?}");
                        return Err(ZigbeeStackError::RouteDiscoveryFailure(
                            "No discovery entry found".to_string(),
                        ));
                    }
                };

            route_discovery_entry.expiration_time - now
        };

        log::debug!(
            "Waiting for route discovery notification for NWK {destination:?} with timeout {discovery_timeout:?}"
        );

        match timeout(discovery_timeout, rx.recv()).await {
            Ok(_) => {
                log::debug!("Route discovery completed for NWK {destination:#?}");
            }
            Err(err) => {
                log::debug!("Route discovery timed out");
                let mut route_table = self
                    .state
                    .route_table
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap();
                let entry = route_table.get_mut(&destination).unwrap();
                entry.status = route::Status::DiscoveryFailed;
                return Err(ZigbeeStackError::RouteDiscoveryTimeout(err));
            }
        };

        let next_hop_address = self
            .state
            .route_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .get(&destination)
            .unwrap()
            .next_hop_address;

        Ok(next_hop_address)
    }

    #[allow(clippy::significant_drop_tightening)]
    pub async fn send_route_discovery(&self, destination: Nwk) {
        // Discover next hop route
        log::debug!("Sending route discovery for NWK {destination:?}");

        // Get or create a routing table entry without keeping a mutable reference
        {
            let mut route_table = self
                .state
                .route_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            let route_table_entry = route_table.entry(destination).or_insert_with(|| {
                route::TableEntry {
                    destination,
                    status: route::Status::Inactive,
                    no_route_cache: false,
                    many_to_one: false,
                    route_record_required: false,
                    expired: false,
                    sequence_number_valid: false,
                    next_hop_address: Nwk(0xFFFF), // Unknown
                    sequence_number: 0,
                    total_usage_count: 0,
                    recent_activity: 0,
                }
            });

            route_table_entry.status = route::Status::DiscoveryUnderway;
        }

        let route_request_identifier = {
            let mut routing_request_sequence_number = self
                .state
                .routing_request_sequence_number
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            *routing_request_sequence_number = routing_request_sequence_number.wrapping_add(1);
            *routing_request_sequence_number
        };

        let route_discovery_table_key = (self.state.network_address, route_request_identifier);

        // We initiated discovery so insert an entry keyed by our NWK and request ID
        let network_address = self.state.network_address;

        self.clean_route_discovery_table();

        {
            let mut route_discovery_table = self
                .state
                .route_discovery_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            let route_discovery_entry = route_discovery_table
                .entry(route_discovery_table_key)
                .or_insert_with(|| route::DiscoveryEntry {
                    route_request_id: route_request_identifier,
                    source_address: network_address,
                    sender_address: Nwk(0xFFFF),
                    forward_cost: 0,
                    residual_cost: 0,
                    expiration_time: Instant::now() + self.constants.route_discovery_time,
                    destination_address: destination,
                });

            log::debug!(
                "Route discovery entry: [{route_discovery_table_key:?}] = {route_discovery_entry:#?}"
            );
        }

        // If we know the EUI64 corresponding to the NWK, use it
        let destination_eui64 = self
            .state
            .address_map
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .iter()
            .find_map(|(&eui64, &nwk)| {
                if nwk == destination {
                    Some(eui64)
                } else {
                    None
                }
            });

        // Construct a frame
        let route_request_frame = NwkFrame {
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Command,
                    protocol_version: self.constants.protocol_version,
                    discover_route: NwkRouteDiscovery::Suppress,
                    multicast: false,
                    security: true,
                    source_route: false,
                    destination: false,
                    extended_source: true,
                    end_device_initiator: false,
                },
                destination: BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
                source: self.state.network_address,
                radius: 2 * self.constants.max_depth,
                sequence_number: *self
                    .state
                    .sequence_number
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap(),
                destination_ieee: None,
                source_ieee: Some(self.state.ieee_address),
                multicast_control: None,
                source_route: None,
            },
            aux_header: None, // will be replaced
            payload: NwkRouteRequestCommand {
                many_to_one: NwkRouteRequestManyToOne::NotManyToOne,
                route_request_identifier,
                destination_address: destination,
                path_cost: 0, // The path cost starts at 0, since we originate it
                destination_eui64,
            }
            .serialize()
            .unwrap(),
        };

        self.background_send_nwk_frame(route_request_frame);
    }

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
    ) -> Result<(), ZigbeeStackError> {
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

        let nwk_frame = NwkFrame {
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Data,
                    protocol_version: self.constants.protocol_version,
                    discover_route: NwkRouteDiscovery::Enable,
                    multicast: false,
                    security: true,
                    source_route: false,
                    destination: false,
                    extended_source: false,
                    end_device_initiator: false,
                },
                destination,
                source: self.state.network_address,
                radius: cmp::max(radius, 1),
                sequence_number: *self
                    .state
                    .sequence_number
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap(),
                destination_ieee: None,
                source_ieee: None,
                multicast_control: None,
                source_route: None,
            },
            aux_header: None, // will be replaced
            payload: aps_frame.to_bytes(),
        };

        log::debug!("Prepared NWK frame: {nwk_frame:#?}");

        if !aps_ack {
            self.background_send_nwk_frame(nwk_frame);
            return Ok(());
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
                .insert(ack_data, ack_tx);
        }

        self.background_send_nwk_frame(nwk_frame);

        // With a 5s timeout
        match tokio::time::timeout(APS_ACK_TIMEOUT, ack_rx).await {
            Ok(Ok(())) => {
                log::info!("APS ACK received");
            }
            Ok(Err(e)) => {
                log::warn!("APS ACK channel hung up: {e:?}");
                return Err(ZigbeeStackError::ApsAckTimeout);
            }
            Err(_) => {
                log::warn!("APS ACK timed out");
                return Err(ZigbeeStackError::ApsAckTimeout);
            }
        }

        Ok(())
    }

    pub async fn send_link_status_broadcast(&self, empty: bool) {
        log::debug!("Sending periodic link status broadcast");

        if self.state.network_address == Nwk(0xFFFF) {
            log::debug!("Skipping, stack has not been initialized yet");
            return;
        }

        // Decrement the `recent_activity` field of every active routing table entry
        for (_, route_table_entry) in self
            .state
            .route_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .iter_mut()
        {
            if route_table_entry.status == route::Status::Active {
                route_table_entry.recent_activity =
                    route_table_entry.recent_activity.saturating_sub(1);
            }
        }

        // Decrement the inbound and outbound activity fields for neighbors
        self.maybe_age_neighbors();

        for (_, neighbor_entry) in self
            .state
            .neighbor_table
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .iter_mut()
        {
            neighbor_entry.router_outbound_activity =
                neighbor_entry.router_outbound_activity.saturating_sub(1);
            neighbor_entry.router_inbound_activity =
                neighbor_entry.router_inbound_activity.saturating_sub(1);
        }

        let mut link_statuses = if !empty {
            self.state
                .neighbor_table
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .iter()
                .filter_map(|(_, neighbor)| {
                    // We only calculate link statuses for neighbors for which we have
                    // seen more than a few packets
                    neighbor.lqa().map(|lqa| NwkLinkStatus {
                        address: neighbor.network_address,
                        incoming_cost: lqi_to_link_cost(lqa),
                        outgoing_cost: neighbor.outgoing_cost,
                    })
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        // Link statuses are sorted in ascending order
        link_statuses.sort_by(|a, b| a.address.as_u16().cmp(&b.address.as_u16()));

        let max_link_statuses = 7;
        let mut remaining_link_statuses = link_statuses.clone();

        loop {
            let link_status_frame = NwkFrame {
                nwk_header: NwkHeader {
                    frame_control: NwkFrameControl {
                        frame_type: NwkFrameType::Command,
                        protocol_version: self.constants.protocol_version,
                        discover_route: NwkRouteDiscovery::Suppress,
                        multicast: false,
                        security: true,
                        source_route: false,
                        destination: false,
                        extended_source: true,
                        end_device_initiator: false,
                    },
                    destination: BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
                    source: self.state.network_address,
                    radius: 1,
                    sequence_number: *self
                        .state
                        .sequence_number
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap(),
                    destination_ieee: None,
                    source_ieee: Some(self.state.ieee_address),
                    multicast_control: None,
                    source_route: None,
                },
                aux_header: None, // will be replaced
                payload: NwkLinkStatusCommand {
                    is_first_frame: remaining_link_statuses.len() == link_statuses.len(),
                    is_last_frame: remaining_link_statuses.len() <= max_link_statuses,
                    link_statuses: if remaining_link_statuses.is_empty() {
                        vec![]
                    } else {
                        // Link status frames overlap by a single entry
                        remaining_link_statuses
                            .drain(..cmp::min(remaining_link_statuses.len(), max_link_statuses - 1))
                            .collect()
                    },
                }
                .serialize()
                .unwrap(),
            };

            self.background_send_nwk_frame(link_status_frame);

            if remaining_link_statuses.is_empty() {
                break;
            }
        }
    }

    pub async fn periodic_link_status_broadcast_task(&self) {
        loop {
            log::debug!("Sending periodic link status broadcast...");
            tokio::time::sleep(self.constants.link_status_period).await;

            self.send_link_status_broadcast(false).await;
        }
    }
}
