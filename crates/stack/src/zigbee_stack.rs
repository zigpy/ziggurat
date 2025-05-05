use crate::ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154Frame, Ieee802154FrameControl,
    Ieee802154FrameType,
};
use crate::spinel::{SpinelFramePropValueIs, SpinelPropertyId, SpinelStatus};
use crate::spinel_client::{SpinelClient, SpinelRxFrame, SpinelTxFrame};
use crate::types::{Eui64, Key, Nwk, PanId};

use crate::zigbee_aps::{
    ApsAckFrame, ApsAckFrameControl, ApsDataFrame, ApsDeliveryMode, ApsFrame, ApsFrameControl,
    ApsFrameType, parse_aps_frame,
};
use crate::zigbee_nwk::{
    BROADCAST_ALL_ROUTERS_AND_COORDINATOR, BROADCAST_RX_ON_WHEN_IDLE, NwkAuxHeader, NwkFrame,
    NwkFrameControl, NwkFrameType, NwkHeader, NwkRouteDiscovery, NwkSecurityHeaderControlField,
    NwkSecurityHeaderKeyId, NwkSecurityLevel,
};
use crate::zigbee_nwk_commands::{
    NwkCommandId, NwkLinkStatus, NwkLinkStatusCommand, NwkRouteRecordCommand, NwkRouteReplyCommand,
    NwkRouteRequestCommand, NwkRouteRequestManyToOne,
};

use std::cmp;
use std::collections::{HashMap, HashSet, VecDeque};
use std::mem::drop;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::spawn_local;
use tokio::time::{Duration, Instant};

mod neighbor;
mod route;

// The number of the most recent samples taken into consideration SHOULD be n = 3, which
// eliminates single outliers maintains a fast response to real changes in link quality,
// and keeps memory requirements to a minimum.
const LINK_QUALITY_SAMPLES: usize = 3;

/// Compute the link cost (1-7) based on the LQI (0-255).
fn lqi_to_link_cost(lqi: u8) -> u8 {
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

// TODO, cut this up (nib) into multiple structs

/// Zigbee spec: 3.5.2 NWK Information Base
///
/// The NWK information base (NIB) comprises the attributes required to manage
/// the NWK layer of a device. Each of these attributes can be read or
/// written using the NLME-GET.request and NLME-SET.request primitives,
/// respectively. Except those who are read only
#[derive(Debug)]
pub struct Nib {
    pub nwk_sequence_number: u8,
    pub nwk_passive_ack_timeout: Duration,
    pub nwk_max_broadcast_retries: u8,
    pub nwk_max_children: u8,
    pub nwk_max_depth: u8,
    pub nwk_neighbor_table: HashMap<Eui64, neighbor::TableEntry>,
    pub nwk_route_table: HashMap<Nwk, route::TableEntry>,
    pub nwk_route_discovery_table: HashMap<(Nwk, route::RequestId), route::DiscoveryEntry>,
    pub nwk_capability_information: NwkCapabilityInformation,
    pub nwk_manager_addr: Nwk,
    pub nwk_max_source_route: u8,
    pub nwk_update_id: u8,
    pub nwk_transaction_persistence_time: Duration,
    pub nwk_network_address: Nwk,
    pub nwk_stack_profile: u8,
    pub nwk_broadcast_transaction_table: HashMap<(Nwk, u8), NwkBroadcastTransaction>,
    pub nwk_extended_pan_id: Eui64,
    pub nwk_route_record_table: HashMap<Nwk, Vec<Nwk>>,
    pub nwk_is_concentrator: bool,
    pub nwk_concentrator_radius: u8,
    pub nwk_concentrator_discovery_time: Duration,
    pub nwk_security_level: u8,
    pub nwk_security_material_primary: NwkSecurityDescriptor,
    pub nwk_security_material_alternate: NwkSecurityDescriptor,
    pub nwk_active_key_seq_number: u8,
    pub nwk_all_fresh: bool,

    /// The minimum time, in seconds, between two consecutive concentrator route
    /// discoveries. If set to 0x00, there is no minimum separation. This only applies
    /// when the device is operating as a Concentrator.
    pub nwk_concentrator_discovery_separation_time: Duration,

    /// The time between link status command frames.
    pub nwk_link_status_period: Duration,

    /// The number of missed link status command frames before resetting the link costs
    /// to zero.
    pub nwk_router_age_limit: u8,
    pub nwk_address_map: HashMap<Eui64, Nwk>,

    /// A flag that determines if a timestamp indication is provided on incoming and
    /// outgoing packets.
    pub nwk_time_stamp: bool,

    pub nwk_pan_id: PanId,

    /// A count of Unicast transmissions made by the NNK layer on this device.
    /// Each time the NWK layer transmits a Unicast frame, by invoking the
    /// MCPS-state.request primitive of the MAC sub-layer, it SHALL increment
    /// this counter. When either the NHL performs an NLME-SET.request on this
    /// attribute or if the value of `nwk_tx_total` rolls over past 0xffff the
    /// NWK layer SHALL reset to 0x00 each Transmit Failure field contained in
    /// the neighbor table.
    pub nwk_tx_total: u16,

    /// This policy determines whether or not a remote NWK leave request command frame
    /// received by the local device is accepted.
    pub nwk_leave_request_allowed: bool,

    pub nwk_parent_information: u8,

    /// This is an index into Table 3-54. It indicates the default timeout in minutes for
    /// any end device that does not negotiate a different timeout value.
    pub nwk_end_device_timeout_default: u8,

    /// This policy determines whether a NWK leave request is accepted when the Rejoin
    /// bit in the message is set to FALSE
    pub nwk_leave_request_without_rejoin_allowed: bool,

    pub nwk_ieee_address: Eui64,

    // A strictly increasing sequence number included in all route request and route
    // reply command frames to allow other routers to determine the chronological order
    // of such route discovery messages.
    // pub nwk_routing_sequence_number: u16,  // Only needed for R23 TLVs

    /// Implied from the spec: "notice that this 8-bit identifier is distinct from the
    /// 16-bit Routing Sequence Number. The former is used to discern route requests
    /// originating in a particular router; the latter is used to identify stale routing
    /// information."
    pub nwk_routing_request_sequence_number: u8,

    /// This indicates whether the router has Hub Connectivity as defined by a higher
    /// level application. The higher level application sets this value and the stack
    /// advertises it.
    pub nwk_hub_connectivity: bool,

    // nwkMacInterfaceTable
    // nwkNetworkWideBeaconAppendixTLVs
    // nwkDeviceLocalBeaconAppendixTLVs
    // nwkDiscoveryTable
    // nwkDiscoveryTableSize = 6
    // nwkNextPanId = 0xFFFF
    // nwkNextChannelChange = 0
    // nwkPerformAdditionalMacDataPollRetries = 0
    // nwkPreferredParent
    // nwkGoodParentLQA = 75
    // nwkPanIdConflictCount = 0
    // nwkMaxInitialJoinParentAttempts = 1
    // nwkMaxRejoinParentAttempts = 3
    pub nwkc_protocol_version: u8,
    pub nwkc_route_discovery_time: Duration,
    pub nwkc_max_broadcast_jitter: Duration,
    pub nwkc_initial_rreq_retries: u8,
    pub nwkc_rreq_retries: u8,
    pub nwkc_rreq_retry_interval: Duration,
    pub nwkc_min_rreq_jitter: Duration,
    pub nwkc_max_rreq_jitter: Duration,
    pub nwkc_max_depth: u8,
    pub nwkc_unicast_retries: u8,
    pub nwkc_unicast_retry_delay: Duration,
    pub nwkc_min_router_bootstrap_jitter: Duration,
    pub nwkc_max_router_bootstrap_jitter: Duration,
    pub nwkc_broadcast_delivery_time: Duration,
}

impl Nib {
    pub fn new() -> Nib {
        Nib {
            nwk_sequence_number: 0,
            nwk_passive_ack_timeout: Duration::from_millis(500),
            nwk_max_broadcast_retries: 2,
            nwk_max_children: 32,
            nwk_max_depth: 15,
            nwk_neighbor_table: HashMap::new(),
            nwk_route_table: HashMap::new(),
            nwk_route_discovery_table: HashMap::new(),
            nwk_capability_information: NwkCapabilityInformation {
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
            nwk_max_source_route: 12,
            nwk_update_id: 0,
            nwk_transaction_persistence_time: Duration::from_millis(7680),
            nwk_network_address: Nwk(0x0000),
            nwk_stack_profile: 2,
            nwk_broadcast_transaction_table: HashMap::new(),
            nwk_extended_pan_id: Eui64::from_hex("0000000000000000"),
            nwk_route_record_table: HashMap::new(),
            nwk_is_concentrator: true,
            nwk_concentrator_radius: 10,
            nwk_concentrator_discovery_time: Duration::from_secs(0),
            nwk_security_level: 5,
            nwk_security_material_primary: NwkSecurityDescriptor {
                key_seq_number: 0,
                outgoing_frame_counter: 0,
                incoming_frame_counter_set: HashMap::new(),
                key: Key::from_hex("00000000000000000000000000000000"),
                network_key_type: NetworkKeyType::Standard,
            },
            nwk_security_material_alternate: NwkSecurityDescriptor {
                key_seq_number: 0,
                outgoing_frame_counter: 0,
                incoming_frame_counter_set: HashMap::new(),
                key: Key::from_hex("00000000000000000000000000000000"),
                network_key_type: NetworkKeyType::Standard,
            },
            nwk_active_key_seq_number: 0,
            nwk_all_fresh: false,
            nwk_concentrator_discovery_separation_time: Duration::from_secs(0),
            nwk_link_status_period: Duration::from_secs(15),
            nwk_router_age_limit: 3,
            nwk_address_map: HashMap::new(),
            nwk_time_stamp: false,
            nwk_pan_id: PanId(0xFFFF),
            nwk_tx_total: 0,
            nwk_leave_request_allowed: false,
            nwk_parent_information: 0,
            nwk_end_device_timeout_default: 0,
            nwk_leave_request_without_rejoin_allowed: false,
            nwk_ieee_address: Eui64::from_hex("0000000000000000"),
            // TODO: The 16-bit routing sequence number is expected to be
            // strictly-increasing, it should be persisted to disk
            // nwk_routing_sequence_number: 0x0000,
            nwk_routing_request_sequence_number: 0x00,
            nwk_hub_connectivity: true,
            // Constants. Theoretically.
            nwkc_protocol_version: 2,
            nwkc_route_discovery_time: Duration::from_millis(10000),
            nwkc_max_broadcast_jitter: Duration::from_millis(64),
            nwkc_initial_rreq_retries: 3,
            nwkc_rreq_retries: 2,
            nwkc_rreq_retry_interval: Duration::from_millis(254),
            nwkc_min_rreq_jitter: Duration::from_millis(2),
            nwkc_max_rreq_jitter: Duration::from_millis(128),
            nwkc_max_depth: 15,
            nwkc_unicast_retries: 3,
            nwkc_unicast_retry_delay: Duration::from_millis(50),
            nwkc_min_router_bootstrap_jitter: Duration::from_millis(500),
            nwkc_max_router_bootstrap_jitter: Duration::from_millis(1000),
            nwkc_broadcast_delivery_time: Duration::from_millis(9000),
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
    pub fn from_aps_ack(src: Nwk, ack: &ApsAckFrame) -> Self {
        ApsAckData {
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
    pub channel: u8,
    pub ieee802154_sequence_number: u8,
    pub nib: Nib,
    pub pending_aps_acks: HashMap<ApsAckData, oneshot::Sender<()>>,
    pub start_time: Option<Instant>,

    // We intentionally violate the spec with these options
    /// The spec mandates that broadcasts be deduplicated only after the stack has been
    /// running for at least 10s, to avoid having our own broadcasts be received. This
    /// slows down development so we will allow it to be disabled.
    pub hack_ignore_broadcast_startup_wait_period: bool,
}

impl State {
    pub fn new() -> Self {
        State {
            channel: 0,
            ieee802154_sequence_number: 0,
            nib: Nib::new(),
            pending_aps_acks: HashMap::new(),
            start_time: None,

            hack_ignore_broadcast_startup_wait_period: true,
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

    pub state: Mutex<State>,
    pub spinel: SpinelClient,
    pub notification_tx: broadcast::Sender<ZigbeeNotification>,
    pub raw_frame_rx: Mutex<mpsc::Receiver<SpinelFramePropValueIs>>,
}

impl ZigbeeStack {
    pub fn new(spinel: SpinelClient) -> (Arc<Self>, broadcast::Receiver<ZigbeeNotification>) {
        let (notification_tx, notification_rx) = broadcast::channel::<ZigbeeNotification>(32);
        let (raw_frame_tx, raw_frame_rx) = mpsc::channel::<SpinelFramePropValueIs>(32);
        spinel.set_property_update_receiver(SpinelPropertyId::StreamRaw as u32, raw_frame_tx);

        let arc_stack = Arc::new_cyclic(|weak_self| ZigbeeStack {
            self_weak: weak_self.clone(),
            state: Mutex::new(State::new()),
            spinel,
            notification_tx,
            raw_frame_rx: Mutex::new(raw_frame_rx),
        });

        (arc_stack, notification_rx)
    }

    pub async fn run(&self) {
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        // Start the background link status broadcaster task
        spawn_local(async move {
            arc_self.periodic_link_status_broadcast_task().await;
        });

        loop {
            let (packet, ieee802154_frame) = self.recv_frame().await;

            match self.process_802154_frame(&ieee802154_frame, packet.lqi, packet.rssi) {
                Some(nwk_frame) => {
                    let aps_frame = match parse_aps_frame(&nwk_frame.payload) {
                        Ok(ApsFrame::Data(data)) => data,
                        Ok(ApsFrame::Ack(ack)) => {
                            let ack_data =
                                ApsAckData::from_aps_ack(nwk_frame.nwk_header.source, &ack);
                            log::debug!("Received APS ack: {:?}", ack_data);

                            self.state
                                .lock()
                                .unwrap()
                                .pending_aps_acks
                                .remove(&ack_data)
                                .map(|tx| {
                                    let _ = tx.send(());
                                });

                            continue;
                        }
                        Err(e) => {
                            log::warn!("Error parsing APS frame: {:?}", e);
                            continue;
                        }
                    };

                    log::debug!("Received APS data frame: {:#?}", aps_frame);

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
                None => {}
            }
        }
    }

    async fn recv_frame(&self) -> (SpinelRxFrame, Ieee802154Frame) {
        loop {
            let Some(spinal_frame) = self
                .raw_frame_rx
                .lock()
                .expect("No thread should panic")
                .recv()
                .await
            else {
                log::warn!("Frame sender hung up");
                continue;
            };
            let packet = match SpinelRxFrame::from_bytes(&spinal_frame.value) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("Error parsing spinel frame: {:?}", e);
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
                    log::debug!("Received 802.15.4 frame: {:?}", frame);
                    return (packet, frame);
                }
                Err(e) => {
                    log::warn!("Error parsing IEEE 802.15.4 frame: {:?}", e);
                    continue;
                }
            };
        }
    }

    pub async fn set_network_settings(
        &self,
        nwk_channel: u8,
        nwk_update_id: u8,
        nwk_pan_id: PanId,
        nwk_extended_pan_id: Eui64,
        nwk_network_address: Nwk,
        nwk_ieee_address: Eui64,
        key: Key,
        key_seq_number: u8,
        outgoing_frame_counter: u32,
    ) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        state.channel = nwk_channel;
        state.nib.nwk_update_id = nwk_update_id;
        state.nib.nwk_pan_id = nwk_pan_id;
        state.nib.nwk_extended_pan_id = nwk_extended_pan_id;
        state.nib.nwk_network_address = nwk_network_address;
        state.nib.nwk_ieee_address = nwk_ieee_address;
        state.nib.nwk_security_material_primary.key = key;
        state.nib.nwk_security_material_primary.key_seq_number = key_seq_number;
        state
            .nib
            .nwk_security_material_primary
            .outgoing_frame_counter = outgoing_frame_counter;

        // Update the hardware with new settings.
        self.spinel
            .prop_value_set(SpinelPropertyId::PhyEnabled as u32, vec![true as u8])
            .await
            .expect("Failed to enable the PHY");

        self.spinel
            .prop_value_set(SpinelPropertyId::PhyChan as u32, vec![nwk_channel])
            .await
            .map_err(|e| format!("Failed to set PHY channel: {:?}", e))?;

        self.spinel
            .prop_value_set(SpinelPropertyId::PhyTxPower as u32, vec![8])
            .await
            .map_err(|e| format!("Failed to set PHY TX power: {:?}", e))?;

        /*
        self.spinel
            .prop_value_set(
                SpinelPropertyId::MacPromiscuousMode as u32,
                vec![SpinelMacPromiscuousMode::Full as u8],
            )
            .await
            .expect("Failed to set the MAC promiscuous mode");
        */

        self.spinel
            .prop_value_set(
                SpinelPropertyId::Mac154Laddr as u32,
                state.nib.nwk_ieee_address.to_bytes().to_vec(),
            )
            .await
            .map_err(|e| format!("Failed to set MAC IEEE address: {:?}", e))?;

        self.spinel
            .prop_value_set(
                SpinelPropertyId::Mac154Saddr as u32,
                state.nib.nwk_network_address.to_bytes().to_vec(),
            )
            .await
            .map_err(|e| format!("Failed to set MAC NWK address: {:?}", e))?;

        self.spinel
            .prop_value_set(
                SpinelPropertyId::Mac154Panid as u32,
                state.nib.nwk_pan_id.to_bytes().to_vec(),
            )
            .await
            .map_err(|e| format!("Failed to set MAC PAN ID: {:?}", e))?;

        self.spinel
            .prop_value_set(
                SpinelPropertyId::MacRxOnWhenIdleMode as u32,
                vec![true as u8],
            )
            .await
            .expect("Failed to set RX on when idle");

        self.spinel
            .prop_value_set(
                SpinelPropertyId::MacRawStreamEnabled as u32,
                vec![true as u8],
            )
            .await
            .expect("Failed to enable the RAW stream");

        // This is treated as the start time of the stack
        state.start_time = Some(Instant::now());
        drop(state);

        // To kick things off, send a link status broadcast. Silicon Labs routers will
        // "respond" to empty link status broadcasts proactively, independent of the
        // link status period
        self.send_link_status_broadcast(true).await;

        Ok(())
    }

    pub fn process_802154_frame(
        &self,
        frame: &Ieee802154Frame,
        lqi: u8,
        rssi: i8,
    ) -> Option<NwkFrame> {
        let state = self.state.lock().unwrap();

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
        match frame.dest_pan_id {
            None => {
                log::debug!("Ignoring frame, destination PAN ID is not present");
                return None;
            }
            Some(dest_pan_id) if dest_pan_id != state.nib.nwk_pan_id => {
                log::debug!(
                    "Ignoring frame, PAN ID does not match {:?} != {:?}",
                    dest_pan_id,
                    state.nib.nwk_pan_id
                );
                return None;
            }
            Some(_) => (),
        }

        // Next, try to parse the NWK frame
        let nwk_frame = match NwkFrame::from_bytes(&frame.payload) {
            Ok(nwk_frame) => nwk_frame,
            Err(_) => {
                log::debug!("Ignoring frame, not a NWK frame");
                return None;
            }
        };

        // Ignore frames that aren't destined for us
        if nwk_frame.nwk_header.destination != state.nib.nwk_network_address
            && nwk_frame.nwk_header.destination.as_u16()
                < BROADCAST_ALL_ROUTERS_AND_COORDINATOR.as_u16()
        {
            log::debug!("Ignoring frame, destination is not us");
            return None;
        }

        // Ignore unencrypted frames
        if !nwk_frame.encrypted {
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
        if aux_header.key_sequence_number != state.nib.nwk_active_key_seq_number {
            log::debug!("Ignoring frame, key sequence number is unknown");
            return None;
        }

        // Validate the security header frame counter for the relaying EUI64
        let src_eui64;

        match aux_header.extended_source {
            None => {
                log::debug!("Ignoring frame, extended source is missing");
                return None;
            }
            Some(eui64) => {
                src_eui64 = eui64;
            }
        }

        match state
            .nib
            .nwk_security_material_primary
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
            state.nib.nwk_security_material_primary
        );

        // Finally, attempt decryption
        let decrypted_nwk_frame =
            match nwk_frame.decrypt(&state.nib.nwk_security_material_primary.key) {
                Ok(decrypted_frame) => decrypted_frame,
                Err(err) => {
                    log::warn!("Ignoring frame, decryption failed: {err:?}");
                    return None;
                }
            };

        // At this point we no longer need to lock `state`
        drop(state);

        log::info!("Decrypted frame: {decrypted_nwk_frame:#?}");

        // TODO: all 802.15.4 frames should be coming in with 16 bit addressing, right?
        let source_nwk = match frame.src_address {
            Some(Ieee802154Address::Nwk(nwk)) => Some(nwk),
            _ => None,
        };

        self.handle_decrypted_frame(&decrypted_nwk_frame, source_nwk.unwrap(), lqi, rssi);

        return Some(decrypted_nwk_frame);
    }

    pub fn update_nwk_eui64_mapping(&self, nwk: Nwk, eui64: Eui64) {
        let mut state = self.state.lock().unwrap();

        match state.nib.nwk_address_map.insert(eui64, nwk) {
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
        let mut state = self.state.lock().unwrap();
        let broadcast_delivery_time = state.nib.nwkc_broadcast_delivery_time;

        // We cannot handle broadcasts until the network has been running for at least
        // the time it takes to deliver one broadcast
        if !state.hack_ignore_broadcast_startup_wait_period
            && (state.start_time.is_none()
                || state.start_time.unwrap() + broadcast_delivery_time > now)
        {
            log::debug!("Filtering broadcast, network started too recently.");
            return true;
        }

        let key = (
            nwk_frame.nwk_header.source,
            nwk_frame.nwk_header.sequence_number,
        );

        // Clean a stale entry first, if one exists.
        if let Some(entry) = state.nib.nwk_broadcast_transaction_table.get(&key) {
            if entry.expiration_time > now {
                return true;
            }
        }

        state.nib.nwk_broadcast_transaction_table.insert(
            key,
            NwkBroadcastTransaction {
                source_nwk: nwk_frame.nwk_header.source,
                sequence_number: nwk_frame.nwk_header.sequence_number,
                expiration_time: now + broadcast_delivery_time,
            },
        );

        return false;
    }

    pub fn handle_decrypted_frame(&self, nwk_frame: &NwkFrame, sender_nwk: Nwk, lqi: u8, rssi: i8) {
        // Update the frame counter for the relaying device
        if let Some(aux_header) = &nwk_frame.aux_header {
            match aux_header.extended_source {
                Some(relaying_eui64) => {
                    let mut state = self.state.lock().unwrap();
                    state
                        .nib
                        .nwk_security_material_primary
                        .incoming_frame_counter_set
                        .insert(relaying_eui64, aux_header.frame_counter);

                    log::debug!(
                        "Incremented frame counter for {relaying_eui64:?} to {}",
                        aux_header.frame_counter
                    );
                }
                None => {}
            }
        }

        // Update the address cache
        if let Some(src_eui64) = nwk_frame.nwk_header.source_ieee {
            self.update_nwk_eui64_mapping(nwk_frame.nwk_header.source, src_eui64);
        }

        // Handle LQA calculation
        self.maybe_recompute_lqa(nwk_frame, lqi, rssi);

        // Ignore frames that aren't destined for us
        if nwk_frame.nwk_header.destination.as_u16()
            >= BROADCAST_ALL_ROUTERS_AND_COORDINATOR.as_u16()
            && self.filter_broadcast(&nwk_frame)
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
                    self.handle_link_status(nwk_frame);
                }
                Ok(NwkCommandId::RouteReply) => {
                    // TODO: Error handling for decoding?
                    log::info!("Route reply command frame received");
                    self.handle_route_reply(nwk_frame);
                }
                Ok(NwkCommandId::RouteRecord) => {
                    // TODO: Error handling for decoding?
                    let route_record_cmd =
                        NwkRouteRecordCommand::from_bytes(&nwk_frame.payload).unwrap();
                    log::info!(
                        "Route record command frame received: {:#?}",
                        route_record_cmd
                    );
                    let mut state = self.state.lock().unwrap();
                    state
                        .nib
                        .nwk_route_record_table
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

    fn maybe_recompute_lqa(&self, nwk_frame: &NwkFrame, lqi: u8, rssi: i8) {
        if nwk_frame.nwk_header.source_ieee.is_none() {
            return;
        }

        let mut state = self.state.lock().unwrap();
        if let Some(entry) = state
            .nib
            .nwk_neighbor_table
            .get_mut(&nwk_frame.nwk_header.source_ieee.unwrap())
        {
            entry.lqas.push_back(lqi);

            if entry.lqas.len() > LINK_QUALITY_SAMPLES {
                entry.lqas.pop_front();
            }
        }
    }

    fn handle_link_status(&self, nwk_frame: &NwkFrame) {
        let link_status_cmd = match NwkLinkStatusCommand::from_bytes(&nwk_frame.payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                log::warn!("Error parsing link status command: {e:?}");
                return;
            }
        };

        log::info!("Link status command frame: {link_status_cmd:#?}");

        if nwk_frame.nwk_header.source_ieee.is_none() {
            log::warn!("Link status command source EUI64 is missing");
            return;
        }

        // We collect a list of neighbors with non-zero outgoing cost up here, before
        // mutating the state
        let neighbors_with_nonzero_outgoing_cost = self
            .state
            .lock()
            .unwrap()
            .nib
            .nwk_neighbor_table
            .iter()
            .filter_map(|(_, neighbor_entry)| {
                if neighbor_entry.outgoing_cost > 0 {
                    Some(neighbor_entry.network_address)
                } else {
                    None
                }
            })
            .collect::<HashSet<Nwk>>();

        let nwk_network_address = self.state.lock().unwrap().nib.nwk_network_address;

        let source_ieee = nwk_frame.nwk_header.source_ieee.unwrap();

        let mut state = self.state.lock().unwrap();
        let neighbor_entry = match state.nib.nwk_neighbor_table.get_mut(&source_ieee) {
            Some(entry) => entry,
            None => {
                // Create one
                log::info!("Creating new neighbor entry for {source_ieee:?}");

                let entry = neighbor::TableEntry {
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

                state.nib.nwk_neighbor_table.insert(source_ieee, entry);
                state.nib.nwk_neighbor_table.get_mut(&source_ieee).unwrap()
            }
        };

        if link_status_cmd.is_first_frame {
            neighbor_entry.last_link_status_timestamp = Instant::now();
            neighbor_entry.router_connectivity = 0;
            neighbor_entry.router_neighbor_set_diversity = 0;
            neighbor_entry.outgoing_cost = 0; // If we do not find it in the list, it is 0
        }

        for link_status in link_status_cmd.link_statuses.iter() {
            if link_status.outgoing_cost > 0 {
                let connectivity =
                    7 - cmp::max(link_status.incoming_cost, link_status.outgoing_cost);

                neighbor_entry.router_connectivity += connectivity;

                if !neighbors_with_nonzero_outgoing_cost.contains(&link_status.address) {
                    neighbor_entry.router_neighbor_set_diversity += connectivity;
                }
            }

            if link_status.address == nwk_network_address {
                neighbor_entry.outgoing_cost = link_status.incoming_cost;
            }
        }

        log::debug!("Updated neighbor table entry: {neighbor_entry:#?}");
    }

    fn handle_route_reply(&self, nwk_frame: &NwkFrame) {
        let route_reply_cmd = match NwkRouteReplyCommand::from_bytes(&nwk_frame.payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                log::warn!("Error parsing route reply command: {e:?}");
                return;
            }
        };

        log::info!("Route reply command frame: {:#?}", route_reply_cmd);

        if route_reply_cmd.multicast {
            return;
        }
    }

    fn handle_route_request(&self, nwk_frame: &NwkFrame, sender_nwk: Nwk) {
        let route_request_cmd = match NwkRouteRequestCommand::from_bytes(&nwk_frame.payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                log::warn!("Error parsing route request command: {e:?}");
                return;
            }
        };

        log::info!("Route request command frame: {:#?}", route_request_cmd);

        let nwk_network_address = self.state.lock().unwrap().nib.nwk_network_address;

        // TODO: for now, only handle route requests back to us
        if route_request_cmd.destination_address == nwk_network_address
            || route_request_cmd.destination_eui64 == route_request_cmd.destination_eui64
        {
            self.handle_route_request_self(nwk_frame, &route_request_cmd, sender_nwk);
        } else {
            self.handle_route_request_relay(nwk_frame, &route_request_cmd, sender_nwk);
        }
    }

    /// Handle route requests that are destined for us (or our child)
    fn handle_route_request_self(
        &self,
        nwk_frame: &NwkFrame,
        route_request_cmd: &NwkRouteRequestCommand,
        sender_nwk: Nwk,
    ) {
        let mut state = self.state.lock().unwrap();

        // We need to know who sent the frame
        let sender_neighbor = match state
            .nib
            .nwk_neighbor_table
            .values()
            .find(|&entry| entry.network_address == sender_nwk)
        {
            Some(neighbor) => neighbor,
            None => {
                // Can we do anything here? Broadcast an unsolicited link status?
                log::warn!("Route request relayer not found in neighbor table");
                return;
            }
        };

        let path_cost = sender_neighbor.incoming_link_cost();
        if path_cost == 0 {
            log::warn!("Path cost to neighbor is 0, not sending route reply");
            return;
        }

        state
            .nib
            .nwk_security_material_primary
            .outgoing_frame_counter = state
            .nib
            .nwk_security_material_primary
            .outgoing_frame_counter
            .wrapping_add(1);

        state.nib.nwk_sequence_number = state.nib.nwk_sequence_number.wrapping_add(1);

        let route_reply_frame = NwkFrame {
            encrypted: false,
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Command,
                    protocol_version: state.nib.nwkc_protocol_version,
                    discover_route: NwkRouteDiscovery::Suppress,
                    multicast: false,
                    security: true,
                    source_route: false,
                    destination: true,
                    extended_source: true,
                    end_device_initiator: false,
                    reserved: 0b00,
                },
                destination: nwk_frame.nwk_header.source,
                source: state.nib.nwk_network_address,
                radius: 2 * state.nib.nwk_max_depth,
                sequence_number: state.nib.nwk_sequence_number,
                destination_ieee: nwk_frame.nwk_header.source_ieee,
                source_ieee: Some(state.nib.nwk_ieee_address),
                multicast_control: None,
                source_route: None,
            },
            aux_header: Some(NwkAuxHeader {
                security_control: NwkSecurityHeaderControlField {
                    security_level: NwkSecurityLevel::NoSecurity,
                    key_id: NwkSecurityHeaderKeyId::NetworkKey,
                    extended_nonce: true,
                    require_verified_frame_counter: false,
                    reserved: 0b0,
                },
                frame_counter: state
                    .nib
                    .nwk_security_material_primary
                    .outgoing_frame_counter,
                extended_source: Some(state.nib.nwk_ieee_address),
                key_sequence_number: state.nib.nwk_active_key_seq_number,
            }),
            payload: NwkRouteReplyCommand {
                multicast: false,
                route_request_identifier: route_request_cmd.route_request_identifier,
                originator_nwk: nwk_frame.nwk_header.source,
                responder_nwk: state.nib.nwk_network_address,
                path_cost: path_cost,
                originator_eui64: nwk_frame.nwk_header.source_ieee,
                responder_eui64: Some(state.nib.nwk_ieee_address),
                tlvs: vec![],
            }
            .serialize(),
        }
        .encrypt(&state.nib.nwk_security_material_primary.key)
        .expect("Encryption somehow failed");

        drop(state);

        let ieee802154_frame = self.wrap_nwk_frame(&route_reply_frame);

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        spawn_local(async move {
            arc_self.send_802154_frame(ieee802154_frame).await;
        });
    }

    /// Handle route requests that we should consider relaying
    fn handle_route_request_relay(
        &self,
        nwk_frame: &NwkFrame,
        route_request_cmd: &NwkRouteRequestCommand,
        sender_nwk: Nwk,
    ) {
        let mut state = self.state.lock().unwrap();

        // We need to know who sent the frame
        let sender_neighbor = match state
            .nib
            .nwk_neighbor_table
            .values()
            .find(|&entry| entry.network_address == sender_nwk)
        {
            Some(neighbor) => neighbor,
            None => {
                // Can we do anything here? Broadcast an unsolicited link status?
                log::warn!("Route request relayer not found in neighbor table");
                return;
            }
        };
    }

    fn handle_aps_ack_request(&self, aps_frame: &ApsDataFrame, nwk_frame: &NwkFrame) {
        log::debug!("Sending back an APS ACK");

        let ack_frame = ApsAckFrame {
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
        };

        // Wrap it in a NWK frame
        let destination = nwk_frame.nwk_header.source;
        let outgoing_nwk_frame = self.wrap_aps_frame(destination, 30, &ApsFrame::Ack(ack_frame));
        let ieee802154_frame = self.wrap_nwk_frame(&outgoing_nwk_frame);

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        spawn_local(async move {
            arc_self.send_802154_frame(ieee802154_frame).await;
        });
    }

    fn prepare_request(
        &self,
        delivery_mode: ApsDeliveryMode,
        destination: Nwk,
        next_hop: Nwk,
        src_ep: u8,
        dst_ep: u8,
        cluster_id: u16,
        profile_id: u16,
        aps_ack: bool,
        radius: u8,
        counter: u8,
        asdu: &Vec<u8>,
    ) -> Ieee802154Frame {
        let aps_frame = match delivery_mode {
            ApsDeliveryMode::Unicast => ApsDataFrame {
                frame_control: ApsFrameControl {
                    frame_type: ApsFrameType::Data,
                    delivery_mode: ApsDeliveryMode::Unicast,
                    reserved: 0b0,
                    security: false,
                    ack_request: aps_ack,
                    extended_header: false,
                },
                group_id: None,
                destination_endpoint: Some(dst_ep),
                cluster_id,
                profile_id,
                source_endpoint: src_ep,
                counter,
                asdu: asdu.to_vec(),
            },
            ApsDeliveryMode::Broadcast => ApsDataFrame {
                frame_control: ApsFrameControl {
                    frame_type: ApsFrameType::Data,
                    delivery_mode: ApsDeliveryMode::Broadcast,
                    reserved: 0b0,
                    security: false,
                    ack_request: false,
                    extended_header: false,
                },
                group_id: None,
                destination_endpoint: Some(dst_ep),
                cluster_id,
                profile_id,
                source_endpoint: src_ep,
                counter,
                asdu: asdu.to_vec(),
            },
            ApsDeliveryMode::Multicast => ApsDataFrame {
                frame_control: ApsFrameControl {
                    frame_type: ApsFrameType::Data,
                    delivery_mode: ApsDeliveryMode::Multicast,
                    reserved: 0b0,
                    security: false,
                    ack_request: false,
                    extended_header: false,
                },
                group_id: Some(destination.as_u16()),
                destination_endpoint: None,
                cluster_id,
                profile_id,
                source_endpoint: src_ep,
                counter,
                asdu: asdu.to_vec(),
            },
        };

        log::debug!("Prepared APS frame: {:#?}", aps_frame);

        let nwk_frame = self.wrap_aps_frame(
            if aps_frame.frame_control.delivery_mode == ApsDeliveryMode::Unicast {
                // TODO: routing :)
                // At this point, we assume the destination device is in range of the coordinator.
                destination
            } else {
                BROADCAST_RX_ON_WHEN_IDLE
            },
            radius,
            &ApsFrame::Data(aps_frame),
        );
        log::debug!("Prepared NWK frame: {:#?}", nwk_frame);
        let ieee802154_frame = self.wrap_nwk_frame(&nwk_frame);

        ieee802154_frame
    }

    fn wrap_aps_frame(&self, destination: Nwk, radius: u8, aps_frame: &ApsFrame) -> NwkFrame {
        // TODO: TX frame counter wrapping is an error condition
        let mut state = self.state.lock().unwrap();

        state
            .nib
            .nwk_security_material_primary
            .outgoing_frame_counter = state
            .nib
            .nwk_security_material_primary
            .outgoing_frame_counter
            .wrapping_add(1);
        state.nib.nwk_sequence_number = state.nib.nwk_sequence_number.wrapping_add(1);

        let plaintext_nwk_frame = NwkFrame {
            encrypted: false,
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Data,
                    protocol_version: state.nib.nwkc_protocol_version,
                    discover_route: NwkRouteDiscovery::Enable,
                    multicast: false,
                    security: true,
                    source_route: false,
                    destination: false,
                    extended_source: false,
                    end_device_initiator: false,
                    reserved: 0b00,
                },
                destination,
                source: state.nib.nwk_network_address,
                radius,
                sequence_number: state.nib.nwk_sequence_number,
                destination_ieee: None,
                source_ieee: None,
                multicast_control: None,
                source_route: None,
            },
            aux_header: Some(NwkAuxHeader {
                security_control: NwkSecurityHeaderControlField {
                    security_level: NwkSecurityLevel::NoSecurity,
                    key_id: NwkSecurityHeaderKeyId::NetworkKey,
                    extended_nonce: true,
                    require_verified_frame_counter: false,
                    reserved: 0b0,
                },
                frame_counter: state
                    .nib
                    .nwk_security_material_primary
                    .outgoing_frame_counter,
                extended_source: Some(state.nib.nwk_ieee_address),
                key_sequence_number: state.nib.nwk_active_key_seq_number,
            }),
            payload: match aps_frame {
                ApsFrame::Data(data_frame) => data_frame.to_bytes(),
                ApsFrame::Ack(ack_frame) => ack_frame.to_bytes(),
            },
        };

        plaintext_nwk_frame
            .encrypt(&state.nib.nwk_security_material_primary.key)
            .expect("Encryption somehow failed")
    }

    fn wrap_nwk_frame(&self, nwk_frame: &NwkFrame) -> Ieee802154Frame {
        let mut state = self.state.lock().unwrap();

        // Increment the 802.15.4 sequence number
        state.ieee802154_sequence_number = state.ieee802154_sequence_number.wrapping_add(1);

        let destination = Ieee802154Address::Nwk(
            if nwk_frame.nwk_header.destination.as_u16()
                >= BROADCAST_ALL_ROUTERS_AND_COORDINATOR.as_u16()
            {
                Nwk(0xFFFF)
            } else {
                nwk_frame.nwk_header.destination
            },
        );

        // TODO: support EUI64 addressing
        Ieee802154Frame {
            frame_control: Ieee802154FrameControl {
                frame_type: Ieee802154FrameType::Data,
                security_enabled: false,
                frame_pending: false,
                ack_request: if destination == Ieee802154Address::Nwk(Nwk(0xFFFF)) {
                    false
                } else {
                    true
                },
                pan_id_compression: true,
                reserved: false,
                sequence_number_suppression: false,
                information_elements_present: false,
                dest_addr_mode: Ieee802154AddressingMode::Short,
                frame_version: 0,
                src_addr_mode: Ieee802154AddressingMode::Short,
            },
            sequence_number: Some(state.ieee802154_sequence_number),
            dest_pan_id: Some(state.nib.nwk_pan_id),
            dest_address: Some(destination),
            src_pan_id: None,
            src_address: Some(Ieee802154Address::Nwk(state.nib.nwk_network_address)),
            payload: nwk_frame.to_bytes(),
            fcs: 0x0000, // It'll be replaced
        }
    }

    async fn send_802154_frame(&self, frame: Ieee802154Frame) {
        // Briefly grab the channel when sending, we don't want to hold the lock while
        // waiting for an ACK
        let channel = { self.state.lock().unwrap().channel };

        log::info!("Sending 802.15.4 frame: {:#?}", frame);
        log::info!("Sending 802.15.4 frame bytes: {:02X?}", frame.to_bytes());
        let status = self
            .spinel
            .transmit_frame(&SpinelTxFrame {
                psdu: frame.to_bytes(),
                channel: Some(channel),
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

        log::info!("Send status: {:?}", status);

        if status != SpinelStatus::Ok as u8 {
            log::warn!("Failed to send frame ({:?}): {:#?}", status, frame);
        }
    }

    pub async fn discover_route(&self, destination: Nwk) -> Result<Nwk, String> {
        // TODO: combine concurrent route discovery requests
        self.discover_route_internal(destination).await
    }

    pub async fn discover_route_internal(&self, destination: Nwk) -> Result<Nwk, String> {
        // Discover next hop route
        let mut state = self.state.lock().unwrap();

        // Check if we have an active routing table entry first
        if let Some(route_table_entry) = state.nib.nwk_route_table.get(&destination) {
            if route_table_entry.status == route::Status::Active {
                assert!(route_table_entry.next_hop_address != Nwk(0xFFFF));
                return Ok(route_table_entry.next_hop_address);
            }
        }

        // Otherwise, send out a discovery request
        state.nib.nwk_routing_request_sequence_number = state
            .nib
            .nwk_routing_request_sequence_number
            .wrapping_add(1);

        // Get or create a routing table entry without keeping a mutable reference
        {
            let route_table_entry =
                state
                    .nib
                    .nwk_route_table
                    .entry(destination)
                    .or_insert_with(|| {
                        route::TableEntry {
                            destination: destination,
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

        let route_request_identifier = state.nib.nwk_routing_request_sequence_number;
        let route_discovery_table_key = (state.nib.nwk_network_address, route_request_identifier);

        // We initiated discovery so insert an entry keyed by our NWK and request ID
        let nwk_network_address = state.nib.nwk_network_address;
        let nwkc_route_discovery_time = state.nib.nwkc_route_discovery_time;
        state
            .nib
            .nwk_route_discovery_table
            .entry(route_discovery_table_key)
            .or_insert_with(|| route::DiscoveryEntry {
                route_request_id: route_request_identifier,
                source_address: nwk_network_address,
                sender_address: Nwk(0xFFFF),
                forward_cost: 0,
                residual_cost: 0,
                expiration_time: Instant::now() + nwkc_route_discovery_time,
            });

        // Construct a frame
        state
            .nib
            .nwk_security_material_primary
            .outgoing_frame_counter = state
            .nib
            .nwk_security_material_primary
            .outgoing_frame_counter
            .wrapping_add(1);
        state.nib.nwk_sequence_number = state.nib.nwk_sequence_number.wrapping_add(1);

        // If we know the EUI64 corresponding to the NWK, use it
        let destination_eui64 = state.nib.nwk_address_map.iter().find_map(|(&eui64, &nwk)| {
            if nwk == destination {
                Some(eui64)
            } else {
                None
            }
        });

        let route_request_frame = NwkFrame {
            encrypted: false,
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Command,
                    protocol_version: state.nib.nwkc_protocol_version,
                    discover_route: NwkRouteDiscovery::Suppress,
                    multicast: false,
                    security: true,
                    source_route: false,
                    destination: false,
                    extended_source: true,
                    end_device_initiator: false,
                    reserved: 0b00,
                },
                destination: BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
                source: state.nib.nwk_network_address,
                radius: 2 * state.nib.nwk_max_depth,
                sequence_number: state.nib.nwk_sequence_number,
                destination_ieee: None,
                source_ieee: Some(state.nib.nwk_ieee_address),
                multicast_control: None,
                source_route: None,
            },
            aux_header: Some(NwkAuxHeader {
                security_control: NwkSecurityHeaderControlField {
                    security_level: NwkSecurityLevel::NoSecurity,
                    key_id: NwkSecurityHeaderKeyId::NetworkKey,
                    extended_nonce: true,
                    require_verified_frame_counter: false,
                    reserved: 0b0,
                },
                frame_counter: state
                    .nib
                    .nwk_security_material_primary
                    .outgoing_frame_counter,
                extended_source: Some(state.nib.nwk_ieee_address),
                key_sequence_number: state.nib.nwk_active_key_seq_number,
            }),
            payload: NwkRouteRequestCommand {
                multicast: false,
                many_to_one: NwkRouteRequestManyToOne::NotManyToOne,
                route_request_identifier: route_request_identifier,
                destination_address: destination,
                path_cost: 0, // The path cost starts at 0, since we originate it
                destination_eui64: destination_eui64,
                tlvs: vec![],
            }
            .serialize(),
        }
        .encrypt(&state.nib.nwk_security_material_primary.key)
        .expect("Encryption somehow failed");

        drop(state);

        // Send the packet
        let ieee802154_frame = self.wrap_nwk_frame(&route_request_frame);

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        spawn_local(async move {
            arc_self.send_802154_frame(ieee802154_frame).await;
        });

        // TODO: wait for route discovery to actually complete. For now, we will be
        // relatively stateless and stop erroring out once the correct state is computed
        return Err("Route discovery started".to_string());
    }

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
    ) -> Result<(), String> {
        let next_hop = self.discover_route(destination).await?;

        let ieee802154_frame = self.prepare_request(
            delivery_mode,
            destination,
            next_hop,
            src_ep,
            dst_ep,
            cluster_id,
            profile_id,
            aps_ack,
            radius,
            aps_seq,
            &data,
        );

        let mut maybe_ack_rx = None;

        if aps_ack {
            let ack_data = ApsAckData {
                src: destination,
                destination_endpoint: Some(src_ep), // These are swapped
                cluster_id: Some(cluster_id),
                profile_id: Some(profile_id),
                source_endpoint: Some(dst_ep), // These are swapped
                counter: aps_seq,
            };

            let (tx, rx) = oneshot::channel();
            maybe_ack_rx = Some(rx);

            log::debug!("APS ACK requested, waiting for {:?}", ack_data);
            self.state
                .lock()
                .unwrap()
                .pending_aps_acks
                .insert(ack_data, tx);
        }

        self.send_802154_frame(ieee802154_frame).await;

        {
            let mut state = self.state.lock().unwrap();

            // Handle `nwk_tx_total` wrapping
            if state.nib.nwk_tx_total == 0xFFFF {
                for (_, neighbor) in state.nib.nwk_neighbor_table.iter_mut() {
                    neighbor.transmit_failure = 0;
                }
            }

            state.nib.nwk_tx_total = state.nib.nwk_tx_total.wrapping_add(1);
        }

        if let Some(ack_rx) = maybe_ack_rx {
            // With a 5s timeout
            let aps_ack_timeout = Duration::from_secs(5);
            match tokio::time::timeout(aps_ack_timeout, ack_rx).await {
                Ok(Ok(())) => {
                    log::info!("APS ACK received");
                }
                Ok(Err(e)) => {
                    log::warn!("APS ACK channel hung up: {:?}", e);
                }
                Err(_) => {
                    log::warn!("APS ACK timed out");
                }
            }
        }

        Ok(())
    }

    pub async fn send_link_status_broadcast(&self, empty: bool) {
        let mut state = self.state.lock().unwrap();
        log::debug!("Sending periodic link status broadcast");

        if state.nib.nwk_network_address == Nwk(0xFFFF) {
            log::debug!("Skipping, stack has not been initialized yet");
            return;
        }

        // Decrement the `recent_activity` field of every active routing table entry
        for (_, route_table_entry) in state.nib.nwk_route_table.iter_mut() {
            if route_table_entry.status == route::Status::Active {
                if route_table_entry.recent_activity > 0 {
                    route_table_entry.recent_activity -= 1;
                }
            }
        }

        let mut link_statuses = if !empty {
            state
                .nib
                .nwk_neighbor_table
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

        drop(state);

        // Link statuses are sorted in ascending order
        link_statuses.sort_by(|a, b| a.address.as_u16().cmp(&b.address.as_u16()));

        let max_link_statuses = 7;
        let mut remaining_link_statuses = link_statuses.clone();

        loop {
            let mut state = self.state.lock().unwrap();

            state
                .nib
                .nwk_security_material_primary
                .outgoing_frame_counter = state
                .nib
                .nwk_security_material_primary
                .outgoing_frame_counter
                .wrapping_add(1);
            state.nib.nwk_sequence_number = state.nib.nwk_sequence_number.wrapping_add(1);

            let link_status_frame = NwkFrame {
                encrypted: false,
                nwk_header: NwkHeader {
                    frame_control: NwkFrameControl {
                        frame_type: NwkFrameType::Command,
                        protocol_version: state.nib.nwkc_protocol_version,
                        discover_route: NwkRouteDiscovery::Suppress,
                        multicast: false,
                        security: true,
                        source_route: false,
                        destination: false,
                        extended_source: true,
                        end_device_initiator: false,
                        reserved: 0b00,
                    },
                    destination: BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
                    source: state.nib.nwk_network_address,
                    radius: 1,
                    sequence_number: state.nib.nwk_sequence_number,
                    destination_ieee: None,
                    source_ieee: Some(state.nib.nwk_ieee_address),
                    multicast_control: None,
                    source_route: None,
                },
                aux_header: Some(NwkAuxHeader {
                    security_control: NwkSecurityHeaderControlField {
                        security_level: NwkSecurityLevel::NoSecurity,
                        key_id: NwkSecurityHeaderKeyId::NetworkKey,
                        extended_nonce: true,
                        require_verified_frame_counter: false,
                        reserved: 0b0,
                    },
                    frame_counter: state
                        .nib
                        .nwk_security_material_primary
                        .outgoing_frame_counter,
                    extended_source: Some(state.nib.nwk_ieee_address),
                    key_sequence_number: state.nib.nwk_active_key_seq_number,
                }),
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
                .serialize(),
            }
            .encrypt(&state.nib.nwk_security_material_primary.key)
            .expect("Encryption somehow failed");

            drop(state);

            let ieee802154_frame = self.wrap_nwk_frame(&link_status_frame);
            self.send_802154_frame(ieee802154_frame).await;

            if remaining_link_statuses.is_empty() {
                break;
            }
        }
    }

    pub async fn periodic_link_status_broadcast_task(&self) {
        loop {
            let nwk_link_status_period = { self.state.lock().unwrap().nib.nwk_link_status_period };
            tokio::time::sleep(nwk_link_status_period).await;

            self.send_link_status_broadcast(false).await;
        }
    }
}
