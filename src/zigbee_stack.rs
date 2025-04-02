use crate::ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154Frame, Ieee802154FrameControl,
    Ieee802154FrameType,
};
use crate::spinel::{SpinelFramePropValueIs, SpinelMacPromiscuousMode, SpinelPropertyId};
use crate::spinel_client::{SpinelClient, SpinelRxFrame, SpinelTxFrame};
use crate::types::{Eui64, Key, Nwk, PanId};
use crate::zigbee_aps::{
    ApsAckFrame, ApsDataFrame, ApsDeliveryMode, ApsFrame, ApsFrameControl, ApsFrameType,
    parse_aps_frame,
};
use crate::zigbee_nwk::{
    NwkAuxHeader, NwkFrame, NwkFrameControl, NwkFrameType, NwkHeader, NwkRouteDiscovery,
    NwkSecurityHeaderControlField, NwkSecurityHeaderKeyId, NwkSecurityLevel,
};
use crate::zigbee_nwk_commands::{
    NwkCommandId, NwkLinkStatusCommand, NwkRouteRecordCommand, NwkRouteReplyCommand,
    NwkRouteRequestCommand,
};
use std::collections::HashMap;
use std::mem::drop;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::spawn_local;
use tokio::time::Duration;

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
    pub expiration_time: u8,
}

#[derive(Debug)]
pub enum NwkRouteStatus {
    Active = 0,
    DiscoveryUnderway = 1,
    DiscoveryFailed = 2,
    Inactive = 3,
}

#[derive(Debug)]
pub struct NwkRoutingTableEntry {
    pub destination: Nwk,
    pub status: NwkRouteStatus,
    pub no_route_cache: bool,
    pub many_to_one: bool,
    pub route_record_required: bool,
    pub expired: bool,
    pub sequence_number_valid: bool,
    pub next_hop_address: Nwk,
    pub sequence_number: u16,
    pub total_usage_count: u32,

    // An 8-bit saturating counter, which is pre-loaded with nwkRouterAgeLimit when the
    // routing table entry is created; incremented whenever this routing table entry is
    // used to forward a state packet towards its destination; and decremented
    // unconditionally once every nwkLinkStatusPeriod. A value of 0 indicates no
    // packets have recently been forwarded along this route.
    pub recent_activity: u8,
}

#[derive(Debug)]
pub struct NwkRouteDiscoveryTableEntry {
    // A sequence number for a route request command frame that is incremented each time
    // a device initiates a route request. Notice that this 8-bit identifier is
    // distinct from the 16-bit Routing Sequence Number. The former is used to discern
    // route requests originating in a particular router; the latter is used to
    // identify stale routing information.
    pub route_request_id: u8,

    // The 16-bit network address of the route request’s initiator.
    pub source_address: Nwk,

    // The 16-bit network address of the device that has sent the most recent lowest
    // cost route request command frame corresponding to this entry’s route request
    // identifier and source address. This field is used to determine the path that an
    // eventual route reply command frame SHOULD follow.
    pub sender_address: Nwk,

    // The accumulated path cost from the source of the route request to the current
    // device.
    pub forward_cost: u8,

    // The accumulated path cost from the current device to the destination device.
    pub residual_cost: u8,

    // A countdown timer indicating the number of milliseconds until route discovery
    // expires. The initial value is nwkcRouteDiscoveryTime.
    pub expiration_time: u16,
}

#[derive(Debug)]
pub enum NwkDeviceType {
    Coordinator = 0x00,
    Router = 0x01,
    EndDevice = 0x02,
}

#[derive(Debug)]
pub enum NwkNeighborRelationship {
    Parent = 0x00,
    Child = 0x01,
    Sibling = 0x02,
    NoneOfTheAbove = 0x03, // NotParentChildOrSibling?
    PreviousChild = 0x04,
    UnauthenticatedChild = 0x05,
    UnauthorizedChildWithRelayAllowed = 0x06,
    LostChild = 0x07,
    AddressConflictChild = 0x08,
    BackboneMeshSibling = 0x09,
}

#[derive(Debug)]
pub struct NwkNeighborTableEntry {
    pub extended_address: Eui64,
    pub network_address: Nwk,
    pub device_type: NwkDeviceType,
    pub rx_on_when_idle: bool,
    pub end_device_configuration: u16,
    pub timeout_counter: u32, // max: 15728640
    pub device_timeout: u32,  // max: 129600
    pub relationship: NwkNeighborRelationship,
    pub transmit_failure: u8,
    pub lqa: u8,
    pub outgoing_cost: u8,
    pub age: u8,
    pub incoming_beacon_timestamp: u32,
    pub beacon_transmission_time_offset: u32,
    pub keepalive_received: bool,
    // pub mac_interface_index: u8,
    pub mac_unicast_bytes_transmitted: u32,
    pub mac_unicast_bytes_received: u32,
    pub router_age: u16,
    pub router_connectivity: u8,
    pub router_neighbor_set_diversity: u8,
    pub router_outbound_activity: u8,
    pub router_inbound_activity: u8,
    pub security_timer: u8,
}

#[derive(Debug)]
pub struct Nib {
    pub nwk_sequence_number: u8,
    pub nwk_passive_ack_timeout: u32,
    pub nwk_max_broadcast_retries: u8,
    pub nwk_max_children: u8,
    pub nwk_max_depth: u8,
    pub nwk_neighbor_table: HashMap<Eui64, NwkNeighborTableEntry>,
    pub nwk_network_broadcast_delivery_time: u32,
    pub nwk_route_table: Vec<NwkRoutingTableEntry>,
    pub nwk_route_discovery_table: HashMap<u8, NwkRouteDiscoveryTableEntry>,
    pub nwk_capability_information: NwkCapabilityInformation,
    pub nwk_manager_addr: Nwk,
    pub nwk_max_source_route: u8,
    pub nwk_update_id: u8,
    pub nwk_transaction_persistence_time: u16,
    pub nwk_network_address: Nwk,
    pub nwk_stack_profile: u8,
    pub nwk_broadcast_transaction_table: Vec<NwkBroadcastTransaction>,
    pub nwk_extended_pan_id: Eui64,
    pub nwk_route_record_table: HashMap<Nwk, Vec<Nwk>>,
    pub nwk_is_concentrator: bool,
    pub nwk_concentrator_radius: u8,
    pub nwk_concentrator_discovery_time: u8,
    pub nwk_security_level: u8,
    pub nwk_security_material_primary: NwkSecurityDescriptor,
    pub nwk_security_material_alternate: NwkSecurityDescriptor,
    pub nwk_active_key_seq_number: u8,
    pub nwk_all_fresh: bool,
    pub nwk_concentrator_discovery_separation_time: u8,
    pub nwk_link_status_period: u8,

    // The number of missed link status command frames before resetting the link costs
    // to zero.
    pub nwk_router_age_limit: u8,
    pub nwk_address_map: HashMap<Eui64, Nwk>,

    // A flag that determines if a time stamp indication is provided on incoming and
    // outgoing packets.
    pub nwk_time_stamp: bool,

    pub nwk_pan_id: PanId,

    // A count of unicast transmissions made by the NNK layer on this device. Each time
    // the NWK layer transmits aunicast frame, by invoking the MCPS-state.request
    // primitive of the MAC sub-layer, it SHALL increment this counter. When either the
    // NHL performs an NLME-SET.request on this attribute or if the value of nwkTxTotal
    // rolls over past 0xffff the NWK layer SHALL reset to 0x00 each Transmit Failure
    // field contained in the neighbor table.
    pub nwk_tx_total: u16,

    // This policy determines whether or not a remote NWK leave request command frame
    // received by the local device is accepted.
    pub nwk_leave_request_allowed: bool,

    pub nwk_parent_information: u8,

    // This is an index into Table 3-54. It indicates the default timeout in minutes for
    // any end device that does not negotiate a different timeout value.
    pub nwk_end_device_timeout_default: u8,

    // This policy determines whether a NWK leave request is accepted when the Rejoin
    // bit in the message is set to FALSE
    pub nwk_leave_request_without_rejoin_allowed: bool,

    pub nwk_ieee_address: Eui64,
    // nwkMacInterfaceTable
    // nwkNetworkWideBeaconAppendixTLVs
    // nwkDeviceLocalBeaconAppendixTLVs
    // nwkDiscoveryTable
    // nwkDiscoveryTableSize = 6
    // nwkNextPanId = 0xFFFF
    // nwkNextChannelChange = 0
    // nwkPerformAdditionalMacDataPollRetries = 0
    // nwkPreferredParent
    // nwkHubConnectivity = true
    // nwkRoutingSequenceNumber = 0
    // nwkGoodParentLQA = 75
    // nwkPanIdConflictCount = 0
    // nwkMaxInitialJoinParentAttempts = 1
    // nwkMaxRejoinParentAttempts = 3
}

impl Nib {
    pub fn new() -> Nib {
        Nib {
            nwk_sequence_number: 0,
            nwk_passive_ack_timeout: 500,
            nwk_max_broadcast_retries: 2,
            nwk_max_children: 32,
            nwk_max_depth: 15,
            nwk_neighbor_table: HashMap::new(),
            nwk_network_broadcast_delivery_time: 0,
            nwk_route_table: Vec::new(),
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
            nwk_transaction_persistence_time: 7680,
            nwk_network_address: Nwk(0x0000),
            nwk_stack_profile: 2,
            nwk_broadcast_transaction_table: Vec::new(),
            nwk_extended_pan_id: Eui64::from_hex("0000000000000000"),
            nwk_route_record_table: HashMap::new(),
            nwk_is_concentrator: true,
            nwk_concentrator_radius: 10,
            nwk_concentrator_discovery_time: 0,
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
            nwk_concentrator_discovery_separation_time: 0,
            nwk_link_status_period: 0x0F,
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
            src: src,
            destination_endpoint: ack.destination_endpoint,
            cluster_id: ack.cluster_id,
            profile_id: ack.profile_id,
            source_endpoint: ack.source_endpoint,
            counter: ack.counter,
        }
    }
}

#[derive(Debug)]
pub struct ZigbeeStackState {
    pub channel: u8,
    pub ieee802154_sequence_number: u8,
    pub nib: Nib,
    pub pending_aps_acks: HashMap<ApsAckData, oneshot::Sender<()>>,
}

impl ZigbeeStackState {
    pub fn new() -> Self {
        ZigbeeStackState {
            channel: 0,
            ieee802154_sequence_number: 0,
            nib: Nib::new(),
            pending_aps_acks: HashMap::new(),
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

    pub state: Mutex<ZigbeeStackState>,
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
            state: Mutex::new(ZigbeeStackState::new()),
            spinel: spinel,
            notification_tx: notification_tx,
            raw_frame_rx: Mutex::new(raw_frame_rx),
        });

        (arc_stack, notification_rx)
    }

    pub async fn run(&self) {
        loop {
            // Parse incoming 802.15.4 frames from Spinel
            let maybe_spinel_frame = {
                self.raw_frame_rx
                    .lock()
                    .expect("Failed to receive frame")
                    .recv()
                    .await
            };

            if maybe_spinel_frame.is_none() {
                log::warn!("Frame sender hung up");
                continue;
            }

            let spinel_frame = maybe_spinel_frame.unwrap();

            let packet = match SpinelRxFrame::from_bytes(&spinel_frame.value) {
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

            let ieee802154_frame = match Ieee802154Frame::from_bytes_without_fcs(frame_data) {
                Ok(f) => f,
                Err(e) => {
                    log::warn!("Error parsing IEEE 802.15.4 frame: {:?}", e);
                    continue;
                }
            };

            log::debug!("Received 802.15.4 frame: {:?}", ieee802154_frame);

            match self.receive_802154_frame(&ieee802154_frame) {
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

                    let notification = ZigbeeNotification::ReceivedApsCommand {
                        source: nwk_frame.nwk_header.source,
                        profile_id: aps_frame.profile_id,
                        cluster_id: aps_frame.cluster_id,
                        src_ep: aps_frame.source_endpoint,
                        dst_ep: aps_frame.destination_endpoint,
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

        Ok(())
    }

    pub fn receive_802154_frame(&self, frame: &Ieee802154Frame) -> Option<NwkFrame> {
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
            Ieee802154FrameType::Data => {
                // Process it below
            }
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
            Some(dest_pan_id) => {
                if dest_pan_id != state.nib.nwk_pan_id {
                    log::debug!(
                        "Ignoring frame, PAN ID does not match {:?} != {:?}",
                        dest_pan_id,
                        state.nib.nwk_pan_id
                    );
                    return None;
                }
            }
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
            && nwk_frame.nwk_header.destination.as_u16() < 0xFFFC
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
                        "Ignoring frame, frame counter has rolled backward from {} to {}",
                        last_stored_frame_counter,
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
                    log::warn!("Ignoring frame, decryption failed: {:?}", err);
                    return None;
                }
            };

        // At this point we no longer need to lock `state`
        drop(state);

        log::info!("Decrypted frame: {:#?}", decrypted_nwk_frame);
        self.handle_decrypted_frame(&decrypted_nwk_frame);

        return Some(decrypted_nwk_frame);
    }

    pub fn update_nwk_eui64_mapping(&self, nwk: Nwk, eui64: Eui64) {
        let mut state = self.state.lock().unwrap();

        match state.nib.nwk_address_map.insert(eui64, nwk) {
            None => {
                log::debug!("Added new address mapping: {:?} -> {:?}", eui64, nwk)
            }
            Some(old_nwk) => {
                log::warn!(
                    "Updated address mapping: {:?} -> {:?} (was {:?})",
                    eui64,
                    nwk,
                    old_nwk,
                )
            }
        }
    }

    pub fn handle_decrypted_frame(&self, nwk_frame: &NwkFrame) {
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
                        "Incremented frame counter for {:?} to {}",
                        relaying_eui64,
                        aux_header.frame_counter
                    );
                }
                None => {}
            }
        }

        // Update the address cache
        match nwk_frame.nwk_header.source_ieee {
            Some(src_eui64) => {
                self.update_nwk_eui64_mapping(nwk_frame.nwk_header.source, src_eui64);
            }
            None => {}
        }

        // Handle NWK commands
        if nwk_frame.nwk_header.frame_control.frame_type == NwkFrameType::Command {
            match NwkCommandId::try_from(nwk_frame.payload[0]) {
                Ok(NwkCommandId::LinkStatus) => {
                    // TODO: Error handling for decoding?
                    let link_status_cmd =
                        NwkLinkStatusCommand::from_bytes(&nwk_frame.payload).unwrap();
                    log::info!("Link status command frame received: {:#?}", link_status_cmd);
                }
                Ok(NwkCommandId::RouteReply) => {
                    // TODO: Error handling for decoding?
                    let route_reply_cmd =
                        NwkRouteReplyCommand::from_bytes(&nwk_frame.payload).unwrap();
                    log::info!("Route reply command frame received: {:#?}", route_reply_cmd);
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
                    self.handle_route_request(nwk_frame);
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

    fn handle_route_request(&self, nwk_frame: &NwkFrame) {
        let route_request_cmd = match NwkRouteRequestCommand::from_bytes(&nwk_frame.payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                log::warn!("Error parsing route request command: {:?}", e);
                return;
            }
        };

        log::info!("Route request command frame: {:#?}", route_request_cmd);

        let state = self.state.lock().unwrap();

        // TODO: for now, only handle route requests back to us
        if route_request_cmd.destination_address != state.nib.nwk_network_address {
            log::debug!("Ignoring route request not destined for us (NWK)");
            return;
        }

        if let Some(destination_eui64) = route_request_cmd.destination_eui64 {
            if destination_eui64 != state.nib.nwk_ieee_address {
                log::debug!("Ignoring route request not destined for us (EUI64)");
                return;
            }
        }

        let route_reply_frame = NwkFrame {
            encrypted: false,
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Command,
                    protocol_version: 2,
                    discover_route: NwkRouteDiscovery::Suppress,
                    multicast: false,
                    security: false,
                    source_route: false,
                    destination: false,
                    extended_source: false,
                    end_device_initiator: false,
                    reserved: 0b00,
                },
                destination: nwk_frame.nwk_header.source,
                source: state.nib.nwk_network_address,
                radius: 30,
                sequence_number: state.nib.nwk_sequence_number,
                destination_ieee: None,
                source_ieee: None,
                multicast_control: None,
                source_route: None,
            },
            aux_header: None,
            payload: NwkRouteReplyCommand {
                multicast: false,
                route_request_identifier: route_request_cmd.route_request_identifier,
                originator_nwk: state.nib.nwk_network_address,
                responder_nwk: nwk_frame.nwk_header.source,
                path_cost: 1, // :)
                originator_eui64: nwk_frame.nwk_header.source_ieee,
                responder_eui64: Some(state.nib.nwk_ieee_address),
                tlvs: vec![],
            }
            .serialize(),
        };

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

    fn prepare_request(
        &self,
        destination: Nwk,
        src_ep: u8,
        dst_ep: u8,
        cluster_id: u16,
        profile_id: u16,
        aps_ack: bool,
        counter: u8,
        asdu: &Vec<u8>,
    ) -> Ieee802154Frame {
        let aps_frame = ApsDataFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Data,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved: 0b0,
                security: false,
                ack_request: aps_ack,
                extended_header: false,
            },
            destination_endpoint: dst_ep,
            cluster_id: cluster_id,
            profile_id: profile_id,
            source_endpoint: src_ep,
            counter: counter,
            asdu: asdu.to_vec(),
        };

        log::debug!("Prepared APS frame: {:#?}", aps_frame);

        // TODO: routing :)
        // At this point, we assume the destination device is in range of the coordinator.
        let nwk_frame = self.wrap_aps_frame(destination, &aps_frame);
        log::debug!("Prepared NWK frame: {:#?}", nwk_frame);
        let ieee802154_frame = self.wrap_nwk_frame(&nwk_frame);

        ieee802154_frame
    }

    fn wrap_aps_frame(&self, destination: Nwk, aps_frame: &ApsDataFrame) -> NwkFrame {
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
                    protocol_version: 2,
                    discover_route: NwkRouteDiscovery::Suppress,
                    multicast: false,
                    security: true,
                    source_route: false,
                    destination: false,
                    extended_source: false,
                    end_device_initiator: false,
                    reserved: 0b00,
                },
                destination: destination,
                source: state.nib.nwk_network_address,
                radius: 30,
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
            payload: aps_frame.to_bytes(),
        };

        plaintext_nwk_frame
            .encrypt(&state.nib.nwk_security_material_primary.key)
            .expect("Encryption somehow failed")
    }

    fn wrap_nwk_frame(&self, nwk_frame: &NwkFrame) -> Ieee802154Frame {
        let mut state = self.state.lock().unwrap();

        // Increment the 802.15.4 sequence number
        state.ieee802154_sequence_number = state.ieee802154_sequence_number.wrapping_add(1);

        // TODO: support EUI64 addressing
        Ieee802154Frame {
            frame_control: Ieee802154FrameControl {
                frame_type: Ieee802154FrameType::Data,
                security_enabled: false,
                frame_pending: false,
                ack_request: true,
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
            dest_address: Some(Ieee802154Address::Nwk(nwk_frame.nwk_header.destination)),
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
                channel: channel,
                max_csma_backoffs: 1,
                max_frame_retries: 0,
                enable_csma_ca: true,
                is_header_updated: true,
                is_a_retransmit: false,
                is_security_processed: true,
                tx_delay: 0 as u32,
                tx_delay_base_time: 0 as u32,
                rx_channel_after_tx: channel,
                tx_power: 8,
            })
            .await
            .expect("Failed to transmit frame");

        log::info!("Send status: {:?}", status);

        // Frames that do not ask for an ACK or that suppress their sequence number
        // cannot be ACKed
        if !frame.frame_control.ack_request || frame.frame_control.sequence_number_suppression {
            return;
        }
    }

    pub async fn send_aps_command(
        &self,
        destination: Nwk,
        profile_id: u16,
        cluster_id: u16,
        src_ep: u8,
        dst_ep: u8,
        aps_ack: bool,
        aps_seq: u8,
        data: Vec<u8>,
    ) -> Result<(), String> {
        let ieee802154_frame = self.prepare_request(
            destination,
            src_ep,
            dst_ep,
            cluster_id,
            profile_id,
            aps_ack,
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
}
