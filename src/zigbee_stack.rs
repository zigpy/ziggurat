use crate::ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154Frame, Ieee802154FrameControl,
    Ieee802154FrameType,
};
use crate::types::{Eui64, Key, Nwk, PanId};
use crate::zigbee_aps::{ApsDeliveryMode, ApsFrame, ApsFrameControl, ApsFrameType};
use crate::zigbee_nwk::{
    NwkAuxHeader, NwkFrame, NwkFrameControl, NwkFrameType, NwkHeader, NwkRouteDiscovery,
    NwkSecurityHeaderControlField, NwkSecurityHeaderKeyId, NwkSecurityLevel,
};
use crate::zigbee_nwk_commands::{
    NwkCommandId, NwkLinkStatusCommand, NwkRouteRecordCommand, NwkRouteReplyCommand,
};
use std::collections::HashMap;

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
    // used to forward a data packet towards its destination; and decremented
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
    // the NWK layer transmits aunicast frame, by invoking the MCPS-DATA.request
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

#[derive(Debug)]
pub struct ZigbeeStack {
    pub nib: Nib,
}

impl ZigbeeStack {
    pub fn new() -> ZigbeeStack {
        ZigbeeStack { nib: Nib::new() }
    }

    pub fn receive_802154_frame(&mut self, frame: &Ieee802154Frame) -> Option<NwkFrame> {
        // 802.15.4 encrypted frames can't be Zigbee NWK
        if frame.frame_control.security_enabled {
            log::debug!("Ignoring frame, 802.15.4 security bit is enabled");
            return None;
        }

        // Only process data frames for now
        if frame.frame_control.frame_type != Ieee802154FrameType::Data {
            log::debug!("Ignoring frame, not a data frame");
            return None;
        }

        // Only process packets destined for our PAN ID
        match frame.dest_pan_id {
            None => {
                log::debug!("Ignoring frame, destination PAN ID is not present");
                return None;
            }
            Some(dest_pan_id) => {
                if dest_pan_id != self.nib.nwk_pan_id {
                    log::debug!(
                        "Ignoring frame, PAN ID does not match {:?} != {:?}",
                        dest_pan_id,
                        self.nib.nwk_pan_id
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
        if nwk_frame.nwk_header.destination != self.nib.nwk_network_address
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
        if aux_header.key_sequence_number != self.nib.nwk_active_key_seq_number {
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

        let last_frame_counter;

        match self
            .nib
            .nwk_security_material_primary
            .incoming_frame_counter_set
            .get(&src_eui64)
        {
            None => {
                log::warn!("Unknown sender, not validating frame counter");
                last_frame_counter = 0;
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

                last_frame_counter = *last_stored_frame_counter;
            }
        };

        log::debug!(
            "Attempting to decrypt {:?} with {:?}",
            nwk_frame,
            self.nib.nwk_security_material_primary
        );

        // Finally, attempt decryption
        let decrypted_nwk_frame =
            match nwk_frame.decrypt(&self.nib.nwk_security_material_primary.key) {
                Ok(decrypted_frame) => decrypted_frame,
                Err(err) => {
                    log::warn!("Ignoring frame, decryption failed: {:?}", err);
                    return None;
                }
            };

        self.handle_decrypted_frame(&decrypted_nwk_frame, frame);

        log::info!("Decrypted frame: {:#?}", decrypted_nwk_frame);
        return Some(decrypted_nwk_frame);
    }

    pub fn update_nwk_eui64_mapping(&mut self, nwk: Nwk, eui64: Eui64) {
        match self.nib.nwk_address_map.insert(eui64, nwk) {
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

    pub fn handle_decrypted_frame(
        &mut self,
        nwk_frame: &NwkFrame,
        ieee802154_frame: &Ieee802154Frame,
    ) {
        // Update the frame counter for the relaying device
        if let Some(aux_header) = &nwk_frame.aux_header {
            match aux_header.extended_source {
                Some(relaying_eui64) => {
                    self.nib
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
                        NwkLinkStatusCommand::from_bytes(&nwk_frame.payload[1..]).unwrap();
                    log::info!("Link status command frame received: {:#?}", link_status_cmd);
                }
                Ok(NwkCommandId::RouteReply) => {
                    // TODO: Error handling for decoding?
                    let route_reply_cmd =
                        NwkRouteReplyCommand::from_bytes(&nwk_frame.payload[1..]).unwrap();
                    log::info!("Route reply command frame received: {:#?}", route_reply_cmd);
                }
                Ok(NwkCommandId::RouteRecord) => {
                    // TODO: Error handling for decoding?
                    let route_record_cmd =
                        NwkRouteRecordCommand::from_bytes(&nwk_frame.payload[1..]).unwrap();
                    log::info!(
                        "Route record command frame received: {:#?}",
                        route_record_cmd
                    );
                    self.nib
                        .nwk_route_record_table
                        .insert(nwk_frame.nwk_header.source, route_record_cmd.relays);
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
}
