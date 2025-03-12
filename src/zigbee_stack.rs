use crate::ieee_802154::{Ieee802154Address, Ieee802154Frame, Ieee802154FrameType};
use crate::types::{format_hex, Eui64, Key, Nwk, PanId};
use crate::zigbee_nwk::{NwkFrame, NwkSecurityHeaderKeyId, NwkSecurityLevel};
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
    pub alternatePanCoordinator: bool,
    pub deviceType: NwkCapabilityInformationDeviceType,
    pub powerSource: NwkCapabilityInformationPowerSource,
    pub receiverOnWhenIdle: bool,
    pub reserved1: bool,
    pub reserved2: bool,
    pub securityCapability: NwkSecurityCapability,
    pub allocateAddress: bool, // = 1
}

#[derive(Debug)]
pub struct NwkSecurityDescriptor {
    pub keySeqNumber: u8,
    pub outgoingFrameCounter: u32,
    pub incomingFrameCounterSet: HashMap<Eui64, u32>,
    pub key: Key,
    pub networkKeyType: NetworkKeyType,
}

#[derive(Debug)]
pub struct NwkBroadcastTransaction {
    pub sourceNwk: Nwk,
    pub sequenceNumber: u8,
    pub expirationTime: u8,
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
pub struct Nib {
    pub nwkSequenceNumber: u8,
    pub nwkPassiveAckTimeout: u32,
    pub nwkMaxBroadcastRetries: u8,
    pub nwkMaxChildren: u8,
    pub nwkMaxDepth: u8,
    // pub nwkNeighborTable: Vec<NwkNeighbor>,
    pub nwkNetworkBroadcastDeliveryTime: u32,
    pub nwkRouteTable: Vec<NwkRoutingTableEntry>,
    pub nwkCapabilityInformation: NwkCapabilityInformation,
    pub nwkManagerAddr: Nwk,
    pub nwkMaxSourceRoute: u8,
    pub nwkUpdateId: u8,
    pub nwkTransactionPersistenceTime: u16,
    pub nwkNetworkAddress: Nwk,
    pub nwkStackProfile: u8,
    pub nwkBroadcastTransactionTable: Vec<NwkBroadcastTransaction>,
    pub nwkExtendedPanId: Eui64,
    pub nwkRouteRecordTable: HashMap<Nwk, Vec<Nwk>>,
    pub nwkIsConcentrator: bool,
    pub nwkConcentratorRadius: u8,
    pub nwkConcentratorDiscoveryTime: u8,
    pub nwkSecurityLevel: u8,
    pub nwkSecurityMaterialPrimary: NwkSecurityDescriptor,
    pub nwkSecurityMaterialAlternate: NwkSecurityDescriptor,
    pub nwkActiveKeySeqNumber: u8,
    pub nwkAllFresh: bool,
    pub nwkConcentratorDiscoverySeparationTime: u8,
    pub nwkLinkStatusPeriod: u8,

    // The number of missed link status command frames before resetting the link costs to zero.
    pub nwkRouterAgeLimit: u8,
    pub nwkAddressMap: HashMap<Eui64, Nwk>,

    // A flag that determines if a time stamp indication is provided on incoming and outgoing packets.
    pub nwkTimeStamp: bool,

    pub nwkPanId: PanId,

    // A count of unicast transmissions made by the NNK layer on this device. Each time
    // the NWK layer transmits aunicast frame, by invoking the MCPS-DATA.request
    // primitive of the MAC sub-layer, it SHALL increment this counter. When either the
    // NHL performs an NLME-SET.request on this attribute or if the value of nwkTxTotal
    // rolls over past 0xffff the NWK layer SHALL reset to 0x00 each Transmit Failure
    // field contained in the neighbor table.
    pub nwkTxTotal: u16,

    // This policy determines whether or not a remote NWK leave request command frame received by the local device is accepted.
    pub nwkLeaveRequestAllowed: bool,

    pub nwkParentInformation: u8,

    // This is an index into Table 3-54. It indicates the default timeout in minutes for any end device that does not negotiate a different timeout value.
    pub nwkEndDeviceTimeoutDefault: u8,

    // This policy determines whether a NWK leave request is accepted when the Rejoin bit in the message is set to FALSE
    pub nwkLeaveRequestWithoutRejoinAllowed: bool,

    pub nwkIeeeAddress: Eui64,
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
            nwkSequenceNumber: 0,
            nwkPassiveAckTimeout: 500,
            nwkMaxBroadcastRetries: 2,
            nwkMaxChildren: 32,
            nwkMaxDepth: 15,
            // nwkNeighborTable: Vec::new(),
            nwkNetworkBroadcastDeliveryTime: 0,
            nwkRouteTable: Vec::new(),
            nwkCapabilityInformation: NwkCapabilityInformation {
                alternatePanCoordinator: false,
                deviceType: NwkCapabilityInformationDeviceType::EndDevice,
                powerSource: NwkCapabilityInformationPowerSource::MainsPower,
                receiverOnWhenIdle: true,
                reserved1: false,
                reserved2: false,
                securityCapability: NwkSecurityCapability::Capable,
                allocateAddress: true,
            },
            nwkManagerAddr: Nwk(0x0000),
            nwkMaxSourceRoute: 12,
            nwkUpdateId: 0,
            nwkTransactionPersistenceTime: 7680,
            nwkNetworkAddress: Nwk(0x0000),
            nwkStackProfile: 2,
            nwkBroadcastTransactionTable: Vec::new(),
            nwkExtendedPanId: Eui64::from_hex("0000000000000000"),
            nwkRouteRecordTable: HashMap::new(),
            nwkIsConcentrator: true,
            nwkConcentratorRadius: 10,
            nwkConcentratorDiscoveryTime: 0,
            nwkSecurityLevel: 5,
            nwkSecurityMaterialPrimary: NwkSecurityDescriptor {
                keySeqNumber: 0,
                outgoingFrameCounter: 0,
                incomingFrameCounterSet: HashMap::new(),
                key: Key::from_hex("00000000000000000000000000000000"),
                networkKeyType: NetworkKeyType::Standard,
            },
            nwkSecurityMaterialAlternate: NwkSecurityDescriptor {
                keySeqNumber: 0,
                outgoingFrameCounter: 0,
                incomingFrameCounterSet: HashMap::new(),
                key: Key::from_hex("00000000000000000000000000000000"),
                networkKeyType: NetworkKeyType::Standard,
            },
            nwkActiveKeySeqNumber: 0,
            nwkAllFresh: false,
            nwkConcentratorDiscoverySeparationTime: 0,
            nwkLinkStatusPeriod: 0x0F,
            nwkRouterAgeLimit: 3,
            nwkAddressMap: HashMap::new(),
            nwkTimeStamp: false,
            nwkPanId: PanId(0xFFFF),
            nwkTxTotal: 0,
            nwkLeaveRequestAllowed: false,
            nwkParentInformation: 0,
            nwkEndDeviceTimeoutDefault: 0,
            nwkLeaveRequestWithoutRejoinAllowed: false,
            nwkIeeeAddress: Eui64::from_hex("0000000000000000"),
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

    pub fn receive_802154_frame(&mut self, frame: &Ieee802154Frame) {
        // 802.15.4 encrypted frames can't be Zigbee NWK
        if frame.frame_control.security_enabled {
            log::debug!("Ignoring frame, 802.15.4 security bit is enabled");
            return;
        }

        // Only process data frames for now
        if frame.frame_control.frame_type != Ieee802154FrameType::Data {
            log::debug!("Ignoring frame, not a data frame");
            return;
        }

        // Only process packets destined for our PAN ID
        match frame.dest_pan_id {
            None => {
                log::debug!("Ignoring frame, destination PAN ID is not present");
                return;
            }
            Some(dest_pan_id) => {
                if dest_pan_id != self.nib.nwkPanId {
                    log::debug!("Ignoring frame, PAN ID does not match");
                    return;
                }
            }
        }

        // Next, try to parse the NWK frame
        let nwk_frame = match NwkFrame::from_bytes(&frame.payload) {
            Ok(nwk_frame) => nwk_frame,
            Err(_) => {
                log::debug!("Ignoring frame, not a NWK frame");
                return;
            }
        };

        // Ignore frames that aren't destined for us
        if nwk_frame.nwk_header.destination != self.nib.nwkNetworkAddress
            && nwk_frame.nwk_header.destination.as_u16() < 0xFFFC
        {
            log::debug!("Ignoring frame, destination is not us");
            return;
        }

        // Ignore unencrypted frames
        if !nwk_frame.encrypted {
            log::debug!("Ignoring frame, it is not encrypted");
            return;
        }

        let aux_header = match nwk_frame.aux_header {
            None => {
                log::debug!("Ignoring frame, auxiliary header is missing");
                return;
            }
            Some(ref header) => header,
        };

        // The frame security level is fixed for a given network and transmitted frames will use "0"
        if aux_header.security_control.security_level != NwkSecurityLevel::NoSecurity {
            log::debug!("Ignoring frame, security level is not 0");
            return;
        }

        // Only the network key is supported for now
        if aux_header.security_control.key_id != NwkSecurityHeaderKeyId::NetworkKey {
            log::debug!("Ignoring frame, key ID is not NetworkKey");
            return;
        }

        // Validate the network key sequence number
        if aux_header.key_sequence_number != self.nib.nwkActiveKeySeqNumber {
            log::debug!("Ignoring frame, key sequence number is unknown");
            return;
        }

        // Validate the security header frame counter for the current IEEE
        let src_eui64;

        match aux_header.extended_source {
            None => {
                log::debug!("Ignoring frame, extended source is missing");
                return;
            }
            Some(eui64) => {
                src_eui64 = eui64;
            }
        }

        let last_frame_counter;

        match self
            .nib
            .nwkSecurityMaterialPrimary
            .incomingFrameCounterSet
            .get(&src_eui64)
        {
            None => {
                log::warn!("Unknown sender, not validating frame counter");
                last_frame_counter = 0;
            }
            Some(last_stored_frame_counter) => {
                if aux_header.frame_counter <= *last_stored_frame_counter {
                    log::debug!(
                        "Ignoring frame, frame counter has rolled backward from {}, to {}",
                        last_stored_frame_counter,
                        aux_header.frame_counter
                    );
                    return;
                }

                last_frame_counter = *last_stored_frame_counter;
            }
        };

        log::debug!(
            "Attempting to decrypt {:?} with {:?}",
            nwk_frame,
            self.nib.nwkSecurityMaterialPrimary
        );

        // Finally, attempt decryption
        let decrypted_nwk_frame = match nwk_frame.decrypt(&self.nib.nwkSecurityMaterialPrimary.key)
        {
            Ok(decrypted_frame) => decrypted_frame,
            Err(err) => {
                log::warn!("Ignoring frame, decryption failed: {:?}", err);
                return;
            }
        };

        // The frame is valid, update the frame counter for the sender
        self.nib
            .nwkSecurityMaterialPrimary
            .incomingFrameCounterSet
            .insert(src_eui64, aux_header.frame_counter);

        log::debug!(
            "Incremented frame counter for {:?} from {} to {}",
            src_eui64,
            last_frame_counter,
            aux_header.frame_counter
        );

        // Update the address cache
        match self
            .nib
            .nwkAddressMap
            .insert(src_eui64, nwk_frame.nwk_header.source)
        {
            None => {
                log::debug!(
                    "Added new address mapping: {:?} -> {:?}",
                    nwk_frame.nwk_header.source,
                    src_eui64
                )
            }
            Some(old_nwk) => {
                log::warn!(
                    "Updated address mapping: {:?} -> {:?}",
                    nwk_frame.nwk_header.source,
                    src_eui64
                )
            }
        }

        log::info!("Decrypted frame: {:#?}", decrypted_nwk_frame);
    }
}
