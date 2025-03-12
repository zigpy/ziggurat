use crate::types::{format_hex, Eui64, Key, Nwk, PanId};

pub enum NwkCapabilityInformationDeviceType {
    EndDevice = 0,
    Router = 1,
}

pub enum NwkCapabilityInformationPowerSource {
    MainsPower = 0,
    Battery = 1,
}

pub enum NetworkKeyType {
    Standard = 1,
}

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
pub struct Nib {
    pub nwkSequenceNumber: u8,
    pub nwkPassiveAckTimeout: u32,
    pub nwkMaxBroadcastRetries: u8,
    pub nwkMaxChildren: u8,
    pub nwkMaxDepth: u8,
    pub nwkNeighborTable: Vec<NwkNeighbor>,
    pub nwkNetworkBroadcastDeliveryTime: u32,
    pub nwkRouteTable: Vec<NwkRoute>,
    pub nwkCapabilityInformation: NwkCapabilityInformation,
    pub nwkManagerAddr: Nwk,
    pub nwkMaxSourceRoute: u8,
    pub nwkUpdateId: u8,
    pub nwkTransactionPersistenceTime: u16,
    pub nwkNetworkAddress: Nwk,
    pub nwkStackProfile: u8,
    pub nwkBroadcastTransactionTable: Vec<NwkBroadcastTransaction>,
    pub nwkExtendedPanId: Eui64,
    pub nwkRouteRecordTable: HashMap<NWK, Vec<NWK>>,
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

    // A count of unicast transmissions made by the NWK layer on this device. Each time
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
            nwkNeighborTable: Vec::new(),
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
            nwkManagerAddr: 0x0000,
            nwkMaxSourceRoute: 12,
            nwkUpdateId: 0,
            nwkTransactionPersistenceTime: 7680,
            nwkNetworkAddress: 0x0000,
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
            nwkPanId: 0xFFFF,
            nwkTxTotal: 0,
            nwkLeaveRequestAllowed: false,
            nwkParentInformation: 0,
            nwkEndDeviceTimeoutDefault: 0,
            nwkLeaveRequestWithoutRejoinAllowed: false,
            nwkIeeeAddress: Eui64::from_hex("0000000000000000"),
        }
    }
}
