#![allow(clippy::useless_conversion)]

use crate::{Command, Request, Response};
use abstract_bits::abstract_bits;
use ieee_802154::types::{Eui64, Nwk, PanId};
use num_enum::TryFromPrimitive;

/// Zigbee spec 3.4
#[abstract_bits(bits = 8)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum NwkCommandId {
    RouteRequest = 0x01,
    RouteReply = 0x02,
    NetworkStatus = 0x03,
    Leave = 0x04,
    RouteRecord = 0x05,
    RejoinRequest = 0x06,
    RejoinResponse = 0x07,
    LinkStatus = 0x08,
    NetworkReport = 0x09,
    NetworkUpdate = 0x0a,
    EndDeviceTimeoutRequest = 0x0b,
    EndDeviceTimeoutResponse = 0x0c,
    LinkPowerDelta = 0x0d,
    NetworkCommissioningRequest = 0x0e,
    NetworkCommissioningResponse = 0x0f,
}

/// Zigbee spec: 3.4.1.3.1.1
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[abstract_bits(bits = 2)]
#[repr(u8)]
pub enum NwkRouteRequestManyToOne {
    NotManyToOne = 0,
    ManyToOneSenderSupportsRouteRecordTable = 1,
    ManyToOneSenderDoesntSupportRouteRecordTable = 2,
    Reserved = 3,
}

/// Zigbee spec: 3.4.1 Route Request Command
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkRouteRequestCommand {
    reserved: u3,
    pub many_to_one: NwkRouteRequestManyToOne,
    #[abstract_bits(presence_of = destination_eui64)]
    reserved: bool,
    reserved: u2,
    pub route_request_identifier: u8,
    pub destination_address: Nwk,
    pub path_cost: u8,
    pub destination_eui64: Option<Eui64>,
}

impl Request for NwkRouteRequestCommand {
    type REPLY = NwkRouteReplyCommand;
}

impl Command for NwkRouteRequestCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::RouteRequest;
}

/// Zigbee spec 3.4.2 Route Reply Command
#[abstract_bits::abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkRouteReplyCommand {
    reserved: u4,
    #[abstract_bits(presence_of = originator_eui64)]
    reserved: bool,
    #[abstract_bits(presence_of = responder_eui64)]
    reserved: bool,
    reserved: u2,
    pub route_request_identifier: u8,
    pub originator_nwk: Nwk,
    pub responder_nwk: Nwk,
    pub path_cost: u8,
    pub originator_eui64: Option<Eui64>,
    pub responder_eui64: Option<Eui64>,
}

impl Response for NwkRouteReplyCommand {
    type REQUEST = NwkRouteRequestCommand;
}

impl Command for NwkRouteReplyCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::RouteReply;
}

/// Zigbee spec 3.4.3: Network Status Command
#[abstract_bits(bits = 8)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum NwkNetworkStatus {
    /// This link code indicates a failure to route across a link. This was used in
    /// previous specifications. Revision 23 devices SHALL no longer send this error
    /// code but SHALL accept and act on it. It SHALL be treated the same as 0x02, Link
    /// failure.
    LegacyNoRouteAvailable = 0x00,
    /// This link code indicates a failure to route across a link. This was used in
    /// previous specifications. Revision 23 devices SHALL no longer send this error
    /// code but SHALL accept and act on it. It SHALL be treated the same as 0x02, Link
    /// failure.
    LegacyLinkFailure = 0x01,
    /// This link code indicates a failure to route across a link.
    LinkFailure = 0x02,

    /// Deprecated in R23. From R22: Low battery level.
    LowBatteryLevel = 0x03,
    /// Deprecated in R23. From R22: No routing capacity.
    NoRoutingCapacity = 0x04,
    /// Deprecated in R23. From R22: No indirect capacity.
    NoIndirectCapacity = 0x05,
    /// Deprecated in R23. From R22: Indirect transaction expiry.
    IndirectTransactionExpiry = 0x06,
    /// Deprecated in R23. From R22: Target device unavailable.
    TargetDeviceUnavailable = 0x07,
    /// Deprecated in R23. From R22: Target address unallocated.
    TargetAddressUnallocated = 0x08,

    /// The failure occurred as a result of a failure in the RF link to the device's
    /// parent. This status is only used locally on a device to indicate loss of
    /// communication with the parent, it is not sent over-the-air.
    ParentLinkFailure = 0x09,

    /// Deprecated in R23. From R22: Validate route.
    ValidateRoute = 0x0A,

    /// Source routing has failed, probably indicating a link failure in one
    /// of the source route's links.
    SourceRouteFailure = 0x0B,
    /// A route established as a result of a many-to-one route request has
    /// failed.
    ManyToOneRouteFailure = 0x0C,
    /// The address in the destination address field has been determined to be
    /// in use by two or more devices.
    AddressConflict = 0x0D,

    /// Deprecated in R23. From R22: Verify addresses.
    VerifyAddresses = 0x0E,

    /// The operational network PAN identifier of the device has been updated.
    PanIdentifierUpdate = 0x0F,
    /// The network address of the local device has been updated.
    NetworkAddressUpdate = 0x10,
    /// Removed in R23. From R22: Bad frame counter.
    BadFrameCounter = 0x11,
    /// Removed in R23. From R22: Bad key sequence number.
    BadKeySequenceNumber = 0x12,
    /// The NWK command ID is not known to the device.
    UnknownCommand = 0x13,
    /// Notification to the local application that a PAN ID Conflict Report has been
    /// received by the local Network Manager. It is not sent over the air.
    PanIdConflictReport = 0x14,
}

#[abstract_bits::abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkNetworkStatusCommand {
    pub status_code: NwkNetworkStatus,
    pub network_address: Nwk,
}

impl Command for NwkNetworkStatusCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::NetworkStatus;
}

/// Zigbee spec 3.4.5: Route Record Command
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkRouteRecordCommand {
    #[abstract_bits(length_of = relays)]
    reserved: u8,
    pub relays: Vec<Nwk>,
}

impl Command for NwkRouteRecordCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::RouteRecord;
}

/// Zigbee spec 3.4.7
#[abstract_bits(bits = 1)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum NwkRejoinCapabilityInformationDeviceType {
    EndDevice = 0,
    Router = 1,
}

#[abstract_bits(bits = 1)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum NwkRejoinCapabilityInformationPowerSource {
    OtherPowerSource = 0,
    MainsPowered = 1,
}

#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkRejoinCapabilityInformation {
    /// This field will always have a value of 0 in implementations of this
    /// specification.
    pub alternate_pan_coordinator: bool,
    /// This field will have a value of 1 if the joining device is a Zigbee router. It
    /// will have a value of 0 if the device is a Zigbee end device or else a
    /// router-capable device that is joining as an end device.
    pub device_type: NwkRejoinCapabilityInformationDeviceType,
    /// This field will be set to the value of lowest-order bit of the PowerSource
    /// parameter passed to the NLME-JOIN-request primitive.
    pub power_source: NwkRejoinCapabilityInformationPowerSource,
    /// This field will be set to the value of the lowest-order bit of the RxOnWhenIdle
    /// parameter passed to the NLME-JOIN.request primitive.
    pub receiver_on_when_idle: bool,
    /// This field will always have a value of 0 in implementations of this
    /// specification.
    reserved1: u1,
    /// This field will always have a value of 0 in implementations of this
    /// specification.
    reserved2: u1,
    /// This field SHALL have a value of 0. Note that this overrides the default meaning
    /// specified in [B1] (802.15.4-2020, IEEE Standard for Local and metropolitan area
    /// networks--Part 15.4: Low-Rate Wireless Personal Area Networks (LR-WPANs))
    pub security_capability: bool,
    /// This field will have a value of 1 in implementations of this specification.
    pub allocate_address: bool,
}

#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkRejoinRequestCommand {
    pub capability_information: NwkRejoinCapabilityInformation,
}

impl Request for NwkRejoinRequestCommand {
    type REPLY = NwkRejoinResponseCommand;
}

impl Command for NwkRejoinRequestCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::RejoinRequest;
}

/// Zigbee spec: 3.4.7 Rejoin Response Command
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[abstract_bits(bits = 8)]
#[repr(u8)]
pub enum Nwk802154AssociationStatus {
    AssociationSuccessful = 0x00,
    PanAtCapacity = 0x01,
    PanAccessDenied = 0x02,
    HoppingSequenceOffsetDuplication = 0x03,
    FastAssociationSuccessful = 0x80,
    // This is not part of the 802.15.4 standard but used in Zigbee
    ZigbeeAddressConflict = 0xF0,
}

#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkRejoinResponseCommand {
    pub network_address: Nwk,
    pub rejoin_status: Nwk802154AssociationStatus,
}

impl Response for NwkRejoinResponseCommand {
    type REQUEST = NwkRejoinRequestCommand;
}

impl Command for NwkRejoinResponseCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::RejoinResponse;
}

/// Zigbee spec compressed: 3.4.8.3
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkLinkStatusCommand {
    #[abstract_bits(length_of = link_statuses)]
    reserved: u5,
    pub is_first_frame: bool,
    pub is_last_frame: bool,
    reserved: u1,
    pub link_statuses: Vec<NwkLinkStatus>,
}

impl Command for NwkLinkStatusCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::LinkStatus;
}

/// Zigbee spec 3.4.8
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkLinkStatus {
    pub address: Nwk,
    pub incoming_cost: u3,
    reserved: u1,
    pub outgoing_cost: u3,
    reserved: u1,
}

/// Zigbee spec: 3.4.4 Leave Command
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkLeaveCommand {
    reserved: u5,
    pub rejoin: bool,
    pub request: bool,
    pub remove_children: bool,
}

impl Command for NwkLeaveCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::Leave;
}

#[abstract_bits(bits = 8)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum EndDeviceTimeout {
    Seconds10 = 0,
    Minutes2 = 1,
    Minutes4 = 2,
    Minutes8 = 3,
    Minutes16 = 4,
    Minutes32 = 5,
    Minutes64 = 6,
    Minutes128 = 7,
    Minutes256 = 8,
    Minutes512 = 9,
    Minutes1024 = 10,
    Minutes2048 = 11,
    Minutes4096 = 12,
    Minutes8192 = 13,
    Minutes16384 = 14,
}

impl EndDeviceTimeout {
    /// The actual timeout for an enumeration value (spec Table 3-58): index 0 is
    /// 10 seconds, every other index n is 2^n minutes.
    pub const fn duration(self) -> core::time::Duration {
        match self {
            Self::Seconds10 => core::time::Duration::from_secs(10),
            _ => core::time::Duration::from_secs(60 * (1 << (self as u32))),
        }
    }
}

/// Zigbee spec 3.4.9: Network Report Command
#[abstract_bits(bits = 3)]
#[derive(Debug, Eq, PartialEq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum NwkReportCommandIdentifier {
    PanIdentifierConflict = 0x00,
    // All other values are reserved
}

#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkNetworkReportCommand {
    #[abstract_bits(length_of = pan_ids)]
    report_information_count: u5,
    pub report_command_identifier: NwkReportCommandIdentifier,
    pub epid: Eui64,
    /// A list of 16-bit PAN identifiers that are in conflict. This field's format is
    /// determined by the `report_command_identifier` but the only defined type is
    /// `PanIdentifierConflict`.
    pub pan_ids: Vec<PanId>,
}

impl Command for NwkNetworkReportCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::NetworkReport;
}

/// Zigbee spec 3.4.10: Network Update Command
#[abstract_bits(bits = 3)]
#[derive(Debug, Eq, PartialEq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum NwkUpdateCommandIdentifier {
    PanIdentifierUpdate = 0x00,
}

#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkNetworkUpdateCommand {
    /// For a PAN Identifier Update, this value SHALL be 1.
    update_information_count: u5,
    pub update_command_identifier: NwkUpdateCommandIdentifier,
    pub epid: Eui64,
    pub update_id: u8,
    /// The new 16-bit PAN identifier for the network. This field's format is dependent
    /// on the `update_command_identifier` but the only defined type is
    /// `PanIdentifierUpdate`.
    pub new_pan_id: Nwk,
}

impl Command for NwkNetworkUpdateCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::NetworkUpdate;
}

/// Zigbee spec 3.4.11 End Device Timeout Request Command
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkEndDeviceTimeoutRequestCommand {
    pub request_timeout_enum: EndDeviceTimeout,
    /// A bitmask of requested end device features. No bits are defined by the spec yet;
    /// a parent SHALL reject nonzero values with UNSUPPORTED_FEATURE (spec 3.4.11.3.2).
    pub end_device_configuration: u8,
}

impl Request for NwkEndDeviceTimeoutRequestCommand {
    type REPLY = NwkEndDeviceTimeoutResponseCommand;
}
impl Command for NwkEndDeviceTimeoutRequestCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::EndDeviceTimeoutRequest;
}

#[abstract_bits(bits = 8)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum NwkEndDeviceTimeoutResponseStatus {
    Success = 0x00,
    IncorrectValue = 0x01,
    UnsupportedFeature = 0x02,
}

/// Zigbee spec: 3.4.12 End Device Timeout Response Command
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkEndDeviceTimeoutResponseCommand {
    pub status: NwkEndDeviceTimeoutResponseStatus,
    pub mac_data_poll_keepalive_supported: bool,
    pub end_device_timeout_request_keepalive_supported: bool,
    pub power_negotation_support: bool,
    reserved: u5,
}

impl Response for NwkEndDeviceTimeoutResponseCommand {
    type REQUEST = NwkEndDeviceTimeoutRequestCommand;
}

impl Command for NwkEndDeviceTimeoutResponseCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::EndDeviceTimeoutResponse;
}

/// Zigbee spec 3.4.13: Link Power Delta Command
#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum NwkLinkPowerDeltaType {
    Notification = 0,
    Request = 1,
    Response = 2,
}

#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkPowerListEntry {
    pub device_address: Nwk,
    /// Delta power calculated as the difference between the optimal power level and the
    /// received power level of the last packet received from the end device parent
    /// device.
    pub power_delta: u8,
}

#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkLinkPowerDeltaCommand {
    pub command_type: NwkLinkPowerDeltaType,
    reserved: u6,
    #[abstract_bits(length_of = power_list)]
    list_count: u8,
    pub power_list: Vec<NwkPowerListEntry>,
}

impl Command for NwkLinkPowerDeltaCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::LinkPowerDelta;
}

/// Zigbee spec 3.4.14: Network Commissioning Request Command
#[abstract_bits(bits = 8)]
#[derive(Debug, Eq, PartialEq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum NwkCommissioningType {
    InitialJoin = 0x00,
    Rejoin = 0x01,
}

#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkNetworkCommissioningRequestCommand {
    pub commissioning_type: NwkCommissioningType,
    pub capability_information: NwkRejoinCapabilityInformation,
}

impl Request for NwkNetworkCommissioningRequestCommand {
    type REPLY = NwkNetworkCommissioningResponseCommand;
}

impl Command for NwkNetworkCommissioningRequestCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::NetworkCommissioningRequest;
}

/// Zigbee spec 3.4.15: Network Commissioning Response Command
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkNetworkCommissioningResponseCommand {
    /// The network address assigned to the joining device.
    pub network_address: Nwk,
    /// Association status.  A value of 0xF0 (`ZigbeeAddressConflict` in this codebase)
    /// indicates an address conflict and the request may be retried.
    pub status: Nwk802154AssociationStatus,
}

impl Response for NwkNetworkCommissioningResponseCommand {
    type REQUEST = NwkNetworkCommissioningRequestCommand;
}

impl Command for NwkNetworkCommissioningResponseCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::NetworkCommissioningResponse;
}

#[cfg(test)]
mod test {
    use super::*;

    /// The capability information bit assignments match the 802.15.4 association
    /// request (Table 3-71): bit 1 set means the device is a router.
    #[test]
    fn test_rejoin_request_round_trip() {
        let command = NwkRejoinRequestCommand {
            capability_information: NwkRejoinCapabilityInformation {
                alternate_pan_coordinator: false,
                device_type: NwkRejoinCapabilityInformationDeviceType::Router,
                power_source: NwkRejoinCapabilityInformationPowerSource::MainsPowered,
                receiver_on_when_idle: true,
                reserved1: 0b0,
                reserved2: 0b0,
                security_capability: false,
                allocate_address: true,
            },
        };

        let bytes = command.serialize().unwrap();
        assert_eq!(bytes, vec![NwkCommandId::RejoinRequest as u8, 0x8E]);
        assert_eq!(
            NwkRejoinRequestCommand::deserialize(&bytes).unwrap(),
            command
        );
    }

    #[test]
    fn test_rejoin_response_round_trip() {
        let command = NwkRejoinResponseCommand {
            network_address: Nwk(0x1234),
            rejoin_status: Nwk802154AssociationStatus::AssociationSuccessful,
        };

        let bytes = command.serialize().unwrap();
        assert_eq!(
            bytes,
            vec![NwkCommandId::RejoinResponse as u8, 0x34, 0x12, 0x00]
        );
        assert_eq!(
            NwkRejoinResponseCommand::deserialize(&bytes).unwrap(),
            command
        );
    }
}
