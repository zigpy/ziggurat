use crate::types::{Eui64, Nwk};
use crate::{Command, Request, Response};
use abstract_bits::abstract_bits;
use num_enum::TryFromPrimitive;

/// Zigbee spec 3.4
#[abstract_bits(bits = 8)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum NwkCommandId {
    RouteRequest = 0x01,
    RouteReply = 0x02,
    //NetworkStatus = 0x03,
    Leave = 0x04,
    RouteRecord = 0x05,
    //RejoinRequest = 0x06,
    //RejoinResponse = 0x07,
    LinkStatus = 0x08,
    //NetworkReport = 0x09
    //NetworkUpdate = 0x0a,
    EndDeviceTimeoutRequest = 0x0b,
    EndDeviceTimeoutResponse = 0x0c,
    //LinkPowerDelta = 0x0d,
    //NetworkCommissioningRequest = 0x0e,
    //NetworkCommissioningResponse = 0x0f,
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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
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

/// Zigbee spec 3.4.5: Route Record Command
#[abstract_bits]
#[derive(Debug, Clone, PartialEq)]
pub struct NwkRouteRecordCommand {
    #[abstract_bits(length_of = relays)]
    reserved: u8,
    pub relays: Vec<Nwk>,
}

impl Command for NwkRouteRecordCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::RouteRecord;
}

/// Zigbee spec compressed: 3.4.8.3
#[abstract_bits]
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
pub struct NwkLinkStatus {
    pub address: Nwk,
    pub incoming_cost: u3,
    reserved: u1,
    pub outgoing_cost: u3,
    reserved: u1,
}

/// Zigbee spec: 3.4.4 Leave Command
#[abstract_bits]
#[derive(Debug, Clone, PartialEq)]
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

/// Zigbee spec 3.4.11 End Device Timeout Request Command
#[abstract_bits]
#[derive(Debug, Clone, PartialEq)]
pub struct NwkEndDeviceTimeoutRequestCommand {
    pub request_timeout_enum: EndDeviceTimeout,
    reserved: u8, // reserved for future use
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
#[derive(Debug, Clone, PartialEq)]
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
