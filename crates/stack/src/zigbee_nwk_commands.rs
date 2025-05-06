use crate::types::{Eui64, Nwk};
use num_enum::TryFromPrimitive;
use wire_format::{BitReader, ZigbeeBytes, zigbee_bytes};

// mod legacy_members;
#[cfg(test)]
mod tests;

/// 802.15.4 mac layer has a maximum payload length of 104 bytes
/// see the introduction of this paper for a good overview:
/// https://www.researchgate.net/publication/305365904_Dissecting_Customized_Protocols_Automatic_Analysis_for_Customized_Protocols_based_on_IEEE_802154
const MAC_PAYLOAD_MAX_LEN: usize = 104;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("Could not serialize {ty}")]
pub struct SerializeError {
    ty: &'static str,
    #[source]
    cause: wire_format::ToBytesError,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeserializeError {
    #[error("Could not deserialize payload to {ty}")]
    Payload {
        ty: &'static str,
        #[source]
        cause: wire_format::FromBytesError,
    },
    #[error(
        "Could not deserialize incorrect Id. \
        Expected {expected_discriminant} (which represents {expected_variant:?}), \
        found: {found_discriminant:?} instead"
    )]
    IncorrectId {
        expected_variant: NwkCommandId,
        expected_discriminant: u8,
        found_discriminant: u8,
    },
    #[error("Got zero bytes, no valid command/request/response is zero bytes")]
    ZeroBytes,
}

fn serialize<T: ZigbeeBytes>(thing: &T, id: NwkCommandId) -> Result<Vec<u8>, SerializeError> {
    let mut bytes = vec![0u8; MAC_PAYLOAD_MAX_LEN];
    bytes[0] = id as u8;
    let mut writer = wire_format::BitWriter::from(&mut bytes[1..]);
    thing
        .write_zigbee_bytes(&mut writer)
        .map_err(|cause| SerializeError {
            ty: core::any::type_name::<T>(),
            cause,
        })?;
    let len = writer.bytes_written();
    dbg!(len);
    bytes.truncate(len + 1); // +1 for id
    Ok(bytes)
}

fn deserialize<T: ZigbeeBytes>(
    bytes: &[u8],
    correct_id: NwkCommandId,
) -> Result<T, DeserializeError> {
    let [command_id, payload @ ..] = bytes else {
        return Err(DeserializeError::ZeroBytes);
    };

    if *command_id != correct_id as u8 {
        return Err(DeserializeError::IncorrectId {
            expected_variant: correct_id,
            expected_discriminant: correct_id as u8,
            found_discriminant: *command_id,
        });
    }

    let mut reader = BitReader::from(payload);
    T::read_zigbee_bytes(&mut reader).map_err(|cause| DeserializeError::Payload {
        ty: core::any::type_name::<T>(),
        cause,
    })
}

pub trait Request: Command {
    type REPLY: Response;
}

pub trait Response: Command {
    type REQUEST: Request;
}

pub trait Command: ZigbeeBytes + Sized {
    const COMMAND_ID: NwkCommandId;

    fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        serialize(self, Self::COMMAND_ID)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        deserialize(bytes, Self::COMMAND_ID)
    }
}

/// Zigbee spec 3.4
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[zigbee_bytes(bits = 8)]
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
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[zigbee_bytes(bits = 2)]
#[repr(u8)]
pub enum NwkRouteRequestManyToOne {
    NotManyToOne = 0,
    ManyToOneSenderSupportsRouteRecordTable = 1,
    ManyToOneSenderDoesntSupportRouteRecordTable = 2,
    Reserved = 3,
}

/// Zigbee spec: 3.4.1 Route Request Command
#[zigbee_bytes]
#[derive(Debug, Clone, PartialEq)]
pub struct NwkRouteRequestCommand {
    reserved: u3,
    pub many_to_one: NwkRouteRequestManyToOne,
    #[wire_format(controls = destination_eui64)]
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
#[wire_format::zigbee_bytes]
#[derive(Debug, Clone, PartialEq)]
pub struct NwkRouteReplyCommand {
    reserved: u4,
    #[wire_format(controls = originator_eui64)]
    reserved: bool,
    #[wire_format(controls = responder_eui64)]
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
#[zigbee_bytes]
#[derive(Debug, Clone, PartialEq)]
pub struct NwkRouteRecordCommand {
    #[wire_format(length_of = relays)]
    reserved: u8,
    pub relays: Vec<Nwk>,
}

impl Command for NwkRouteRecordCommand {
    const COMMAND_ID: NwkCommandId = NwkCommandId::RouteRecord;
}

/// Zigbee spec compressed: 3.4.8.3
#[zigbee_bytes]
#[derive(Debug, Clone, PartialEq)]
pub struct NwkLinkStatusCommand {
    #[wire_format(length_of = link_statuses)]
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
#[zigbee_bytes]
#[derive(Debug, Clone, PartialEq)]
pub struct NwkLinkStatus {
    pub address: Nwk,
    pub incoming_cost: u3,
    reserved: u1,
    pub outgoing_cost: u3,
    reserved: u1,
}

/// Zigbee spec: 3.4.4 Leave Command
#[zigbee_bytes]
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

#[zigbee_bytes(bits = 8)]
#[derive(Debug, Eq, PartialEq, Clone, TryFromPrimitive, Copy)]
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
#[zigbee_bytes]
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

#[zigbee_bytes(bits = 8)]
#[derive(Debug, Eq, PartialEq, Clone, TryFromPrimitive, Copy)]
#[repr(u8)]
pub enum NwkEndDeviceTimeoutResponseStatus {
    Success = 0x00,
    IncorrectValue = 0x01,
    UnsupportedFeature = 0x02,
}

/// Zigbee spec: 3.4.12 End Device Timeout Response Command
#[zigbee_bytes]
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
