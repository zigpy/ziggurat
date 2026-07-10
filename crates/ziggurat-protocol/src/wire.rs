//! The binary command set.
//!
//! Request/response keyed by request id, streamed events, unsolicited notifications,
//! fixed-layout payloads, and index-free scan/load state transfer. Pure codec: no
//! runtime, no stack, no transport.

// The `#[abstract_bits(length_from = …)]` expansion iterates `(0..len).into_iter()`.
#![allow(clippy::useless_conversion)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use abstract_bits::{abstract_bits, AbstractBits, BitReader};
use num_enum::TryFromPrimitive;

use ziggurat_ieee_802154::types::{Eui64, Key, Nwk, PanId};
use ziggurat_zigbee::aps::frame::ApsDeliveryMode;

pub const PROTOCOL_VERSION: u8 = 1;
pub type RequestId = u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum CommandId {
    // Notifications (device -> host, unsolicited).
    Hello = 0x00,
    // Requests (host -> device).
    Ping = 0x01,
    Reset = 0x02,
    GetFirmwareInfo = 0x03,
    GetHwAddress = 0x04,
    Shutdown = 0x05,
    Configure = 0x10,
    LoadKeyTable = 0x11,
    LoadChildren = 0x12,
    LoadAddressCache = 0x13,
    StartNetwork = 0x14,
    GetNetworkInfo = 0x18,
    ScanKeyTable = 0x19,
    ScanChildren = 0x1A,
    ScanAddressCache = 0x1B,
    ScanRouteTable = 0x1C,
    SendAps = 0x20,
    PermitJoins = 0x21,
    SetChannel = 0x22,
    SetNwkUpdateId = 0x23,
    SetProvisionalKey = 0x24,
    EnergyScan = 0x25,
    NetworkScan = 0x26,
    PacketCapture = 0x27,
    PacketCaptureChannel = 0x28,
    SetTunable = 0x29,
    // More notifications.
    ReceivedAps = 0x30,
    SendConfirm = 0x31,
    ApsAckConfirm = 0x32,
    DeviceJoined = 0x33,
    DeviceLeft = 0x34,
    FrameCounter = 0x35,
    LinkKey = 0x36,
    ApsDecryptFailure = 0x37,
    LastReset = 0x38,
}

impl From<CommandId> for u8 {
    fn from(id: CommandId) -> Self {
        id as Self
    }
}

/// How the host must route a device -> host frame. Inbound frames are always
/// requests, so they carry no frame type. `Error` folds into `Response`: a
/// response carries a [`Status`], so `Status::Ok` + payload is success and any
/// other status + message is failure — one terminal path for the client.
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum FrameType {
    Response = 1,
    Event = 2,
    Notification = 3,
}

/// Response status. `Ok` carries the response payload; any other value carries a
/// diagnostic message string instead (see [`Error`]).
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    Parse = 1,
    UnknownCommand = 2,
    InvalidState = 3,
    NotConfigured = 4,
    RadioError = 5,
    NetworkStartFailed = 6,
    TransmitFailed = 7,
    ScanFailed = 8,
    InvalidRequest = 9,
}

/// Role a `configure` sets the coordinator up as.
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum NodeRole {
    Coordinator = 0,
    Router = 1,
}

/// The trust-center-link-key derivation scheme carried over from a prior stack.
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TclkFlavorId {
    ZStack = 0,
    Ezsp = 1,
}

/// A restored child's type. `Unknown` (a backup that didn't record it) is restored
/// as a sleepy end device - the safe default for frame-pending.
#[abstract_bits(bits = 2)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum ChildDeviceType {
    Unknown = 0,
    Router = 1,
    EndDevice = 2,
}

/// Which key an undecryptable APS frame was secured with (the NWK aux header's
/// key-id field). A byte-wide wire mirror of the driver's `NwkSecurityHeaderKeyId`.
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum KeyId {
    Data = 0,
    Network = 1,
    KeyTransport = 2,
    KeyLoad = 3,
}

/// How the stack learned a device left (mirrors the driver's `DeviceLeaveReason`).
/// The `rejoin` / `router` / `router_ieee` fields of the notification are only
/// meaningful for `Announced` / `RouterReported` respectively.
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum LeaveReason {
    Announced = 0,
    RouterReported = 1,
    KeepaliveTimeout = 2,
}

/// The 3-byte header of every host -> device frame (always a request).
#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub command: u8,
    pub request_id: RequestId,
}

impl RequestHeader {
    /// Parse the request header off the front of a frame, returning it and the
    /// number of bytes it consumed (the payload starts there).
    pub fn parse(bytes: &[u8]) -> Option<(Self, usize)> {
        let mut reader = BitReader::from(bytes);
        let header = Self::read_abstract_bits(&mut reader).ok()?;
        Some((header, reader.bytes_read()))
    }
}

/// The 4-byte header of every device -> host frame.
#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyHeader {
    pub frame_type: FrameType,
    pub command: u8,
    pub request_id: RequestId,
}

// -- payload structs -------------------------------------------------------------

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ResetPayload {
    pub hard: bool,
    pub reserved: u7,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct FirmwareInfoPayload {
    pub protocol_version: u8,
    pub version_len: u16,
    // A human-readable firmware version ("ziggurat/0.1.0"); inherently a string.
    #[abstract_bits(length_from = version_len)]
    pub version: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct HwAddressPayload {
    pub ieee: Eui64,
}

/// The persistent network state shared by `configure` and `get_network_info`
#[abstract_bits]
#[derive(Debug, Clone)]
pub struct NetworkState {
    pub channel: u8,
    pub nwk_update_id: u8,
    pub pan_id: PanId,
    pub extended_pan_id: Eui64,
    pub nwk_address: Nwk,
    pub ieee_address: Eui64,
    pub network_key: Key,
    pub network_key_seq: u8,
    pub network_key_tx_counter: u32,
    pub tc_link_key: Key,
    pub has_tclk_seed: bool,
    pub reserved: u7,
    pub tclk_seed: Key,
    pub tclk_flavor: TclkFlavorId,
    pub tx_power: u8, // i8 two's complement (abstract-bits has no signed types)
    pub aps_frame_counter: u32,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ConfigurePayload {
    pub role: NodeRole,
    pub source_routing: bool,
    pub reserved: u7,
    pub state: NetworkState,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub key: Key,
    pub tx_counter: u32,
    pub rx_counter: u32,
    pub seq: u8,
    pub partner_ieee: Eui64,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct LoadKeyTablePayload {
    pub count: u16,
    #[abstract_bits(length_from = count)]
    pub entries: Vec<KeyEntry>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ChildFlags {
    pub rx_on_when_idle: bool,
    pub device_type: ChildDeviceType,
    pub reserved: u5,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ChildEntry {
    pub ieee: Eui64,
    pub nwk: Nwk,
    pub flags: ChildFlags,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct LoadChildrenPayload {
    pub count: u16,
    #[abstract_bits(length_from = count)]
    pub entries: Vec<ChildEntry>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct AddressEntry {
    pub ieee: Eui64,
    pub nwk: Nwk,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct LoadAddressCachePayload {
    pub count: u16,
    #[abstract_bits(length_from = count)]
    pub entries: Vec<AddressEntry>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct NetworkInfoPayload {
    pub state: NetworkState,
    pub key_count: u16,
    pub started: bool,
    pub reserved: u7,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ScanCountPayload {
    pub count: u16,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub destination: Nwk,
    pub next_hop: Nwk,
    pub path_cost: u8,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct SendApsFlags {
    pub has_eui64: bool,
    pub aps_ack: bool,
    pub aps_encryption: bool,
    pub delivery_mode: ApsDeliveryMode,
    pub reserved: u3,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct SendApsPayload {
    pub flags: SendApsFlags,
    pub destination: Nwk,
    pub destination_eui64: Eui64,
    pub profile_id: u16,
    pub cluster_id: u16,
    pub src_ep: u8,
    pub dst_ep: u8,
    pub aps_seq: u8,
    pub radius: u8,
    pub priority: u8, // i8 two's complement
    pub asdu_len: u16,
    #[abstract_bits(length_from = asdu_len)]
    pub asdu: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct PermitJoinsPayload {
    pub duration: u16,
    pub accept_direct_joins: bool,
    pub reserved: u7,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ChannelPayload {
    pub channel: u8,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct NwkUpdateIdPayload {
    pub nwk_update_id: u8,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ProvisionalKeyPayload {
    pub ieee: Eui64,
    pub key: Key,
}

/// Sets one driver tunable by its Rust field name (see the `tunables!` block in
/// `ziggurat-zigbee`). The value is type-punned into a `u64`: integers as-is,
/// bools as 0/1, durations in microseconds, enums as their discriminant; the
/// stack rejects out-of-range values and unknown names.
#[abstract_bits]
#[derive(Debug, Clone)]
pub struct SetTunablePayload {
    pub name_len: u8,
    #[abstract_bits(length_from = name_len)]
    pub name: Vec<u8>,
    pub value: u64,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ScanRequestPayload {
    pub count: u16,
    #[abstract_bits(length_from = count)]
    pub channels: Vec<u8>,
    pub duration_per_channel_ms: u16,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct EnergyResultPayload {
    pub channel: u8,
    pub rssi: u8, // i8 two's complement
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct BeaconPayload {
    pub channel: u8,
    pub source: Nwk, // 0xFFFF when the beacon had no short source
    pub pan_id: PanId,
    pub extended_pan_id: Eui64,
    pub permit_joining: bool,
    pub router_capacity: bool,
    pub end_device_capacity: bool,
    pub reserved: u5,
    pub stack_profile: u8,
    pub protocol_version: u8,
    pub device_depth: u8,
    pub update_id: u8,
    pub lqi: u8,
    pub rssi: u8, // i8 two's complement
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct CapturedPacketPayload {
    pub channel: u8,
    pub rssi: u8, // i8 two's complement
    pub lqi: u8,
    pub psdu_len: u16,
    #[abstract_bits(length_from = psdu_len)]
    pub psdu: Vec<u8>,
}

/// The body of a failed response: a `Status` other than `Ok` followed by a
/// diagnostic, human-readable message.
#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ErrorPayload {
    pub status: Status,
    pub message_len: u16,
    #[abstract_bits(length_from = message_len)]
    pub message: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct HelloPayload {
    pub protocol_version: u8,
    pub configured: bool,
    pub reserved: u7,
}

/// Why the MCU last rebooted, when the reboot was abnormal (a fault dump or the
/// stored Rust panic message). Sent once, right after `hello`.
#[abstract_bits]
#[derive(Debug, Clone)]
pub struct LastResetPayload {
    pub message_len: u16,
    #[abstract_bits(length_from = message_len)]
    pub message: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ReceivedApsPayload {
    pub source: Nwk,
    pub destination: Nwk,
    pub has_group: bool,
    pub reserved: u7,
    pub group: u16,
    pub profile_id: u16,
    pub cluster_id: u16,
    pub src_ep: u8,
    pub dst_ep: u8,
    pub lqi: u8,
    pub rssi: u8, // i8 two's complement
    pub data_len: u16,
    #[abstract_bits(length_from = data_len)]
    pub data: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct SendConfirmPayload {
    pub confirmed: bool,
    pub reserved: u7,
    pub next_hop: Nwk, // 0xFFFF when unknown
    pub reason_len: u16,
    #[abstract_bits(length_from = reason_len)]
    pub reason: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ApsAckConfirmPayload {
    pub acked: bool,
    pub reserved: u7,
    pub reason_len: u16,
    #[abstract_bits(length_from = reason_len)]
    pub reason: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct DeviceJoinedPayload {
    pub nwk: Nwk,
    pub ieee: Eui64,
    pub parent: Nwk,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct DeviceLeftPayload {
    pub nwk: Nwk,
    pub has_ieee: bool,
    pub rejoin: bool,
    pub has_router_ieee: bool,
    pub reserved: u5,
    pub ieee: Eui64,
    pub reason: LeaveReason,
    pub router: Nwk, // 0xFFFF when not router_reported
    pub router_ieee: Eui64,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct FrameCounterPayload {
    pub frame_counter: u32,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct LinkKeyPayload {
    pub ieee: Eui64,
    pub key: Key,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ApsDecryptFailPayload {
    pub source: Nwk,
    pub source_ieee: Eui64,
    pub frame_counter: u32,
    pub key_id: KeyId,
}

// -- typed frames ------------------------------------------------------------------

/// A parsed host -> device request.
pub enum Request {
    Ping,
    Reset(ResetPayload),
    GetFirmwareInfo,
    GetHwAddress,
    Shutdown,
    Configure(ConfigurePayload),
    LoadKeyTable(LoadKeyTablePayload),
    LoadChildren(LoadChildrenPayload),
    LoadAddressCache(LoadAddressCachePayload),
    StartNetwork,
    GetNetworkInfo,
    ScanKeyTable,
    ScanChildren,
    ScanAddressCache,
    ScanRouteTable,
    SendAps(SendApsPayload),
    PermitJoins(PermitJoinsPayload),
    SetChannel(ChannelPayload),
    SetNwkUpdateId(NwkUpdateIdPayload),
    SetProvisionalKey(ProvisionalKeyPayload),
    EnergyScan(ScanRequestPayload),
    NetworkScan(ScanRequestPayload),
    PacketCapture(ChannelPayload),
    PacketCaptureChannel(ChannelPayload),
    SetTunable(SetTunablePayload),
}

impl Request {
    pub fn parse(command: CommandId, payload: &[u8]) -> Result<Self, Error> {
        Ok(match command {
            CommandId::Ping => Self::Ping,
            CommandId::Reset => Self::Reset(require(payload, "reset")?),
            CommandId::GetFirmwareInfo => Self::GetFirmwareInfo,
            CommandId::GetHwAddress => Self::GetHwAddress,
            CommandId::Shutdown => Self::Shutdown,
            CommandId::Configure => Self::Configure(require(payload, "configure")?),
            CommandId::LoadKeyTable => Self::LoadKeyTable(require(payload, "key entries")?),
            CommandId::LoadChildren => Self::LoadChildren(require(payload, "child entries")?),
            CommandId::LoadAddressCache => {
                Self::LoadAddressCache(require(payload, "addr entries")?)
            }
            CommandId::StartNetwork => Self::StartNetwork,
            CommandId::GetNetworkInfo => Self::GetNetworkInfo,
            CommandId::ScanKeyTable => Self::ScanKeyTable,
            CommandId::ScanChildren => Self::ScanChildren,
            CommandId::ScanAddressCache => Self::ScanAddressCache,
            CommandId::ScanRouteTable => Self::ScanRouteTable,
            CommandId::SendAps => Self::SendAps(require(payload, "send_aps")?),
            CommandId::PermitJoins => Self::PermitJoins(require(payload, "permit_joins")?),
            CommandId::SetChannel => Self::SetChannel(require(payload, "channel")?),
            CommandId::SetNwkUpdateId => Self::SetNwkUpdateId(require(payload, "update id")?),
            CommandId::SetProvisionalKey => Self::SetProvisionalKey(require(payload, "key")?),
            CommandId::EnergyScan => Self::EnergyScan(require(payload, "energy_scan")?),
            CommandId::NetworkScan => Self::NetworkScan(require(payload, "network_scan")?),
            CommandId::PacketCapture => Self::PacketCapture(require(payload, "channel")?),
            CommandId::PacketCaptureChannel => {
                Self::PacketCaptureChannel(require(payload, "channel")?)
            }
            CommandId::SetTunable => Self::SetTunable(require(payload, "set_tunable")?),
            // Everything else (the device -> host notification opcodes) is not a request.
            _ => return Err(Error::new(Status::UnknownCommand, "not a request")),
        })
    }
}

/// The typed body of a successful response.
pub enum Response {
    Empty,
    FirmwareInfo(FirmwareInfoPayload),
    HwAddress(HwAddressPayload),
    NetworkInfo(NetworkInfoPayload),
    ScanCount(ScanCountPayload),
}

impl Response {
    pub fn frame(&self, command: u8, request_id: RequestId) -> Vec<u8> {
        let mut bytes = envelope(FrameType::Response, command, request_id);
        append(&mut bytes, &Status::Ok);
        let fits = match self {
            Self::Empty => true,
            Self::FirmwareInfo(payload) => append(&mut bytes, payload),
            Self::HwAddress(payload) => append(&mut bytes, payload),
            Self::NetworkInfo(payload) => append(&mut bytes, payload),
            Self::ScanCount(payload) => append(&mut bytes, payload),
        };
        if !fits {
            return Error::new(Status::InvalidRequest, "reply too large")
                .frame(command, request_id);
        }
        bytes
    }
}

/// A failed reply: any non-`Ok` [`Status`] plus a diagnostic message. The client
/// branches on the status; the text is for humans.
pub struct Error {
    pub status: Status,
    pub message: String,
}

impl Error {
    pub fn new(status: Status, message: &str) -> Self {
        Self {
            status,
            message: message.to_string(),
        }
    }

    pub fn parse(what: &str) -> Self {
        Self::new(Status::Parse, what)
    }

    pub fn not_configured() -> Self {
        Self::new(Status::NotConfigured, "")
    }

    pub fn frame(&self, command: u8, request_id: RequestId) -> Vec<u8> {
        let message = &self.message.as_bytes()[..self.message.len().min(255)];
        let mut bytes = envelope(FrameType::Response, command, request_id);
        append(
            &mut bytes,
            &ErrorPayload {
                status: self.status,
                message: message.to_vec(),
            },
        );
        bytes
    }
}

/// A streamed item, sent before its request's terminal response, carrying the
/// request's id.
pub enum Event {
    KeyEntry(KeyEntry),
    Child(ChildEntry),
    Address(AddressEntry),
    Route(RouteEntry),
    EnergyResult(EnergyResultPayload),
    Beacon(BeaconPayload),
    CapturedPacket(CapturedPacketPayload),
}

impl Event {
    pub fn frame(&self, request_id: RequestId) -> Option<Vec<u8>> {
        let command = match self {
            Self::KeyEntry(_) => CommandId::ScanKeyTable,
            Self::Child(_) => CommandId::ScanChildren,
            Self::Address(_) => CommandId::ScanAddressCache,
            Self::Route(_) => CommandId::ScanRouteTable,
            Self::EnergyResult(_) => CommandId::EnergyScan,
            Self::Beacon(_) => CommandId::NetworkScan,
            Self::CapturedPacket(_) => CommandId::PacketCapture,
        };
        let mut bytes = envelope(FrameType::Event, command.into(), request_id);
        let fits = match self {
            Self::KeyEntry(payload) => append(&mut bytes, payload),
            Self::Child(payload) => append(&mut bytes, payload),
            Self::Address(payload) => append(&mut bytes, payload),
            Self::Route(payload) => append(&mut bytes, payload),
            Self::EnergyResult(payload) => append(&mut bytes, payload),
            Self::Beacon(payload) => append(&mut bytes, payload),
            Self::CapturedPacket(payload) => append(&mut bytes, payload),
        };
        fits.then_some(bytes)
    }
}

/// An unsolicited device -> host frame. Confirms carry their originating send's
/// request id; everything else uses 0.
pub enum Notification {
    Hello(HelloPayload),
    LastReset(LastResetPayload),
    ReceivedAps(ReceivedApsPayload),
    SendConfirm(RequestId, SendConfirmPayload),
    ApsAckConfirm(RequestId, ApsAckConfirmPayload),
    DeviceJoined(DeviceJoinedPayload),
    DeviceLeft(DeviceLeftPayload),
    FrameCounter(FrameCounterPayload),
    LinkKey(LinkKeyPayload),
    ApsDecryptFailure(ApsDecryptFailPayload),
}

impl Notification {
    pub fn frame(&self) -> Option<Vec<u8>> {
        let (command, request_id) = match self {
            Self::Hello(_) => (CommandId::Hello, 0),
            Self::LastReset(_) => (CommandId::LastReset, 0),
            Self::ReceivedAps(_) => (CommandId::ReceivedAps, 0),
            Self::SendConfirm(request_id, _) => (CommandId::SendConfirm, *request_id),
            Self::ApsAckConfirm(request_id, _) => (CommandId::ApsAckConfirm, *request_id),
            Self::DeviceJoined(_) => (CommandId::DeviceJoined, 0),
            Self::DeviceLeft(_) => (CommandId::DeviceLeft, 0),
            Self::FrameCounter(_) => (CommandId::FrameCounter, 0),
            Self::LinkKey(_) => (CommandId::LinkKey, 0),
            Self::ApsDecryptFailure(_) => (CommandId::ApsDecryptFailure, 0),
        };
        let mut bytes = envelope(FrameType::Notification, command.into(), request_id);
        let fits = match self {
            Self::Hello(payload) => append(&mut bytes, payload),
            Self::LastReset(payload) => append(&mut bytes, payload),
            Self::ReceivedAps(payload) => append(&mut bytes, payload),
            Self::SendConfirm(_, payload) => append(&mut bytes, payload),
            Self::ApsAckConfirm(_, payload) => append(&mut bytes, payload),
            Self::DeviceJoined(payload) => append(&mut bytes, payload),
            Self::DeviceLeft(payload) => append(&mut bytes, payload),
            Self::FrameCounter(payload) => append(&mut bytes, payload),
            Self::LinkKey(payload) => append(&mut bytes, payload),
            Self::ApsDecryptFailure(payload) => append(&mut bytes, payload),
        };
        fits.then_some(bytes)
    }
}

// -- frame assembly ----------------------------------------------------------------

/// Bounds one encoded frame: the envelope plus the largest payload (a captured
/// packet or an error string).
pub const MAX_FRAME: usize = 512;

/// Append `value`'s serialization; false (nothing appended) if it exceeds
/// [`MAX_FRAME`].
pub fn append<T: AbstractBits>(bytes: &mut Vec<u8>, value: &T) -> bool {
    let mut buffer = [0u8; MAX_FRAME];
    let mut writer = abstract_bits::BitWriter::from(&mut buffer[..]);
    if value.write_abstract_bits(&mut writer).is_err() {
        return false;
    }
    let written = writer.bytes_written();
    bytes.extend_from_slice(&buffer[..written]);
    true
}

pub fn envelope(frame_type: FrameType, command: u8, request_id: RequestId) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    append(
        &mut bytes,
        &ReplyHeader {
            frame_type,
            command,
            request_id,
        },
    );
    bytes
}

/// Parse one payload, ignoring trailing bytes (append-only forward compatibility).
pub fn parse<T: AbstractBits>(payload: &[u8]) -> Option<T> {
    let mut reader = BitReader::from(payload);
    T::read_abstract_bits(&mut reader).ok()
}

pub fn require<T: AbstractBits>(payload: &[u8], what: &str) -> Result<T, Error> {
    parse(payload).ok_or_else(|| Error::parse(what))
}
