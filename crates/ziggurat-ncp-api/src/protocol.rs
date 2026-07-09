//! The binary command set: request/response keyed by request id, streamed events,
//! unsolicited notifications, fixed-layout payloads, and index-free scan/load state
//! transfer.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use abstract_bits::{AbstractBits, BitReader, abstract_bits};
use num_enum::TryFromPrimitive;

use ziggurat_driver::runtime::Spawn;
use ziggurat_driver::zigbee_stack::aps_security::TclkFlavor;
use ziggurat_driver::zigbee_stack::{
    ApsAck, ApsAckResult, DeviceLeaveReason, NetworkConfig, NwkDeviceType,
    RequestId as StackRequestId, SendResult, TclkSeed, Tunables, TxPriority, ZigbeeNotification,
    ZigbeeStack,
};
use ziggurat_driver::ziggurat_ieee_802154::types::{Eui64, Key, Nwk, PanId};
use ziggurat_phy::{RadioPhy, Receiver};
use ziggurat_zigbee::aps::frame::ApsDeliveryMode;
use ziggurat_zigbee::nwk::frame::NwkSecurityHeaderKeyId;
use ziggurat_zigbee::nwk::neighbors::{ChildDescriptor, Relationship};
use ziggurat_zigbee::nwk::routing;

use crate::{App, CaptureStop, capture_config, push_outbound, send_outbound, spawn_stack_pumps};

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
    GetDiagnostics = 0x06,
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

/// Child entries restored from a backup re-negotiate their real timeout at the
/// first keepalive; until then they age out after a conservative day.
const RESTORED_CHILD_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

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
struct ResetPayload {
    hard: bool,
    reserved: u7,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct FirmwareInfoPayload {
    protocol_version: u8,
    version_len: u16,
    // A human-readable firmware version ("ziggurat/0.1.0"); inherently a string.
    #[abstract_bits(length_from = version_len)]
    version: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct HwAddressPayload {
    ieee: Eui64,
}

/// The persistent network state shared by `configure` and `get_network_info`
#[abstract_bits]
#[derive(Debug, Clone)]
struct NetworkState {
    channel: u8,
    nwk_update_id: u8,
    pan_id: PanId,
    extended_pan_id: Eui64,
    nwk_address: Nwk,
    ieee_address: Eui64,
    network_key: Key,
    network_key_seq: u8,
    network_key_tx_counter: u32,
    tc_link_key: Key,
    has_tclk_seed: bool,
    reserved: u7,
    tclk_seed: Key,
    tclk_flavor: TclkFlavorId,
    tx_power: u8, // i8 two's complement (abstract-bits has no signed types)
    aps_frame_counter: u32,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ConfigurePayload {
    role: NodeRole,
    source_routing: bool,
    reserved: u7,
    state: NetworkState,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct KeyEntry {
    key: Key,
    tx_counter: u32,
    rx_counter: u32,
    seq: u8,
    partner_ieee: Eui64,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct LoadKeyTablePayload {
    count: u16,
    #[abstract_bits(length_from = count)]
    entries: Vec<KeyEntry>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ChildFlags {
    rx_on_when_idle: bool,
    device_type: ChildDeviceType,
    reserved: u5,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ChildEntry {
    ieee: Eui64,
    nwk: Nwk,
    flags: ChildFlags,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct LoadChildrenPayload {
    count: u16,
    #[abstract_bits(length_from = count)]
    entries: Vec<ChildEntry>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct AddressEntry {
    ieee: Eui64,
    nwk: Nwk,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct LoadAddressCachePayload {
    count: u16,
    #[abstract_bits(length_from = count)]
    entries: Vec<AddressEntry>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct NetworkInfoPayload {
    state: NetworkState,
    key_count: u16,
    started: bool,
    reserved: u7,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ScanCountPayload {
    count: u16,
}

/// The reply to `get_diagnostics`: heap health, radio counters, and the live size of every
/// table and queue the stack maintains. Always available (the heap/radio fields are valid
/// even before `configure`; the stack fields are zero until a stack exists).
#[abstract_bits]
#[derive(Debug, Clone)]
struct DiagnosticsPayload {
    // Whether a stack is configured and started (so zeros below can be read correctly).
    configured: bool,
    started: bool,
    reserved: u6,
    // Heap (bytes / cumulative counts since boot).
    heap_size: u32,
    heap_used: u32,
    heap_free: u32,
    heap_peak_used: u32,
    heap_alloc_ok: u32,
    heap_alloc_failures: u32,
    heap_dealloc: u32,
    heap_largest_request: u32,
    heap_largest_request_align: u16,
    // Radio counters since boot.
    rx_total: u32,
    rx_dropped: u32,
    // Frame-token budget occupancy (0 total means unbounded).
    frame_tokens_used: u16,
    frame_tokens_total: u16,
    // Outbound protocol-frame queue occupancy.
    outbound_queued: u16,
    // Stack tables and queues (live entry counts).
    tx_total: u16,
    neighbors_total: u16,
    neighbors_children: u16,
    route_table: u16,
    route_discovery: u16,
    route_records: u16,
    address_map: u16,
    aps_device_keys: u16,
    indirect_transactions: u16,
    pending_aps_acks: u16,
    pending_routes: u16,
    pending_broadcasts: u16,
    pending_unicast_retries: u16,
    address_conflicts: u16,
    aps_duplicates: u16,
    notifications_queued: u16,
    scan_beacons_queued: u16,
    scan_beacon_frames: u32,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct RouteEntry {
    destination: Nwk,
    next_hop: Nwk,
    path_cost: u8,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct SendApsFlags {
    has_eui64: bool,
    aps_ack: bool,
    aps_encryption: bool,
    delivery_mode: ApsDeliveryMode,
    reserved: u3,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct SendApsPayload {
    flags: SendApsFlags,
    destination: Nwk,
    destination_eui64: Eui64,
    profile_id: u16,
    cluster_id: u16,
    src_ep: u8,
    dst_ep: u8,
    aps_seq: u8,
    radius: u8,
    priority: u8, // i8 two's complement
    asdu_len: u16,
    #[abstract_bits(length_from = asdu_len)]
    asdu: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct PermitJoinsPayload {
    duration: u16,
    accept_direct_joins: bool,
    reserved: u7,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ChannelPayload {
    channel: u8,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct NwkUpdateIdPayload {
    nwk_update_id: u8,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ProvisionalKeyPayload {
    ieee: Eui64,
    key: Key,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ScanRequestPayload {
    count: u16,
    #[abstract_bits(length_from = count)]
    channels: Vec<u8>,
    duration_per_channel_ms: u16,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct EnergyResultPayload {
    channel: u8,
    rssi: u8, // i8 two's complement
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct BeaconPayload {
    channel: u8,
    source: Nwk, // 0xFFFF when the beacon had no short source
    pan_id: PanId,
    extended_pan_id: Eui64,
    permit_joining: bool,
    router_capacity: bool,
    end_device_capacity: bool,
    reserved: u5,
    stack_profile: u8,
    protocol_version: u8,
    device_depth: u8,
    update_id: u8,
    lqi: u8,
    rssi: u8, // i8 two's complement
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct CapturedPacketPayload {
    channel: u8,
    rssi: u8, // i8 two's complement
    lqi: u8,
    psdu_len: u16,
    #[abstract_bits(length_from = psdu_len)]
    psdu: Vec<u8>,
}

/// The body of a failed response: a `Status` other than `Ok` followed by a
/// diagnostic, human-readable message.
#[abstract_bits]
#[derive(Debug, Clone)]
struct ErrorPayload {
    status: Status,
    message_len: u16,
    #[abstract_bits(length_from = message_len)]
    message: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct HelloPayload {
    protocol_version: u8,
    configured: bool,
    reserved: u7,
}

/// Why the MCU last rebooted, when the reboot was abnormal (a fault dump or the
/// stored Rust panic message). Sent once, right after `hello`.
#[abstract_bits]
#[derive(Debug, Clone)]
struct LastResetPayload {
    message_len: u16,
    #[abstract_bits(length_from = message_len)]
    message: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ReceivedApsPayload {
    source: Nwk,
    destination: Nwk,
    has_group: bool,
    reserved: u7,
    group: u16,
    profile_id: u16,
    cluster_id: u16,
    src_ep: u8,
    dst_ep: u8,
    lqi: u8,
    rssi: u8, // i8 two's complement
    data_len: u16,
    #[abstract_bits(length_from = data_len)]
    data: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct SendConfirmPayload {
    confirmed: bool,
    reserved: u7,
    next_hop: Nwk, // 0xFFFF when unknown
    reason_len: u16,
    #[abstract_bits(length_from = reason_len)]
    reason: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ApsAckConfirmPayload {
    acked: bool,
    reserved: u7,
    reason_len: u16,
    #[abstract_bits(length_from = reason_len)]
    reason: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct DeviceJoinedPayload {
    nwk: Nwk,
    ieee: Eui64,
    parent: Nwk,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct DeviceLeftPayload {
    nwk: Nwk,
    has_ieee: bool,
    rejoin: bool,
    has_router_ieee: bool,
    reserved: u5,
    ieee: Eui64,
    reason: LeaveReason,
    router: Nwk, // 0xFFFF when not router_reported
    router_ieee: Eui64,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct FrameCounterPayload {
    frame_counter: u32,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct LinkKeyPayload {
    ieee: Eui64,
    key: Key,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ApsDecryptFailPayload {
    source: Nwk,
    source_ieee: Eui64,
    frame_counter: u32,
    key_id: KeyId,
}

// -- typed frames ------------------------------------------------------------------

/// A parsed host -> device request.
enum Request {
    Ping,
    Reset(ResetPayload),
    GetFirmwareInfo,
    GetHwAddress,
    Shutdown,
    GetDiagnostics,
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
}

impl Request {
    fn parse(command: CommandId, payload: &[u8]) -> Result<Self, Error> {
        Ok(match command {
            CommandId::Ping => Self::Ping,
            CommandId::Reset => Self::Reset(require(payload, "reset")?),
            CommandId::GetFirmwareInfo => Self::GetFirmwareInfo,
            CommandId::GetHwAddress => Self::GetHwAddress,
            CommandId::Shutdown => Self::Shutdown,
            CommandId::GetDiagnostics => Self::GetDiagnostics,
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
            CommandId::Hello
            | CommandId::ReceivedAps
            | CommandId::SendConfirm
            | CommandId::ApsAckConfirm
            | CommandId::DeviceJoined
            | CommandId::DeviceLeft
            | CommandId::FrameCounter
            | CommandId::LinkKey
            | CommandId::ApsDecryptFailure
            | CommandId::LastReset => {
                return Err(Error::new(Status::UnknownCommand, "not a request"));
            }
        })
    }
}

/// The typed body of a successful response.
enum Response {
    Empty,
    FirmwareInfo(FirmwareInfoPayload),
    HwAddress(HwAddressPayload),
    NetworkInfo(NetworkInfoPayload),
    ScanCount(ScanCountPayload),
    Diagnostics(DiagnosticsPayload),
}

impl Response {
    fn frame(&self, command: u8, request_id: RequestId) -> Vec<u8> {
        let mut bytes = envelope(FrameType::Response, command, request_id);
        append(&mut bytes, &Status::Ok);
        let fits = match self {
            Self::Empty => true,
            Self::FirmwareInfo(payload) => append(&mut bytes, payload),
            Self::HwAddress(payload) => append(&mut bytes, payload),
            Self::NetworkInfo(payload) => append(&mut bytes, payload),
            Self::ScanCount(payload) => append(&mut bytes, payload),
            Self::Diagnostics(payload) => append(&mut bytes, payload),
        };
        if !fits {
            return Error::new(Status::InvalidRequest, "reply too large").frame(command, request_id);
        }
        bytes
    }
}

/// A failed reply: any non-`Ok` [`Status`] plus a diagnostic message. The client
/// branches on the status; the text is for humans.
struct Error {
    status: Status,
    message: String,
}

impl Error {
    fn new(status: Status, message: &str) -> Self {
        Self {
            status,
            message: message.to_string(),
        }
    }

    fn parse(what: &str) -> Self {
        Self::new(Status::Parse, what)
    }

    fn not_configured() -> Self {
        Self::new(Status::NotConfigured, "")
    }

    fn frame(&self, command: u8, request_id: RequestId) -> Vec<u8> {
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
enum Event {
    KeyEntry(KeyEntry),
    Child(ChildEntry),
    Address(AddressEntry),
    Route(RouteEntry),
    EnergyResult(EnergyResultPayload),
    Beacon(BeaconPayload),
    CapturedPacket(CapturedPacketPayload),
}

impl Event {
    fn frame(&self, request_id: RequestId) -> Option<Vec<u8>> {
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

async fn send_event(request_id: RequestId, event: Event) {
    if let Some(frame) = event.frame(request_id) {
        send_outbound(frame).await;
    }
}

/// An unsolicited device -> host frame. Confirms carry their originating send's
/// request id; everything else uses 0.
enum Notification {
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
    fn frame(&self) -> Option<Vec<u8>> {
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
const MAX_FRAME: usize = 512;

/// Append `value`'s serialization; false (nothing appended) if it exceeds
/// [`MAX_FRAME`].
fn append<T: AbstractBits>(bytes: &mut Vec<u8>, value: &T) -> bool {
    let mut buffer = [0u8; MAX_FRAME];
    let mut writer = abstract_bits::BitWriter::from(&mut buffer[..]);
    if value.write_abstract_bits(&mut writer).is_err() {
        return false;
    }
    let written = writer.bytes_written();
    bytes.extend_from_slice(&buffer[..written]);
    true
}

fn envelope(frame_type: FrameType, command: u8, request_id: RequestId) -> Vec<u8> {
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
fn parse<T: AbstractBits>(payload: &[u8]) -> Option<T> {
    let mut reader = BitReader::from(payload);
    T::read_abstract_bits(&mut reader).ok()
}

fn require<T: AbstractBits>(payload: &[u8], what: &str) -> Result<T, Error> {
    parse(payload).ok_or_else(|| Error::parse(what))
}

pub fn hello_frame(configured: bool) -> Option<Vec<u8>> {
    Notification::Hello(HelloPayload {
        protocol_version: PROTOCOL_VERSION,
        configured,
    })
    .frame()
}

pub fn last_reset_frame(message: &str) -> Option<Vec<u8>> {
    let message = &message.as_bytes()[..message.len().min(255)];
    Notification::LastReset(LastResetPayload {
        message: message.to_vec(),
    })
    .frame()
}

// -- dispatch ------------------------------------------------------------------------

/// Dispatch one inbound frame; every path emits exactly one response or error,
/// preceded by any streamed events.
pub async fn handle_frame<P: RadioPhy>(app: &mut App<P>, bytes: &[u8]) {
    let mut reader = BitReader::from(bytes);
    let Ok(header) = RequestHeader::read_abstract_bits(&mut reader) else {
        send_outbound(Error::parse("truncated header").frame(0, 0)).await;
        return;
    };
    let payload = &bytes[reader.bytes_read()..];
    let request_id = header.request_id;

    let request = CommandId::try_from(header.command)
        .map_err(|_| Error::new(Status::UnknownCommand, ""))
        .and_then(|command| Request::parse(command, payload));

    let reply = match request {
        Ok(request) => dispatch(app, request_id, request).await,
        Err(e) => Err(e),
    };

    let frame = match reply {
        Ok(response) => response.frame(header.command, request_id),
        Err(e) => e.frame(header.command, request_id),
    };
    send_outbound(frame).await;
}

async fn dispatch<P: RadioPhy>(
    app: &mut App<P>,
    request_id: RequestId,
    request: Request,
) -> Result<Response, Error> {
    match request {
        Request::Ping => Ok(Response::Empty),
        Request::Reset(payload) => handle_reset(app, payload),
        Request::GetFirmwareInfo => {
            let version = concat!("ziggurat/", env!("CARGO_PKG_VERSION"));
            Ok(Response::FirmwareInfo(FirmwareInfoPayload {
                protocol_version: PROTOCOL_VERSION,
                version: version.as_bytes().to_vec(),
            }))
        }
        Request::GetHwAddress => Ok(Response::HwAddress(HwAddressPayload {
            ieee: app.platform.hw_eui64(),
        })),
        Request::Shutdown => handle_shutdown(app).await,
        Request::GetDiagnostics => handle_get_diagnostics(app),
        Request::Configure(payload) => handle_configure(app, payload).await,
        Request::LoadKeyTable(payload) => handle_load_key_table(app, payload),
        Request::LoadChildren(payload) => handle_load_children(app, payload),
        Request::LoadAddressCache(payload) => handle_load_address_cache(app, payload),
        Request::StartNetwork => handle_start_network(app).await,
        Request::GetNetworkInfo => handle_get_network_info(app),
        Request::ScanKeyTable => {
            scan_table(app, request_id, |stack| {
                let core = stack.state.core.lock();
                let aps = &core.aib.aps_security;
                let outgoing = aps.outgoing_frame_counter();
                aps.device_keys()
                    .map(|(partner, entry)| {
                        Event::KeyEntry(KeyEntry {
                            key: entry.key.clone(),
                            tx_counter: outgoing,
                            rx_counter: aps.incoming_frame_counter(partner).unwrap_or(0),
                            seq: 0,
                            partner_ieee: partner,
                        })
                    })
                    .collect()
            })
            .await
        }
        Request::ScanChildren => {
            scan_table(app, request_id, |stack| {
                let core = stack.state.core.lock();
                core.nib
                    .neighbors
                    .entries()
                    .filter(|entry| entry.is_child())
                    .map(|entry| {
                        Event::Child(ChildEntry {
                            ieee: entry.extended_address,
                            nwk: entry.network_address,
                            flags: ChildFlags {
                                rx_on_when_idle: entry.rx_on_when_idle,
                                device_type: match entry.device_type {
                                    NwkDeviceType::Router => ChildDeviceType::Router,
                                    _ => ChildDeviceType::EndDevice,
                                },
                            },
                        })
                    })
                    .collect()
            })
            .await
        }
        Request::ScanAddressCache => {
            scan_table(app, request_id, |stack| {
                let core = stack.state.core.lock();
                core.nib
                    .address_map
                    .entries()
                    .map(|(ieee, nwk)| Event::Address(AddressEntry { ieee, nwk }))
                    .collect()
            })
            .await
        }
        Request::ScanRouteTable => {
            scan_table(app, request_id, |stack| {
                let core = stack.state.core.lock();
                core.nib
                    .routing
                    .entries()
                    .filter(|entry| matches!(entry.status, routing::Status::Active))
                    .map(|entry| {
                        Event::Route(RouteEntry {
                            destination: entry.destination,
                            next_hop: entry.next_hop_address,
                            path_cost: entry.path_cost,
                        })
                    })
                    .collect()
            })
            .await
        }
        Request::SendAps(payload) => handle_send_aps(app, request_id, payload),
        Request::PermitJoins(payload) => handle_permit_joins(app, payload),
        Request::SetChannel(payload) => handle_set_channel(app, payload).await,
        Request::SetNwkUpdateId(payload) => handle_set_nwk_update_id(app, payload),
        Request::SetProvisionalKey(payload) => handle_set_provisional_key(app, payload),
        Request::EnergyScan(payload) => handle_energy_scan(app, request_id, payload).await,
        Request::NetworkScan(payload) => handle_network_scan(app, request_id, payload).await,
        Request::PacketCapture(payload) => handle_packet_capture(app, request_id, payload).await,
        Request::PacketCaptureChannel(payload) => {
            handle_packet_capture_channel(app, payload).await
        }
    }
}

// -- guards ------------------------------------------------------------------------

/// The stack, in any state after `configure`.
fn configured<P: RadioPhy>(app: &App<P>) -> Result<&Arc<ZigbeeStack<P>>, Error> {
    app.stack.as_ref().ok_or_else(Error::not_configured)
}

/// The stack, if it is in the load window (configured but not started).
fn loadable<P: RadioPhy>(app: &App<P>) -> Result<&Arc<ZigbeeStack<P>>, Error> {
    match app.stack.as_ref() {
        Some(stack) if !app.started => Ok(stack),
        Some(_) => Err(Error::new(Status::InvalidState, "network already started")),
        None => Err(Error::not_configured()),
    }
}

/// The stack, if it is running.
fn running<P: RadioPhy>(app: &App<P>) -> Result<&Arc<ZigbeeStack<P>>, Error> {
    match app.stack.as_ref() {
        Some(stack) if app.started => Ok(stack),
        _ => Err(Error::not_configured()),
    }
}

// -- handlers ----------------------------------------------------------------------

/// Soft reset stops transient radio activity; hard reset reboots (diverges).
fn handle_reset<P: RadioPhy>(app: &mut App<P>, request: ResetPayload) -> Result<Response, Error> {
    if let Some(stop) = app.capture_stop.take() {
        stop.signal(());
    }

    if request.hard {
        app.platform.hard_reset();
    }

    Ok(Response::Empty)
}

/// Tear the stack fully down.
async fn handle_shutdown<P: RadioPhy>(app: &mut App<P>) -> Result<Response, Error> {
    if let Some(stop) = app.capture_stop.take() {
        stop.signal(());
    }

    if let Some(stack) = app.stack.take() {
        stack.shutdown().await;
    }
    app.started = false;

    // Clear the source-match table
    if let Err(e) = app.phy.set_frame_pending_table(&[], &[]).await {
        return Err(Error::new(Status::RadioError, &e.to_string()));
    }

    Ok(Response::Empty)
}

async fn handle_configure<P: RadioPhy>(
    app: &mut App<P>,
    request: ConfigurePayload,
) -> Result<Response, Error> {
    let state = request.state;

    let config = NetworkConfig {
        role: match request.role {
            NodeRole::Router => NwkDeviceType::Router,
            NodeRole::Coordinator => NwkDeviceType::Coordinator,
        },
        channel: state.channel,
        update_id: state.nwk_update_id,
        pan_id: state.pan_id,
        extended_pan_id: state.extended_pan_id,
        network_address: state.nwk_address,
        ieee_address: state.ieee_address,
        network_key: state.network_key,
        network_key_seq_number: state.network_key_seq,
        network_key_tx_counter: state.network_key_tx_counter,
        tc_link_key: state.tc_link_key,
        tclk_seed: state.has_tclk_seed.then_some(TclkSeed {
            seed: state.tclk_seed,
            flavor: match state.tclk_flavor {
                TclkFlavorId::Ezsp => TclkFlavor::Ezsp,
                TclkFlavorId::ZStack => TclkFlavor::ZStack,
            },
        }),
        tx_power: state.tx_power as i8,
        source_routing: request.source_routing,
    };

    if let Some(old_stack) = app.stack.take() {
        old_stack.shutdown().await;
    }
    app.started = false;

    let stack = ZigbeeStack::new(app.phy.clone(), config, Tunables::new(), app.spawner);
    stack
        .state
        .core
        .lock()
        .aib
        .aps_security
        .restore_outgoing_frame_counter(state.aps_frame_counter);
    app.stack = Some(stack);

    Ok(Response::Empty)
}

fn handle_load_key_table<P: RadioPhy>(
    app: &mut App<P>,
    request: LoadKeyTablePayload,
) -> Result<Response, Error> {
    let stack = loadable(app)?;

    let mut core = stack.state.core.lock();
    for entry in request.entries {
        core.aib
            .aps_security
            .restore_device_key(entry.partner_ieee, entry.key);
        if entry.rx_counter != 0 {
            core.aib
                .aps_security
                .restore_incoming_frame_counter(entry.partner_ieee, entry.rx_counter);
        }
    }

    Ok(Response::Empty)
}

fn handle_load_children<P: RadioPhy>(
    app: &mut App<P>,
    request: LoadChildrenPayload,
) -> Result<Response, Error> {
    let stack = loadable(app)?;

    let now = stack.core_now();
    let mut core = stack.state.core.lock();
    for entry in request.entries {
        let device_type = match entry.flags.device_type {
            ChildDeviceType::Router => NwkDeviceType::Router,
            // Unknown restores as an end device (the safe frame-pending default).
            ChildDeviceType::Unknown | ChildDeviceType::EndDevice => NwkDeviceType::EndDevice,
        };
        core.nib.neighbors.upsert_child(
            ChildDescriptor {
                eui64: entry.ieee,
                network_address: entry.nwk,
                device_type,
                rx_on_when_idle: entry.flags.rx_on_when_idle,
                device_timeout: RESTORED_CHILD_TIMEOUT,
                relationship: Relationship::Child,
            },
            now,
        );
        core.nib.address_map.update_mapping(entry.ieee, entry.nwk);
    }

    Ok(Response::Empty)
}

fn handle_load_address_cache<P: RadioPhy>(
    app: &mut App<P>,
    request: LoadAddressCachePayload,
) -> Result<Response, Error> {
    let stack = loadable(app)?;

    let mut core = stack.state.core.lock();
    for entry in request.entries {
        core.nib.address_map.update_mapping(entry.ieee, entry.nwk);
    }

    Ok(Response::Empty)
}

async fn handle_start_network<P: RadioPhy>(app: &mut App<P>) -> Result<Response, Error> {
    let stack = loadable(app)?.clone();

    if let Err(e) = stack.start_network().await {
        return Err(Error::new(Status::NetworkStartFailed, &e.to_string()));
    }

    spawn_stack_pumps(&stack);
    app.started = true;
    Ok(Response::Empty)
}

/// Report heap health, radio counters, and every stack table/queue size. Deliberately
/// unguarded: it works before `configure` and after an OOM reboot (stack fields are zero),
/// which is exactly when you want to inspect it.
fn handle_get_diagnostics<P: RadioPhy>(app: &App<P>) -> Result<Response, Error> {
    let heap = app.platform.heap_stats();
    let (rx_total, rx_dropped) = app.platform.rx_counters();
    let stack = app
        .stack
        .as_ref()
        .map(|stack| stack.diagnostics())
        .unwrap_or_default();

    Ok(Response::Diagnostics(DiagnosticsPayload {
        configured: app.stack.is_some(),
        started: app.started,
        heap_size: heap.size as u32,
        heap_used: heap.used as u32,
        heap_free: heap.free as u32,
        heap_peak_used: heap.peak_used as u32,
        heap_alloc_ok: heap.alloc_ok as u32,
        heap_alloc_failures: heap.alloc_failures as u32,
        heap_dealloc: heap.dealloc as u32,
        heap_largest_request: heap.largest_request as u32,
        heap_largest_request_align: heap.largest_request_align as u16,
        rx_total: rx_total as u32,
        rx_dropped: rx_dropped as u32,
        frame_tokens_used: ziggurat_driver::frame_token::used() as u16,
        frame_tokens_total: ziggurat_driver::frame_token::total() as u16,
        outbound_queued: crate::OUTBOUND.len() as u16,
        tx_total: stack.tx_total,
        neighbors_total: stack.neighbors_total,
        neighbors_children: stack.neighbors_children,
        route_table: stack.route_table,
        route_discovery: stack.route_discovery,
        route_records: stack.route_records,
        address_map: stack.address_map,
        aps_device_keys: stack.aps_device_keys,
        indirect_transactions: stack.indirect_transactions,
        pending_aps_acks: stack.pending_aps_acks,
        pending_routes: stack.pending_routes,
        pending_broadcasts: stack.pending_broadcasts,
        pending_unicast_retries: stack.pending_unicast_retries,
        address_conflicts: stack.address_conflicts,
        aps_duplicates: stack.aps_duplicates,
        notifications_queued: stack.notifications_queued,
        scan_beacons_queued: stack.scan_beacons_queued,
        scan_beacon_frames: stack.scan_beacon_frames,
    }))
}

fn handle_get_network_info<P: RadioPhy>(app: &App<P>) -> Result<Response, Error> {
    let stack = configured(app)?;

    let stack_state = &stack.state;
    let core = stack_state.core.lock();
    let nwk_security = &core.nib.nwk_security;
    let aps_security = &core.aib.aps_security;

    let (has_tclk_seed, tclk_seed, tclk_flavor) = match &stack.config.tclk_seed {
        Some(tclk) => (
            true,
            tclk.seed.clone(),
            match tclk.flavor {
                TclkFlavor::ZStack => TclkFlavorId::ZStack,
                TclkFlavor::Ezsp => TclkFlavorId::Ezsp,
            },
        ),
        None => (false, Key([0; 16]), TclkFlavorId::ZStack),
    };

    Ok(Response::NetworkInfo(NetworkInfoPayload {
        state: NetworkState {
            channel: core.mac.channel,
            nwk_update_id: core.nib.update_id,
            pan_id: core.mac.pan_id,
            extended_pan_id: stack_state.extended_pan_id,
            nwk_address: stack_state.network_address,
            ieee_address: stack_state.ieee_address,
            network_key: nwk_security.network_key(),
            network_key_seq: nwk_security.key_seq_number(),
            network_key_tx_counter: nwk_security.outgoing_frame_counter(),
            tc_link_key: stack.config.tc_link_key.clone(),
            has_tclk_seed,
            tclk_seed,
            tclk_flavor,
            tx_power: stack.config.tx_power as u8,
            aps_frame_counter: aps_security.outgoing_frame_counter(),
        },
        key_count: aps_security.device_key_count() as u16,
        started: app.started,
    }))
}

/// Stream one table scan: snapshot under the core lock, then stream outside it
/// (the awaiting sends must not hold the mutex), then respond with the count.
async fn scan_table<P: RadioPhy>(
    app: &App<P>,
    request_id: RequestId,
    snapshot: impl FnOnce(&ZigbeeStack<P>) -> Vec<Event>,
) -> Result<Response, Error> {
    let stack = configured(app)?;

    let events = snapshot(stack);
    let count = events.len() as u16;
    for event in events {
        send_event(request_id, event).await;
    }

    Ok(Response::ScanCount(ScanCountPayload { count }))
}

fn handle_send_aps<P: RadioPhy>(
    app: &App<P>,
    request_id: RequestId,
    request: SendApsPayload,
) -> Result<Response, Error> {
    let stack = running(app)?;

    let aps_security = (request.flags.aps_encryption && request.flags.has_eui64)
        .then_some(request.destination_eui64);

    let aps_ack = if request.flags.aps_ack {
        ApsAck::Request
    } else {
        ApsAck::None
    };

    let outcome = stack.send_aps(
        request.flags.delivery_mode,
        request.destination,
        request.profile_id,
        request.cluster_id,
        request.src_ep,
        request.dst_ep,
        aps_ack,
        request.radius,
        request.aps_seq,
        request.asdu,
        aps_security,
        TxPriority::from_host(request.priority as i8),
        StackRequestId::from(request_id),
    );

    match outcome {
        Ok(()) => Ok(Response::Empty),
        Err(e) => Err(Error::new(Status::TransmitFailed, &e.to_string())),
    }
}

fn handle_permit_joins<P: RadioPhy>(
    app: &App<P>,
    request: PermitJoinsPayload,
) -> Result<Response, Error> {
    let stack = running(app)?;

    stack.permit_joins(u64::from(request.duration), request.accept_direct_joins);
    Ok(Response::Empty)
}

async fn handle_set_channel<P: RadioPhy>(
    app: &App<P>,
    request: ChannelPayload,
) -> Result<Response, Error> {
    let stack = running(app)?.clone();

    match stack.set_channel(request.channel).await {
        Ok(()) => Ok(Response::Empty),
        Err(e) => Err(Error::new(Status::RadioError, &e.to_string())),
    }
}

fn handle_set_nwk_update_id<P: RadioPhy>(
    app: &App<P>,
    request: NwkUpdateIdPayload,
) -> Result<Response, Error> {
    let stack = running(app)?;

    stack.set_nwk_update_id(request.nwk_update_id);
    Ok(Response::Empty)
}

fn handle_set_provisional_key<P: RadioPhy>(
    app: &App<P>,
    request: ProvisionalKeyPayload,
) -> Result<Response, Error> {
    let stack = running(app)?;

    stack.set_provisional_key(request.ieee, request.key);
    Ok(Response::Empty)
}

async fn handle_energy_scan<P: RadioPhy>(
    app: &App<P>,
    request_id: RequestId,
    request: ScanRequestPayload,
) -> Result<Response, Error> {
    let duration = Duration::from_millis(u64::from(request.duration_per_channel_ms));
    for channel in request.channels {
        match app.phy.energy_detect(channel, duration).await {
            Ok(rssi) => {
                send_event(
                    request_id,
                    Event::EnergyResult(EnergyResultPayload {
                        channel,
                        rssi: rssi as u8,
                    }),
                )
                .await;
            }
            Err(e) => return Err(Error::new(Status::ScanFailed, &e.to_string())),
        }
    }

    Ok(Response::Empty)
}

async fn handle_network_scan<P: RadioPhy>(
    app: &App<P>,
    request_id: RequestId,
    request: ScanRequestPayload,
) -> Result<Response, Error> {
    let stack = running(app)?.clone();

    stack.begin_network_scan();
    let duration = Duration::from_millis(u64::from(request.duration_per_channel_ms));
    let result = stack.run_network_scan(&request.channels, duration).await;

    loop {
        let batch = stack.next_scan_beacons().await;
        if batch.is_empty() {
            break;
        }
        for beacon in batch {
            send_event(
                request_id,
                Event::Beacon(BeaconPayload {
                    channel: beacon.channel,
                    source: beacon.source.unwrap_or(Nwk(0xFFFF)),
                    pan_id: beacon.pan_id,
                    extended_pan_id: beacon.extended_pan_id,
                    permit_joining: beacon.permit_joining,
                    router_capacity: beacon.router_capacity,
                    end_device_capacity: beacon.end_device_capacity,
                    stack_profile: beacon.stack_profile,
                    protocol_version: beacon.protocol_version,
                    device_depth: beacon.device_depth,
                    update_id: beacon.update_id,
                    lqi: beacon.lqi,
                    rssi: beacon.rssi as u8,
                }),
            )
            .await;
        }
    }

    match result {
        Ok(()) => Ok(Response::Empty),
        Err(e) => Err(Error::new(Status::ScanFailed, &e.to_string())),
    }
}

async fn handle_packet_capture<P: RadioPhy>(
    app: &mut App<P>,
    request_id: RequestId,
    request: ChannelPayload,
) -> Result<Response, Error> {
    if let Err(e) = app.phy.reconfigure(&capture_config(request.channel)).await {
        return Err(Error::new(Status::RadioError, &e.to_string()));
    }

    // Already capturing: the reconfigure above retuned it; don't spawn a second task.
    if app.capture_stop.is_none() {
        let stop = Arc::new(CaptureStop::new());
        app.capture_stop = Some(stop.clone());

        let phy = app.phy.clone();
        app.spawner.spawn(alloc::boxed::Box::pin(async move {
            let mut rx = phy.subscribe_rx();
            loop {
                match embassy_futures::select::select(rx.recv(), stop.wait()).await {
                    embassy_futures::select::Either::First(Some(frame)) => {
                        let event = Event::CapturedPacket(CapturedPacketPayload {
                            channel: frame.channel,
                            rssi: frame.rssi as u8,
                            lqi: frame.lqi,
                            psdu: frame.psdu,
                        });
                        // Drop on a full queue: a sniffer must not block.
                        if let Some(bytes) = event.frame(request_id) {
                            push_outbound(bytes);
                        }
                    }
                    _ => break,
                }
            }
        }));
    }

    Ok(Response::Empty)
}

async fn handle_packet_capture_channel<P: RadioPhy>(
    app: &App<P>,
    request: ChannelPayload,
) -> Result<Response, Error> {
    match app.phy.reconfigure(&capture_config(request.channel)).await {
        Ok(()) => Ok(Response::Empty),
        Err(e) => Err(Error::new(Status::RadioError, &e.to_string())),
    }
}

// -- notifications ---------------------------------------------------------------------

/// Encode one unsolicited notification. `send_confirm`/`aps_ack_confirm` carry
/// their originating request id in the envelope.
pub fn notification_frame(update: &ZigbeeNotification) -> Option<Vec<u8>> {
    let notification = match update {
        ZigbeeNotification::ReceivedApsCommand {
            source,
            destination,
            group,
            profile_id,
            cluster_id,
            src_ep,
            dst_ep,
            lqi,
            rssi,
            data,
        } => Notification::ReceivedAps(ReceivedApsPayload {
            source: *source,
            destination: *destination,
            has_group: group.is_some(),
            group: group.unwrap_or(0),
            profile_id: *profile_id,
            cluster_id: *cluster_id,
            src_ep: *src_ep,
            dst_ep: *dst_ep,
            lqi: *lqi,
            rssi: *rssi as u8,
            data: data.clone(),
        }),
        ZigbeeNotification::SendConfirm { request_id, result } => {
            let (confirmed, next_hop, reason) = match result {
                SendResult::Confirmed { next_hop } => {
                    (true, next_hop.unwrap_or(Nwk(0xFFFF)), Vec::new())
                }
                SendResult::Failed { reason } => {
                    (false, Nwk(0xFFFF), reason.to_string().into_bytes())
                }
            };
            Notification::SendConfirm(
                *request_id as u16,
                SendConfirmPayload {
                    confirmed,
                    next_hop,
                    reason,
                },
            )
        }
        ZigbeeNotification::ApsAckConfirm { request_id, result } => {
            let (acked, reason) = match result {
                ApsAckResult::Acked => (true, Vec::new()),
                ApsAckResult::Failed { reason } => (false, reason.to_string().into_bytes()),
            };
            Notification::ApsAckConfirm(*request_id as u16, ApsAckConfirmPayload { acked, reason })
        }
        ZigbeeNotification::DeviceJoined { nwk, ieee, parent } => {
            Notification::DeviceJoined(DeviceJoinedPayload {
                nwk: *nwk,
                ieee: *ieee,
                parent: *parent,
            })
        }
        ZigbeeNotification::DeviceLeft { nwk, ieee, reason } => {
            let (reason_code, rejoin, router, router_ieee) = match reason {
                DeviceLeaveReason::Announced { rejoin } => {
                    (LeaveReason::Announced, *rejoin, None, None)
                }
                DeviceLeaveReason::RouterReported {
                    router,
                    router_ieee,
                } => (
                    LeaveReason::RouterReported,
                    false,
                    Some(*router),
                    *router_ieee,
                ),
                DeviceLeaveReason::KeepaliveTimeout => {
                    (LeaveReason::KeepaliveTimeout, false, None, None)
                }
            };
            Notification::DeviceLeft(DeviceLeftPayload {
                nwk: *nwk,
                has_ieee: ieee.is_some(),
                rejoin,
                has_router_ieee: router_ieee.is_some(),
                ieee: ieee.unwrap_or(Eui64([0; 8])),
                reason: reason_code,
                router: router.unwrap_or(Nwk(0xFFFF)),
                router_ieee: router_ieee.unwrap_or(Eui64([0; 8])),
            })
        }
        ZigbeeNotification::FrameCounterUpdate { frame_counter } => {
            Notification::FrameCounter(FrameCounterPayload {
                frame_counter: *frame_counter,
            })
        }
        ZigbeeNotification::LinkKeyUpdate { ieee, key } => Notification::LinkKey(LinkKeyPayload {
            ieee: *ieee,
            key: key.clone(),
        }),
        ZigbeeNotification::ApsDecryptionFailure {
            source,
            source_ieee,
            frame_counter,
            key_id,
        } => {
            let key_id = match key_id {
                NwkSecurityHeaderKeyId::DataKey => KeyId::Data,
                NwkSecurityHeaderKeyId::NetworkKey => KeyId::Network,
                NwkSecurityHeaderKeyId::KeyTransportKey => KeyId::KeyTransport,
                NwkSecurityHeaderKeyId::KeyLoadKey => KeyId::KeyLoad,
            };
            Notification::ApsDecryptFailure(ApsDecryptFailPayload {
                source: *source,
                source_ieee: *source_ieee,
                frame_counter: *frame_counter,
                key_id,
            })
        }
    };
    notification.frame()
}
