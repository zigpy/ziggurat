//! The binary wire format, shared by both the WebSocket server and MCUs over serial.
//!
//! The transport provides the framing: one frame per WebSocket binary message, or
//! COBS-encoded frames delimited by `0x00` over a raw byte stream (serial, stdio).
//! Within a frame, fields pack LSB-first in declaration order and multi-byte integers
//! are little-endian.
//!
//! Every frame in both directions leads with the same 3-byte [`Header`], packing the
//! command, frame type, and request id into 24 bits (bit 0 leftmost within a byte):
//!
//! ```text
//!        byte 0            byte 1              byte 2
//! +----------------+------+------------+------------------+
//! |    command     | type | request id |    request id    |
//! |       u8       |  u2  | u14 (low)  |    u14 (high)    |
//! +----------------+------+------------+------------------+
//! ```
//!
//! Bytes 1-2 read as one little-endian u16 equal to `request_id << 2 | frame_type`.
//!
//! The [`FrameType`] distinguishes between requests, responses, and notifications.
//!
//! - `Request` (host -> device): asks the device to do something. Every request is
//!   answered by exactly one `Response` echoing its command and request id.
//! - `Event` (device -> host): a streamed item belonging to a still-pending request
//!   (table scan rows, beacons, captured packets), carrying that request's command and
//!   id. All of a request's events precede its response.
//! - `Response` (device -> host): the final reply to a request. The body begins with a
//!   [`Status`] byte and contains either the command response or an error-specific
//!   payload.
//! - `Notification` (device -> host): unsolicited notifications.
//!
//! Request ids are host-chosen: 14 bits wide, with 0 left for notifications.

use alloc::vec::Vec;
use core::time::Duration;

use abstract_bits::{abstract_bits, AbstractBits, BitReader};
use num_enum::TryFromPrimitive;

use ziggurat_ieee_802154::types::{Eui64, Key, Nwk, PanId};

pub const PROTOCOL_VERSION: u8 = 2;

/// Host-chosen request id. 14 bits on the wire: values must stay below `0x4000`.
pub type RequestId = u16;

/// Host -> device opcodes. `Response` and `Event` frames echo the opcode of the
/// request they belong to, so three frame types share this namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum RequestCommand {
    // Device management.
    Reset = 0x00,
    GetFirmwareInfo = 0x01,
    GetHwAddress = 0x02,
    Shutdown = 0x03,
    // Phased bring-up: configure, load state into the stopped stack, start.
    Configure = 0x10,
    LoadKeyTable = 0x11,
    LoadChildren = 0x12,
    LoadAddressCache = 0x13,
    LoadRouteTable = 0x14,
    LoadSourceRoutes = 0x15,
    StartNetwork = 0x16,
    // Introspection: one-shot info and streamed table scans.
    GetNetworkInfo = 0x20,
    ScanKeyTable = 0x21,
    ScanChildren = 0x22,
    ScanAddressCache = 0x23,
    ScanRouteTable = 0x24,
    // The send path and runtime control.
    SendUnicast = 0x30,
    SendBroadcast = 0x31,
    SendGroupcast = 0x32,
    CancelRequest = 0x33,
    PermitJoins = 0x34,
    SetChannel = 0x35,
    SetNwkUpdateId = 0x36,
    SetProvisionalKey = 0x37,
    SetTunable = 0x38,
    // Radio scans and packet capture.
    EnergyScan = 0x40,
    NetworkScan = 0x41,
    PacketCapture = 0x42,
    PacketCaptureChannel = 0x43,
}

impl From<RequestCommand> for u8 {
    fn from(command: RequestCommand) -> Self {
        command as Self
    }
}

/// Device -> host opcodes for unsolicited [`FrameType::Notification`] frames. A
/// separate namespace from [`RequestCommand`]; the frame type disambiguates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum NotificationCommand {
    // Connection lifecycle.
    Hello = 0x00,
    LastReset = 0x01,
    // Traffic: received frames and send verdicts.
    ReceivedAps = 0x10,
    SendConfirm = 0x11,
    ApsAckConfirm = 0x12,
    BroadcastConfirm = 0x13,
    // Network membership.
    DeviceJoined = 0x20,
    DeviceLeft = 0x21,
    // Security and routing state the host must persist or act on.
    FrameCounter = 0x30,
    ApsFrameCounter = 0x31,
    LinkKey = 0x32,
    ApsDecryptFailure = 0x33,
    RouteRecord = 0x34,
}

impl From<NotificationCommand> for u8 {
    fn from(command: NotificationCommand) -> Self {
        command as Self
    }
}

/// What a frame is, and which namespace its command byte indexes (see the module
/// docs). Two bits of the [`Header`].
#[abstract_bits(bits = 2)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum FrameType {
    Request = 0,
    Response = 1,
    Event = 2,
    Notification = 3,
}

/// Response status. `Ok` is followed by the command's response payload; any other
/// value by that status's tail (empty unless documented on the variant). The set is
/// append-only — a new failure condition gets a new code, never a repurposed one —
/// and clients must treat an unknown value as a generic failure.
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum Status {
    Ok = 0x00,
    /// The command is known but its payload did not decode.
    MalformedPayload = 0x01,
    UnknownCommand = 0x02,
    /// The request decoded but is semantically invalid: a non-request frame type,
    /// an empty source route, a bad tunable name or value.
    InvalidRequest = 0x03,
    // Lifecycle (the phased bring-up: unconfigured -> load window -> started).
    NotConfigured = 0x10,
    NotStarted = 0x11,
    AlreadyStarted = 0x12,
    // Send admission (synchronous rejects; delivery failures ride [`SendStatus`]).
    /// Tail: `retry_in_ms: u32` ([`RateLimitedPayload`]).
    RateLimited = 0x20,
    BudgetExhausted = 0x21,
    PayloadTooLong = 0x22,
    SecurityUnavailable = 0x23,
    /// No route to the destination exists, and the request's route control forbade
    /// discovering one.
    NoRoute = 0x24,
    // Execution.
    RadioError = 0x30,
    NetworkStartFailed = 0x31,
    ScanFailed = 0x32,
    // Device-side failures.
    /// The device built a reply exceeding [`MAX_FRAME`].
    ResponseTooLarge = 0x40,
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

/// The 3-byte header leading every frame in both directions (the module docs show
/// the bit layout). `request_id` is `u14` on the wire, `u16` in Rust.
#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub command: u8,
    pub frame_type: FrameType,
    pub request_id: u14,
}

impl Header {
    /// Parse the header off the front of a frame, returning it and the number of
    /// bytes it consumed (the payload starts there).
    pub fn parse(bytes: &[u8]) -> Option<(Self, usize)> {
        let mut reader = BitReader::from(bytes);
        let header = Self::read_abstract_bits(&mut reader).ok()?;
        Some((header, reader.bytes_read()))
    }
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
pub struct LoadRouteTablePayload {
    pub count: u16,
    #[abstract_bits(length_from = count)]
    pub entries: Vec<RouteEntry>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct SourceRouteEntry {
    pub destination: Nwk,
    pub relay_count: u8,
    #[abstract_bits(length_from = relay_count)]
    pub relays: Vec<Nwk>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct LoadSourceRoutesPayload {
    pub count: u16,
    #[abstract_bits(length_from = count)]
    pub entries: Vec<SourceRouteEntry>,
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
pub struct SendUnicastFlags {
    pub has_eui64: bool,
    pub aps_ack: bool,
    pub aps_encryption: bool,
    /// The destination is a sleepy device. It only sees frames by polling its parent,
    /// so the APS ack wait must cover a poll cycle.
    pub sleepy_destination: bool,
    pub reserved: u4,
}

/// How the host wants a unicast routed.
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum RouteControl {
    /// Leave routing entirely to the stack. No route data follows.
    StackDecides = 0,
    /// Use `next_hop` only if the stack has no route of its own (stands in for discovery).
    HintNextHop = 1,
    /// Use `next_hop` unconditionally, overriding a known route and suppressing discovery.
    ForceNextHop = 2,
    /// Use `relays` as a source route only if the stack has no route of its own.
    HintSourceRoute = 3,
    /// Use `relays` as a source route unconditionally, overriding a known route.
    ForceSourceRoute = 4,
}

/// The ordered relay path of a host-supplied source route (excluding the destination).
#[abstract_bits]
#[derive(Debug, Clone)]
pub struct SourceRouteRelays {
    pub relay_count: u8,
    #[abstract_bits(length_from = relay_count)]
    pub relays: Vec<Nwk>,
}

/// A unicast APS send. The route control and its optional `next_hop`/`relays` are
/// unicast-only; broadcast and groupcast have their own commands.
#[abstract_bits]
#[derive(Debug, Clone)]
pub struct SendUnicastPayload {
    pub flags: SendUnicastFlags,
    pub destination: Nwk,
    pub destination_eui64: Eui64,
    pub profile_id: u16,
    pub cluster_id: u16,
    pub src_ep: u8,
    pub dst_ep: u8,
    /// Ignored: the stack owns the APS counter space so that host sends cannot collide
    /// with stack-originated frames (ZDP, APS commands). Kept for wire stability.
    pub aps_seq: u8,
    pub radius: u8,
    pub priority: u8, // i8 two's complement
    pub route: RouteControl,
    #[abstract_bits(
        presence_from = matches!(route, RouteControl::HintNextHop | RouteControl::ForceNextHop)
    )]
    pub next_hop: Option<Nwk>,
    #[abstract_bits(
        presence_from = matches!(route, RouteControl::HintSourceRoute | RouteControl::ForceSourceRoute)
    )]
    pub relays: Option<SourceRouteRelays>,
    pub asdu_len: u16,
    #[abstract_bits(length_from = asdu_len)]
    pub asdu: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct SendBroadcastFlags {
    pub reserved: u8,
}

/// A broadcast APS send to a broadcast sink (`destination`). Never APS-secured or acked,
/// so it carries no flags, EUI64, or route control.
#[abstract_bits]
#[derive(Debug, Clone)]
pub struct SendBroadcastPayload {
    pub flags: SendBroadcastFlags,
    pub destination: Nwk,
    pub profile_id: u16,
    pub cluster_id: u16,
    pub src_ep: u8,
    pub dst_ep: u8,
    /// Ignored, as in [`SendUnicastPayload::aps_seq`].
    pub aps_seq: u8,
    pub radius: u8,
    pub priority: u8, // i8 two's complement
    pub asdu_len: u16,
    #[abstract_bits(length_from = asdu_len)]
    pub asdu: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct SendGroupcastFlags {
    pub reserved: u8,
}

/// A groupcast (APS multicast) send. The group lives in the APS header and the NWK frame
/// is broadcast to rx-on-when-idle devices, so there is no destination endpoint.
#[abstract_bits]
#[derive(Debug, Clone)]
pub struct SendGroupcastPayload {
    pub flags: SendGroupcastFlags,
    pub group_id: u16,
    pub profile_id: u16,
    pub cluster_id: u16,
    pub src_ep: u8,
    /// Ignored, as in [`SendUnicastPayload::aps_seq`].
    pub aps_seq: u8,
    pub radius: u8,
    pub priority: u8, // i8 two's complement
    pub asdu_len: u16,
    #[abstract_bits(length_from = asdu_len)]
    pub asdu: Vec<u8>,
}

/// Cancels an in-flight send by the `request_id` it was issued under. Best-effort:
/// the send is torn down only if it is still in a pre-delivery state (queued, awaiting
/// route discovery, or between retries). The reply reports whether anything was caught.
#[abstract_bits]
#[derive(Debug, Clone)]
pub struct CancelRequestPayload {
    pub request_id: RequestId,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct CancelResultPayload {
    pub cancelled: bool,
    pub reserved: u7,
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

/// The body of a `Status::RateLimited` response: the delay (milliseconds) after which
/// the host may retry the rejected send. Leads with `status` like every failed reply,
/// so the client dispatches on that byte and parses this body when it reads
/// `RateLimited`.
#[abstract_bits]
#[derive(Debug, Clone)]
pub struct RateLimitedPayload {
    pub status: Status,
    pub retry_in_ms: u32,
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

/// A send's terminal verdict, carried in its `SendConfirm` / `ApsAckConfirm` /
/// `BroadcastConfirm` notification. Mirrors the driver's `DeliveryError`; admission
/// failures ride the synchronous `Error` frame's [`Status`] instead.
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum SendStatus {
    Success = 0,
    RouteDiscoveryTimeout = 1,
    RouteDiscoveryNoEntry = 2,
    RouteInactiveAfterDiscovery = 3,
    NwkNoAck = 4,
    CcaFailure = 5,
    TransmitFailed = 6,
    ApsAckTimeout = 7,
    BroadcastQuorumNotReached = 8,
    IndirectExpired = 9,
    FrameBudgetExhausted = 10,
    Cancelled = 11,
    RadioError = 12,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct SendConfirmPayload {
    pub status: SendStatus,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ApsAckConfirmPayload {
    pub status: SendStatus,
}

/// The passive-ack quorum verdict of a broadcast or groupcast send.
#[abstract_bits]
#[derive(Debug, Clone)]
pub struct BroadcastConfirmPayload {
    pub status: SendStatus,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct DeviceJoinedPayload {
    pub nwk: Nwk,
    pub ieee: Eui64,
    pub parent: Nwk,
    pub flags: ChildFlags,
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
pub struct RouteRecordPayload {
    pub destination: Nwk,
    pub relay_count: u8,
    #[abstract_bits(length_from = relay_count)]
    pub relays: Vec<Nwk>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
pub struct ApsFrameCounterPayload {
    pub frame_counter: u32,
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
    Reset(ResetPayload),
    GetFirmwareInfo,
    GetHwAddress,
    Shutdown,
    Configure(ConfigurePayload),
    LoadKeyTable(LoadKeyTablePayload),
    LoadChildren(LoadChildrenPayload),
    LoadAddressCache(LoadAddressCachePayload),
    LoadRouteTable(LoadRouteTablePayload),
    LoadSourceRoutes(LoadSourceRoutesPayload),
    StartNetwork,
    GetNetworkInfo,
    ScanKeyTable,
    ScanChildren,
    ScanAddressCache,
    ScanRouteTable,
    SendUnicast(SendUnicastPayload),
    SendBroadcast(SendBroadcastPayload),
    SendGroupcast(SendGroupcastPayload),
    PermitJoins(PermitJoinsPayload),
    SetChannel(ChannelPayload),
    SetNwkUpdateId(NwkUpdateIdPayload),
    SetProvisionalKey(ProvisionalKeyPayload),
    EnergyScan(ScanRequestPayload),
    NetworkScan(ScanRequestPayload),
    PacketCapture(ChannelPayload),
    PacketCaptureChannel(ChannelPayload),
    SetTunable(SetTunablePayload),
    CancelRequest(CancelRequestPayload),
}

impl Request {
    pub fn parse(command: RequestCommand, payload: &[u8]) -> Result<Self, Error> {
        Ok(match command {
            RequestCommand::Reset => Self::Reset(require(payload)?),
            RequestCommand::GetFirmwareInfo => Self::GetFirmwareInfo,
            RequestCommand::GetHwAddress => Self::GetHwAddress,
            RequestCommand::Shutdown => Self::Shutdown,
            RequestCommand::Configure => Self::Configure(require(payload)?),
            RequestCommand::LoadKeyTable => Self::LoadKeyTable(require(payload)?),
            RequestCommand::LoadChildren => Self::LoadChildren(require(payload)?),
            RequestCommand::LoadAddressCache => Self::LoadAddressCache(require(payload)?),
            RequestCommand::LoadRouteTable => Self::LoadRouteTable(require(payload)?),
            RequestCommand::LoadSourceRoutes => Self::LoadSourceRoutes(require(payload)?),
            RequestCommand::StartNetwork => Self::StartNetwork,
            RequestCommand::GetNetworkInfo => Self::GetNetworkInfo,
            RequestCommand::ScanKeyTable => Self::ScanKeyTable,
            RequestCommand::ScanChildren => Self::ScanChildren,
            RequestCommand::ScanAddressCache => Self::ScanAddressCache,
            RequestCommand::ScanRouteTable => Self::ScanRouteTable,
            RequestCommand::SendUnicast => Self::SendUnicast(require(payload)?),
            RequestCommand::SendBroadcast => Self::SendBroadcast(require(payload)?),
            RequestCommand::SendGroupcast => Self::SendGroupcast(require(payload)?),
            RequestCommand::PermitJoins => Self::PermitJoins(require(payload)?),
            RequestCommand::SetChannel => Self::SetChannel(require(payload)?),
            RequestCommand::SetNwkUpdateId => Self::SetNwkUpdateId(require(payload)?),
            RequestCommand::SetProvisionalKey => Self::SetProvisionalKey(require(payload)?),
            RequestCommand::EnergyScan => Self::EnergyScan(require(payload)?),
            RequestCommand::NetworkScan => Self::NetworkScan(require(payload)?),
            RequestCommand::PacketCapture => Self::PacketCapture(require(payload)?),
            RequestCommand::PacketCaptureChannel => Self::PacketCaptureChannel(require(payload)?),
            RequestCommand::SetTunable => Self::SetTunable(require(payload)?),
            RequestCommand::CancelRequest => Self::CancelRequest(require(payload)?),
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
    CancelResult(CancelResultPayload),
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
            Self::CancelResult(payload) => append(&mut bytes, payload),
        };
        if !fits {
            return Error::Status(Status::ResponseTooLarge).frame(command, request_id);
        }
        bytes
    }
}

/// A failed reply. The client always branches on the `Status` byte that leads the
/// body; each variant serializes that status's tail (nothing, for most of them).
pub enum Error {
    Status(Status),
    /// `Status::RateLimited` with a machine-readable retry delay, so the host can pace
    /// itself instead of busy-retrying a rejected broadcast.
    RateLimited {
        retry_in: Duration,
    },
}

impl From<Status> for Error {
    fn from(status: Status) -> Self {
        Self::Status(status)
    }
}

impl Error {
    pub const fn rate_limited(retry_in: Duration) -> Self {
        Self::RateLimited { retry_in }
    }

    pub fn frame(&self, command: u8, request_id: RequestId) -> Vec<u8> {
        let mut bytes = envelope(FrameType::Response, command, request_id);
        match self {
            Self::Status(status) => {
                append(&mut bytes, status);
            }
            Self::RateLimited { retry_in } => {
                append(
                    &mut bytes,
                    &RateLimitedPayload {
                        status: Status::RateLimited,
                        retry_in_ms: retry_in.as_millis() as u32,
                    },
                );
            }
        }
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
            Self::KeyEntry(_) => RequestCommand::ScanKeyTable,
            Self::Child(_) => RequestCommand::ScanChildren,
            Self::Address(_) => RequestCommand::ScanAddressCache,
            Self::Route(_) => RequestCommand::ScanRouteTable,
            Self::EnergyResult(_) => RequestCommand::EnergyScan,
            Self::Beacon(_) => RequestCommand::NetworkScan,
            Self::CapturedPacket(_) => RequestCommand::PacketCapture,
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
    BroadcastConfirm(RequestId, BroadcastConfirmPayload),
    DeviceJoined(DeviceJoinedPayload),
    DeviceLeft(DeviceLeftPayload),
    FrameCounter(FrameCounterPayload),
    LinkKey(LinkKeyPayload),
    ApsDecryptFailure(ApsDecryptFailPayload),
    RouteRecord(RouteRecordPayload),
    ApsFrameCounter(ApsFrameCounterPayload),
}

impl Notification {
    pub fn frame(&self) -> Option<Vec<u8>> {
        let (command, request_id) = match self {
            Self::Hello(_) => (NotificationCommand::Hello, 0),
            Self::LastReset(_) => (NotificationCommand::LastReset, 0),
            Self::ReceivedAps(_) => (NotificationCommand::ReceivedAps, 0),
            Self::SendConfirm(request_id, _) => (NotificationCommand::SendConfirm, *request_id),
            Self::ApsAckConfirm(request_id, _) => (NotificationCommand::ApsAckConfirm, *request_id),
            Self::BroadcastConfirm(request_id, _) => {
                (NotificationCommand::BroadcastConfirm, *request_id)
            }
            Self::DeviceJoined(_) => (NotificationCommand::DeviceJoined, 0),
            Self::DeviceLeft(_) => (NotificationCommand::DeviceLeft, 0),
            Self::FrameCounter(_) => (NotificationCommand::FrameCounter, 0),
            Self::LinkKey(_) => (NotificationCommand::LinkKey, 0),
            Self::ApsDecryptFailure(_) => (NotificationCommand::ApsDecryptFailure, 0),
            Self::RouteRecord(_) => (NotificationCommand::RouteRecord, 0),
            Self::ApsFrameCounter(_) => (NotificationCommand::ApsFrameCounter, 0),
        };
        let mut bytes = envelope(FrameType::Notification, command.into(), request_id);
        let fits = match self {
            Self::Hello(payload) => append(&mut bytes, payload),
            Self::LastReset(payload) => append(&mut bytes, payload),
            Self::ReceivedAps(payload) => append(&mut bytes, payload),
            Self::SendConfirm(_, payload) => append(&mut bytes, payload),
            Self::ApsAckConfirm(_, payload) => append(&mut bytes, payload),
            Self::BroadcastConfirm(_, payload) => append(&mut bytes, payload),
            Self::DeviceJoined(payload) => append(&mut bytes, payload),
            Self::DeviceLeft(payload) => append(&mut bytes, payload),
            Self::FrameCounter(payload) => append(&mut bytes, payload),
            Self::LinkKey(payload) => append(&mut bytes, payload),
            Self::ApsDecryptFailure(payload) => append(&mut bytes, payload),
            Self::RouteRecord(payload) => append(&mut bytes, payload),
            Self::ApsFrameCounter(payload) => append(&mut bytes, payload),
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
        &Header {
            command,
            frame_type,
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

pub fn require<T: AbstractBits>(payload: &[u8]) -> Result<T, Error> {
    parse(payload).ok_or(Error::Status(Status::MalformedPayload))
}
