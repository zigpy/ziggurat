//! The binary command set (see claude/docs/serial-wire-format.md in the repo
//! root): request/response keyed by request id, streamed events, unsolicited
//! notifications, fixed-layout payloads, and index-free scan/load state transfer.

use alloc::string::ToString;
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

/// Every command and notification, keyed by its wire id. The frame header carries
/// the raw byte (so an unknown id still parses far enough to reply with an error);
/// dispatch converts to this enum.
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

/// How the host must route a frame. `Error` folds into `Response`: a response
/// carries a [`Status`], so `Status::Ok` + payload is success and any other status
/// + message is failure — one terminal path for the client. `Request` exists only
/// so the header is identical in both directions.
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum FrameType {
    Request = 1,
    Response = 2,
    Event = 3,
    Notification = 4,
}

/// Response status. `Ok` carries the response payload; any other value carries a
/// diagnostic message string instead (see [`error`]).
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

#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub frame_type: FrameType,
    pub command: u8,
    pub request_id: RequestId,
}

// -- payload structs -------------------------------------------------------------

/// A bool padded to one byte, keeping the protocol byte-aligned.
#[abstract_bits]
#[derive(Debug, Clone)]
struct BoolFlag {
    value: bool,
    reserved: u7,
}

impl From<bool> for BoolFlag {
    fn from(value: bool) -> Self {
        Self { value }
    }
}

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
    version_len: u8,
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
    has_tclk_seed: BoolFlag,
    tclk_seed: Key,
    tclk_flavor: TclkFlavorId,
    tx_power: u8, // i8 two's complement (abstract-bits has no signed types)
    aps_frame_counter: u32,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ConfigurePayload {
    role: NodeRole,
    source_routing: BoolFlag,
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
    count: u8,
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
    count: u8,
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
    count: u8,
    #[abstract_bits(length_from = count)]
    entries: Vec<AddressEntry>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct NetworkInfoPayload {
    state: NetworkState,
    key_count: u16,
    started: BoolFlag,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ScanCountPayload {
    count: u16,
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
    accept_direct_joins: BoolFlag,
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
    count: u8,
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
    permit_joining: BoolFlag,
    stack_profile: u8,
    protocol_version: u8,
    router_capacity: BoolFlag,
    end_device_capacity: BoolFlag,
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
    message_len: u8,
    #[abstract_bits(length_from = message_len)]
    message: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct HelloPayload {
    protocol_version: u8,
    configured: BoolFlag,
}

/// Why the MCU last rebooted, when the reboot was abnormal (a fault dump or the
/// stored Rust panic message). Sent once, right after `hello`.
#[abstract_bits]
#[derive(Debug, Clone)]
struct LastResetPayload {
    message_len: u8,
    #[abstract_bits(length_from = message_len)]
    message: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ReceivedApsPayload {
    source: Nwk,
    destination: Nwk,
    has_group: BoolFlag,
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
    confirmed: BoolFlag,
    next_hop: Nwk, // 0xFFFF when unknown
    reason_len: u8,
    #[abstract_bits(length_from = reason_len)]
    reason: Vec<u8>,
}

#[abstract_bits]
#[derive(Debug, Clone)]
struct ApsAckConfirmPayload {
    acked: BoolFlag,
    reason_len: u8,
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
    has_ieee: BoolFlag,
    ieee: Eui64,
    reason: LeaveReason,
    rejoin: BoolFlag,
    router: Nwk, // 0xFFFF when not router_reported
    has_router_ieee: BoolFlag,
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

// -- frame assembly ----------------------------------------------------------------

/// Bounds one encoded frame: the envelope plus the largest payload (a captured
/// packet or an error string).
const MAX_FRAME: usize = 512;

fn append<T: AbstractBits>(bytes: &mut Vec<u8>, value: &T) {
    let mut buffer = [0u8; MAX_FRAME];
    let mut writer = abstract_bits::BitWriter::from(&mut buffer[..]);
    value.write_abstract_bits(&mut writer).unwrap();
    let written = writer.bytes_written();
    bytes.extend_from_slice(&buffer[..written]);
}

fn envelope(frame_type: FrameType, command: u8, request_id: RequestId) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    append(
        &mut bytes,
        &FrameHeader {
            frame_type,
            command,
            request_id,
        },
    );
    bytes
}

fn frame<T: AbstractBits>(
    frame_type: FrameType,
    command: CommandId,
    request_id: RequestId,
    payload: &T,
) -> Vec<u8> {
    let mut bytes = envelope(frame_type, command.into(), request_id);
    append(&mut bytes, payload);
    bytes
}

/// A successful response: `Status::Ok` then the typed payload.
fn response<T: AbstractBits>(command: CommandId, request_id: RequestId, payload: &T) -> Vec<u8> {
    let mut bytes = envelope(FrameType::Response, command.into(), request_id);
    append(&mut bytes, &Status::Ok);
    append(&mut bytes, payload);
    bytes
}

/// A successful response with no payload: just `Status::Ok`.
fn ok(command: CommandId, request_id: RequestId) -> Vec<u8> {
    let mut bytes = envelope(FrameType::Response, command.into(), request_id);
    append(&mut bytes, &Status::Ok);
    bytes
}

fn event<T: AbstractBits>(command: CommandId, request_id: RequestId, payload: &T) -> Vec<u8> {
    frame(FrameType::Event, command, request_id, payload)
}

fn notification<T: AbstractBits>(id: CommandId, request_id: RequestId, payload: &T) -> Vec<u8> {
    frame(FrameType::Notification, id, request_id, payload)
}

fn error(command: CommandId, request_id: RequestId, status: Status, message: &str) -> Vec<u8> {
    error_raw(command.into(), request_id, status, message)
}

/// A failed response for a possibly-unknown command byte (the header parsed but the
/// command did not resolve): a `Response` carrying a non-`Ok` status and a
/// diagnostic message.
fn error_raw(command: u8, request_id: RequestId, status: Status, message: &str) -> Vec<u8> {
    let message = &message.as_bytes()[..message.len().min(255)];
    let mut bytes = envelope(FrameType::Response, command, request_id);
    append(
        &mut bytes,
        &ErrorPayload {
            status,
            message: message.to_vec(),
        },
    );
    bytes
}

/// Parse one payload, ignoring trailing bytes (append-only forward compatibility).
fn parse<T: AbstractBits>(payload: &[u8]) -> Option<T> {
    let mut reader = BitReader::from(payload);
    T::read_abstract_bits(&mut reader).ok()
}

pub fn hello_frame(configured: bool) -> Vec<u8> {
    notification(
        CommandId::Hello,
        0,
        &HelloPayload {
            protocol_version: PROTOCOL_VERSION,
            configured: configured.into(),
        },
    )
}

pub fn last_reset_frame(message: &str) -> Vec<u8> {
    let message = &message.as_bytes()[..message.len().min(255)];
    notification(
        CommandId::LastReset,
        0,
        &LastResetPayload {
            message: message.to_vec(),
        },
    )
}

// -- dispatch ------------------------------------------------------------------------

/// Dispatch one inbound frame; every path emits exactly one response or error,
/// preceded by any streamed events.
pub async fn handle_frame<P: RadioPhy>(app: &mut App<P>, bytes: &[u8]) {
    let mut reader = BitReader::from(bytes);
    let Ok(header) = FrameHeader::read_abstract_bits(&mut reader) else {
        send_outbound(error_raw(0, 0, Status::Parse, "truncated envelope")).await;
        return;
    };
    let payload = &bytes[reader.bytes_read()..];
    let request_id = header.request_id;

    if header.frame_type != FrameType::Request {
        send_outbound(error_raw(
            header.command,
            request_id,
            Status::Parse,
            "not a request",
        ))
        .await;
        return;
    }

    let Ok(command) = CommandId::try_from(header.command) else {
        send_outbound(error_raw(header.command, request_id, Status::UnknownCommand, "")).await;
        return;
    };

    let reply = match command {
        CommandId::Ping => ok(CommandId::Ping, request_id),
        CommandId::Reset => handle_reset(app, request_id, payload),
        CommandId::GetFirmwareInfo => {
            let version = concat!("ziggurat/", env!("CARGO_PKG_VERSION"));
            response(
                CommandId::GetFirmwareInfo,
                request_id,
                &FirmwareInfoPayload {
                    protocol_version: PROTOCOL_VERSION,
                    version: version.as_bytes().to_vec(),
                },
            )
        }
        CommandId::GetHwAddress => response(
            CommandId::GetHwAddress,
            request_id,
            &HwAddressPayload {
                ieee: app.platform.hw_eui64(),
            },
        ),
        CommandId::Configure => handle_configure(app, request_id, payload).await,
        CommandId::LoadKeyTable => handle_load_key_table(app, request_id, payload),
        CommandId::LoadChildren => handle_load_children(app, request_id, payload),
        CommandId::LoadAddressCache => handle_load_address_cache(app, request_id, payload),
        CommandId::StartNetwork => handle_start_network(app, request_id).await,
        CommandId::GetNetworkInfo => handle_get_network_info(app, request_id),
        CommandId::ScanKeyTable => handle_scan_key_table(app, request_id).await,
        CommandId::ScanChildren => handle_scan_children(app, request_id).await,
        CommandId::ScanAddressCache => handle_scan_address_cache(app, request_id).await,
        CommandId::ScanRouteTable => handle_scan_route_table(app, request_id).await,
        CommandId::SendAps => handle_send_aps(app, request_id, payload),
        CommandId::PermitJoins => handle_permit_joins(app, request_id, payload),
        CommandId::SetChannel => handle_set_channel(app, request_id, payload).await,
        CommandId::SetNwkUpdateId => handle_set_nwk_update_id(app, request_id, payload),
        CommandId::SetProvisionalKey => handle_set_provisional_key(app, request_id, payload),
        CommandId::EnergyScan => handle_energy_scan(app, request_id, payload).await,
        CommandId::NetworkScan => handle_network_scan(app, request_id, payload).await,
        CommandId::PacketCapture => handle_packet_capture(app, request_id, payload).await,
        CommandId::PacketCaptureChannel => {
            handle_packet_capture_channel(app, request_id, payload).await
        }
        other => error(other, request_id, Status::UnknownCommand, ""),
    };

    send_outbound(reply).await;
}

/// Soft reset stops transient radio activity; hard reset reboots (diverges).
fn handle_reset<P: RadioPhy>(app: &mut App<P>, request_id: RequestId, payload: &[u8]) -> Vec<u8> {
    let Some(request) = parse::<ResetPayload>(payload) else {
        return error(CommandId::Reset, request_id, Status::Parse, "reset type");
    };

    if let Some(stop) = app.capture_stop.take() {
        stop.signal(());
    }

    if request.hard {
        app.platform.hard_reset();
    }

    ok(CommandId::Reset, request_id)
}

async fn handle_configure<P: RadioPhy>(
    app: &mut App<P>,
    request_id: RequestId,
    payload: &[u8],
) -> Vec<u8> {
    let Some(request) = parse::<ConfigurePayload>(payload) else {
        return error(CommandId::Configure, request_id, Status::Parse, "configure");
    };
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
        tclk_seed: state.has_tclk_seed.value.then_some(TclkSeed {
            seed: state.tclk_seed,
            flavor: match state.tclk_flavor {
                TclkFlavorId::Ezsp => TclkFlavor::Ezsp,
                TclkFlavorId::ZStack => TclkFlavor::ZStack,
            },
        }),
        tx_power: state.tx_power as i8,
        source_routing: request.source_routing.value,
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

    ok(CommandId::Configure, request_id)
}

/// The stack, if it is in the load window (configured but not started).
fn loadable<P: RadioPhy>(
    app: &App<P>,
    command: CommandId,
    request_id: RequestId,
) -> Result<&Arc<ZigbeeStack<P>>, Vec<u8>> {
    match app.stack.as_ref() {
        Some(stack) if !app.started => Ok(stack),
        Some(_) => Err(error(
            command,
            request_id,
            Status::InvalidState,
            "network already started",
        )),
        None => Err(error(command, request_id, Status::NotConfigured, "")),
    }
}

/// The stack, if it is running.
fn running<P: RadioPhy>(
    app: &App<P>,
    command: CommandId,
    request_id: RequestId,
) -> Result<&Arc<ZigbeeStack<P>>, Vec<u8>> {
    match app.stack.as_ref() {
        Some(stack) if app.started => Ok(stack),
        _ => Err(error(command, request_id, Status::NotConfigured, "")),
    }
}

fn handle_load_key_table<P: RadioPhy>(
    app: &mut App<P>,
    request_id: RequestId,
    payload: &[u8],
) -> Vec<u8> {
    let stack = match loadable(app, CommandId::LoadKeyTable, request_id) {
        Ok(stack) => stack,
        Err(e) => return e,
    };

    let Some(request) = parse::<LoadKeyTablePayload>(payload) else {
        return error(CommandId::LoadKeyTable, request_id, Status::Parse, "key entries");
    };

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

    ok(CommandId::LoadKeyTable, request_id)
}

fn handle_load_children<P: RadioPhy>(
    app: &mut App<P>,
    request_id: RequestId,
    payload: &[u8],
) -> Vec<u8> {
    let stack = match loadable(app, CommandId::LoadChildren, request_id) {
        Ok(stack) => stack,
        Err(e) => return e,
    };

    let Some(request) = parse::<LoadChildrenPayload>(payload) else {
        return error(CommandId::LoadChildren, request_id, Status::Parse, "child entries");
    };

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

    ok(CommandId::LoadChildren, request_id)
}

fn handle_load_address_cache<P: RadioPhy>(
    app: &mut App<P>,
    request_id: RequestId,
    payload: &[u8],
) -> Vec<u8> {
    let stack = match loadable(app, CommandId::LoadAddressCache, request_id) {
        Ok(stack) => stack,
        Err(e) => return e,
    };

    let Some(request) = parse::<LoadAddressCachePayload>(payload) else {
        return error(CommandId::LoadAddressCache, request_id, Status::Parse, "addr entries");
    };

    let mut core = stack.state.core.lock();
    for entry in request.entries {
        core.nib.address_map.update_mapping(entry.ieee, entry.nwk);
    }

    ok(CommandId::LoadAddressCache, request_id)
}

async fn handle_start_network<P: RadioPhy>(app: &mut App<P>, request_id: RequestId) -> Vec<u8> {
    let stack = match loadable(app, CommandId::StartNetwork, request_id) {
        Ok(stack) => stack.clone(),
        Err(e) => return e,
    };

    if let Err(e) = stack.start_network().await {
        return error(
            CommandId::StartNetwork,
            request_id,
            Status::NetworkStartFailed,
            &e.to_string(),
        );
    }

    spawn_stack_pumps(&stack);
    app.started = true;
    ok(CommandId::StartNetwork, request_id)
}

fn handle_get_network_info<P: RadioPhy>(app: &App<P>, request_id: RequestId) -> Vec<u8> {
    let Some(stack) = app.stack.as_ref() else {
        return error(CommandId::GetNetworkInfo, request_id, Status::NotConfigured, "");
    };

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

    response(
        CommandId::GetNetworkInfo,
        request_id,
        &NetworkInfoPayload {
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
                has_tclk_seed: has_tclk_seed.into(),
                tclk_seed,
                tclk_flavor,
                tx_power: stack.config.tx_power as u8,
                aps_frame_counter: aps_security.outgoing_frame_counter(),
            },
            key_count: aps_security.device_key_count() as u16,
            started: app.started.into(),
        },
    )
}

async fn handle_scan_key_table<P: RadioPhy>(app: &App<P>, request_id: RequestId) -> Vec<u8> {
    let Some(stack) = app.stack.as_ref() else {
        return error(CommandId::ScanKeyTable, request_id, Status::NotConfigured, "");
    };

    // Snapshot under the lock, stream outside it: the awaiting sends must not hold
    // the core mutex.
    let entries: Vec<KeyEntry> = {
        let core = stack.state.core.lock();
        let aps = &core.aib.aps_security;
        let outgoing = aps.outgoing_frame_counter();
        aps.device_keys()
            .map(|(partner, entry)| KeyEntry {
                key: entry.key.clone(),
                tx_counter: outgoing,
                rx_counter: aps.incoming_frame_counter(partner).unwrap_or(0),
                seq: 0,
                partner_ieee: partner,
            })
            .collect()
    };

    let count = entries.len() as u16;
    for entry in entries {
        send_outbound(event(CommandId::ScanKeyTable, request_id, &entry)).await;
    }

    response(CommandId::ScanKeyTable, request_id, &ScanCountPayload { count })
}

async fn handle_scan_children<P: RadioPhy>(app: &App<P>, request_id: RequestId) -> Vec<u8> {
    let Some(stack) = app.stack.as_ref() else {
        return error(CommandId::ScanChildren, request_id, Status::NotConfigured, "");
    };

    let entries: Vec<ChildEntry> = {
        let core = stack.state.core.lock();
        core.nib
            .neighbors
            .entries()
            .filter(|entry| entry.is_child())
            .map(|entry| ChildEntry {
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
            .collect()
    };

    let count = entries.len() as u16;
    for entry in entries {
        send_outbound(event(CommandId::ScanChildren, request_id, &entry)).await;
    }

    response(CommandId::ScanChildren, request_id, &ScanCountPayload { count })
}

async fn handle_scan_address_cache<P: RadioPhy>(app: &App<P>, request_id: RequestId) -> Vec<u8> {
    let Some(stack) = app.stack.as_ref() else {
        return error(CommandId::ScanAddressCache, request_id, Status::NotConfigured, "");
    };

    let entries: Vec<AddressEntry> = {
        let core = stack.state.core.lock();
        core.nib
            .address_map
            .entries()
            .map(|(ieee, nwk)| AddressEntry { ieee, nwk })
            .collect()
    };

    let count = entries.len() as u16;
    for entry in entries {
        send_outbound(event(CommandId::ScanAddressCache, request_id, &entry)).await;
    }

    response(CommandId::ScanAddressCache, request_id, &ScanCountPayload { count })
}

async fn handle_scan_route_table<P: RadioPhy>(app: &App<P>, request_id: RequestId) -> Vec<u8> {
    let Some(stack) = app.stack.as_ref() else {
        return error(CommandId::ScanRouteTable, request_id, Status::NotConfigured, "");
    };

    let entries: Vec<RouteEntry> = {
        let core = stack.state.core.lock();
        core.nib
            .routing
            .entries()
            .filter(|entry| matches!(entry.status, routing::Status::Active))
            .map(|entry| RouteEntry {
                destination: entry.destination,
                next_hop: entry.next_hop_address,
                path_cost: entry.path_cost,
            })
            .collect()
    };

    let count = entries.len() as u16;
    for entry in entries {
        send_outbound(event(CommandId::ScanRouteTable, request_id, &entry)).await;
    }

    response(CommandId::ScanRouteTable, request_id, &ScanCountPayload { count })
}

fn handle_send_aps<P: RadioPhy>(app: &App<P>, request_id: RequestId, payload: &[u8]) -> Vec<u8> {
    let stack = match running(app, CommandId::SendAps, request_id) {
        Ok(stack) => stack,
        Err(e) => return e,
    };

    let Some(request) = parse::<SendApsPayload>(payload) else {
        return error(CommandId::SendAps, request_id, Status::Parse, "send_aps");
    };

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
        TxPriority(request.priority as i8),
        StackRequestId::from(request_id),
    );

    match outcome {
        Ok(()) => ok(CommandId::SendAps, request_id),
        Err(e) => error(CommandId::SendAps, request_id, Status::TransmitFailed, &e.to_string()),
    }
}

fn handle_permit_joins<P: RadioPhy>(app: &App<P>, request_id: RequestId, payload: &[u8]) -> Vec<u8> {
    let stack = match running(app, CommandId::PermitJoins, request_id) {
        Ok(stack) => stack,
        Err(e) => return e,
    };

    let Some(request) = parse::<PermitJoinsPayload>(payload) else {
        return error(CommandId::PermitJoins, request_id, Status::Parse, "permit_joins");
    };

    stack.permit_joins(u64::from(request.duration), request.accept_direct_joins.value);
    ok(CommandId::PermitJoins, request_id)
}

async fn handle_set_channel<P: RadioPhy>(app: &App<P>, request_id: RequestId, payload: &[u8]) -> Vec<u8> {
    let stack = match running(app, CommandId::SetChannel, request_id) {
        Ok(stack) => stack.clone(),
        Err(e) => return e,
    };

    let Some(request) = parse::<ChannelPayload>(payload) else {
        return error(CommandId::SetChannel, request_id, Status::Parse, "channel");
    };

    match stack.set_channel(request.channel).await {
        Ok(()) => ok(CommandId::SetChannel, request_id),
        Err(e) => error(CommandId::SetChannel, request_id, Status::RadioError, &e.to_string()),
    }
}

fn handle_set_nwk_update_id<P: RadioPhy>(
    app: &App<P>,
    request_id: RequestId,
    payload: &[u8],
) -> Vec<u8> {
    let stack = match running(app, CommandId::SetNwkUpdateId, request_id) {
        Ok(stack) => stack,
        Err(e) => return e,
    };

    let Some(request) = parse::<NwkUpdateIdPayload>(payload) else {
        return error(CommandId::SetNwkUpdateId, request_id, Status::Parse, "update id");
    };

    stack.set_nwk_update_id(request.nwk_update_id);
    ok(CommandId::SetNwkUpdateId, request_id)
}

fn handle_set_provisional_key<P: RadioPhy>(
    app: &App<P>,
    request_id: RequestId,
    payload: &[u8],
) -> Vec<u8> {
    let stack = match running(app, CommandId::SetProvisionalKey, request_id) {
        Ok(stack) => stack,
        Err(e) => return e,
    };

    let Some(request) = parse::<ProvisionalKeyPayload>(payload) else {
        return error(CommandId::SetProvisionalKey, request_id, Status::Parse, "key");
    };

    stack.set_provisional_key(request.ieee, request.key);
    ok(CommandId::SetProvisionalKey, request_id)
}

async fn handle_energy_scan<P: RadioPhy>(app: &App<P>, request_id: RequestId, payload: &[u8]) -> Vec<u8> {
    let Some(request) = parse::<ScanRequestPayload>(payload) else {
        return error(CommandId::EnergyScan, request_id, Status::Parse, "energy_scan");
    };

    let duration = Duration::from_millis(u64::from(request.duration_per_channel_ms));
    for channel in request.channels {
        match app.phy.energy_detect(channel, duration).await {
            Ok(rssi) => {
                send_outbound(event(
                    CommandId::EnergyScan,
                    request_id,
                    &EnergyResultPayload {
                        channel,
                        rssi: rssi as u8,
                    },
                ))
                .await;
            }
            Err(e) => {
                return error(CommandId::EnergyScan, request_id, Status::ScanFailed, &e.to_string());
            }
        }
    }

    ok(CommandId::EnergyScan, request_id)
}

async fn handle_network_scan<P: RadioPhy>(
    app: &App<P>,
    request_id: RequestId,
    payload: &[u8],
) -> Vec<u8> {
    let stack = match running(app, CommandId::NetworkScan, request_id) {
        Ok(stack) => stack.clone(),
        Err(e) => return e,
    };

    let Some(request) = parse::<ScanRequestPayload>(payload) else {
        return error(CommandId::NetworkScan, request_id, Status::Parse, "network_scan");
    };

    stack.begin_network_scan();
    let duration = Duration::from_millis(u64::from(request.duration_per_channel_ms));
    let result = stack.run_network_scan(&request.channels, duration).await;

    loop {
        let batch = stack.next_scan_beacons().await;
        if batch.is_empty() {
            break;
        }
        for beacon in batch {
            send_outbound(event(
                CommandId::NetworkScan,
                request_id,
                &BeaconPayload {
                    channel: beacon.channel,
                    source: beacon.source.unwrap_or(Nwk(0xFFFF)),
                    pan_id: beacon.pan_id,
                    extended_pan_id: beacon.extended_pan_id,
                    permit_joining: beacon.permit_joining.into(),
                    stack_profile: beacon.stack_profile,
                    protocol_version: beacon.protocol_version,
                    router_capacity: beacon.router_capacity.into(),
                    end_device_capacity: beacon.end_device_capacity.into(),
                    device_depth: beacon.device_depth,
                    update_id: beacon.update_id,
                    lqi: beacon.lqi,
                    rssi: beacon.rssi as u8,
                },
            ))
            .await;
        }
    }

    match result {
        Ok(()) => ok(CommandId::NetworkScan, request_id),
        Err(e) => error(CommandId::NetworkScan, request_id, Status::ScanFailed, &e.to_string()),
    }
}

async fn handle_packet_capture<P: RadioPhy>(
    app: &mut App<P>,
    request_id: RequestId,
    payload: &[u8],
) -> Vec<u8> {
    let Some(request) = parse::<ChannelPayload>(payload) else {
        return error(CommandId::PacketCapture, request_id, Status::Parse, "channel");
    };

    if let Err(e) = app.phy.reconfigure(&capture_config(request.channel)).await {
        return error(CommandId::PacketCapture, request_id, Status::RadioError, &e.to_string());
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
                        // Drop on a full queue: a sniffer must not block.
                        push_outbound(event(
                            CommandId::PacketCapture,
                            request_id,
                            &CapturedPacketPayload {
                                channel: frame.channel,
                                rssi: frame.rssi as u8,
                                lqi: frame.lqi,
                                psdu: frame.psdu,
                            },
                        ));
                    }
                    _ => break,
                }
            }
        }));
    }

    ok(CommandId::PacketCapture, request_id)
}

async fn handle_packet_capture_channel<P: RadioPhy>(
    app: &App<P>,
    request_id: RequestId,
    payload: &[u8],
) -> Vec<u8> {
    let Some(request) = parse::<ChannelPayload>(payload) else {
        return error(CommandId::PacketCaptureChannel, request_id, Status::Parse, "channel");
    };

    match app.phy.reconfigure(&capture_config(request.channel)).await {
        Ok(()) => ok(CommandId::PacketCaptureChannel, request_id),
        Err(e) => error(
            CommandId::PacketCaptureChannel,
            request_id,
            Status::RadioError,
            &e.to_string(),
        ),
    }
}

// -- notifications ---------------------------------------------------------------------

/// Encode one unsolicited notification. `send_confirm`/`aps_ack_confirm` carry
/// their originating request id in the envelope.
pub fn notification_frame(update: &ZigbeeNotification) -> Vec<u8> {
    match update {
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
        } => notification(
            CommandId::ReceivedAps,
            0,
            &ReceivedApsPayload {
                source: *source,
                destination: *destination,
                has_group: group.is_some().into(),
                group: group.unwrap_or(0),
                profile_id: *profile_id,
                cluster_id: *cluster_id,
                src_ep: *src_ep,
                dst_ep: *dst_ep,
                lqi: *lqi,
                rssi: *rssi as u8,
                data: data.clone(),
            },
        ),
        ZigbeeNotification::SendConfirm { request_id, result } => {
            let (confirmed, next_hop, reason) = match result {
                SendResult::Confirmed { next_hop } => {
                    (true, next_hop.unwrap_or(Nwk(0xFFFF)), Vec::new())
                }
                SendResult::Failed { reason } => {
                    (false, Nwk(0xFFFF), reason.to_string().into_bytes())
                }
            };
            notification(
                CommandId::SendConfirm,
                *request_id as u16,
                &SendConfirmPayload {
                    confirmed: confirmed.into(),
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
            notification(
                CommandId::ApsAckConfirm,
                *request_id as u16,
                &ApsAckConfirmPayload {
                    acked: acked.into(),
                    reason,
                },
            )
        }
        ZigbeeNotification::DeviceJoined { nwk, ieee, parent } => notification(
            CommandId::DeviceJoined,
            0,
            &DeviceJoinedPayload {
                nwk: *nwk,
                ieee: *ieee,
                parent: *parent,
            },
        ),
        ZigbeeNotification::DeviceLeft { nwk, ieee, reason } => {
            let (reason_code, rejoin, router, router_ieee) = match reason {
                DeviceLeaveReason::Announced { rejoin } => {
                    (LeaveReason::Announced, *rejoin, None, None)
                }
                DeviceLeaveReason::RouterReported {
                    router,
                    router_ieee,
                } => (LeaveReason::RouterReported, false, Some(*router), *router_ieee),
                DeviceLeaveReason::KeepaliveTimeout => {
                    (LeaveReason::KeepaliveTimeout, false, None, None)
                }
            };
            notification(
                CommandId::DeviceLeft,
                0,
                &DeviceLeftPayload {
                    nwk: *nwk,
                    has_ieee: ieee.is_some().into(),
                    ieee: ieee.unwrap_or(Eui64([0; 8])),
                    reason: reason_code,
                    rejoin: rejoin.into(),
                    router: router.unwrap_or(Nwk(0xFFFF)),
                    has_router_ieee: router_ieee.is_some().into(),
                    router_ieee: router_ieee.unwrap_or(Eui64([0; 8])),
                },
            )
        }
        ZigbeeNotification::FrameCounterUpdate { frame_counter } => notification(
            CommandId::FrameCounter,
            0,
            &FrameCounterPayload {
                frame_counter: *frame_counter,
            },
        ),
        ZigbeeNotification::LinkKeyUpdate { ieee, key } => notification(
            CommandId::LinkKey,
            0,
            &LinkKeyPayload {
                ieee: *ieee,
                key: key.clone(),
            },
        ),
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
            notification(
                CommandId::ApsDecryptFailure,
                0,
                &ApsDecryptFailPayload {
                    source: *source,
                    source_ieee: *source_ieee,
                    frame_counter: *frame_counter,
                    key_id,
                },
            )
        }
    }
}
