#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod client;

use alloc::vec::Vec;
use core::time::Duration;
use crc_all::CrcAlgo;
use num_enum::TryFromPrimitive;
use thiserror::Error;

const CRC_KERMIT: CrcAlgo<u16> = CrcAlgo::<u16>::new(0x1021, 16, 0xFFFF, 0xFFFF, true);
const U21_MAX: u32 = 1 << 21;

/// No valid HDLC frame comes close to this size; a buffer this large without a flag
/// byte means we have desynced from the stream.
const MAX_HDLC_BUFFER_SIZE: usize = 4096;

/// Consecutive command timeouts before the RCP is presumed wedged and the
/// reset-recovery path is triggered.
const MAX_CONSECUTIVE_TIMEOUTS: u32 = 4;

/// OpenThread's `SPINEL_FRAME_MAX_SIZE`: no spinel frame exceeds this unescaped.
pub const SPINEL_FRAME_MAX_SIZE: usize = 1300;

#[derive(Debug, Eq, PartialEq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum SpinelCommandId {
    Noop = 0,
    Reset = 1,
    PropValueGet = 2,
    PropValueSet = 3,
    PropValueInsert = 4,
    PropValueRemove = 5,
    PropValueIs = 6,
    PropValueInserted = 7,
    PropValueRemoved = 8,
    Peek = 18,
    PeekRet = 19,
    Poke = 20,
    PropValueMultiGet = 21,
    PropValueMultiSet = 22,
    PropValuesAre = 23,
    NetSave = 9,
    NetClear = 10,
    NetRecall = 11,
    HboOffload = 12,
    HboReclaim = 13,
    HboDrop = 14,
    HboOffloaded = 15,
    HboReclaimed = 16,
    HboDropped = 17,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, TryFromPrimitive, Hash)]
#[repr(u32)]
pub enum SpinelPropertyId {
    // Core Properties
    LastStatus = 0,
    ProtocolVersion = 1,
    NcpVersion = 2,
    InterfaceType = 3,
    InterfaceVendorId = 4,
    Caps = 5,
    InterfaceCount = 6,
    PowerState = 7,
    Hwaddr = 8,
    Lock = 9,

    // Host Buffer Offload
    HboMemMax = 10,
    HboBlockMax = 11,

    // Stream Properties
    StreamDebug = 112,
    StreamRaw = 113,
    StreamNet = 114,

    // PHY Properties
    PhyEnabled = 32,
    PhyChan = 33,
    PhyChanSupported = 34,
    PhyFreq = 35,
    PhyCcaThreshold = 36,
    PhyTxPower = 37,
    PhyRssi = 38,
    PhyRxSensitivity = 39,

    // MAC Properties
    MacScanState = 48,
    MacScanMask = 49,
    MacScanPeriod = 50,
    MacScanBeacon = 51,
    Mac154Laddr = 52,
    Mac154Saddr = 53,
    Mac154Panid = 54,
    MacRawStreamEnabled = 55,
    MacPromiscuousMode = 56,
    MacEnergyScanResult = 57,
    MacDataPollPeriod = 58,
    MacRxOnWhenIdleMode = 59,
    Mac154AltSaddr = 60,
    MacWhitelist = 4864,
    MacWhitelistEnabled = 4865,
    MacSrcMatchEnabled = 4867,
    MacSrcMatchShortAddresses = 4868,
    MacSrcMatchExtendedAddresses = 4869,

    // NET Properties
    NetSaved = 64,
    NetIfUp = 65,
    NetStackUp = 66,
    NetRole = 67,
    NetNetworkName = 68,
    NetXpanid = 69,
    NetMasterKey = 70,
    NetKeySequenceCounter = 71,
    NetPartitionId = 72,
    NetRequireJoinExisting = 73,
    NetKeySwitchGuardtime = 74,
    NetPskc = 75,

    // IPv6 Properties
    Ipv6LlAddr = 96,
    Ipv6MlAddr = 97,
    Ipv6MlPrefix = 98,
    Ipv6AddressTable = 99,
    Ipv6IcmpPingOffload = 101,

    // Debug Properties
    DebugTestAssert = 16384,
    DebugNcpLogLevel = 16385,

    // Thread Properties
    ThreadLeaderAddr = 80,
    ThreadParent = 81,
    ThreadChildTable = 82,
    ThreadLeaderRid = 83,
    ThreadLeaderWeight = 84,
    ThreadLocalLeaderWeight = 85,
    ThreadNetworkData = 86,
    ThreadNetworkDataVersion = 87,
    ThreadStableNetworkData = 88,
    ThreadStableNetworkDataVersion = 89,
    ThreadOnMeshNets = 90,
    ThreadLocalRoutes = 91,
    ThreadAssistingPorts = 92,
    ThreadAllowLocalNetDataChange = 93,
    ThreadMode = 94,
    ThreadChildTimeout = 5376,
    ThreadRloc16 = 5377,
    ThreadRouterUpgradeThreshold = 5378,
    ThreadContextReuseDelay = 5379,
    ThreadNetworkIdTimeout = 5380,
    ThreadActiveRouterIds = 5381,
    ThreadRloc16DebugPassthru = 5382,
    ThreadRouterRoleEnabled = 5383,
    ThreadRouterDowngradeThreshold = 5384,
    ThreadRouterSelectionJitter = 5385,
    ThreadPreferredRouterId = 5386,
    ThreadNeighborTable = 5387,
    ThreadChildCountMax = 5388,
    ThreadLeaderNetworkData = 5389,
    ThreadStableLeaderNetworkData = 5390,
    ThreadJoiners = 5391,
    ThreadCommissionerEnabled = 5392,
    ThreadBaProxyEnabled = 5393,
    ThreadBaProxyStream = 5394,
    ThreadDisoveryScanJoinerFlag = 5395,
    ThreadDiscoveryScanEnableFiltering = 5396,
    ThreadDiscoveryScanPanid = 5397,
    ThreadSteeringData = 5398,

    // Jam detection
    JamDetectEnable = 4608,
    JamDetected = 4609,
    JamDetectRssiThreshold = 4610,
    JamDetectWindow = 4611,
    JamDetectBusy = 4612,
    JamDetectHistoryBitmap = 4613,

    // GPIO
    GpioConfig = 4096,
    GpioState = 4098,
    GpioStateSet = 4099,
    GpioStateClear = 4100,

    // True random number generation
    Trng32 = 4101,
    Trng128 = 4102,
    TrngRaw32 = 4103,

    NestStreamMfg = 0x3BC0,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum SpinelResetReason {
    Platform = 1,
    Stack = 2,
    Bootloader = 3,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum SpinelStatus {
    Ok = 0,
    Failure = 1,
    Unimplemented = 2,
    InvalidArgument = 3,
    InvalidState = 4,
    InvalidCommand = 5,
    InvalidInterface = 6,
    InternalError = 7,
    SecurityError = 8,
    ParseError = 9,
    InProgress = 10,
    Nomem = 11,
    Busy = 12,
    PropNotFound = 13,
    Dropped = 14,
    Empty = 15,
    CmdTooBig = 16,
    NoAck = 17,
    CcaFailure = 18,
    Already = 19,
    ItemNotFound = 20,
    InvalidCommandForProp = 21,
    UnknownNeighbor = 22,
    NotCapable = 23,
    ResponseTimeout = 24,
    ResetPowerOn = 112,
    ResetExternal = 113,
    ResetSoftware = 114,
    ResetFault = 115,
    ResetCrash = 116,
    ResetAssert = 117,
    ResetOther = 118,
    ResetUnknown = 119,
    ResetWatchdog = 120,
}

impl SpinelStatus {
    pub const fn is_reset(self) -> bool {
        self as u8 >= Self::ResetPowerOn as u8
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum SpinelMacScanState {
    Idle = 0,
    Beacon = 1,
    Energy = 2,
    Discover = 3,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum SpinelMacPromiscuousMode {
    //  Normal MAC filtering is in place.
    Off = 0,
    // All MAC packets matching network are passed up the stack.
    Network = 1,
    // All decoded MAC packets are passed up the stack.
    Full = 2,
}

#[derive(Error, Debug)]
pub enum SpinelFrameParsingError {
    #[error("payload is too short, expected at least {expected} bytes, got {got}")]
    PayloadTooShort { expected: usize, got: usize },
    #[error("not a spinel frame, expected flag 0b10, got {flag}")]
    NotSpinelFrame { flag: u8 },
    #[error("packed uint21 did not terminate")]
    PackedU21DidNotTerminate,
    #[error("invalid property id: {property_id}")]
    InvalidPropertyId { property_id: u32 },
    #[error("invalid command id: {command_id}")]
    InvalidCommandId { command_id: u8 },
}

pub fn packed_uint21_deserialize(bytes: &[u8]) -> Result<(u32, &[u8]), SpinelFrameParsingError> {
    let mut result = 0u32;

    for (index, byte) in bytes.iter().enumerate() {
        result |= ((byte & 0b01111111) as u32) << (7 * index);

        if byte & 0b10000000 == 0 {
            return Ok((result, &bytes[index + 1..]));
        }

        if index >= 2 {
            break;
        }
    }

    Err(SpinelFrameParsingError::PackedU21DidNotTerminate)
}

pub fn packed_uint21_to_bytes(value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    packed_uint21_into(value, &mut bytes);
    bytes
}

/// Append the packed form of `value` to `bytes`.
pub fn packed_uint21_into(value: u32, bytes: &mut Vec<u8>) {
    if value == 0 {
        bytes.push(0);
        return;
    }

    if value > U21_MAX {
        panic!("Cannot serialize value, too big");
    }

    let mut temp = value;

    while temp > 0 {
        // Set the least significant bit on all other octets
        bytes.push(((temp as u8) & 0b01111111) | 0b10000000);
        temp >>= 7;
    }

    // Clear the most significant bit of the most significant octet
    let last = bytes.len() - 1;
    bytes[last] &= 0b01111111;
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum HdlcSpecial {
    Flag = 0x7E,
    Escape = 0x7D,
    Xon = 0x11,
    Xoff = 0x13,
    Vendor = 0xF8,
}

#[derive(Error, Debug)]
pub enum HdlcLiteFrameParsingError {
    #[error("bad escape byte encountered: {byte}")]
    BadEscapeByte { byte: u8 },
    #[error("invalid crc, expected {expected_crc}, got {got_crc}")]
    InvalidCrc { expected_crc: u16, got_crc: u16 },
    #[error("frame is too short, expected at least {expected} bytes, got {got}")]
    FrameTooShort { expected: usize, got: usize },
    #[error("payload is too short, expected at least {expected} bytes, got {got}")]
    PayloadTooShort { expected: usize, got: usize },
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HdlcLiteFrame {
    pub data: Vec<u8>,
}

/// Unescape and CRC-check one HDLC-lite frame into `data`, cleared first.
///
/// The trailing CRC is left out. Writing into a caller-provided buffer lets the
/// reader reuse one scratch allocation for every frame.
pub fn hdlc_unescape_into(
    bytes: &[u8],
    data: &mut Vec<u8>,
) -> Result<(), HdlcLiteFrameParsingError> {
    if bytes.len() < 2 {
        return Err(HdlcLiteFrameParsingError::FrameTooShort {
            expected: 2,
            got: bytes.len(),
        });
    }

    data.clear();
    let mut unescaping = false;

    for byte in bytes.iter() {
        let mut result_byte = *byte;

        if unescaping {
            result_byte ^= 0x20;
            unescaping = false;

            if result_byte != (HdlcSpecial::Flag as u8)
                && result_byte != (HdlcSpecial::Escape as u8)
                && result_byte != (HdlcSpecial::Xon as u8)
                && result_byte != (HdlcSpecial::Xoff as u8)
                && result_byte != (HdlcSpecial::Vendor as u8)
            {
                return Err(HdlcLiteFrameParsingError::BadEscapeByte { byte: result_byte });
            }
        } else if result_byte == HdlcSpecial::Escape as u8 {
            unescaping = true;
            continue;
        } else if result_byte == HdlcSpecial::Flag as u8 {
            continue;
        }

        data.push(result_byte);
    }

    if data.len() < 2 {
        return Err(HdlcLiteFrameParsingError::PayloadTooShort {
            expected: 2,
            got: data.len(),
        });
    }

    let mut crc = 0x0000u16;
    CRC_KERMIT.init_crc(&mut crc);
    CRC_KERMIT.update_crc(&mut crc, &data[..data.len() - 2]);
    CRC_KERMIT.finish_crc(&crc);
    crc ^= 0xFFFF;

    let expected_crc = u16::from_le_bytes([data[data.len() - 2], data[data.len() - 1]]);

    if crc != expected_crc {
        return Err(HdlcLiteFrameParsingError::InvalidCrc {
            expected_crc,
            got_crc: crc,
        });
    }

    data.truncate(data.len() - 2);
    Ok(())
}

/// Append the CRC-suffixed, escaped form of `data` to `result`, without the framing
/// flag bytes.
pub fn hdlc_escape_into(data: &[u8], result: &mut Vec<u8>) {
    let mut crc = 0x0000u16;
    CRC_KERMIT.init_crc(&mut crc);
    CRC_KERMIT.update_crc(&mut crc, data);
    CRC_KERMIT.finish_crc(&crc);
    crc ^= 0xFFFF;

    for byte in data.iter().chain(&crc.to_le_bytes()) {
        let result_byte = *byte;

        if result_byte == (HdlcSpecial::Flag as u8)
            || result_byte == (HdlcSpecial::Escape as u8)
            || result_byte == (HdlcSpecial::Xon as u8)
            || result_byte == (HdlcSpecial::Xoff as u8)
            || result_byte == (HdlcSpecial::Vendor as u8)
        {
            result.push(HdlcSpecial::Escape as u8);
            result.push(result_byte ^ 0x20);
        } else {
            result.push(result_byte);
        }
    }
}

impl HdlcLiteFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HdlcLiteFrameParsingError> {
        let mut data = Vec::with_capacity(bytes.len());
        hdlc_unescape_into(bytes, &mut data)?;

        Ok(Self { data })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.data.len() + 8);
        hdlc_escape_into(&self.data, &mut result);
        result
    }

    pub fn to_bytes_with_flags(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.data.len() + 10);

        result.push(HdlcSpecial::Flag as u8);
        hdlc_escape_into(&self.data, &mut result);
        result.push(HdlcSpecial::Flag as u8);

        result
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct SpinelHeader {
    pub flag: u8,
    pub network_link_id: u8,
    pub transaction_id: u8,
}

impl SpinelHeader {
    pub const fn from_bytes(bytes: &[u8]) -> Result<Self, SpinelFrameParsingError> {
        if bytes.is_empty() {
            return Err(SpinelFrameParsingError::PayloadTooShort {
                expected: 1,
                got: bytes.len(),
            });
        }

        let byte = bytes[0];

        // 10_00_0001
        Ok(Self {
            flag: (byte & 0b11000000) >> 6,
            network_link_id: (byte & 0b00110000) >> 4,
            transaction_id: (byte & 0b00001111),
        })
    }

    pub const fn to_bytes(&self) -> [u8; 1] {
        [(self.flag << 6) | (self.network_link_id << 4) | self.transaction_id]
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct SpinelFrame {
    pub header: SpinelHeader,
    pub command_id: SpinelCommandId,
    pub payload: Vec<u8>,
}

/// Parse a Spinel frame into its header, command and a borrowed payload, so callers
/// that only route the frame can avoid copying the payload out of the read buffer.
pub fn parse_spinel_parts(
    bytes: &[u8],
) -> Result<(SpinelHeader, SpinelCommandId, &[u8]), SpinelFrameParsingError> {
    if bytes.len() < 3 {
        return Err(SpinelFrameParsingError::PayloadTooShort {
            expected: 3,
            got: bytes.len(),
        });
    }

    let header = SpinelHeader::from_bytes(&bytes[..1])?;

    if header.flag != 0b10 {
        return Err(SpinelFrameParsingError::NotSpinelFrame { flag: header.flag });
    }

    let command_id = bytes[1];
    let command_id = SpinelCommandId::try_from(command_id)
        .map_err(|_| SpinelFrameParsingError::InvalidCommandId { command_id })?;

    Ok((header, command_id, &bytes[2..]))
}

impl SpinelFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SpinelFrameParsingError> {
        let (header, command_id, payload) = parse_spinel_parts(bytes)?;

        Ok(Self {
            header,
            command_id,
            payload: payload.to_vec(),
        })
    }

    pub fn serialize_into(&self, result: &mut Vec<u8>) {
        result.extend(&self.header.to_bytes());
        result.push(self.command_id as u8);
        result.extend_from_slice(&self.payload);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(2 + self.payload.len());
        self.serialize_into(&mut result);

        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpinelFramePropValueIs {
    pub property_id: SpinelPropertyId,
    pub value: Vec<u8>,
}

impl SpinelFramePropValueIs {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SpinelFrameParsingError> {
        match packed_uint21_deserialize(bytes) {
            Ok((property_id, remaining)) => Ok(Self {
                property_id: SpinelPropertyId::try_from(property_id)
                    .map_err(|_| SpinelFrameParsingError::InvalidPropertyId { property_id })?,
                value: remaining.to_vec(),
            }),
            Err(err) => Err(err),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = packed_uint21_to_bytes(self.property_id as u32);
        result.extend(self.value.iter());

        result
    }
}

/// Something the RCP link produced that the caller must act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpinelEvent {
    /// The response to the request with this transaction id arrived. It waits in
    /// its [`Transaction`] for the command to take it.
    Response(u8),
    /// The response to an abandoned request arrived and was discarded. Its
    /// transaction id is free again.
    LateResponse(u8),
    /// An unsolicited update of this property. Its value is handed over beside the event.
    PropertyUpdate(SpinelPropertyId),
    /// The RCP reset, or is presumed wedged. Every pending request was cancelled.
    Reset(SpinelStatus),
}

/// Where a transaction stands.
///
/// A command holds its transaction id from [`SpinelProtocol::allocate_tid`] to
/// [`SpinelProtocol::release_request`]. An id that is not `Free` is never given to
/// another command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transaction {
    /// No command holds the id.
    Free,
    /// The request waits to be written to the RCP.
    Queued,
    /// The request is written and the RCP has not answered.
    AwaitingResponse,
    /// The RCP answered. The command has yet to take the response, which waits in the
    /// transaction's response buffer.
    Answered,
    /// An RCP reset cancelled the request.
    Cancelled,
    /// The command left after its request was sent and before the response came. The
    /// id stays out of use until that response arrives or `until` passes, so the
    /// response cannot reach a later command.
    Abandoned { until: Duration },
}

#[derive(Debug)]
pub struct SpinelProtocol {
    pub buffer: Vec<u8>,
    /// Reused for the unescaped form of every inbound frame: the transport needs
    /// exactly one frame's worth of scratch, since frames arrive serially.
    unescape_scratch: Vec<u8>,
    pub ignoring_until_next_flag: bool,
    pub next_tid: u8,
    /// Indexed by transaction id. We use ids 1 to 7; id 0 marks unsolicited frames
    /// and stays `Free`.
    transactions: [Transaction; 8],
    /// Each transaction's request frame and response payload, indexed like
    /// `transactions`. They keep their capacity, so a request allocates only when it is
    /// larger than any before it under the same id.
    requests: [Vec<u8>; 8],
    responses: [Vec<u8>; 8],
    consecutive_timeouts: u32,
}

impl Default for SpinelProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl SpinelProtocol {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            unescape_scratch: Vec::with_capacity(SPINEL_FRAME_MAX_SIZE),
            ignoring_until_next_flag: true,
            next_tid: 1,
            transactions: [const { Transaction::Free }; 8],
            requests: [const { Vec::new() }; 8],
            responses: [const { Vec::new() }; 8],
            consecutive_timeouts: 0,
        }
    }

    /// Extract the next complete HDLC frame from the accumulation buffer into
    /// `scratch`, returning `false` once no complete frame remains. Garbage between
    /// flags (bad CRC, runts, post-resync noise) is discarded silently.
    fn next_frame_into(&mut self, scratch: &mut Vec<u8>) -> bool {
        loop {
            let Some(index) = self
                .buffer
                .iter()
                .position(|&x| x == HdlcSpecial::Flag as u8)
            else {
                if self.buffer.len() > MAX_HDLC_BUFFER_SIZE {
                    tracing::warn!(
                        "Discarding {} buffered bytes without an HDLC flag, resyncing",
                        self.buffer.len()
                    );
                    self.buffer.clear();
                    self.ignoring_until_next_flag = true;
                }

                return false;
            };

            let ignoring = self.ignoring_until_next_flag;
            self.ignoring_until_next_flag = false;

            // `index > 0` ignores consecutive flags
            let parsed = !ignoring
                && index > 0
                && hdlc_unescape_into(&self.buffer[..index], scratch).is_ok();
            self.buffer.drain(0..=index);

            if parsed {
                return true;
            }
        }
    }

    pub fn parse_frames_from_bytes(&mut self, bytes: &[u8]) -> Vec<SpinelFrame> {
        self.buffer.extend(bytes);

        let mut scratch = core::mem::take(&mut self.unescape_scratch);
        let mut frames = Vec::new();

        while self.next_frame_into(&mut scratch) {
            if let Ok(frame) = SpinelFrame::from_bytes(&scratch) {
                frames.push(frame);
            }
        }

        self.unescape_scratch = scratch;
        frames
    }

    /// Buffer bytes read from the RCP. [`Self::next_event`] takes what they produce.
    pub fn receive(&mut self, bytes: &[u8]) {
        tracing::trace!("RX bytes: {bytes:?}");
        self.buffer.extend(bytes);
    }

    /// The next event the buffered bytes produce, or `None` once they hold no complete
    /// frame. The value of a property update is copied into `update`, cleared first.
    pub fn next_event(&mut self, update: &mut Vec<u8>) -> Option<SpinelEvent> {
        // The scratch is moved out of `self` so the routing below can borrow the
        // payload from it while still mutating protocol state
        let mut scratch = core::mem::take(&mut self.unescape_scratch);

        let event = loop {
            if !self.next_frame_into(&mut scratch) {
                break None;
            }

            match parse_spinel_parts(&scratch) {
                Ok((header, command_id, payload)) => {
                    if let Some(event) =
                        self.handle_inbound_frame(header, command_id, payload, update)
                    {
                        break Some(event);
                    }
                }
                Err(err) => {
                    tracing::warn!("Failed to parse Spinel frame: {err:?}");
                }
            }
        };

        self.unescape_scratch = scratch;
        event
    }

    /// Route one inbound frame. The payload is borrowed from the read scratch: a
    /// response is copied into its transaction's buffer, a property update's value
    /// into `update`.
    pub fn handle_inbound_frame(
        &mut self,
        header: SpinelHeader,
        command_id: SpinelCommandId,
        payload: &[u8],
        update: &mut Vec<u8>,
    ) -> Option<SpinelEvent> {
        tracing::trace!("RX: {header:?} {command_id:?} {payload:02X?}");
        let tid = header.transaction_id;

        if tid == 0 {
            if command_id != SpinelCommandId::PropValueIs {
                tracing::warn!("Unhandled unsolicited frame: {command_id:?} {payload:02X?}");
                return None;
            }

            let property = match packed_uint21_deserialize(payload) {
                Ok((property_id, value)) => SpinelPropertyId::try_from(property_id)
                    .ok()
                    .map(|property_id| (property_id, value)),
                Err(_) => None,
            };

            match property {
                Some((SpinelPropertyId::LastStatus, value)) => {
                    self.handle_unsolicited_last_status(value)
                }
                Some((property_id, value)) => {
                    update.clear();
                    update.extend_from_slice(value);
                    Some(SpinelEvent::PropertyUpdate(property_id))
                }
                None => {
                    tracing::warn!("Failed to parse PropValueIs frame: {payload:02X?}");
                    None
                }
            }
        } else if let Some(transaction @ (Transaction::Queued | Transaction::AwaitingResponse)) =
            self.transactions.get_mut(usize::from(tid))
        {
            // `Queued` too: the response can be read before the write is reported
            *transaction = Transaction::Answered;
            let response = &mut self.responses[usize::from(tid)];
            response.clear();
            response.extend_from_slice(payload);
            self.consecutive_timeouts = 0;
            Some(SpinelEvent::Response(tid))
        } else if let Some(transaction @ Transaction::Abandoned { .. }) =
            self.transactions.get_mut(usize::from(tid))
        {
            tracing::debug!("Discarding the response to an abandoned request: {command_id:?}");
            *transaction = Transaction::Free;
            Some(SpinelEvent::LateResponse(tid))
        } else {
            tracing::warn!("Unsolicited or unmatched frame: {command_id:?} {payload:02X?}");
            None
        }
    }

    /// The RCP announces a reset (brownout, watchdog, firmware assert, our own
    /// `CMD_RESET`) with an unsolicited `LastStatus = RESET_*` notification. The reset
    /// wipes the radio configuration, so every in-flight command is cancelled and the
    /// reset is reported for recovery.
    fn handle_unsolicited_last_status(&mut self, value: &[u8]) -> Option<SpinelEvent> {
        let status = match packed_uint21_deserialize(value) {
            Ok((status_int, _)) => {
                match u8::try_from(status_int)
                    .ok()
                    .and_then(|s| SpinelStatus::try_from(s).ok())
                {
                    Some(status) => status,
                    None => {
                        tracing::warn!("Unknown unsolicited status: {status_int}");
                        return None;
                    }
                }
            }
            Err(err) => {
                tracing::warn!("Failed to parse unsolicited status: {err:?}");
                return None;
            }
        };

        if status.is_reset() {
            tracing::error!("RCP announced a reset: {status:?}");
            self.cancel_requests();
            Some(SpinelEvent::Reset(status))
        } else {
            tracing::warn!("Unsolicited status notification: {status:?}");
            None
        }
    }

    /// Take a transaction id for a new request, or `None` while all seven are in use.
    /// `now` is the time since any fixed moment.
    pub fn allocate_tid(&mut self, now: Duration) -> Option<u8> {
        for transaction in &mut self.transactions {
            if matches!(transaction, Transaction::Abandoned { until } if *until <= now) {
                *transaction = Transaction::Free;
            }
        }

        // Ids cycle from 1 to 7, so a released id is the last to be given out again.
        // A late response to a request that timed out then finds its id free
        let tid = (0..7)
            .map(|offset| 1 + (self.next_tid - 1 + offset) % 7)
            .find(|&tid| self.transactions[usize::from(tid)] == Transaction::Free)?;

        self.next_tid = 1 + (tid % 7);
        self.transactions[usize::from(tid)] = Transaction::Queued;

        Some(tid)
    }

    /// The frame of a request under a transaction id from [`Self::allocate_tid`].
    pub const fn request_frame(
        tid: u8,
        command_id: SpinelCommandId,
        payload: Vec<u8>,
    ) -> SpinelFrame {
        SpinelFrame {
            header: SpinelHeader {
                flag: 0b10,
                network_link_id: 0,
                transaction_id: tid,
            },
            command_id,
            payload,
        }
    }

    pub fn transaction(&self, tid: u8) -> &Transaction {
        &self.transactions[usize::from(tid)]
    }

    /// Write the request of a transaction id from [`Self::allocate_tid`]: its header
    /// and command, then the payload `write` appends.
    pub fn write_request(
        &mut self,
        tid: u8,
        command_id: SpinelCommandId,
        write: impl FnOnce(&mut Vec<u8>),
    ) {
        let header = SpinelHeader {
            flag: 0b10,
            network_link_id: 0,
            transaction_id: tid,
        };

        let request = &mut self.requests[usize::from(tid)];
        request.clear();
        request.extend(header.to_bytes());
        request.push(command_id as u8);
        write(request);
    }

    /// The request frame of `tid`, as [`Self::write_request`] wrote it.
    pub fn request(&self, tid: u8) -> &[u8] {
        &self.requests[usize::from(tid)]
    }

    /// The response payload of `tid` once it is [`Transaction::Answered`]. It stays
    /// until the id carries another response, so it can still be read under the same
    /// borrow that released the id.
    pub fn response(&self, tid: u8) -> &[u8] {
        &self.responses[usize::from(tid)]
    }

    /// The request `tid` was written to the RCP.
    pub fn request_written(&mut self, tid: u8) {
        let transaction = &mut self.transactions[usize::from(tid)];

        if *transaction == Transaction::Queued {
            *transaction = Transaction::AwaitingResponse;
        }
    }

    /// The command that holds `tid` is done with it. Returns where the transaction
    /// stood: the response, if one arrived.
    pub fn release_request(&mut self, tid: u8) -> Transaction {
        core::mem::replace(&mut self.transactions[usize::from(tid)], Transaction::Free)
    }

    /// The command that holds `tid` left with its request sent and no response yet.
    /// The id is kept out of use until `until`, on the clock of
    /// [`Self::allocate_tid`]. Returns where the transaction stood.
    pub fn abandon_request(&mut self, tid: u8, until: Duration) -> Transaction {
        core::mem::replace(
            &mut self.transactions[usize::from(tid)],
            Transaction::Abandoned { until },
        )
    }

    /// When the first abandoned transaction id comes back into use by itself.
    pub fn next_abandoned_expiry(&self) -> Option<Duration> {
        self.transactions
            .iter()
            .filter_map(|transaction| match transaction {
                Transaction::Abandoned { until } => Some(*until),
                _ => None,
            })
            .min()
    }

    /// The RCP reset: cancel every request that has no response yet. No response to
    /// an abandoned request will come either.
    fn cancel_requests(&mut self) {
        for transaction in &mut self.transactions {
            match transaction {
                Transaction::Queued | Transaction::AwaitingResponse => {
                    *transaction = Transaction::Cancelled;
                }
                Transaction::Abandoned { .. } => *transaction = Transaction::Free,
                Transaction::Free | Transaction::Answered | Transaction::Cancelled => {}
            }
        }
    }

    /// A new link to the RCP starts: bytes of a frame the old link cut off are dropped.
    pub fn link_restarted(&mut self) {
        self.buffer.clear();
        self.ignoring_until_next_flag = true;
    }

    /// Presume the RCP reset without its announcement, as after a new link it did not
    /// announce one. Cancels the pending requests like an announced reset.
    pub fn presume_reset(&mut self) -> SpinelEvent {
        self.consecutive_timeouts = 0;
        self.cancel_requests();

        SpinelEvent::Reset(SpinelStatus::ResetUnknown)
    }

    /// A request got no response in time. Returns the reset to recover from once
    /// enough consecutive requests have timed out; that reset cancels the others.
    pub fn request_timed_out(&mut self) -> Option<SpinelEvent> {
        self.consecutive_timeouts += 1;

        if self.consecutive_timeouts < MAX_CONSECUTIVE_TIMEOUTS {
            return None;
        }

        tracing::error!(
            "RCP unresponsive after {} consecutive command timeouts",
            self.consecutive_timeouts
        );
        self.consecutive_timeouts = 0;
        self.cancel_requests();

        Some(SpinelEvent::Reset(SpinelStatus::ResponseTimeout))
    }
}

#[cfg(test)]
mod tests;
