use crc_all::CrcAlgo;
use log;
use num_enum::TryFromPrimitive;
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

const CRC_KERMIT: CrcAlgo<u16> = CrcAlgo::<u16>::new(0x1021, 16, 0xFFFF, 0xFFFF, true);
const U21_MAX: u32 = 1 << 21;

#[derive(Debug, PartialEq, Copy, Clone, TryFromPrimitive)]
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

#[derive(Debug, PartialEq, Copy, Clone, TryFromPrimitive, Hash, Eq)]
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
    // MacScanState = 38,  // collides with PhyRssi
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

#[derive(Debug, PartialEq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum SpinelResetReason {
    Platform = 1,
    Stack = 2,
    Bootloader = 3,
}

#[derive(Debug, PartialEq, Copy, Clone, TryFromPrimitive)]
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

#[derive(Debug, PartialEq, Copy, Clone, TryFromPrimitive)]
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

    return Err(SpinelFrameParsingError::PackedU21DidNotTerminate);
}

pub fn packed_uint21_to_bytes(value: u32) -> Vec<u8> {
    if value == 0 {
        return [0].to_vec();
    }

    if value > U21_MAX {
        panic!("Cannot serialize value, too big");
    }

    let mut chunks = Vec::new();
    let mut temp = value;

    while temp > 0 {
        // Set the least significant bit on all other octets
        chunks.push(((temp as u8) & 0b01111111) | 0b10000000);
        temp >>= 7;
    }

    // Clear the most significant bit of the most significant octet
    let len = chunks.len();
    chunks[len - 1] &= 0b01111111;

    chunks
}

#[derive(Debug, PartialEq, Copy, Clone, TryFromPrimitive)]
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

#[derive(Debug, PartialEq, Clone)]
pub struct HdlcLiteFrame {
    pub data: Vec<u8>,
}

impl HdlcLiteFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HdlcLiteFrameParsingError> {
        if bytes.len() < 2 {
            return Err(HdlcLiteFrameParsingError::FrameTooShort {
                expected: 2,
                got: bytes.len(),
            });
        }

        let mut data = Vec::new();
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
        CRC_KERMIT.finish_crc(&mut crc);
        crc ^= 0xFFFF;

        let expected_crc = u16::from_le_bytes([data[data.len() - 2], data[data.len() - 1]]);

        if crc != expected_crc {
            return Err(HdlcLiteFrameParsingError::InvalidCrc {
                expected_crc: expected_crc,
                got_crc: crc,
            });
        }

        Ok(Self {
            data: data[..data.len() - 2].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut crc = 0x0000u16;
        CRC_KERMIT.init_crc(&mut crc);
        CRC_KERMIT.update_crc(&mut crc, &self.data);
        CRC_KERMIT.finish_crc(&mut crc);
        crc ^= 0xFFFF;

        let mut result = Vec::new();

        for byte in self.data.iter().chain(&crc.to_le_bytes()) {
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

        result
    }

    pub fn to_bytes_with_flags(&self) -> Vec<u8> {
        let mut result = Vec::new();

        result.push(HdlcSpecial::Flag as u8);
        result.extend(self.to_bytes());
        result.push(HdlcSpecial::Flag as u8);

        result
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct SpinelHeader {
    pub flag: u8,
    pub network_link_id: u8,
    pub transaction_id: u8,
}

impl SpinelHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SpinelFrameParsingError> {
        if bytes.len() < 1 {
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
            transaction_id: (byte & 0b00001111) >> 0,
        })
    }

    pub fn to_bytes(&self) -> [u8; 1] {
        [(self.flag << 6) | (self.network_link_id << 4) | (self.transaction_id << 0)]
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct SpinelFrame {
    pub header: SpinelHeader,
    pub command_id: SpinelCommandId,
    pub payload: Vec<u8>,
}

impl SpinelFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SpinelFrameParsingError> {
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
        let payload = bytes[2..].to_vec();

        Ok(Self {
            header,
            command_id: SpinelCommandId::try_from(command_id)
                .map_err(|_| SpinelFrameParsingError::InvalidCommandId { command_id })?,
            payload,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        result.extend(&self.header.to_bytes());
        result.push(self.command_id as u8);
        result.extend(self.payload.iter());

        result
    }
}

#[derive(Debug, Clone)]
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

#[derive(Debug)]
pub struct SpinelProtocol {
    pub buffer: Vec<u8>,
    pub ignoring_until_next_flag: bool,
    pub next_tid: u8,
    pub pending_frames: HashMap<u8, oneshot::Sender<SpinelFrame>>,
    pub unsolicited_frame_receiver: Option<mpsc::Sender<SpinelFrame>>,
    pub property_update_receivers: HashMap<SpinelPropertyId, mpsc::Sender<SpinelFramePropValueIs>>,
}

impl SpinelProtocol {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            ignoring_until_next_flag: true,
            next_tid: 1,
            pending_frames: HashMap::new(),
            unsolicited_frame_receiver: None,
            property_update_receivers: HashMap::new(),
        }
    }

    pub fn set_unsolicited_frame_receiver(&mut self, tx: mpsc::Sender<SpinelFrame>) {
        self.unsolicited_frame_receiver = Some(tx);
    }

    pub fn set_property_update_receiver(
        &mut self,
        property_id: SpinelPropertyId,
        tx: mpsc::Sender<SpinelFramePropValueIs>,
    ) {
        self.property_update_receivers.insert(property_id, tx);
    }

    pub fn parse_frames_from_bytes_into(
        &mut self,
        bytes: &[u8],
        into: &mut Vec<SpinelFrame>,
    ) -> usize {
        self.buffer.extend(bytes);

        let mut num_parsed_frames = 0;

        loop {
            let index = self
                .buffer
                .iter()
                .position(|&x| x == HdlcSpecial::Flag as u8);

            if index.is_none() {
                break;
            }

            if self.ignoring_until_next_flag {
                self.ignoring_until_next_flag = false;
                continue;
            }

            // Ignore consecutive flags
            if index.unwrap() > 0 {
                match HdlcLiteFrame::from_bytes(&self.buffer[0..index.unwrap()]) {
                    Err(HdlcLiteFrameParsingError::BadEscapeByte { .. })
                    | Err(HdlcLiteFrameParsingError::InvalidCrc { .. })
                    | Err(HdlcLiteFrameParsingError::FrameTooShort { .. })
                    | Err(HdlcLiteFrameParsingError::PayloadTooShort { .. }) => {}
                    Ok(frame) => match SpinelFrame::from_bytes(&frame.data) {
                        Err(SpinelFrameParsingError::PayloadTooShort { .. })
                        | Err(SpinelFrameParsingError::PackedU21DidNotTerminate { .. })
                        | Err(SpinelFrameParsingError::NotSpinelFrame { .. }) => {}
                        Err(SpinelFrameParsingError::InvalidPropertyId { .. }) => { /* This cannot happen */
                        }
                        Err(SpinelFrameParsingError::InvalidCommandId { .. }) => { /* This cannot happen */
                        }
                        Ok(parsed_frame) => {
                            into.push(parsed_frame);
                            num_parsed_frames += 1;
                        }
                    },
                }
            }

            self.buffer.drain(0..index.unwrap() + 1);
        }

        return num_parsed_frames;
    }

    pub fn parse_frames_from_bytes(&mut self, bytes: &[u8]) -> Vec<SpinelFrame> {
        let mut frames = Vec::new();
        self.parse_frames_from_bytes_into(bytes, &mut frames);

        frames
    }

    pub fn handle_inbound_bytes(&mut self, bytes: &[u8]) {
        log::debug!("RX bytes: {bytes:?}");

        for frame in self.parse_frames_from_bytes(bytes) {
            self.handle_inbound_frame(frame);
        }
    }

    pub fn handle_inbound_frame(&mut self, frame: SpinelFrame) {
        log::debug!("RX: {frame:?}");
        let tid = frame.header.transaction_id;

        if tid == 0 {
            if frame.command_id == SpinelCommandId::PropValueIs {
                match SpinelFramePropValueIs::from_bytes(&frame.payload) {
                    Ok(prop_value_is) => {
                        match self
                            .property_update_receivers
                            .get(&prop_value_is.property_id)
                        {
                            Some(sender) => {
                                let _ = sender.try_send(prop_value_is);
                            }
                            None => {
                                eprintln!("No receiver for property update: {:?}", prop_value_is);
                            }
                        }
                    }
                    Err(_) => {
                        eprintln!("Failed to parse PropValueIs frame: {:?}", frame);
                    }
                }
            } else {
                eprintln!("Unhandled unsolicited frame: {:?}", frame);
            }
        } else if let Some(sender) = self.pending_frames.remove(&tid) {
            let _ = sender.send(frame);
        } else {
            eprintln!("Unsolicited or unmatched frame: {:?}", frame);
        }
    }

    pub fn prepare_request(
        &mut self,
        command_id: SpinelCommandId,
        payload: Vec<u8>,
    ) -> (SpinelFrame, oneshot::Receiver<SpinelFrame>) {
        // Cycle TIDs from 1..7
        let tid = self.next_tid;
        self.next_tid = 1 + (tid % 7);

        let header = SpinelHeader {
            flag: 0b10,
            network_link_id: 0,
            transaction_id: tid,
        };

        let frame = SpinelFrame {
            header,
            command_id,
            payload,
        };

        // Create a one-shot channel for the response
        let (tx, rx) = oneshot::channel();
        self.pending_frames.insert(tid, tx);

        (frame, rx)
    }

    pub fn cancel_request(&mut self, tid: u8) {
        self.pending_frames.remove(&tid);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use rand::Rng;
    use rand::RngCore;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_uint21_to_bytes() {
        assert_eq!(packed_uint21_to_bytes(0x1FD7FC), hex!("fcaf7f").to_vec());
    }

    #[test]
    fn test_uint21_deserialize() {
        let data = hex!("fcaf7fabcd");
        let (value, remaining) = packed_uint21_deserialize(&data).unwrap();

        assert_eq!(value, 0x1FD7FC);
        assert_eq!(remaining, hex!("abcd").to_vec());
    }

    #[test]
    fn test_uint21_stress() {
        for value in 0..U21_MAX {
            let mut serialized = packed_uint21_to_bytes(value);
            serialized.extend(hex!("abcd"));

            let (parsed_value, remaining) = packed_uint21_deserialize(&serialized).unwrap();

            assert_eq!(value, parsed_value);
            assert_eq!(remaining, hex!("abcd").to_vec());
        }
    }

    #[test]
    fn test_hdlc_lite_frame() {
        let frame = HdlcLiteFrame {
            // Special bytes interleaved with 00
            data: hex!("00 7E 00 7D 00 11 00 13 00 F8 00").to_vec(),
        };

        assert_eq!(
            frame.to_bytes(),
            hex!("00 7D5E 00 7D5D 00 7D31 00 7D33 00 7DD8 00 2881")
        );

        let parsed_frame = HdlcLiteFrame::from_bytes(&frame.to_bytes()).unwrap();
        assert_eq!(frame, parsed_frame);
    }

    #[test]
    fn test_hdlc_lite_frame_vectors() {
        assert_eq!(
            HdlcLiteFrame {
                data: hex!("810243").to_vec()
            }
            .to_bytes(),
            hex!("810243d3d3")
        );

        assert_eq!(
            HdlcLiteFrame {
                data: hex!("8103367e7d").to_vec()
            }
            .to_bytes(),
            hex!("8103367d5e7d5d6af9")
        );
    }

    #[test]
    fn test_hdlc_lite_frame_stress() {
        let mut rng = StdRng::seed_from_u64(0);

        for _ in 0..1000 {
            let len = rng.random_range(1..1000);
            let mut data = Vec::new();

            for _ in 0..len {
                data.push((rng.next_u32() & 0xFF) as u8);
            }

            let frame = HdlcLiteFrame { data: data.clone() };
            let parsed_frame = HdlcLiteFrame::from_bytes(&frame.to_bytes()).unwrap();

            assert_eq!(frame, parsed_frame);
        }
    }

    #[test]
    fn test_spinel_header_parsing() {
        let data = hex!("81");
        let header = SpinelHeader::from_bytes(&data).unwrap();

        assert_eq!(
            header,
            SpinelHeader {
                flag: 0b10,
                network_link_id: 0,
                transaction_id: 1
            }
        );

        assert_eq!(header.to_bytes(), data);
    }

    #[test]
    fn test_spinel_parsing_bulk() {
        let data = hex!("7E   81 02 02 5E 80   7E 7E   7E 81 02 02 5E 80  7E 81 02 02 5E 80 7E");
        let mut protocol = SpinelProtocol::new();

        let frames = protocol.parse_frames_from_bytes(&data);

        assert_eq!(
            frames,
            vec![
                SpinelFrame {
                    header: SpinelHeader {
                        flag: 0b10,
                        network_link_id: 0,
                        transaction_id: 1
                    },
                    command_id: SpinelCommandId::PropValueGet,
                    payload: vec![2]
                },
                SpinelFrame {
                    header: SpinelHeader {
                        flag: 0b10,
                        network_link_id: 0,
                        transaction_id: 1
                    },
                    command_id: SpinelCommandId::PropValueGet,
                    payload: vec![2]
                },
                SpinelFrame {
                    header: SpinelHeader {
                        flag: 0b10,
                        network_link_id: 0,
                        transaction_id: 1
                    },
                    command_id: SpinelCommandId::PropValueGet,
                    payload: vec![2]
                }
            ]
        );
    }

    #[test]
    fn test_spinel_parsing_byte_by_byte() {
        let data = hex!("7E   81 02 02 5E 80   7E 7E   7E 81 02 02 5E 80  7E 81 02 02 5E 80 7E");

        let mut protocol = SpinelProtocol::new();
        let mut frames = Vec::new();

        for byte in data {
            frames.extend(protocol.parse_frames_from_bytes(&[byte]));
        }

        assert_eq!(
            frames,
            vec![
                SpinelFrame {
                    header: SpinelHeader {
                        flag: 0b10,
                        network_link_id: 0,
                        transaction_id: 1
                    },
                    command_id: SpinelCommandId::PropValueGet,
                    payload: vec![2]
                },
                SpinelFrame {
                    header: SpinelHeader {
                        flag: 0b10,
                        network_link_id: 0,
                        transaction_id: 1
                    },
                    command_id: SpinelCommandId::PropValueGet,
                    payload: vec![2]
                },
                SpinelFrame {
                    header: SpinelHeader {
                        flag: 0b10,
                        network_link_id: 0,
                        transaction_id: 1
                    },
                    command_id: SpinelCommandId::PropValueGet,
                    payload: vec![2]
                }
            ]
        );
    }

    #[test]
    fn test_spinel_sending_request() {
        let mut protocol = SpinelProtocol::new();

        // Simulate sending a request. This transaction was taken from a universal-silabs-flasher
        // session with a real device.
        protocol.next_tid = 3;

        let (request, mut rx) = protocol.prepare_request(
            SpinelCommandId::PropValueGet,
            packed_uint21_to_bytes(SpinelPropertyId::NcpVersion as u32),
        );
        assert_eq!(
            request,
            SpinelFrame {
                header: SpinelHeader {
                    flag: 0b10,
                    network_link_id: 0,
                    transaction_id: 3,
                },
                command_id: SpinelCommandId::PropValueGet,
                payload: packed_uint21_to_bytes(SpinelPropertyId::NcpVersion as u32)
            }
        );

        // Receive a response
        protocol.handle_inbound_bytes(
            b"~\x83\x06\x02SL-OPENTHREAD/2.4.4.0_GitHub-7074a43e4; EFR32; Oct 21 2024 1",
        );
        protocol.handle_inbound_bytes(b"4:40:57\x00\x81\xf7~");

        let response = rx.try_recv().unwrap();
        assert_eq!(
            response,
            SpinelFrame {
                header: SpinelHeader {
                    flag: 0b10,
                    network_link_id: 0,
                    transaction_id: 3,
                },
                command_id: SpinelCommandId::PropValueIs,
                payload:
                    b"\x02SL-OPENTHREAD/2.4.4.0_GitHub-7074a43e4; EFR32; Oct 21 2024 14:40:57\x00"
                        .to_vec()
            }
        );
    }
}
