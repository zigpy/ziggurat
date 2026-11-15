//! A simulated OpenThread RCP, sans-io: the host's Spinel frames, frames from the air,
//! and the passing of time go in; Spinel frames for the host and frames for the air come
//! out. It answers like OpenThread's `ncp_base_radio.cpp` with a radio driver behind it.

use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::time::Duration;
use tracing::debug;
use ziggurat_ieee_802154::types::{Eui64, Nwk, PanId};
use ziggurat_ieee_802154::{
    FCS_LENGTH, Ieee802154AckFrame, Ieee802154Address, Ieee802154AddressingMode,
    Ieee802154CommandId, Ieee802154Frame, Ieee802154FrameControl, Ieee802154FrameHeader,
    Ieee802154FrameType, Ieee802154FrameVersion, Psdu, compute_fcs,
};
use ziggurat_sim_proto::Frame;
use ziggurat_spinel::client::{SpinelRxFrame, SpinelTxDone, SpinelTxFrame};
use ziggurat_spinel::{
    SPINEL_MD_FLAG_ACKED_FP, SPINEL_MIN_HOST_SUPPORTED_RCP_API_VERSION,
    SPINEL_PROTOCOL_VERSION_MAJOR, SPINEL_PROTOCOL_VERSION_MINOR, SPINEL_RCP_API_VERSION,
    SpinelCapability, SpinelCommandId, SpinelFrame, SpinelHeader, SpinelPropertyId, SpinelStatus,
    packed_uint21_deserialize, packed_uint21_into, parse_spinel_parts, radio_caps,
};

const BROADCAST_PAN_ID: u16 = 0xFFFF;
const BROADCAST_ADDRESS: u16 = 0xFFFF;

const CHANNELS: RangeInclusive<u8> = 11..=26;

const CAPS: [SpinelCapability; 4] = [
    SpinelCapability::ConfigRadio,
    SpinelCapability::MacRaw,
    SpinelCapability::RcpApiVersion,
    SpinelCapability::RcpMinHostApiVersion,
];

/// An OpenThread host at Thread 1.2 or later requires `TRANSMIT_SEC` and
/// `TRANSMIT_TIMING`. Claiming `TRANSMIT_SEC` commits the RCP to the MAC struct in
/// received frames, which `SpinelRxFrame` always writes.
const RADIO_CAPS: u32 = radio_caps::ACK_TIMEOUT
    | radio_caps::ENERGY_SCAN
    | radio_caps::TRANSMIT_RETRIES
    | radio_caps::CSMA_BACKOFF
    | radio_caps::SLEEP_TO_TX
    | radio_caps::TRANSMIT_SEC
    | radio_caps::TRANSMIT_TIMING;

/// `macMaxFrameRetries`, for a transmit whose metadata does not say
const DEFAULT_MAX_FRAME_RETRIES: u8 = 3;

// Every link is perfect until the medium models link quality
const RSSI: i8 = -50;
const NOISE_FLOOR: i8 = -100;
const LQI: u8 = 255;
const RX_SENSITIVITY: i8 = -100;

const SCAN_STATE_IDLE: u8 = 0;
const SCAN_STATE_ENERGY: u8 = 2;

pub enum Output {
    /// An unescaped Spinel frame for the host
    Host(Vec<u8>),
    /// A frame to put on the air
    Air(Frame),
}

/// Where a reply goes: the request's interface and transaction ids. Unsolicited frames
/// use transaction id 0.
#[derive(Debug, Clone, Copy)]
struct Reply {
    iid: u8,
    tid: u8,
}

#[derive(Debug)]
enum TransmitState {
    /// A timed transmit waiting for its start time
    Delayed { at: Duration },
    /// On air, listening on the transmit channel for the ACK
    AwaitingAck { until: Duration },
}

#[derive(Debug)]
struct Transmit {
    reply: Reply,
    psdu: Psdu,
    channel: u8,
    rx_channel_after: u8,
    /// The sequence number the ACK must carry, for a frame that requests one
    ack_sequence: Option<u8>,
    retries_left: u8,
    state: TransmitState,
}

#[derive(Debug)]
struct EnergyScan {
    iid: u8,
    channels: VecDeque<u8>,
    period: Duration,
    next_result: Duration,
}

/// What a host can configure. A reset returns all of it to these defaults.
#[derive(Debug)]
struct Radio {
    enabled: bool,
    channel: u8,
    /// `MAC_RAW_STREAM_ENABLED`: receiving, rather than asleep
    receiving: bool,
    pan_id: PanId,
    short_address: Nwk,
    extended_address: Eui64,
    promiscuous_mode: u8,
    rx_on_when_idle: bool,
    src_match_enabled: bool,
    src_match_short: Vec<Nwk>,
    src_match_extended: Vec<Eui64>,
    tx_power: i8,
    cca_threshold: i8,
    coex_enabled: bool,
    scan_mask: Vec<u8>,
    scan_period_ms: u16,
}

impl Default for Radio {
    fn default() -> Self {
        Self {
            enabled: false,
            channel: *CHANNELS.start(),
            receiving: false,
            pan_id: PanId(BROADCAST_PAN_ID),
            short_address: Nwk(0xFFFE),
            extended_address: Eui64([0; 8]),
            promiscuous_mode: 0,
            rx_on_when_idle: true,
            src_match_enabled: false,
            src_match_short: Vec::new(),
            src_match_extended: Vec::new(),
            tx_power: 0,
            cca_threshold: -75,
            coex_enabled: false,
            scan_mask: Vec::new(),
            scan_period_ms: 0,
        }
    }
}

pub struct Rcp {
    eui64: Eui64,
    ack_timeout: Duration,
    radio: Radio,
    /// The interface id of the host's latest frame, for unsolicited frames. An
    /// OpenThread host drops frames on interfaces it does not use.
    host_iid: u8,
    transmit: Option<Transmit>,
    energy_scan: Option<EnergyScan>,
    outputs: VecDeque<Output>,
}

const fn flag(value: &[u8]) -> bool {
    value[0] != 0
}

const fn u16_le(value: &[u8]) -> u16 {
    u16::from_le_bytes([value[0], value[1]])
}

fn eui64_be(value: &[u8]) -> Eui64 {
    Eui64::from_be_bytes(value.try_into().unwrap())
}

fn packed(values: impl IntoIterator<Item = u32>) -> Vec<u8> {
    let mut bytes = Vec::new();

    for value in values {
        packed_uint21_into(value, &mut bytes);
    }

    bytes
}

fn ack(sequence: u8, frame_pending: bool) -> Psdu {
    let frame: Ieee802154Frame = Ieee802154Frame::Ack(Ieee802154AckFrame {
        header: Ieee802154FrameHeader {
            frame_control: Ieee802154FrameControl {
                frame_type: Ieee802154FrameType::Ack,
                security_enabled: false,
                frame_pending,
                ack_request: false,
                pan_id_compression: false,
                reserved1: false,
                sequence_number_suppression: false,
                information_elements_present: false,
                dest_addr_mode: Ieee802154AddressingMode::None,
                frame_version: Ieee802154FrameVersion::Ieee2003,
                src_addr_mode: Ieee802154AddressingMode::None,
            },
            sequence_number: Some(sequence),
            dest_pan_id: None,
            dest_address: None,
            src_pan_id: None,
            src_address: None,
        },
        fcs: 0,
    });

    frame.to_bytes()
}

impl Rcp {
    pub fn new(eui64: Eui64, ack_timeout: Duration) -> Self {
        Self {
            eui64,
            ack_timeout,
            radio: Radio::default(),
            host_iid: 0,
            transmit: None,
            energy_scan: None,
            outputs: VecDeque::new(),
        }
    }

    pub fn poll_output(&mut self) -> Option<Output> {
        self.outputs.pop_front()
    }

    /// When [`Self::handle_timeout`] must next run.
    pub fn next_deadline(&self) -> Option<Duration> {
        let transmit = self.transmit.as_ref().map(|transmit| match transmit.state {
            TransmitState::Delayed { at } => at,
            TransmitState::AwaitingAck { until } => until,
        });
        let energy_scan = self.energy_scan.as_ref().map(|scan| scan.next_result);

        transmit.into_iter().chain(energy_scan).min()
    }

    fn send(
        &mut self,
        reply: Reply,
        command: SpinelCommandId,
        property: SpinelPropertyId,
        value: &[u8],
    ) {
        debug!("To host: {command:?} {property:?} {value:02x?}");

        let mut payload = packed([property as u32]);
        payload.extend_from_slice(value);

        let frame = SpinelFrame {
            header: SpinelHeader {
                flag: 0b10,
                network_link_id: reply.iid,
                transaction_id: reply.tid,
            },
            command_id: command,
            payload,
        };

        self.outputs.push_back(Output::Host(frame.to_bytes()));
    }

    const fn notification(&self) -> Reply {
        Reply {
            iid: self.host_iid,
            tid: 0,
        }
    }

    /// Handles one unescaped Spinel frame from the host. Anything the RCP does not
    /// implement panics, naming it, so it can be added.
    pub fn handle_host_frame(&mut self, frame: &[u8], now: Duration) {
        let (header, command, payload) = parse_spinel_parts(frame)
            .unwrap_or_else(|err| panic!("unparsable Spinel frame {frame:02x?}: {err}"));

        self.host_iid = header.network_link_id;
        let reply = Reply {
            iid: header.network_link_id,
            tid: header.transaction_id,
        };

        if command == SpinelCommandId::Reset {
            debug!("From host: Reset");
            self.radio = Radio::default();
            self.transmit = None;
            self.energy_scan = None;

            let status = packed([SpinelStatus::ResetSoftware as u32]);
            self.send(
                reply,
                SpinelCommandId::PropValueIs,
                SpinelPropertyId::LastStatus,
                &status,
            );
            return;
        }

        let (property, value) = packed_uint21_deserialize(payload).unwrap();
        let property = SpinelPropertyId::try_from(property).unwrap_or_else(|_| {
            panic!("unhandled Spinel {command:?} of property {property} (0x{property:x})")
        });

        debug!("From host: {command:?} {property:?} {value:02x?}");

        match command {
            SpinelCommandId::PropValueGet => {
                let value = self.get(property);
                self.send(reply, SpinelCommandId::PropValueIs, property, &value);
            }
            SpinelCommandId::PropValueSet if property == SpinelPropertyId::StreamRaw => {
                self.start_transmit(reply, value, now);
            }
            SpinelCommandId::PropValueSet => {
                self.set(property, value, reply, now);
                let value = self.get(property);
                self.send(reply, SpinelCommandId::PropValueIs, property, &value);
            }
            SpinelCommandId::PropValueInsert => {
                self.insert(property, value);
                self.send(reply, SpinelCommandId::PropValueInserted, property, value);
            }
            SpinelCommandId::PropValueRemove => {
                self.remove(property, value);
                self.send(reply, SpinelCommandId::PropValueRemoved, property, value);
            }
            command => panic!("unhandled Spinel {command:?} of {property:?}"),
        }
    }

    fn get(&self, property: SpinelPropertyId) -> Vec<u8> {
        let radio = &self.radio;

        match property {
            SpinelPropertyId::ProtocolVersion => {
                packed([SPINEL_PROTOCOL_VERSION_MAJOR, SPINEL_PROTOCOL_VERSION_MINOR])
            }
            SpinelPropertyId::NcpVersion => {
                format!("ZIGGURAT-SIM-RCP/{}\0", env!("CARGO_PKG_VERSION")).into_bytes()
            }
            SpinelPropertyId::Caps => packed(CAPS.map(|cap| cap as u32)),
            SpinelPropertyId::Hwaddr => self.eui64.to_be_bytes().to_vec(),
            SpinelPropertyId::RcpApiVersion => packed([SPINEL_RCP_API_VERSION]),
            SpinelPropertyId::RcpMinHostApiVersion => {
                packed([SPINEL_MIN_HOST_SUPPORTED_RCP_API_VERSION])
            }
            SpinelPropertyId::RadioCaps => packed([RADIO_CAPS]),
            SpinelPropertyId::PhyEnabled => vec![u8::from(radio.enabled)],
            SpinelPropertyId::PhyChan => vec![radio.channel],
            SpinelPropertyId::PhyChanSupported | SpinelPropertyId::PhyChanPreferred => {
                CHANNELS.collect()
            }
            SpinelPropertyId::PhyTxPower => vec![radio.tx_power as u8],
            SpinelPropertyId::PhyCcaThreshold => vec![radio.cca_threshold as u8],
            SpinelPropertyId::PhyRssi => vec![NOISE_FLOOR as u8],
            SpinelPropertyId::PhyRxSensitivity => vec![RX_SENSITIVITY as u8],
            SpinelPropertyId::MacScanState => {
                if self.energy_scan.is_some() {
                    vec![SCAN_STATE_ENERGY]
                } else {
                    vec![SCAN_STATE_IDLE]
                }
            }
            SpinelPropertyId::MacScanMask => radio.scan_mask.clone(),
            SpinelPropertyId::MacScanPeriod => radio.scan_period_ms.to_le_bytes().to_vec(),
            SpinelPropertyId::Mac154Laddr => radio.extended_address.to_be_bytes().to_vec(),
            SpinelPropertyId::Mac154Saddr => radio.short_address.to_bytes().to_vec(),
            SpinelPropertyId::Mac154Panid => radio.pan_id.to_bytes().to_vec(),
            SpinelPropertyId::MacRawStreamEnabled => vec![u8::from(radio.receiving)],
            SpinelPropertyId::MacPromiscuousMode => vec![radio.promiscuous_mode],
            SpinelPropertyId::MacRxOnWhenIdleMode => vec![u8::from(radio.rx_on_when_idle)],
            SpinelPropertyId::MacSrcMatchEnabled => vec![u8::from(radio.src_match_enabled)],
            SpinelPropertyId::MacSrcMatchShortAddresses => radio
                .src_match_short
                .iter()
                .flat_map(Nwk::to_bytes)
                .collect(),
            SpinelPropertyId::MacSrcMatchExtendedAddresses => radio
                .src_match_extended
                .iter()
                .flat_map(Eui64::to_be_bytes)
                .collect(),
            SpinelPropertyId::RadioCoexEnable => vec![u8::from(radio.coex_enabled)],
            property => panic!("unhandled Spinel get of {property:?}"),
        }
    }

    fn set(&mut self, property: SpinelPropertyId, value: &[u8], reply: Reply, now: Duration) {
        let radio = &mut self.radio;

        match property {
            SpinelPropertyId::PhyEnabled => radio.enabled = flag(value),
            SpinelPropertyId::PhyChan => radio.channel = value[0],
            SpinelPropertyId::PhyTxPower => radio.tx_power = value[0] as i8,
            SpinelPropertyId::PhyCcaThreshold => radio.cca_threshold = value[0] as i8,
            SpinelPropertyId::MacScanMask => radio.scan_mask = value.to_vec(),
            SpinelPropertyId::MacScanPeriod => radio.scan_period_ms = u16_le(value),
            SpinelPropertyId::MacScanState => match value[0] {
                SCAN_STATE_IDLE => self.energy_scan = None,
                SCAN_STATE_ENERGY => {
                    let period = Duration::from_millis(u64::from(radio.scan_period_ms));
                    self.energy_scan = Some(EnergyScan {
                        iid: reply.iid,
                        channels: radio.scan_mask.iter().copied().collect(),
                        period,
                        next_result: now + period,
                    });
                }
                state => panic!("unhandled scan state {state}"),
            },
            SpinelPropertyId::Mac154Laddr => radio.extended_address = eui64_be(value),
            SpinelPropertyId::Mac154Saddr => radio.short_address = Nwk(u16_le(value)),
            SpinelPropertyId::Mac154Panid => radio.pan_id = PanId(u16_le(value)),
            SpinelPropertyId::MacRawStreamEnabled => radio.receiving = flag(value),
            SpinelPropertyId::MacPromiscuousMode => radio.promiscuous_mode = value[0],
            SpinelPropertyId::MacRxOnWhenIdleMode => radio.rx_on_when_idle = flag(value),
            SpinelPropertyId::MacSrcMatchEnabled => radio.src_match_enabled = flag(value),
            SpinelPropertyId::MacSrcMatchShortAddresses => {
                radio.src_match_short = value
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|address| Nwk(u16::from_le_bytes(*address)))
                    .collect();
            }
            SpinelPropertyId::MacSrcMatchExtendedAddresses => {
                radio.src_match_extended = value
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|address| Eui64::from_be_bytes(*address))
                    .collect();
            }
            SpinelPropertyId::RadioCoexEnable => radio.coex_enabled = flag(value),
            property => panic!("unhandled Spinel set of {property:?}"),
        }
    }

    fn insert(&mut self, property: SpinelPropertyId, value: &[u8]) {
        let radio = &mut self.radio;

        match property {
            SpinelPropertyId::MacSrcMatchShortAddresses => {
                let address = Nwk(u16_le(value));

                if !radio.src_match_short.contains(&address) {
                    radio.src_match_short.push(address);
                }
            }
            SpinelPropertyId::MacSrcMatchExtendedAddresses => {
                let address = eui64_be(value);

                if !radio.src_match_extended.contains(&address) {
                    radio.src_match_extended.push(address);
                }
            }
            property => panic!("unhandled Spinel insert into {property:?}"),
        }
    }

    fn remove(&mut self, property: SpinelPropertyId, value: &[u8]) {
        let radio = &mut self.radio;

        match property {
            SpinelPropertyId::MacSrcMatchShortAddresses => {
                let address = Nwk(u16_le(value));
                radio.src_match_short.retain(|other| *other != address);
            }
            SpinelPropertyId::MacSrcMatchExtendedAddresses => {
                let address = eui64_be(value);
                radio.src_match_extended.retain(|other| *other != address);
            }
            property => panic!("unhandled Spinel removal from {property:?}"),
        }
    }

    fn start_transmit(&mut self, reply: Reply, value: &[u8], now: Duration) {
        assert!(
            self.transmit.is_none(),
            "the host started a transmit while another is in flight"
        );

        let request = SpinelTxFrame::from_bytes(value).unwrap();

        // The host leaves the FCS to the radio
        let mut psdu = request.psdu;
        let end = psdu.len() - FCS_LENGTH;
        let fcs = compute_fcs(&psdu[..end]);
        psdu[end..].copy_from_slice(&fcs.to_le_bytes());

        let ack_sequence = Ieee802154Frame::from_bytes(&psdu)
            .ok()
            .filter(|frame| frame.header().frame_control.ack_request)
            .and_then(|frame| frame.header().sequence_number);

        let channel = request.channel.unwrap_or(self.radio.channel);
        let mut transmit = Transmit {
            reply,
            psdu,
            channel,
            rx_channel_after: request.rx_channel_after_tx.unwrap_or(channel),
            ack_sequence,
            retries_left: request
                .max_frame_retries
                .unwrap_or(DEFAULT_MAX_FRAME_RETRIES),
            state: TransmitState::Delayed { at: now },
        };

        // A timed transmit starts at a time in the RCP's 32-bit microsecond clock, the
        // one received frames are stamped with
        match request.tx_delay.filter(|delay| *delay != 0) {
            None => self.put_on_air(transmit, now),
            Some(delay) => {
                let start = request.tx_delay_base_time.unwrap_or(0).wrapping_add(delay);
                let ahead = start.wrapping_sub(now.as_micros() as u32) as i32;

                if ahead < 0 {
                    self.finish_transmit(transmit, SpinelStatus::StackNativeAbort, None, now);
                } else {
                    transmit.state = TransmitState::Delayed {
                        at: now + Duration::from_micros(ahead as u64),
                    };
                    self.transmit = Some(transmit);
                }
            }
        }
    }

    fn put_on_air(&mut self, mut transmit: Transmit, now: Duration) {
        self.outputs.push_back(Output::Air(Frame {
            channel: transmit.channel,
            psdu: transmit.psdu.clone(),
        }));

        if transmit.ack_sequence.is_some() {
            transmit.state = TransmitState::AwaitingAck {
                until: now + self.ack_timeout,
            };
            self.transmit = Some(transmit);
        } else {
            self.finish_transmit(transmit, SpinelStatus::Ok, None, now);
        }
    }

    fn finish_transmit(
        &mut self,
        transmit: Transmit,
        status: SpinelStatus,
        ack: Option<Psdu>,
        now: Duration,
    ) {
        self.radio.channel = transmit.rx_channel_after;

        let frame_pending = ack
            .as_ref()
            .and_then(|ack| Ieee802154Frame::from_bytes(ack).ok())
            .is_some_and(|ack| ack.header().frame_control.frame_pending);

        let done = SpinelTxDone {
            status,
            frame_pending,
            ack: ack.map(|psdu| SpinelRxFrame {
                psdu,
                rssi: RSSI,
                noise_floor: NOISE_FLOOR,
                flags: 0,
                channel: transmit.channel,
                lqi: LQI,
                timestamp_us: now.as_micros() as u64,
                receive_error: 0,
            }),
        };

        let mut value = Vec::new();
        done.serialize_into(&mut value);
        self.send(
            transmit.reply,
            SpinelCommandId::PropValueIs,
            SpinelPropertyId::LastStatus,
            &value,
        );
    }

    pub fn handle_timeout(&mut self, now: Duration) {
        if let Some(mut transmit) = self.transmit.take() {
            match transmit.state {
                TransmitState::Delayed { at } if at <= now => self.put_on_air(transmit, now),
                TransmitState::AwaitingAck { until } if until <= now => {
                    if transmit.retries_left > 0 {
                        transmit.retries_left -= 1;
                        self.put_on_air(transmit, now);
                    } else {
                        self.finish_transmit(transmit, SpinelStatus::NoAck, None, now);
                    }
                }
                _ => self.transmit = Some(transmit),
            }
        }

        if let Some(mut scan) = self.energy_scan.take() {
            if scan.next_result > now {
                self.energy_scan = Some(scan);
                return;
            }

            if let Some(channel) = scan.channels.pop_front() {
                self.send(
                    Reply {
                        iid: scan.iid,
                        tid: 0,
                    },
                    SpinelCommandId::PropValueIs,
                    SpinelPropertyId::MacEnergyScanResult,
                    &[channel, NOISE_FLOOR as u8],
                );
            }

            if scan.channels.is_empty() {
                self.send(
                    Reply {
                        iid: scan.iid,
                        tid: 0,
                    },
                    SpinelCommandId::PropValueIs,
                    SpinelPropertyId::MacScanState,
                    &[SCAN_STATE_IDLE],
                );
            } else {
                scan.next_result += scan.period;
                self.energy_scan = Some(scan);
            }
        }
    }

    /// The channel the radio listens on: the transmit channel while waiting for an ACK.
    const fn listening_channel(&self) -> u8 {
        match &self.transmit {
            Some(Transmit {
                channel,
                state: TransmitState::AwaitingAck { .. },
                ..
            }) => *channel,
            _ => self.radio.channel,
        }
    }

    /// The 802.15.4 receive filter, for a radio that is not promiscuous.
    fn accepts(&self, header: &Ieee802154FrameHeader) -> bool {
        let pan_id = self.radio.pan_id;

        match (header.dest_pan_id, header.dest_address) {
            (Some(dest_pan_id), Some(dest_address)) => {
                let pan_matches = dest_pan_id.0 == BROADCAST_PAN_ID || dest_pan_id == pan_id;
                let address_matches = match dest_address {
                    Ieee802154Address::Nwk(nwk) => {
                        nwk.0 == BROADCAST_ADDRESS || nwk == self.radio.short_address
                    }
                    Ieee802154Address::Eui64(eui64) => eui64 == self.radio.extended_address,
                };

                pan_matches && address_matches
            }
            // Without a destination, a frame is for the coordinator of its source PAN.
            // A beacon also reaches a radio on no PAN, which is how scans hear networks.
            _ => {
                header.src_pan_id == Some(pan_id)
                    || (header.frame_control.frame_type == Ieee802154FrameType::Beacon
                        && pan_id.0 == BROADCAST_PAN_ID)
            }
        }
    }

    fn is_addressed_to_us(&self, header: &Ieee802154FrameHeader) -> bool {
        match header.dest_address {
            Some(Ieee802154Address::Nwk(nwk)) => {
                nwk.0 != BROADCAST_ADDRESS && nwk == self.radio.short_address
            }
            Some(Ieee802154Address::Eui64(eui64)) => eui64 == self.radio.extended_address,
            None => false,
        }
    }

    /// The frame-pending bit of the ACK to a frame. Only a data request can be told
    /// data is pending. With source match off every poller is; with it on, only
    /// pollers in the tables are.
    fn frame_pending(&self, frame: &Ieee802154Frame<&[u8]>) -> bool {
        let Ieee802154Frame::Command(command) = frame else {
            return false;
        };

        if command.command_payload.command_id() != Some(Ieee802154CommandId::DataRequest) {
            return false;
        }

        if !self.radio.src_match_enabled {
            return true;
        }

        match command.header.src_address {
            Some(Ieee802154Address::Nwk(nwk)) => self.radio.src_match_short.contains(&nwk),
            Some(Ieee802154Address::Eui64(eui64)) => self.radio.src_match_extended.contains(&eui64),
            None => false,
        }
    }

    pub fn handle_air_frame(&mut self, frame: Frame, now: Duration) {
        if !self.radio.enabled || frame.channel != self.listening_channel() {
            return;
        }

        // A bad FCS or an unparsable header is dropped by the radio
        let Ok(parsed) = Ieee802154Frame::from_bytes(&frame.psdu) else {
            return;
        };
        let header = parsed.header();
        let promiscuous = self.radio.promiscuous_mode != 0;

        if header.frame_control.frame_type == Ieee802154FrameType::Ack {
            let awaited = matches!(
                &self.transmit,
                Some(Transmit { ack_sequence, state: TransmitState::AwaitingAck { .. }, .. })
                    if *ack_sequence == header.sequence_number
            );

            if awaited {
                let transmit = self.transmit.take().unwrap();
                self.finish_transmit(transmit, SpinelStatus::Ok, Some(frame.psdu.clone()), now);
            }

            if !promiscuous {
                return;
            }
        }

        if !self.radio.receiving || (!promiscuous && !self.accepts(header)) {
            return;
        }

        let mut flags = 0;

        if header.frame_control.ack_request
            && self.is_addressed_to_us(header)
            && let Some(sequence) = header.sequence_number
        {
            let frame_pending = self.frame_pending(&parsed);

            self.outputs.push_back(Output::Air(Frame {
                channel: frame.channel,
                psdu: ack(sequence, frame_pending),
            }));

            if frame_pending {
                flags |= SPINEL_MD_FLAG_ACKED_FP;
            }
        }

        let mut value = Vec::new();
        SpinelRxFrame {
            psdu: frame.psdu.clone(),
            rssi: RSSI,
            noise_floor: NOISE_FLOOR,
            flags,
            channel: frame.channel,
            lqi: LQI,
            timestamp_us: now.as_micros() as u64,
            receive_error: 0,
        }
        .serialize_into(&mut value);

        self.send(
            self.notification(),
            SpinelCommandId::PropValueIs,
            SpinelPropertyId::StreamRaw,
            &value,
        );
    }
}
