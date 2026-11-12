use crate::{
    HdlcSpecial, SPINEL_FRAME_MAX_SIZE, SpinelCommandId, SpinelEvent, SpinelFrame,
    SpinelFrameParsingError, SpinelHeader, SpinelPropertyId, SpinelProtocol, SpinelResetReason,
    SpinelStatus, hdlc_escape_into, packed_uint21_deserialize, packed_uint21_to_bytes,
};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::pin::pin;
use core::time::Duration;
use embedded_io_async::{Error as _, Read, Write};
use futures::future::{Either, select};
use thiserror::Error;
use ziggurat_ieee_802154::FrameBytes;
use ziggurat_ieee_802154::types::Eui64;
use ziggurat_runtime::runtime::{DefaultRuntime, Runtime};
use ziggurat_runtime::sync::{AsyncMutex, AsyncMutexGuard, Mutex, Notify};

/// A local RCP link — serial, or Ethernet to a network-attached RCP — answers in
/// milliseconds; anything beyond this is a failure. Wi-Fi is not supported: its
/// latency variance can spuriously trip the consecutive-timeout limit and force a
/// reset-recovery against a perfectly healthy radio.
const TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SpinelTxFrame {
    pub psdu: Vec<u8>,
    pub channel: Option<u8>,
    pub max_csma_backoffs: Option<u8>,
    pub max_frame_retries: Option<u8>,
    pub enable_csma_ca: Option<bool>,
    pub is_header_updated: Option<bool>,
    pub is_a_retransmit: Option<bool>,
    pub is_security_processed: Option<bool>,
    pub tx_delay: Option<u32>,
    pub tx_delay_base_time: Option<u32>,
    pub rx_channel_after_tx: Option<u8>,
    pub tx_power: Option<i8>,
}

impl SpinelTxFrame {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&(self.psdu.len() as u16).to_le_bytes());
        result.extend_from_slice(&self.psdu);

        // TODO: These are not really optional per-field, they must be contiguous: if a
        // field is not provided, all subsequent fields must be omitted as well
        if let Some(channel) = self.channel {
            result.push(channel);
        }

        if let Some(max_csma_backoffs) = self.max_csma_backoffs {
            result.push(max_csma_backoffs);
        }

        if let Some(max_frame_retries) = self.max_frame_retries {
            result.push(max_frame_retries);
        }

        if let Some(enable_csma_ca) = self.enable_csma_ca {
            result.push(enable_csma_ca as u8);
        }

        if let Some(is_header_updated) = self.is_header_updated {
            result.push(is_header_updated as u8);
        }

        if let Some(is_a_retransmit) = self.is_a_retransmit {
            result.push(is_a_retransmit as u8);
        }

        if let Some(is_security_processed) = self.is_security_processed {
            result.push(is_security_processed as u8);
        }

        if let Some(tx_delay) = self.tx_delay {
            result.extend_from_slice(&tx_delay.to_le_bytes());
        }

        if let Some(tx_delay_base_time) = self.tx_delay_base_time {
            result.extend_from_slice(&tx_delay_base_time.to_le_bytes());
        }

        if let Some(rx_channel_after_tx) = self.rx_channel_after_tx {
            result.push(rx_channel_after_tx);
        }

        if let Some(tx_power) = self.tx_power {
            result.push(tx_power as u8);
        }

        result
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SpinelRxFrame {
    pub psdu: FrameBytes,
    pub rssi: i8,
    pub noise_floor: i8,
    pub flags: u32,
    pub channel: u8,
    pub lqi: u8,
    pub timestamp_us: u64,
    pub receive_error: u8,
    pub manufacturer_specific: Vec<u8>,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SpinelRxFrameError {
    #[error("frame too short, expected at least {expected} bytes, got {got}")]
    TooShort { expected: usize, got: usize },
    #[error("PSDU too long to fit its frame bound, got {got} bytes")]
    PsduTooLong { got: usize },
}

impl SpinelRxFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SpinelRxFrameError> {
        let mut offset = 0;

        // The 2-byte PSDU length prefix must be present before it can be read
        if bytes.len() < 2 {
            return Err(SpinelRxFrameError::TooShort {
                expected: 2,
                got: bytes.len(),
            });
        }
        let psdu_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        // The PSDU is followed by a fixed metadata trailer: rssi, noise floor, flags,
        // channel, lqi, timestamp, and receive error
        let expected = offset + psdu_len + (1 + 1 + 4 + 1 + 1 + 8 + 1);
        if expected > bytes.len() {
            return Err(SpinelRxFrameError::TooShort {
                expected,
                got: bytes.len(),
            });
        }

        let psdu = FrameBytes::from_slice(&bytes[offset..offset + psdu_len])
            .map_err(|_| SpinelRxFrameError::PsduTooLong { got: psdu_len })?;
        offset += psdu_len;

        let rssi = bytes[offset] as i8;
        offset += 1;

        let noise_floor = bytes[offset] as i8;
        offset += 1;

        let flags = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;

        let channel = bytes[offset];
        offset += 1;

        let lqi = bytes[offset];
        offset += 1;

        let timestamp_us = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;

        let receive_error = bytes[offset];
        offset += 1;

        let manufacturer_specific = bytes[offset..].to_vec();

        Ok(Self {
            psdu,
            rssi,
            noise_floor,
            flags,
            channel,
            lqi,
            timestamp_us,
            receive_error,
            manufacturer_specific,
        })
    }
}

#[derive(Error, Debug)]
pub enum SpinelError {
    #[error("io error: {0:?}")]
    Io(embedded_io_async::ErrorKind),
    #[error("command cancelled by an RCP reset")]
    CancelledByReset,
    #[error("the spinel transport closed")]
    TransportClosed,
    #[error("timeout")]
    Timeout,
    #[error("spinel U21 parsing error")]
    U21ParsingError(#[from] SpinelFrameParsingError),
    #[error("invalid property id {property_id} in response")]
    InvalidResponsePropertyId { property_id: u32 },
    #[error("NCP version is not valid UTF-8")]
    NcpVersionNotUtf8,
    #[error("invalid hardware address: {got:02X?}")]
    InvalidHardwareAddress { got: Vec<u8> },
    #[error("unexpected response property: expected {expected:?}, got {got:?}")]
    UnexpectedResponseProperty {
        expected: SpinelPropertyId,
        got: SpinelPropertyId,
    },
    #[error("response payload was empty")]
    EmptyResponse,
    #[error("invalid spinel status {status}")]
    InvalidStatus { status: u8 },
}

/// How a request ended, left in its transaction's slot for the waiting command.
enum Outcome {
    Response(SpinelFrame),
    CancelledByReset,
}

struct State {
    protocol: SpinelProtocol,
    /// Indexed by transaction id.
    outcomes: [Option<Outcome>; 8],
    /// Frames waiting for the write loop.
    outbound: VecDeque<SpinelFrame>,
}

impl State {
    /// Cancel every request still waiting for its response.
    fn cancel_waiting(&mut self) {
        for outcome in &mut self.outcomes {
            if outcome.is_none() {
                *outcome = Some(Outcome::CancelledByReset);
            }
        }
    }
}

/// Receives the unsolicited events: property updates and resets.
pub type EventHandler = Box<dyn Fn(SpinelEvent) + Send + Sync>;

/// The RCP link. Commands queue frames and wait for their responses; [`Self::run`] does
/// all the transport IO.
pub struct SpinelClient<R: Runtime = DefaultRuntime> {
    state: Mutex<State>,
    /// Indexed by transaction id; woken when that transaction's outcome is set.
    outcome_ready: [Notify; 8],
    outbound_ready: Notify,
    on_event: EventHandler,
    /// Functional ownership of the radio (scan, reset recovery, channel retune), taken via
    /// [`Self::lock_radio`].
    exclusive_lock: AsyncMutex<()>,
    runtime: PhantomData<R>,
}

impl<R: Runtime> SpinelClient<R> {
    pub fn new(on_event: EventHandler) -> Self {
        Self {
            state: Mutex::new(State {
                protocol: SpinelProtocol::new(),
                outcomes: [const { None }; 8],
                outbound: VecDeque::new(),
            }),
            outcome_ready: core::array::from_fn(|_| Notify::new()),
            outbound_ready: Notify::new(),
            on_event,
            exclusive_lock: AsyncMutex::new(()),
            runtime: PhantomData,
        }
    }

    /// Drive the link: parse inbound bytes and write queued frames. Returns only when
    /// the transport fails.
    pub async fn run<Rd: Read, Wr: Write>(&self, reader: Rd, writer: Wr) -> SpinelError {
        let read = pin!(self.read_loop(reader));
        let write = pin!(self.write_loop(writer));

        match select(read, write).await {
            Either::Left((error, _)) | Either::Right((error, _)) => error,
        }
    }

    // The state lock is held across parsing and delivery on purpose (see below), and
    // `drain` keeps the event buffers' capacity across reads
    #[allow(clippy::significant_drop_tightening, clippy::iter_with_drain)]
    async fn read_loop<Rd: Read>(&self, mut reader: Rd) -> SpinelError {
        let mut buffer = [0u8; 2048];
        let mut events = Vec::new();
        let mut unsolicited = Vec::new();

        loop {
            let n = match reader.read(&mut buffer).await {
                Ok(0) => return SpinelError::TransportClosed,
                Ok(n) => n,
                Err(e) => return SpinelError::Io(e.kind()),
            };

            {
                // Outcomes are set under the same lock that parsed them, so a transaction
                // id cannot be reused before its response is delivered
                let mut state = self.state.lock();
                state
                    .protocol
                    .handle_inbound_bytes(&buffer[..n], &mut events);

                for event in events.drain(..) {
                    match event {
                        SpinelEvent::Response(frame) => {
                            let tid = usize::from(frame.header.transaction_id);
                            state.outcomes[tid] = Some(Outcome::Response(frame));
                            self.outcome_ready[tid].notify_one();
                        }
                        SpinelEvent::Reset(_) => {
                            state.cancel_waiting();
                            unsolicited.push(event);
                        }
                        SpinelEvent::PropertyUpdate(_) => unsolicited.push(event),
                    }
                }
            }

            for event in unsolicited.drain(..) {
                if matches!(event, SpinelEvent::Reset(_)) {
                    self.wake_all_waiters();
                }
                (self.on_event)(event);
            }
        }
    }

    async fn write_loop<Wr: Write>(&self, mut writer: Wr) -> SpinelError {
        // Frames go out one at a time, so two persistent buffers cover every TX
        let mut frame_scratch = Vec::with_capacity(SPINEL_FRAME_MAX_SIZE);
        // Worst-case HDLC escaping doubles the frame, plus two flags
        let mut hdlc_scratch = Vec::with_capacity(2 * SPINEL_FRAME_MAX_SIZE + 2);

        loop {
            let frame = self.state.lock().outbound.pop_front();
            let Some(frame) = frame else {
                self.outbound_ready.notified().await;
                continue;
            };

            frame_scratch.clear();
            frame.serialize_into(&mut frame_scratch);

            hdlc_scratch.clear();
            hdlc_scratch.push(HdlcSpecial::Flag as u8);
            hdlc_escape_into(&frame_scratch, &mut hdlc_scratch);
            hdlc_scratch.push(HdlcSpecial::Flag as u8);

            tracing::trace!("Writing {hdlc_scratch:02X?}");

            if let Err(e) = writer.write_all(&hdlc_scratch).await {
                return SpinelError::Io(e.kind());
            }
        }
    }

    fn wake_all_waiters(&self) {
        for ready in &self.outcome_ready {
            ready.notify_one();
        }
    }

    fn queue_frame(&self, frame: SpinelFrame) {
        self.state.lock().outbound.push_back(frame);
        self.outbound_ready.notify_one();
    }

    /// `CMD_RESET` is acknowledged with an unsolicited `LastStatus = RESET_*`
    /// notification rather than a tid-matched response, so this only sends.
    pub fn send_reset(&self, reason: SpinelResetReason) {
        self.queue_frame(SpinelFrame {
            header: SpinelHeader {
                flag: 0b10,
                network_link_id: 0,
                transaction_id: 0,
            },
            command_id: SpinelCommandId::Reset,
            payload: vec![reason as u8],
        });
    }

    pub async fn send_command(
        &self,
        command_id: SpinelCommandId,
        payload: Vec<u8>,
    ) -> Result<SpinelFrame, SpinelError> {
        let tid = {
            let mut state = self.state.lock();
            let frame = state.protocol.prepare_request(command_id, payload);
            tracing::trace!("Sending frame {frame:?}");

            let tid = frame.header.transaction_id;
            state.outcomes[usize::from(tid)] = None;
            state.outbound.push_back(frame);
            tid
        };
        self.outbound_ready.notify_one();

        let outcome = R::timeout(TIMEOUT, async {
            loop {
                let outcome = self.state.lock().outcomes[usize::from(tid)].take();
                if let Some(outcome) = outcome {
                    return outcome;
                }
                self.outcome_ready[usize::from(tid)].notified().await;
            }
        })
        .await;

        match outcome {
            Ok(Outcome::Response(frame)) => Ok(frame),
            Ok(Outcome::CancelledByReset) => Err(SpinelError::CancelledByReset),
            Err(_) => {
                let reset = {
                    let mut state = self.state.lock();
                    // A frame the write loop has not reached yet must not go out late
                    state
                        .outbound
                        .retain(|frame| frame.header.transaction_id != tid);

                    let reset = state.protocol.request_timed_out(tid);
                    if reset.is_some() {
                        state.cancel_waiting();
                    }
                    reset
                };

                if let Some(reset) = reset {
                    self.wake_all_waiters();
                    (self.on_event)(reset);
                }

                Err(SpinelError::Timeout)
            }
        }
    }

    pub async fn prop_value_get(
        &self,
        property_id: SpinelPropertyId,
    ) -> Result<Vec<u8>, SpinelError> {
        match self.prop_value_get_once(property_id).await {
            Err(SpinelError::Timeout) => self.prop_value_get_once(property_id).await,
            result => result,
        }
    }

    async fn prop_value_get_once(
        &self,
        property_id: SpinelPropertyId,
    ) -> Result<Vec<u8>, SpinelError> {
        let response = self
            .send_command(
                SpinelCommandId::PropValueGet,
                packed_uint21_to_bytes(property_id as u32),
            )
            .await?;

        let response_payload = response.payload;
        let (_rsp_property_id, payload) =
            packed_uint21_deserialize(&response_payload).map_err(SpinelError::U21ParsingError)?;

        Ok(payload.to_vec())
    }

    pub async fn prop_value_set(
        &self,
        property_id: SpinelPropertyId,
        value: Vec<u8>,
    ) -> Result<(SpinelPropertyId, Vec<u8>), SpinelError> {
        match self.prop_value_set_once(property_id, value.clone()).await {
            Err(SpinelError::Timeout) => self.prop_value_set_once(property_id, value).await,
            result => result,
        }
    }

    async fn prop_value_set_once(
        &self,
        property_id: SpinelPropertyId,
        value: Vec<u8>,
    ) -> Result<(SpinelPropertyId, Vec<u8>), SpinelError> {
        let response = self
            .send_command(
                SpinelCommandId::PropValueSet,
                packed_uint21_to_bytes(property_id as u32)
                    .iter()
                    .chain(value.iter())
                    .cloned()
                    .collect(),
            )
            .await?;

        let response_payload = response.payload;
        let (rsp_property_id_int, payload) =
            packed_uint21_deserialize(&response_payload).map_err(SpinelError::U21ParsingError)?;

        let rsp_property_id = SpinelPropertyId::try_from(rsp_property_id_int).map_err(|_| {
            SpinelError::InvalidResponsePropertyId {
                property_id: rsp_property_id_int,
            }
        })?;

        tracing::trace!(
            "Setting property {property_id:?}={value:02X?}, result {rsp_property_id:?}={payload:02X?}"
        );

        Ok((rsp_property_id, payload.to_vec()))
    }

    /// Take functional ownership of the radio, fencing out transmits for the life of the
    /// guard. The right tool for any operation that drives the radio across multiple
    /// commands: scans, channel retune, reset recovery. The guard can itself transmit —
    /// see [`ExclusiveRadio::transmit_frame`].
    pub async fn lock_radio(&self) -> ExclusiveRadio<'_, R> {
        ExclusiveRadio {
            client: self,
            _guard: self.exclusive_lock.lock().await,
        }
    }

    // Convenience method wrapping broad functionality are below
    pub async fn get_ncp_version(&self) -> Result<String, SpinelError> {
        let ncp_version_rsp = self.prop_value_get(SpinelPropertyId::NcpVersion).await?;

        let ncp_version_with_null =
            String::from_utf8(ncp_version_rsp).map_err(|_| SpinelError::NcpVersionNotUtf8)?;

        Ok(ncp_version_with_null
            .trim_matches(char::from(0x00))
            .to_string())
    }

    /// The radio's factory-programmed EUI64, a core property readable in any RCP state.
    pub async fn get_hw_address(&self) -> Result<Eui64, SpinelError> {
        let rsp = self.prop_value_get(SpinelPropertyId::Hwaddr).await?;

        let bytes: [u8; 8] = rsp
            .try_into()
            .map_err(|rsp: Vec<u8>| SpinelError::InvalidHardwareAddress { got: rsp })?;

        Ok(Eui64::from_be_bytes(bytes))
    }

    pub async fn transmit_frame(
        &self,
        tx_frame: &SpinelTxFrame,
    ) -> Result<SpinelStatus, SpinelError> {
        let _exclusive_lock = self.exclusive_lock.lock().await;
        self.transmit_frame_inner(tx_frame).await
    }

    /// Put a frame on the air, assuming the caller already holds the radio.
    async fn transmit_frame_inner(
        &self,
        tx_frame: &SpinelTxFrame,
    ) -> Result<SpinelStatus, SpinelError> {
        // No retry on timeout: a duplicate transmit is worse than a failed one, and the
        // NWK retry paths handle the failure
        let (rsp_prop_id, rsp) = self
            .prop_value_set_once(SpinelPropertyId::StreamRaw, tx_frame.to_bytes())
            .await?;

        if rsp_prop_id != SpinelPropertyId::LastStatus {
            return Err(SpinelError::UnexpectedResponseProperty {
                expected: SpinelPropertyId::LastStatus,
                got: rsp_prop_id,
            });
        }

        if rsp.is_empty() {
            return Err(SpinelError::EmptyResponse);
        }

        SpinelStatus::try_from(rsp[0]).map_err(|_| SpinelError::InvalidStatus { status: rsp[0] })
    }
}

/// Functional ownership of the radio, handed out by [`SpinelClient::lock_radio`].
pub struct ExclusiveRadio<'a, R: Runtime = DefaultRuntime> {
    client: &'a SpinelClient<R>,
    _guard: AsyncMutexGuard<'a, ()>,
}

impl<R: Runtime> ExclusiveRadio<'_, R> {
    /// Put a frame on the air while owning the radio.
    pub async fn transmit_frame(
        &self,
        tx_frame: &SpinelTxFrame,
    ) -> Result<SpinelStatus, SpinelError> {
        self.client.transmit_frame_inner(tx_frame).await
    }
}
