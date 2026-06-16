use crate::{
    HdlcSpecial, SPINEL_FRAME_MAX_SIZE, SpinelCommandId, SpinelFrame, SpinelFrameParsingError,
    SpinelFramePropValueIs, SpinelHeader, SpinelPropertyId, SpinelProtocol, SpinelResetReason,
    SpinelStatus, hdlc_escape_into, packed_uint21_deserialize, packed_uint21_to_bytes,
};
use ieee_802154::FrameBytes;
use ieee_802154::types::Eui64;
use std::string::String;
use thiserror::Error;
use tokio_serial::SerialStream;

use crate::priority_lock::PriorityLock;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::task::{Context, Poll};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf, WriteHalf,
};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

/// A local serial link answers in milliseconds; anything beyond this is a failure.
const TIMEOUT: Duration = Duration::from_secs(2);

/// Consecutive command timeouts before the RCP is presumed wedged and the
/// reset-recovery path is triggered.
const MAX_CONSECUTIVE_TIMEOUTS: u32 = 4;

/// The byte transport under the Spinel client, either a serial port or a raw stream.
#[derive(Debug)]
pub enum SpinelTransport {
    Serial(SerialStream),
    Duplex(DuplexStream),
}

impl From<SerialStream> for SpinelTransport {
    fn from(port: SerialStream) -> Self {
        Self::Serial(port)
    }
}

impl From<DuplexStream> for SpinelTransport {
    fn from(pipe: DuplexStream) -> Self {
        Self::Duplex(pipe)
    }
}

impl AsyncRead for SpinelTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Serial(port) => Pin::new(port).poll_read(cx, buf),
            Self::Duplex(pipe) => Pin::new(pipe).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SpinelTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Serial(port) => Pin::new(port).poll_write(cx, buf),
            Self::Duplex(pipe) => Pin::new(pipe).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Serial(port) => Pin::new(port).poll_flush(cx),
            Self::Duplex(pipe) => Pin::new(pipe).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Serial(port) => Pin::new(port).poll_shutdown(cx),
            Self::Duplex(pipe) => Pin::new(pipe).poll_shutdown(cx),
        }
    }
}

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
    #[error("io error")]
    IoError(#[from] std::io::Error),
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

/// The writer half of the port plus its serialization scratch: frames go out one at a
/// time, so two persistent buffers cover every TX without per-frame allocation.
#[derive(Debug)]
struct SpinelWriter {
    port: WriteHalf<SpinelTransport>,
    frame_scratch: Vec<u8>,
    hdlc_scratch: Vec<u8>,
}

/// Radio transmit priority
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TxPriority(pub i8);

impl TxPriority {
    pub const BACKGROUND: Self = Self(-2);
    pub const USER_LOW: Self = Self(-1);
    pub const USER_NORMAL: Self = Self(0);
    pub const USER_HIGH: Self = Self(1);
    pub const USER_CRITICAL: Self = Self(2);
    pub const STACK_CRITICAL: Self = Self(3);
}

impl Default for TxPriority {
    fn default() -> Self {
        Self::USER_NORMAL
    }
}

#[derive(Debug)]
pub struct SpinelClient {
    /// The reader half of the port, owned by the task spawned in `spawn_reader`.
    reader: Mutex<Option<ReadHalf<SpinelTransport>>>,
    /// The writer half of the port. The mutex also serializes outbound HDLC writes so
    /// concurrent commands cannot interleave partial frames inside the byte stream.
    writer: AsyncMutex<SpinelWriter>,
    pub protocol: Arc<Mutex<SpinelProtocol>>,
    /// Orders queued transmits among themselves; priority decides which goes first.
    transmit_lock: PriorityLock<TxPriority>,
    /// Functional ownership of the radio (scan, reset recovery, channel retune), taken via
    /// [`Self::lock_radio`]. A transmit locks it only for its send; an exclusive op holds it
    /// throughout. Because transmits queue on `transmit_lock` first, an exclusive op waits
    /// out only the in-flight frame, not the whole backlog.
    exclusive_lock: AsyncMutex<()>,
    consecutive_timeouts: AtomicU32,
}

impl SpinelClient {
    pub fn new(transport: impl Into<SpinelTransport>) -> Self {
        let (reader, writer) = tokio::io::split(transport.into());

        Self {
            reader: Mutex::new(Some(reader)),
            writer: AsyncMutex::new(SpinelWriter {
                port: writer,
                frame_scratch: Vec::with_capacity(SPINEL_FRAME_MAX_SIZE),
                // Worst-case HDLC escaping doubles the frame, plus two flags
                hdlc_scratch: Vec::with_capacity(2 * SPINEL_FRAME_MAX_SIZE + 2),
            }),
            protocol: Arc::new(Mutex::new(SpinelProtocol::new())),
            transmit_lock: PriorityLock::new(),
            exclusive_lock: AsyncMutex::new(()),
            consecutive_timeouts: AtomicU32::new(0),
        }
    }

    pub fn set_property_update_receiver(
        &self,
        property_id: SpinelPropertyId,
        tx: mpsc::Sender<SpinelFramePropValueIs>,
    ) {
        self.protocol
            .lock()
            .expect("Failed to lock Spinel")
            .property_update_receivers
            .insert(property_id, tx);
    }

    pub fn set_reset_notification_receiver(&self, tx: mpsc::Sender<SpinelStatus>) {
        self.protocol
            .lock()
            .expect("Failed to lock Spinel")
            .set_reset_notification_receiver(tx);
    }

    /// Start a reading loop to parse and handle inbound frames.
    ///
    /// Serial death (USB yank, EOF) exits the whole process: the supervisor (Docker)
    /// restarts us. A half-dead process with a deaf radio is the worst failure mode.
    pub fn spawn_reader(&self) {
        self.spawn_reader_inner(true);
    }

    /// Like [`Self::spawn_reader`] but stops the reader task on transport close instead
    /// of exiting the process. For embedders (e.g. the Python bindings) whose transport
    /// closing is a normal shutdown, not a fault that warrants killing the host process.
    pub fn spawn_reader_graceful(&self) {
        self.spawn_reader_inner(false);
    }

    fn spawn_reader_inner(&self, exit_on_close: bool) {
        let mut reader = self
            .reader
            .lock()
            .expect("Failed to lock reader")
            .take()
            .expect("Reader already taken");
        let protocol = Arc::clone(&self.protocol);

        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];

            loop {
                match reader.read(&mut buffer).await {
                    Ok(n) if n > 0 => {
                        let mut protocol = protocol.lock().expect("Failed to lock Spinel");
                        protocol.handle_inbound_bytes(&buffer[..n])
                    }
                    Ok(_) if exit_on_close => {
                        tracing::error!("Serial port EOF, exiting");
                        std::process::exit(1);
                    }
                    Err(e) if exit_on_close => {
                        tracing::error!("Serial port read failed ({e}), exiting");
                        std::process::exit(1);
                    }
                    Ok(_) => {
                        tracing::warn!("Spinel transport closed, stopping reader");
                        return;
                    }
                    Err(e) => {
                        tracing::warn!("Spinel transport read failed ({e}), stopping reader");
                        return;
                    }
                }
            }
        });
    }

    /// Serialize and HDLC-frame `frame` into the writer's persistent scratch buffers
    /// and put it on the wire.
    // The writer lock is intentionally held until the write completes: it is what
    // serializes outbound frames on the wire
    #[allow(clippy::significant_drop_tightening)]
    async fn send_frame(&self, frame: &SpinelFrame) -> Result<(), SpinelError> {
        let mut writer = self.writer.lock().await;
        let SpinelWriter {
            port,
            frame_scratch,
            hdlc_scratch,
        } = &mut *writer;

        frame_scratch.clear();
        frame.serialize_into(frame_scratch);

        hdlc_scratch.clear();
        hdlc_scratch.push(HdlcSpecial::Flag as u8);
        hdlc_escape_into(frame_scratch, hdlc_scratch);
        hdlc_scratch.push(HdlcSpecial::Flag as u8);

        tracing::trace!("Writing {hdlc_scratch:02X?}");

        port.write_all(hdlc_scratch)
            .await
            .map_err(SpinelError::IoError)?;

        Ok(())
    }

    /// `CMD_RESET` is acknowledged with an unsolicited `LastStatus = RESET_*`
    /// notification rather than a tid-matched response, so this only sends.
    pub async fn send_reset(&self, reason: SpinelResetReason) -> Result<(), SpinelError> {
        let frame = SpinelFrame {
            header: SpinelHeader {
                flag: 0b10,
                network_link_id: 0,
                transaction_id: 0,
            },
            command_id: SpinelCommandId::Reset,
            payload: vec![reason as u8],
        };

        self.send_frame(&frame).await
    }

    pub async fn send_command(
        &self,
        command_id: SpinelCommandId,
        payload: Vec<u8>,
    ) -> Result<SpinelFrame, SpinelError> {
        let (frame, rx) = {
            self.protocol
                .lock()
                .expect("Failed to lock Spinel")
                .prepare_request(command_id, payload)
        };

        tracing::trace!("Sending frame {frame:?}");

        self.send_frame(&frame).await?;

        match timeout(TIMEOUT, rx).await {
            Ok(Ok(response_frame)) => {
                self.consecutive_timeouts.store(0, Ordering::Relaxed);
                Ok(response_frame)
            }
            Ok(Err(_)) => {
                self.protocol
                    .lock()
                    .expect("Failed to lock Spinel")
                    .cancel_request(frame.header.transaction_id);

                Err(SpinelError::CancelledByReset)
            }
            Err(_) => {
                self.protocol
                    .lock()
                    .expect("Failed to lock Spinel")
                    .cancel_request(frame.header.transaction_id);

                let timeouts = self.consecutive_timeouts.fetch_add(1, Ordering::Relaxed) + 1;
                if timeouts >= MAX_CONSECUTIVE_TIMEOUTS {
                    self.consecutive_timeouts.store(0, Ordering::Relaxed);
                    tracing::error!(
                        "RCP unresponsive after {timeouts} consecutive command timeouts, triggering reset recovery"
                    );
                    self.protocol
                        .lock()
                        .expect("Failed to lock Spinel")
                        .notify_reset(SpinelStatus::ResponseTimeout);
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
    pub async fn lock_radio(&self) -> ExclusiveRadio<'_> {
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

        Ok(crate::eui64_from_spinel_bytes(bytes))
    }

    pub async fn transmit_frame(
        &self,
        tx_frame: &SpinelTxFrame,
        priority: TxPriority,
    ) -> Result<SpinelStatus, SpinelError> {
        // Wait our turn among transmits, then the radio-ownership gate. This order keeps
        // the backlog on `transmit_lock`, so an exclusive op only outwaits the in-flight
        // frame.
        let _transmit_lock = self.transmit_lock.acquire(priority).await;
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
pub struct ExclusiveRadio<'a> {
    client: &'a SpinelClient,
    _guard: tokio::sync::MutexGuard<'a, ()>,
}

impl ExclusiveRadio<'_> {
    /// Put a frame on the air while owning the radio.
    pub async fn transmit_frame(
        &self,
        tx_frame: &SpinelTxFrame,
    ) -> Result<SpinelStatus, SpinelError> {
        self.client.transmit_frame_inner(tx_frame).await
    }
}
