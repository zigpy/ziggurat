use crate::spinel::{
    HdlcLiteFrame, SpinelCommandId, SpinelFrame, SpinelFrameParsingError, SpinelFramePropValueIs,
    SpinelHeader, SpinelPropertyId, SpinelProtocol, SpinelStatus, packed_uint21_deserialize,
    packed_uint21_to_bytes,
};
use std::string::String;
use thiserror::Error;
use tokio_serial::SerialStream;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

/// A local serial link answers in milliseconds; anything beyond this is a failure.
const TIMEOUT: Duration = Duration::from_secs(2);

/// Consecutive command timeouts before the RCP is presumed wedged and the
/// reset-recovery path is triggered.
const MAX_CONSECUTIVE_TIMEOUTS: u32 = 4;

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
    pub psdu: Vec<u8>,
    pub rssi: i8,
    pub noise_floor: i8,
    pub flags: u32,
    pub channel: u8,
    pub lqi: u8,
    pub timestamp_us: u64,
    pub receive_error: u8,
    pub manufacturer_specific: Vec<u8>,
}

impl SpinelRxFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut offset = 0;

        let psdu_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        if offset + (psdu_len + 1 + 1 + 4 + 1 + 1 + 8 + 1) > bytes.len() {
            return Err("Invalid frame length");
        }

        let psdu = bytes[offset..offset + psdu_len].to_vec();
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
    #[error("client has disconnected")]
    ChannelClosed,
    #[error("timeout")]
    Timeout,
    #[error("spinel U21 parsing error")]
    U21ParsingError(#[from] SpinelFrameParsingError),
    #[error("spinel parsing error: {reason}")]
    InvalidResponseError { reason: String },
}

#[derive(Debug)]
pub struct SpinelClient {
    /// The reader half of the port, owned by the task spawned in `spawn_reader`.
    reader: Mutex<Option<ReadHalf<SerialStream>>>,
    /// The writer half of the port. The mutex also serializes outbound HDLC writes so
    /// concurrent commands cannot interleave partial frames inside the byte stream.
    writer: AsyncMutex<WriteHalf<SerialStream>>,
    pub protocol: Arc<Mutex<SpinelProtocol>>,
    /// The RCP has a single radio (and a single TX buffer): transmit transactions are
    /// serialized end to end, and energy scans hold the lock per scanned channel via
    /// [`Self::lock_radio`].
    radio_lock: AsyncMutex<()>,
    consecutive_timeouts: AtomicU32,
    reader_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl SpinelClient {
    pub fn new(port: SerialStream) -> Self {
        let (reader, writer) = tokio::io::split(port);

        Self {
            reader: Mutex::new(Some(reader)),
            writer: AsyncMutex::new(writer),
            protocol: Arc::new(Mutex::new(SpinelProtocol::new())),
            radio_lock: AsyncMutex::new(()),
            consecutive_timeouts: AtomicU32::new(0),
            reader_task: Mutex::new(None),
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
        let mut reader = self
            .reader
            .lock()
            .expect("Failed to lock reader")
            .take()
            .expect("Reader already taken");
        let protocol = Arc::clone(&self.protocol);

        let handle = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];

            loop {
                match reader.read(&mut buffer).await {
                    Ok(n) if n > 0 => {
                        let mut protocol = protocol.lock().expect("Failed to lock Spinel");
                        protocol.handle_inbound_bytes(&buffer[..n])
                    }
                    Ok(_) => {
                        log::error!("Serial port EOF, exiting");
                        std::process::exit(1);
                    }
                    Err(e) => {
                        log::error!("Serial port read failed ({e}), exiting");
                        std::process::exit(1);
                    }
                }
            }
        });

        *self.reader_task.lock().expect("Failed to lock reader task") = Some(handle);
    }

    /// Stops the reader task so that a replaced client releases the serial port
    /// instead of competing with its successor for inbound frames.
    pub fn shutdown(&self) {
        let maybe_handle = self
            .reader_task
            .lock()
            .expect("Failed to lock reader task")
            .take();

        if let Some(handle) = maybe_handle {
            handle.abort();
        }
    }

    async fn write_bytes(&self, data: &[u8]) -> Result<(), SpinelError> {
        log::trace!("Writing {data:02X?}");

        self.writer
            .lock()
            .await
            .write_all(data)
            .await
            .map_err(SpinelError::IoError)?;

        Ok(())
    }

    /// `CMD_RESET` is acknowledged with an unsolicited `LastStatus = RESET_*`
    /// notification rather than a tid-matched response, so this only sends.
    pub async fn send_reset(&self) -> Result<(), SpinelError> {
        let frame = SpinelFrame {
            header: SpinelHeader {
                flag: 0b10,
                network_link_id: 0,
                transaction_id: 0,
            },
            command_id: SpinelCommandId::Reset,
            payload: vec![],
        };

        let hdlc_frame = HdlcLiteFrame {
            data: frame.to_bytes(),
        };

        self.write_bytes(&hdlc_frame.to_bytes_with_flags()).await
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

        log::debug!("Sending frame {frame:?}");

        let hdlc_frame = HdlcLiteFrame {
            data: frame.to_bytes(),
        };

        self.write_bytes(&hdlc_frame.to_bytes_with_flags()).await?;

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

                Err(SpinelError::ChannelClosed)
            }
            Err(_) => {
                self.protocol
                    .lock()
                    .expect("Failed to lock Spinel")
                    .cancel_request(frame.header.transaction_id);

                let timeouts = self.consecutive_timeouts.fetch_add(1, Ordering::Relaxed) + 1;
                if timeouts >= MAX_CONSECUTIVE_TIMEOUTS {
                    self.consecutive_timeouts.store(0, Ordering::Relaxed);
                    log::error!(
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
            SpinelError::InvalidResponseError {
                reason: "Invalid property ID in response".to_string(),
            }
        })?;

        log::debug!(
            "Setting property {property_id:?}={value:02X?}, result {rsp_property_id:?}={payload:02X?}"
        );

        Ok((rsp_property_id, payload.to_vec()))
    }

    /// Take exclusive ownership of the radio, pausing transmissions for as long as the
    /// guard is held. A transmit submitted during an energy scan is put on the air by
    /// the RCP the moment the scanned channel completes, and a scan start is rejected
    /// with `INVALID_STATE` while a frame is in flight — holding this lock around a
    /// scan makes that race impossible, since a transmit holds it until its frame is
    /// off the air.
    pub async fn lock_radio(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.radio_lock.lock().await
    }

    // Convenience method wrapping broad functionality are below
    pub async fn get_ncp_version(&self) -> Result<String, SpinelError> {
        let ncp_version_rsp = self.prop_value_get(SpinelPropertyId::NcpVersion).await?;

        let ncp_version_with_null =
            String::from_utf8(ncp_version_rsp).map_err(|_| SpinelError::InvalidResponseError {
                reason: "NCP version is not valid UTF-8".to_string(),
            })?;

        Ok(ncp_version_with_null
            .trim_matches(char::from(0x00))
            .to_string())
    }

    pub async fn transmit_frame(
        &self,
        tx_frame: &SpinelTxFrame,
    ) -> Result<SpinelStatus, SpinelError> {
        let _radio_lock = self.radio_lock.lock().await;

        // No retry on timeout: a duplicate transmit is worse than a failed one, and the
        // NWK retry paths handle the failure
        let (rsp_prop_id, rsp) = self
            .prop_value_set_once(SpinelPropertyId::StreamRaw, tx_frame.to_bytes())
            .await?;

        if rsp_prop_id != SpinelPropertyId::LastStatus {
            return Err(SpinelError::InvalidResponseError {
                reason: "Unexpected response property ID".to_string(),
            });
        }

        if rsp.is_empty() {
            return Err(SpinelError::InvalidResponseError {
                reason: "Unexpected response length".to_string(),
            });
        }

        SpinelStatus::try_from(rsp[0]).map_err(|_| SpinelError::InvalidResponseError {
            reason: "Invalid Spinel status".to_string(),
        })
    }
}
