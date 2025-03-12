use crate::spinel::{
    packed_uint21_deserialize, packed_uint21_to_bytes, HdlcLiteFrame, SpinelCommandId, SpinelFrame,
    SpinelPropertyId, SpinelProtocol,
};
use serial2_tokio::SerialPort;
use std::string::String;

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, PartialEq, Clone)]
pub struct SpinelTxFrame {
    pub psdu: Vec<u8>,
    pub channel: u8,
    pub max_csma_backoffs: u8,
    pub max_frame_retries: u8,
    pub enable_csma_ca: bool,
    pub is_header_updated: bool,
    pub is_a_retransmit: bool,
    pub is_security_processed: bool,
    pub tx_delay: u32,
    pub tx_delay_base_time: u32,
    pub rx_channel_after_tx: u8,
    pub tx_power: i8,
}

impl SpinelTxFrame {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&(self.psdu.len() as u16).to_le_bytes());
        result.extend_from_slice(&self.psdu);
        result.push(self.channel);
        result.push(self.max_csma_backoffs);
        result.push(self.max_frame_retries);
        result.push(self.enable_csma_ca as u8);
        result.push(self.is_header_updated as u8);
        result.push(self.is_a_retransmit as u8);
        result.push(self.is_security_processed as u8);
        result.extend_from_slice(&self.tx_delay.to_le_bytes());
        result.extend_from_slice(&self.tx_delay_base_time.to_le_bytes());
        result.push(self.rx_channel_after_tx);
        result.push(self.tx_power as u8);

        result
    }
}

#[derive(Debug, PartialEq, Clone)]
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

#[derive(Clone)]
pub struct SpinelClient {
    pub port: Arc<SerialPort>,
    pub protocol: Arc<Mutex<SpinelProtocol>>,
}

#[derive(Debug)]
pub enum SpinelSendError {
    IoError(std::io::Error),
    ChannelClosed,
    Timeout,
}

impl SpinelClient {
    pub fn new(port: SerialPort) -> Self {
        Self {
            port: Arc::new(port),
            protocol: Arc::new(Mutex::new(SpinelProtocol::new())),
        }
    }

    /// Start a reading loop to parse and handle inbound frames.
    pub fn spawn_reader(&self) {
        let port_clone = Arc::clone(&self.port);
        let client_clone = Arc::clone(&self.protocol);

        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];

            loop {
                match port_clone.read(&mut buffer).await {
                    Ok(n) if n > 0 => {
                        let mut protocol = client_clone.lock().await;
                        protocol.handle_inbound_bytes(&buffer[..n])
                    }
                    Ok(_) => {
                        eprintln!("EOF or 0 bytes read, stopping.");
                        break;
                    }
                    Err(e) => {
                        eprintln!("Error reading port: {:?}", e);
                        break;
                    }
                }
            }
        });
    }

    pub async fn send_command(
        &self,
        command_id: u8,
        payload: Vec<u8>,
    ) -> Result<SpinelFrame, SpinelSendError> {
        let (frame, rx) = {
            let mut guard = self.protocol.lock().await;
            guard.prepare_request(command_id, payload)
        };

        log::debug!("Sending frame {:?}", frame);

        let hdlc_frame = HdlcLiteFrame {
            data: frame.to_bytes(),
        };

        let data = hdlc_frame.to_bytes_with_flags();

        log::debug!("Writing {:02X?}", data);
        self.port
            .write(&data)
            .await
            .map_err(SpinelSendError::IoError)?;

        match timeout(TIMEOUT, rx).await {
            Ok(Ok(response_frame)) => Ok(response_frame),
            Ok(Err(_recv_closed)) => {
                let mut guard = self.protocol.lock().await;
                guard.cancel_request(frame.header.transaction_id);

                Err(SpinelSendError::ChannelClosed)
            }
            Err(_elapsed) => {
                let mut guard = self.protocol.lock().await;
                guard.cancel_request(frame.header.transaction_id);

                Err(SpinelSendError::Timeout)
            }
        }
    }

    pub async fn prop_value_get(&self, property_id: u32) -> Result<Vec<u8>, SpinelSendError> {
        let response = self
            .send_command(
                SpinelCommandId::PropValueGet as u8,
                packed_uint21_to_bytes(property_id),
            )
            .await?;

        let response_payload = response.payload;
        let (_rsp_property_id, payload) = match packed_uint21_deserialize(&response_payload) {
            Ok((property_id, payload)) => (property_id, payload),
            Err(e) => {
                return Err(SpinelSendError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e,
                )))
            }
        };

        Ok(payload.to_vec())
    }

    pub async fn prop_value_set(
        &self,
        property_id: u32,
        value: Vec<u8>,
    ) -> Result<(u32, Vec<u8>), SpinelSendError> {
        let response = self
            .send_command(
                SpinelCommandId::PropValueSet as u8,
                packed_uint21_to_bytes(property_id)
                    .iter()
                    .chain(value.iter())
                    .cloned()
                    .collect(),
            )
            .await?;

        let response_payload = response.payload;
        let (rsp_property_id, payload) = match packed_uint21_deserialize(&response_payload) {
            Ok((property_id, payload)) => (property_id, payload),
            Err(e) => {
                return Err(SpinelSendError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e,
                )))
            }
        };

        log::info!(
            "Setting property {}={:02X?}, result {}={:02X?}",
            property_id,
            value,
            rsp_property_id,
            payload
        );

        Ok((rsp_property_id, payload.to_vec()))
    }

    // Convenience method wrapping broad functionality are below
    pub async fn get_ncp_version(&self) -> Result<String, SpinelSendError> {
        let ncp_version_rsp = self
            .prop_value_get(SpinelPropertyId::NcpVersion as u32)
            .await
            .unwrap();

        let ncp_version_with_null =
            String::from_utf8(ncp_version_rsp).expect("Invalid UTF-8 string");

        Ok(ncp_version_with_null
            .trim_matches(char::from(0x00))
            .to_string())
    }

    pub async fn transmit_frame(&self, tx_frame: &SpinelTxFrame) -> Result<u8, SpinelSendError> {
        let (_rsp_prop_id, _rsp) = self
            .prop_value_set(SpinelPropertyId::StreamRaw as u32, tx_frame.to_bytes())
            .await
            .unwrap();

        Ok(1)
        /*

        if rsp_prop_id != SpinelPropertyId::LastStatus as u32 {
            return Err(SpinelSendError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unexpected response property ID",
            )));
        }

        if rsp.len() < 1 {
            return Err(SpinelSendError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unexpected response length",
            )));
        }

        let status = rsp[0];
        Ok(status)
        */
    }
}
