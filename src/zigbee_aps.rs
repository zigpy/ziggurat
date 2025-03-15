#![allow(dead_code)]

use std::convert::TryFrom;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ApsFrameType {
    Data = 0b00,
    Command = 0b10,
    Interpan = 0b11,
}

impl TryFrom<u8> for ApsFrameType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(ApsFrameType::Data),
            0b10 => Ok(ApsFrameType::Command),
            0b11 => Ok(ApsFrameType::Interpan),
            _ => Err("Invalid APS frame type"),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ApsDeliveryMode {
    Unicast = 0b00,
    Broadcast = 0b10,
    Multicast = 0b11,
}

impl TryFrom<u8> for ApsDeliveryMode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(ApsDeliveryMode::Unicast),
            0b10 => Ok(ApsDeliveryMode::Broadcast),
            0b11 => Ok(ApsDeliveryMode::Multicast),
            _ => Err("Invalid APS delivery mode"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApsFrameControl {
    pub frame_type: ApsFrameType,
    pub delivery_mode: ApsDeliveryMode,
    pub reserved: u8,
    pub security: bool,
    pub ack_request: bool,
    pub extended_header: bool,
}

impl ApsFrameControl {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 1 {
            return Err("Not enough data to parse ApsFrameControl");
        }

        Ok((
            Self {
                frame_type: ApsFrameType::try_from((bytes[0] >> 0) & 0b11)?,
                delivery_mode: ApsDeliveryMode::try_from((bytes[0] >> 2) & 0b11)?,
                reserved: (bytes[0] >> 4) & 0b1,
                security: (bytes[0] >> 5) & 0b1 == 1,
                ack_request: (bytes[0] >> 6) & 0b1 == 1,
                extended_header: (bytes[0] >> 7) & 0b1 == 1,
            },
            &bytes[1..],
        ))
    }

    pub fn to_bytes(&self) -> [u8; 1] {
        [(((self.frame_type as u8) & 0b11) << 0)
            | (((self.delivery_mode as u8) & 0b11) << 2)
            | (((self.reserved as u8) & 0b1) << 4)
            | (((self.security as u8) & 0b1) << 5)
            | (((self.ack_request as u8) & 0b1) << 6)
            | (((self.extended_header as u8) & 0b1) << 7)]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApsFrame {
    pub frame_control: ApsFrameControl,
    pub destination_endpoint: u8,
    pub cluster_id: u16,
    pub profile_id: u16,
    pub source_endpoint: u8,
    pub counter: u8,
    pub asdu: Vec<u8>,
}

impl ApsFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 {
            return Err("Not enough data to parse ApsFrame");
        }

        let (frame_control, remaining) = ApsFrameControl::deserialize(bytes)?;
        let destination_endpoint = u8::from_le_bytes([remaining[0]]);
        let cluster_id = u16::from_le_bytes([remaining[1], remaining[2]]);
        let profile_id = u16::from_le_bytes([remaining[3], remaining[4]]);
        let source_endpoint = u8::from_le_bytes([remaining[5]]);
        let counter = u8::from_le_bytes([remaining[6]]);
        let asdu = remaining[7..].to_vec();

        Ok(Self {
            frame_control: frame_control,
            destination_endpoint: destination_endpoint,
            cluster_id: cluster_id,
            profile_id: profile_id,
            source_endpoint: source_endpoint,
            counter: counter,
            asdu: asdu,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.frame_control.to_bytes());
        bytes.extend(self.destination_endpoint.to_le_bytes());
        bytes.extend(self.cluster_id.to_le_bytes());
        bytes.extend(self.profile_id.to_le_bytes());
        bytes.extend(self.source_endpoint.to_le_bytes());
        bytes.extend(self.counter.to_le_bytes());
        bytes.extend(self.asdu.clone());

        bytes
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_nwk_decryption_unicast() {
        let data = hex!("4001060004010103015a00");
        let aps_frame = ApsFrame::from_bytes(&data).unwrap();

        let expected_aps_frame = ApsFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Data,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved: 0b0,
                security: false,
                ack_request: true,
                extended_header: false,
            },
            destination_endpoint: 1,
            cluster_id: 0x0006,
            profile_id: 0x0104,
            source_endpoint: 1,
            counter: 3,
            asdu: hex!("01 5a 00").to_vec(),
        };

        assert_eq!(aps_frame, expected_aps_frame);
        assert_eq!(aps_frame.to_bytes(), data.to_vec());
    }

    #[test]
    fn test_nwk_decryption_broadcast() {
        let aps_frame =
            ApsFrame::from_bytes(&hex!("080013000000000000426b4fdeb726004b12008e")).unwrap();

        let expected_aps_frame = ApsFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Data,
                delivery_mode: ApsDeliveryMode::Broadcast,
                reserved: 0b0,
                security: false,
                ack_request: false,
                extended_header: false,
            },
            destination_endpoint: 0,
            cluster_id: 0x0013,
            profile_id: 0x0000,
            source_endpoint: 0,
            counter: 0,
            asdu: hex!("00426b4fdeb726004b12008e").to_vec(),
        };

        assert_eq!(aps_frame, expected_aps_frame);
    }
}
