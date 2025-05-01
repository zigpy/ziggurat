#![allow(dead_code)]

use std::convert::TryFrom;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ApsFrameType {
    Data = 0b00,
    Ack = 0b10,
    Interpan = 0b11,
}

impl TryFrom<u8> for ApsFrameType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(ApsFrameType::Data),
            0b10 => Ok(ApsFrameType::Ack),
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
pub struct ApsAckFrameControl {
    pub frame_type: ApsFrameType,
    pub delivery_mode: ApsDeliveryMode,
    pub ack_format: bool,
    pub security: bool,
    pub ack_request: bool,
    pub extended_header: bool,
}

impl ApsAckFrameControl {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 1 {
            return Err("Not enough data to parse ApsAckFrameControl");
        }

        let frame_type = ApsFrameType::try_from((bytes[0] >> 0) & 0b11)?;

        if frame_type != ApsFrameType::Ack {
            return Err("Invalid frame type for ApsAckFrameControl");
        }

        Ok((
            Self {
                frame_type: frame_type,
                delivery_mode: ApsDeliveryMode::try_from((bytes[0] >> 2) & 0b11)?,
                ack_format: (bytes[0] >> 4) & 0b1 == 1,
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
            | (((self.ack_format as u8) & 0b1) << 4)
            | (((self.security as u8) & 0b1) << 5)
            | (((self.ack_request as u8) & 0b1) << 6)
            | (((self.extended_header as u8) & 0b1) << 7)]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApsAckFrame {
    pub frame_control: ApsAckFrameControl,
    pub destination_endpoint: Option<u8>,
    pub cluster_id: Option<u16>,
    pub profile_id: Option<u16>,
    pub source_endpoint: Option<u8>,
    pub counter: u8,
}

impl ApsAckFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 {
            return Err("Not enough data to parse ApsAckFrame");
        }

        let (frame_control, remaining) = ApsAckFrameControl::deserialize(bytes)?;

        if frame_control.frame_type != ApsFrameType::Ack {
            return Err("Invalid frame type for ApsAckFrame");
        }

        let destination_endpoint;
        let cluster_id;
        let profile_id;
        let source_endpoint;
        let counter;

        if frame_control.ack_format {
            destination_endpoint = None;
            cluster_id = None;
            profile_id = None;
            source_endpoint = None;
            counter = u8::from_le_bytes([remaining[0]]);
        } else {
            destination_endpoint = Some(u8::from_le_bytes([remaining[0]]));
            cluster_id = Some(u16::from_le_bytes([remaining[1], remaining[2]]));
            profile_id = Some(u16::from_le_bytes([remaining[3], remaining[4]]));
            source_endpoint = Some(u8::from_le_bytes([remaining[5]]));
            counter = u8::from_le_bytes([remaining[6]]);
        }

        Ok(Self {
            frame_control: frame_control,
            destination_endpoint: destination_endpoint,
            cluster_id: cluster_id,
            profile_id: profile_id,
            source_endpoint: source_endpoint,
            counter: counter,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.frame_control.to_bytes());

        if let Some(destination_endpoint) = self.destination_endpoint {
            bytes.extend(destination_endpoint.to_le_bytes());
        }
        if let Some(cluster_id) = self.cluster_id {
            bytes.extend(cluster_id.to_le_bytes());
        }
        if let Some(profile_id) = self.profile_id {
            bytes.extend(profile_id.to_le_bytes());
        }
        if let Some(source_endpoint) = self.source_endpoint {
            bytes.extend(source_endpoint.to_le_bytes());
        }
        bytes.extend(self.counter.to_le_bytes());

        bytes
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApsDataFrame {
    pub frame_control: ApsFrameControl,
    pub group_id: Option<u16>,
    pub destination_endpoint: Option<u8>,
    pub cluster_id: u16,
    pub profile_id: u16,
    pub source_endpoint: u8,
    pub counter: u8,
    pub asdu: Vec<u8>,
}

impl ApsDataFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 {
            return Err("Not enough data to parse ApsDataFrame");
        }

        let (frame_control, remaining) = ApsFrameControl::deserialize(bytes)?;

        let group_id;
        let destination_endpoint;

        if frame_control.delivery_mode == ApsDeliveryMode::Multicast {
            group_id = Some(u16::from_le_bytes([remaining[0], remaining[1]]));
            destination_endpoint = None;
        } else {
            group_id = None;
            destination_endpoint = Some(u8::from_le_bytes([remaining[0]]));
        }

        let cluster_id = u16::from_le_bytes([remaining[1], remaining[2]]);
        let profile_id = u16::from_le_bytes([remaining[3], remaining[4]]);
        let source_endpoint = u8::from_le_bytes([remaining[5]]);
        let counter = u8::from_le_bytes([remaining[6]]);
        let asdu = remaining[7..].to_vec();

        Ok(Self {
            frame_control: frame_control,
            group_id: group_id,
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

        if let Some(group_id) = self.group_id {
            bytes.extend(group_id.to_le_bytes());
        }

        if let Some(destination_endpoint) = self.destination_endpoint {
            bytes.extend(destination_endpoint.to_le_bytes());
        }

        bytes.extend(self.cluster_id.to_le_bytes());
        bytes.extend(self.profile_id.to_le_bytes());
        bytes.extend(self.source_endpoint.to_le_bytes());
        bytes.extend(self.counter.to_le_bytes());
        bytes.extend(self.asdu.clone());

        bytes
    }
}

pub enum ApsFrame {
    Data(ApsDataFrame),
    Ack(ApsAckFrame),
}

pub fn parse_aps_frame(bytes: &[u8]) -> Result<ApsFrame, &'static str> {
    if bytes.len() < 1 {
        return Err("Not enough data to parse ApsFrame");
    }

    let frame_type = ApsFrameType::try_from((bytes[0] >> 0) & 0b11)?;

    match frame_type {
        ApsFrameType::Data => Ok(ApsFrame::Data(ApsDataFrame::from_bytes(bytes)?)),
        ApsFrameType::Ack => Ok(ApsFrame::Ack(ApsAckFrame::from_bytes(bytes)?)),
        ApsFrameType::Interpan => Err("Interpan not supported"),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_aps_parsing_unicast() {
        let data = hex!("4001060004010103015a00");
        let aps_frame = ApsDataFrame::from_bytes(&data).unwrap();

        let expected_aps_frame = ApsDataFrame {
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
    fn test_aps_parsing_broadcast() {
        let aps_frame =
            ApsDataFrame::from_bytes(&hex!("080013000000000000426b4fdeb726004b12008e")).unwrap();

        let expected_aps_frame = ApsDataFrame {
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

    #[test]
    fn test_aps_parsing_acks() {
        let aps_frame = ApsAckFrame::from_bytes(&hex!("0201060004010100")).unwrap();

        let expected_aps_frame = ApsAckFrame {
            frame_control: ApsAckFrameControl {
                frame_type: ApsFrameType::Ack,
                delivery_mode: ApsDeliveryMode::Unicast,
                ack_format: false,
                security: false,
                ack_request: false,
                extended_header: false,
            },
            destination_endpoint: Some(1),
            cluster_id: Some(0x0006),
            profile_id: Some(0x0104),
            source_endpoint: Some(1),
            counter: 0,
        };

        assert_eq!(aps_frame, expected_aps_frame);
    }
}
