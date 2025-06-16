use abstract_bits::{AbstractBits, abstract_bits};
use num_enum::TryFromPrimitive;

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum ApsFrameType {
    Data = 0b00,
    Ack = 0b10,
    Interpan = 0b11,
}

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum ApsDeliveryMode {
    Unicast = 0b00,
    Broadcast = 0b10,
    Multicast = 0b11,
}

#[abstract_bits]
#[derive(Debug, Clone, PartialEq)]
pub struct ApsFrameControl {
    pub frame_type: ApsFrameType,
    pub delivery_mode: ApsDeliveryMode,
    pub reserved1: u1,
    pub security: bool,
    pub ack_request: bool,
    pub extended_header: bool,
}

#[abstract_bits]
#[derive(Debug, Clone, PartialEq)]
pub struct ApsAckFrameControl {
    pub frame_type: ApsFrameType,
    pub delivery_mode: ApsDeliveryMode,
    pub ack_format: bool,
    pub security: bool,
    pub ack_request: bool,
    pub extended_header: bool,
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

        let frame_control = ApsAckFrameControl::from_abstract_bits(bytes)
            .map_err(|_| "Failed to parse ApsAckFrameControl")?;
        let remaining = &bytes[1..];

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
            frame_control,
            destination_endpoint,
            cluster_id,
            profile_id,
            source_endpoint,
            counter,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.frame_control.to_abstract_bits().unwrap());

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

        let frame_control = ApsFrameControl::from_abstract_bits(bytes)
            .map_err(|_| "Failed to parse ApsFrameControl")?;
        let remaining = &bytes[1..];

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
            frame_control,
            group_id,
            destination_endpoint,
            cluster_id,
            profile_id,
            source_endpoint,
            counter,
            asdu,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.frame_control.to_abstract_bits().unwrap());

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

    let frame_type =
        ApsFrameType::try_from((bytes[0] >> 0) & 0b11).map_err(|_| "Invalid frame type")?;

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
                reserved1: 0b0,
                security: false,
                ack_request: true,
                extended_header: false,
            },
            group_id: None,
            destination_endpoint: Some(1),
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
                reserved1: 0b0,
                security: false,
                ack_request: false,
                extended_header: false,
            },
            group_id: None,
            destination_endpoint: Some(0),
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
