pub mod types;
use crate::types::{Eui64, Nwk, PanId, format_hex};
use abstract_bits::{AbstractBits, abstract_bits};
use num_enum::TryFromPrimitive;

use derivative::Derivative;

#[abstract_bits(bits = 3)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum Ieee802154FrameType {
    Beacon = 0b000,
    Data = 0b001,
    Command = 0b011,
    Ack = 0b010,
}

#[derive(Debug, PartialEq, Copy, Clone)]
#[abstract_bits(bits = 8)]
#[repr(u8)]
pub enum Ieee802154AssociationStatus {
    AssociationSuccessful = 0x00,
    PanAtCapacity = 0x01,
    PanAccessDenied = 0x02,
    HoppingSequenceOffsetDuplication = 0x03,
    FastAssociationSuccessful = 0x80,
}

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum Ieee802154AddressingMode {
    None = 0b00,
    Short = 0b10,
    Long = 0b11,
}

#[abstract_bits]
#[derive(Debug, Clone, PartialEq)]
pub struct Ieee802154FrameControl {
    pub frame_type: Ieee802154FrameType,
    pub security_enabled: bool,
    pub frame_pending: bool,
    pub ack_request: bool,
    pub pan_id_compression: bool,
    pub reserved1: bool,
    pub sequence_number_suppression: bool,
    pub information_elements_present: bool,
    pub dest_addr_mode: Ieee802154AddressingMode,
    pub frame_version: u2,
    pub src_addr_mode: Ieee802154AddressingMode,
}

#[derive(Debug, PartialEq, Copy, Clone)]
#[abstract_bits(bits = 8)]
#[repr(u8)]
pub enum Ieee802154CommandId {
    NotAMacCommand = 0x00,
    AssociationRequest = 0x01,
    AssociationResponse = 0x02,
    DisassociationNotification = 0x03,
    DataRequest = 0x04,
    PanIdConflictNotification = 0x05,
    OrphanNotification = 0x06,
    BeaconRequest = 0x07,
    CoordinatorRealignment = 0x08,
    GtsRequest = 0x09,
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Ieee802154Address {
    Nwk(Nwk),
    Eui64(Eui64),
}

#[derive(Derivative)]
#[derivative(Debug, PartialEq)]
pub struct Ieee802154Frame {
    pub frame_control: Ieee802154FrameControl,
    pub sequence_number: Option<u8>,
    pub dest_pan_id: Option<PanId>,
    pub dest_address: Option<Ieee802154Address>,
    pub src_pan_id: Option<PanId>,
    pub src_address: Option<Ieee802154Address>,
    #[derivative(Debug(format_with = "format_hex"))]
    pub payload: Vec<u8>,
    pub fcs: u16,
}

impl Ieee802154Frame {
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 2 + 2 {
            return Err("Data too short to contain a frame");
        }

        let fcs = u16::from_le_bytes([data[data.len() - 2], data[data.len() - 1]]);
        let mut remaining = &data[..data.len() - 2];

        if Self::compute_fcs(remaining) != fcs {
            return Err("Invalid FCS");
        }

        // Parse frame control
        let frame_control = Ieee802154FrameControl::from_abstract_bits(remaining)
            .map_err(|_| "Failed to parse frame control")?;
        remaining = &remaining[frame_control.to_abstract_bits().unwrap().len()..];

        // Parse sequence number
        let sequence_number = if frame_control.sequence_number_suppression {
            None
        } else {
            let seq = remaining[0];
            remaining = &remaining[1..];
            Some(seq)
        };

        // Parse destination PAN ID and address
        let (dest_pan_id, dest_address) = match frame_control.dest_addr_mode {
            Ieee802154AddressingMode::Short => {
                let pan_id;
                (pan_id, remaining) = PanId::deserialize(remaining)?;

                let nwk;
                (nwk, remaining) = Nwk::deserialize(remaining)?;
                (Some(pan_id), Some(Ieee802154Address::Nwk(nwk)))
            }
            Ieee802154AddressingMode::Long => {
                let pan_id;
                (pan_id, remaining) = PanId::deserialize(remaining)?;

                let eui64;
                (eui64, remaining) = Eui64::deserialize(remaining)?;
                (Some(pan_id), Some(Ieee802154Address::Eui64(eui64)))
            }
            Ieee802154AddressingMode::None => (None, None),
        };

        // Parse source PAN ID
        let src_pan_id = if frame_control.pan_id_compression {
            dest_pan_id
        } else if frame_control.frame_type == Ieee802154FrameType::Data {
            let pan_id;
            (pan_id, remaining) = PanId::deserialize(remaining)?;
            Some(pan_id)
        } else {
            None
        };

        // Parse source address
        let src_address = match frame_control.src_addr_mode {
            Ieee802154AddressingMode::Short => {
                let nwk;
                (nwk, remaining) = Nwk::deserialize(remaining)?;
                Some(Ieee802154Address::Nwk(nwk))
            }
            Ieee802154AddressingMode::Long => {
                let eui64;
                (eui64, remaining) = Eui64::deserialize(remaining)?;
                Some(Ieee802154Address::Eui64(eui64))
            }
            _ => None,
        };

        // Remaining bytes are payload
        let payload = remaining.to_vec();

        Ok(Self {
            frame_control,
            sequence_number,
            dest_pan_id,
            dest_address,
            src_pan_id,
            src_address,
            payload,
            fcs,
        })
    }

    pub fn from_bytes_without_fcs(data: &[u8]) -> Result<Self, &'static str> {
        let mut data_with_fcs = Vec::new();
        data_with_fcs.extend(data);
        data_with_fcs.extend(&Self::compute_fcs(data).to_le_bytes());

        Self::from_bytes(&data_with_fcs)
    }

    pub fn to_bytes_without_fcs(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Serialize frame control
        data.extend(self.frame_control.to_abstract_bits().unwrap());

        // Serialize sequence number
        if let Some(seq) = self.sequence_number {
            data.push(seq);
        }

        // Serialize destination
        if let Some(pan_id) = self.dest_pan_id {
            data.extend(pan_id.to_bytes());
        }
        if let Some(address) = &self.dest_address {
            data.extend(match address {
                Ieee802154Address::Nwk(addr) => addr.to_bytes().to_vec(),
                Ieee802154Address::Eui64(addr) => addr.to_bytes().to_vec(),
            });
        }

        // Serialize source
        if !self.frame_control.pan_id_compression {
            if let Some(pan_id) = self.src_pan_id {
                data.extend(pan_id.to_bytes());
            }
        }

        if let Some(address) = &self.src_address {
            data.extend(match address {
                Ieee802154Address::Nwk(addr) => addr.to_bytes().to_vec(),
                Ieee802154Address::Eui64(addr) => addr.to_bytes().to_vec(),
            });
        }

        // Add payload
        data.extend(&self.payload);

        data
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = self.to_bytes_without_fcs();
        data.extend(&Self::compute_fcs(&data).to_le_bytes());

        data
    }

    #[allow(clippy::identity_op)]
    pub fn compute_fcs(data: &[u8]) -> u16 {
        let mut crc: u16 = 0x0000;

        for c in data.iter() {
            let q = (((crc & 0x0F) as u8) ^ (c >> 0)) & 0x0F;
            crc = (crc >> 4) ^ ((q as u16) * 0x1081);

            let r = (((crc & 0x0F) as u8) ^ (c >> 4)) & 0x0F;
            crc = (crc >> 4) ^ ((r as u16) * 0x1081);
        }

        crc
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_frame_control() {
        let bytes = [0x61, 0x88, 0xFF];
        let frame_control = Ieee802154FrameControl::from_abstract_bits(&bytes).unwrap();
        let remaining = &bytes[2..];

        assert_eq!(frame_control.frame_type, Ieee802154FrameType::Data);
        assert!(!frame_control.security_enabled);
        assert!(!frame_control.frame_pending);
        assert!(frame_control.ack_request);
        assert!(frame_control.pan_id_compression);
        assert!(!frame_control.sequence_number_suppression);
        assert!(!frame_control.information_elements_present);
        assert_eq!(
            frame_control.dest_addr_mode,
            Ieee802154AddressingMode::Short
        );
        assert_eq!(frame_control.frame_version, 0);
        assert_eq!(frame_control.src_addr_mode, Ieee802154AddressingMode::Short);

        assert_eq!(remaining, [0xFF]);
        assert_eq!(frame_control.to_abstract_bits().unwrap(), bytes[..2]);
    }

    #[test]
    fn test_frame_data() {
        let bytes = [
            0x61, 0x88, 0xa3, 0xf5, 0x3e, 0x34, 0x52, 0x63, 0xf6, 0x48, 0x02, 0x00, 0x00, 0xa5,
            0x79, 0x1d, 0xc1, 0x28, 0x41, 0xf0, 0x48, 0x02, 0x8b, 0x86, 0x34, 0xfe, 0xff, 0x27,
            0x71, 0x84, 0x00, 0x13, 0xdc, 0x42, 0x64, 0x0f, 0xca, 0x9c, 0x6e, 0xff, 0xc9, 0xcf,
            0xd3, 0x35, 0x53, 0x54, 0xca, 0x68, 0x16, 0x1c, 0xc9, 0x44, 0xc4, 0xad, 0x37, 0xc5,
            0xea,
        ];

        let frame = Ieee802154Frame::from_bytes(&bytes).unwrap();

        assert_eq!(frame.frame_control.frame_type, Ieee802154FrameType::Data);
        assert_eq!(frame.frame_control.security_enabled, false);
        assert_eq!(frame.frame_control.frame_pending, false);
        assert_eq!(frame.frame_control.ack_request, true);
        assert_eq!(frame.frame_control.pan_id_compression, true);
        assert_eq!(frame.frame_control.sequence_number_suppression, false);
        assert_eq!(frame.frame_control.information_elements_present, false);
        assert_eq!(
            frame.frame_control.dest_addr_mode,
            Ieee802154AddressingMode::Short
        );
        assert_eq!(frame.frame_control.frame_version, 0);
        assert_eq!(
            frame.frame_control.src_addr_mode,
            Ieee802154AddressingMode::Short
        );

        assert_eq!(frame.sequence_number, Some(163));
        assert_eq!(frame.dest_pan_id, Some(PanId(0x3EF5)));
        assert_eq!(
            frame.dest_address,
            Some(Ieee802154Address::Nwk(Nwk(0x5234)))
        );
        assert_eq!(frame.src_pan_id, Some(PanId(0x3EF5)));
        assert_eq!(frame.src_address, Some(Ieee802154Address::Nwk(Nwk(0xF663))));

        assert_eq!(frame.payload, bytes[9..bytes.len() - 2]);
        assert_eq!(frame.fcs, 0xEAC5);

        assert_eq!(frame.to_bytes(), bytes);
    }

    #[test]
    fn test_frame_bad_fcs() {
        let mut bytes = [
            0x61, 0x88, 0xa3, 0xf5, 0x3e, 0x34, 0x52, 0x63, 0xf6, 0x48, 0x02, 0x00, 0x00, 0xa5,
            0x79, 0x1d, 0xc1, 0x28, 0x41, 0xf0, 0x48, 0x02, 0x8b, 0x86, 0x34, 0xfe, 0xff, 0x27,
            0x71, 0x84, 0x00, 0x13, 0xdc, 0x42, 0x64, 0x0f, 0xca, 0x9c, 0x6e, 0xff, 0xc9, 0xcf,
            0xd3, 0x35, 0x53, 0x54, 0xca, 0x68, 0x16, 0x1c, 0xc9, 0x44, 0xc4, 0xad, 0x37, 0xc5,
            0xea,
        ];

        bytes[5] ^= 0xFF;

        let err = Ieee802154Frame::from_bytes(&bytes).unwrap_err();
        assert_eq!(err, "Invalid FCS");
    }

    #[test]
    fn test_frame_ack() {
        let bytes = [0x02, 0x00, 0xd1, 0xbc, 0x72];

        let frame = Ieee802154Frame::from_bytes(&bytes).unwrap();

        assert_eq!(frame.frame_control.frame_type, Ieee802154FrameType::Ack);
        assert_eq!(frame.frame_control.security_enabled, false);
        assert_eq!(frame.frame_control.frame_pending, false);
        assert_eq!(frame.frame_control.ack_request, false);
        assert_eq!(frame.frame_control.pan_id_compression, false);
        assert_eq!(frame.frame_control.sequence_number_suppression, false);
        assert_eq!(frame.frame_control.information_elements_present, false);
        assert_eq!(
            frame.frame_control.dest_addr_mode,
            Ieee802154AddressingMode::None
        );
        assert_eq!(frame.frame_control.frame_version, 0);
        assert_eq!(
            frame.frame_control.src_addr_mode,
            Ieee802154AddressingMode::None
        );

        assert_eq!(frame.sequence_number, Some(209));
        assert_eq!(frame.dest_pan_id, None);
        assert_eq!(frame.dest_address, None);
        assert_eq!(frame.src_pan_id, None);
        assert_eq!(frame.src_address, None);

        assert_eq!(frame.payload, hex!("").to_vec());
        assert_eq!(frame.fcs, 0x72BC);

        assert_eq!(frame.to_bytes(), bytes);
    }

    #[test]
    fn test_frame_data2() {
        let bytes = hex!(
            "618834efbe909d443e48020000443e1eb4287cc54700e095dd0c018817000033a8fc4eb11941104ea261f13064f175f477d311e62736b708a6a390a4f8b120df6cd3ec5c244681"
        );
        let frame = Ieee802154Frame::from_bytes(&bytes).unwrap();

        let expected_frame = Ieee802154Frame {
            frame_control: Ieee802154FrameControl {
                frame_type: Ieee802154FrameType::Data,
                security_enabled: false,
                frame_pending: false,
                ack_request: true,
                pan_id_compression: true,
                reserved1: false,
                sequence_number_suppression: false,
                information_elements_present: false,
                dest_addr_mode: Ieee802154AddressingMode::Short,
                frame_version: 0,
                src_addr_mode: Ieee802154AddressingMode::Short,
            },
            sequence_number: Some(52),
            dest_pan_id: Some(PanId(0xBEEF)),
            dest_address: Some(Ieee802154Address::Nwk(Nwk(0x9D90))),
            src_pan_id: Some(PanId(0xBEEF)),
            src_address: Some(Ieee802154Address::Nwk(Nwk(0x3E44))),
            payload: hex!("48020000443e1eb4287cc54700e095dd0c018817000033a8fc4eb11941104ea261f13064f175f477d311e62736b708a6a390a4f8b120df6cd3ec5c24").to_vec(),
            fcs: 0x8146,
        };

        assert_eq!(frame, expected_frame);
    }

    #[test]
    fn test_frame_ack2() {
        let bytes = hex!(
            "6188034072f42600000802f42600001e03284975922d90db24feff6e02bc00e1ddd9ffbbc3dadee840b61bf2ef2b 1c2e"
        );
        let frame = Ieee802154Frame::from_bytes(&bytes).unwrap();

        let expected_frame = Ieee802154Frame {
            frame_control: Ieee802154FrameControl {
                frame_type: Ieee802154FrameType::Data,
                security_enabled: false,
                frame_pending: false,
                ack_request: true,
                pan_id_compression: true,
                reserved1: false,
                sequence_number_suppression: false,
                information_elements_present: false,
                dest_addr_mode: Ieee802154AddressingMode::Short,
                frame_version: 0,
                src_addr_mode: Ieee802154AddressingMode::Short,
            },
            sequence_number: Some(3),
            dest_pan_id: Some(PanId(0x7240)),
            dest_address: Some(Ieee802154Address::Nwk(Nwk(0x26F4))),
            src_pan_id: Some(PanId(0x7240)),
            src_address: Some(Ieee802154Address::Nwk(Nwk(0x0000))),
            payload: hex!(
                "0802f42600001e03284975922d90db24feff6e02bc00e1ddd9ffbbc3dadee840b61bf2ef2b"
            )
            .to_vec(),
            fcs: 0x2e1c,
        };

        assert_eq!(frame, expected_frame);
        assert_eq!(frame.to_bytes(), bytes);
    }

    #[test]
    fn test_frame_ack3() {
        let bytes = hex!(
            "4188034072f42600000802f42600001e03284975922d90db24feff6e02bc00e1ddd9ffbbc3dadee840b61bf2ef2b"
        );
        let frame = Ieee802154Frame::from_bytes_without_fcs(&bytes).unwrap();

        let expected_frame = Ieee802154Frame {
            frame_control: Ieee802154FrameControl {
                frame_type: Ieee802154FrameType::Data,
                security_enabled: false,
                frame_pending: false,
                ack_request: false,
                pan_id_compression: true,
                reserved1: false,
                sequence_number_suppression: false,
                information_elements_present: false,
                dest_addr_mode: Ieee802154AddressingMode::Short,
                frame_version: 0,
                src_addr_mode: Ieee802154AddressingMode::Short,
            },
            sequence_number: Some(3),
            dest_pan_id: Some(PanId(0x7240)),
            dest_address: Some(Ieee802154Address::Nwk(Nwk(0x26F4))),
            src_pan_id: Some(PanId(0x7240)),
            src_address: Some(Ieee802154Address::Nwk(Nwk(0x0000))),
            payload: hex!(
                "0802f42600001e03284975922d90db24feff6e02bc00e1ddd9ffbbc3dadee840b61bf2ef2b"
            )
            .to_vec(),
            fcs: 0x4bdd,
        };

        assert_eq!(frame, expected_frame);
        assert_eq!(frame.to_bytes_without_fcs(), bytes);
    }
}
