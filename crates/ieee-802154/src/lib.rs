pub mod commands;
pub mod types;

use crate::commands::Ieee802154Command;
use crate::types::{Eui64, Nwk, PanId, format_hex};
use abstract_bits::{AbstractBits, BitReader, abstract_bits};
use num_enum::TryFromPrimitive;

use educe::Educe;

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone)]
pub enum Ieee802154Address {
    Nwk(Nwk),
    Eui64(Eui64),
}

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum Ieee802154AddressingMode {
    None = 0b00,
    Short = 0b10,
    Long = 0b11,
}

#[abstract_bits(bits = 3)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum Ieee802154FrameType {
    Beacon = 0b000,
    Data = 0b001,
    Command = 0b011,
    Ack = 0b010,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, TryFromPrimitive)]
#[abstract_bits(bits = 8)]
#[repr(u8)]
pub enum Ieee802154AssociationStatus {
    AssociationSuccessful = 0x00,
    PanAtCapacity = 0x01,
    PanAccessDenied = 0x02,
    HoppingSequenceOffsetDuplication = 0x03,
    FastAssociationSuccessful = 0x80,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, TryFromPrimitive)]
#[abstract_bits(bits = 8)]
#[repr(u8)]
pub enum Ieee802154DisassociationReason {
    /// Reserved value - should not be used
    Reserved = 0x00,
    /// The coordinator wishes the device to leave the PAN
    CoordinatorWishesToLeave = 0x01,
    /// The device wishes to leave the PAN
    DeviceWishesToLeave = 0x02,
    // Values 0x03-0xFF are reserved
}

#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
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

#[derive(Debug, Eq, PartialEq, Copy, Clone, TryFromPrimitive)]
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ieee802154FrameHeader {
    pub frame_control: Ieee802154FrameControl,
    pub sequence_number: Option<u8>,
    pub dest_pan_id: Option<PanId>,
    pub dest_address: Option<Ieee802154Address>,
    pub src_pan_id: Option<PanId>,
    pub src_address: Option<Ieee802154Address>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Ieee802154Frame {
    Beacon(Ieee802154BeaconFrame),
    Data(Ieee802154DataFrame),
    Ack(Ieee802154AckFrame),
    Command(Ieee802154CommandFrame),
}

#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SuperframeSpecification {
    pub beacon_interval: u4,
    pub superframe_interval: u4,
    pub final_cap_slot: u4,
    pub battery_extension: bool,
    pub reserved1: u1,
    pub pan_coordinator: bool,
    pub association_permit: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ieee802154BeaconFrame {
    pub header: Ieee802154FrameHeader,
    pub superframe_specification: SuperframeSpecification,
    pub gts_specification: u8,
    pub pending_address_specification: u8,
    pub beacon_payload: Vec<u8>,
    pub fcs: u16,
}

#[derive(Educe, Clone, Eq, PartialEq)]
#[educe(Debug)]
pub struct Ieee802154DataFrame {
    pub header: Ieee802154FrameHeader,
    #[educe(Debug(method(format_hex)))]
    pub payload: Vec<u8>,
    pub fcs: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ieee802154AckFrame {
    pub header: Ieee802154FrameHeader,
    pub fcs: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ieee802154CommandFrame {
    pub header: Ieee802154FrameHeader,
    pub command_id: Ieee802154CommandId,
    pub command_payload: Ieee802154CommandPayload,
    pub fcs: u16,
}

/// `aMaxPhyPacketSize`: a full 802.15.4 frame, FCS included, fits in 127 bytes
pub const MAX_PHY_PACKET_SIZE: usize = 127;

/// Maximum 802.15.4 MAC payload length
const MAC_COMMAND_MAX_LEN: usize = MAX_PHY_PACKET_SIZE - 2 - 23; // FCS and maximum header

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("Could not serialize {ty}")]
pub struct SerializeError {
    ty: &'static str,
    #[source]
    cause: abstract_bits::ToBytesError,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeserializeError {
    #[error("Could not deserialize payload to {ty}")]
    Payload {
        ty: &'static str,
        #[source]
        cause: abstract_bits::FromBytesError,
    },
    #[error(
        "Could not deserialize incorrect Id. \
        Expected {expected_discriminant} (which represents {expected_variant:?}), \
        found: {found_discriminant:?} instead"
    )]
    IncorrectId {
        expected_variant: Ieee802154CommandId,
        expected_discriminant: u8,
        found_discriminant: u8,
    },
    #[error("Got zero bytes, no valid command is zero bytes")]
    ZeroBytes,
}

/// Append a structure's serialized form to `bytes`.
///
/// Avoids the intermediate Vec that [`AbstractBits::to_abstract_bits`] allocates; the
/// scratch buffer fits anything that can go on the air (a full 802.15.4 frame is at
/// most 127 bytes).
pub fn extend_abstract_bits<T: AbstractBits>(bytes: &mut Vec<u8>, value: &T) {
    let mut buffer = [0u8; MAX_PHY_PACKET_SIZE];
    let mut writer = abstract_bits::BitWriter::from(&mut buffer[..]);
    value.write_abstract_bits(&mut writer).unwrap();
    let written = writer.bytes_written();
    bytes.extend_from_slice(&buffer[..written]);
}

fn serialize_command<T: AbstractBits>(
    thing: &T,
    id: Ieee802154CommandId,
) -> Result<Vec<u8>, SerializeError> {
    let mut bytes = vec![0u8; MAC_COMMAND_MAX_LEN];
    bytes[0] = id as u8;
    let mut writer = abstract_bits::BitWriter::from(&mut bytes[1..]);
    thing
        .write_abstract_bits(&mut writer)
        .map_err(|cause| SerializeError {
            ty: core::any::type_name::<T>(),
            cause,
        })?;
    let len = writer.bytes_written();
    bytes.truncate(len + 1); // +1 for id
    Ok(bytes)
}

fn deserialize_command<T: AbstractBits>(
    bytes: &[u8],
    correct_id: Ieee802154CommandId,
) -> Result<T, DeserializeError> {
    let [command_id, payload @ ..] = bytes else {
        return Err(DeserializeError::ZeroBytes);
    };

    if *command_id != correct_id as u8 {
        return Err(DeserializeError::IncorrectId {
            expected_variant: correct_id,
            expected_discriminant: correct_id as u8,
            found_discriminant: *command_id,
        });
    }

    let mut reader = BitReader::from(payload);
    T::read_abstract_bits(&mut reader).map_err(|cause| DeserializeError::Payload {
        ty: core::any::type_name::<T>(),
        cause,
    })
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Ieee802154CommandPayload {
    AssociationRequest(commands::Ieee802154AssociationRequestCommand),
    AssociationResponse(commands::Ieee802154AssociationResponseCommand),
    DisassociationNotification(commands::Ieee802154DisassociationNotificationCommand),
    DataRequest(commands::Ieee802154DataRequestCommand),
    BeaconRequest(commands::Ieee802154BeaconRequestCommand),
    // Stub implementations for other commands
    Unknown(Vec<u8>),
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
        let mut reader = BitReader::from(remaining);
        let frame_control = Ieee802154FrameControl::read_abstract_bits(&mut reader)
            .map_err(|_| "Failed to parse frame control")?;
        remaining = &remaining[reader.bytes_read()..];

        // Parse sequence number
        let sequence_number = if frame_control.sequence_number_suppression {
            None
        } else {
            if remaining.is_empty() {
                return Err("Not enough data to parse sequence number");
            }

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
        } else if frame_control.src_addr_mode != Ieee802154AddressingMode::None {
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

        let header = Ieee802154FrameHeader {
            frame_control,
            sequence_number,
            dest_pan_id,
            dest_address,
            src_pan_id,
            src_address,
        };

        // Branch based on frame type
        match header.frame_control.frame_type {
            Ieee802154FrameType::Beacon => {
                if remaining.len() < 4 {
                    return Err("Beacon frame too short");
                }
                let superframe_specification =
                    SuperframeSpecification::from_abstract_bits(&remaining[..4])
                        .map_err(|_| "Failed to parse superframe specification")?;
                let gts_specification = remaining[2];
                let pending_address_specification = remaining[3];
                let beacon_payload = remaining[4..].to_vec();

                Ok(Self::Beacon(Ieee802154BeaconFrame {
                    header,
                    superframe_specification,
                    gts_specification,
                    pending_address_specification,
                    beacon_payload,
                    fcs,
                }))
            }
            Ieee802154FrameType::Data => {
                let payload = remaining.to_vec();
                Ok(Self::Data(Ieee802154DataFrame {
                    header,
                    payload,
                    fcs,
                }))
            }
            Ieee802154FrameType::Ack => Ok(Self::Ack(Ieee802154AckFrame { header, fcs })),
            Ieee802154FrameType::Command => {
                if remaining.is_empty() {
                    return Err("Command frame missing command ID");
                }
                let command_id = Ieee802154CommandId::try_from(remaining[0])
                    .map_err(|_| "Invalid command ID")?;
                let command_payload = Self::parse_command_payload(command_id, &remaining[1..])?;

                Ok(Self::Command(Ieee802154CommandFrame {
                    header,
                    command_id,
                    command_payload,
                    fcs,
                }))
            }
        }
    }

    fn parse_command_payload(
        command_id: Ieee802154CommandId,
        payload: &[u8],
    ) -> Result<Ieee802154CommandPayload, &'static str> {
        // Reconstruct the full command bytes (command ID + payload)
        let mut full_command = Vec::with_capacity(payload.len() + 1);
        full_command.push(command_id as u8);
        full_command.extend_from_slice(payload);

        match command_id {
            Ieee802154CommandId::AssociationRequest => {
                commands::Ieee802154AssociationRequestCommand::deserialize(&full_command)
                    .map(Ieee802154CommandPayload::AssociationRequest)
                    .map_err(|_| "Failed to parse AssociationRequest command")
            }
            Ieee802154CommandId::AssociationResponse => {
                commands::Ieee802154AssociationResponseCommand::deserialize(&full_command)
                    .map(Ieee802154CommandPayload::AssociationResponse)
                    .map_err(|_| "Failed to parse AssociationResponse command")
            }
            Ieee802154CommandId::DisassociationNotification => {
                commands::Ieee802154DisassociationNotificationCommand::deserialize(&full_command)
                    .map(Ieee802154CommandPayload::DisassociationNotification)
                    .map_err(|_| "Failed to parse DisassociationNotification command")
            }
            Ieee802154CommandId::DataRequest => {
                commands::Ieee802154DataRequestCommand::deserialize(&full_command)
                    .map(Ieee802154CommandPayload::DataRequest)
                    .map_err(|_| "Failed to parse DataRequest command")
            }
            Ieee802154CommandId::BeaconRequest => {
                commands::Ieee802154BeaconRequestCommand::deserialize(&full_command)
                    .map(Ieee802154CommandPayload::BeaconRequest)
                    .map_err(|_| "Failed to parse BeaconRequest command")
            }
            _ => Ok(Ieee802154CommandPayload::Unknown(payload.to_vec())),
        }
    }

    pub fn from_bytes_without_fcs(data: &[u8]) -> Result<Self, &'static str> {
        let mut data_with_fcs = Vec::new();
        data_with_fcs.extend(data);
        data_with_fcs.extend(&Self::compute_fcs(data).to_le_bytes());

        Self::from_bytes(&data_with_fcs)
    }

    pub fn to_bytes_without_fcs(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(MAX_PHY_PACKET_SIZE);

        let header = self.header();

        // Serialize frame control
        extend_abstract_bits(&mut data, &header.frame_control);

        // Serialize sequence number
        if let Some(seq) = header.sequence_number {
            data.push(seq);
        }

        // Serialize destination
        if let Some(pan_id) = header.dest_pan_id {
            data.extend(pan_id.to_bytes());
        }
        if let Some(address) = &header.dest_address {
            match address {
                Ieee802154Address::Nwk(addr) => data.extend(addr.to_bytes()),
                Ieee802154Address::Eui64(addr) => data.extend(addr.to_bytes()),
            }
        }

        // Serialize source
        if !header.frame_control.pan_id_compression
            && let Some(pan_id) = header.src_pan_id
        {
            data.extend(pan_id.to_bytes());
        }

        if let Some(address) = &header.src_address {
            match address {
                Ieee802154Address::Nwk(addr) => data.extend(addr.to_bytes()),
                Ieee802154Address::Eui64(addr) => data.extend(addr.to_bytes()),
            }
        }

        // Add payload based on frame type
        match self {
            Self::Beacon(frame) => {
                extend_abstract_bits(&mut data, &frame.superframe_specification);
                data.push(frame.gts_specification);
                data.push(frame.pending_address_specification);
                data.extend(&frame.beacon_payload);
            }
            Self::Data(frame) => {
                data.extend(&frame.payload);
            }
            Self::Ack(_) => {
                // ACK frames have no payload
            }
            Self::Command(frame) => {
                data.push(frame.command_id as u8);
                data.extend(&Self::serialize_command_payload(&frame.command_payload));
            }
        }

        data
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = self.to_bytes_without_fcs();
        data.extend(&Self::compute_fcs(&data).to_le_bytes());

        data
    }

    pub const fn header(&self) -> &Ieee802154FrameHeader {
        match self {
            Self::Beacon(frame) => &frame.header,
            Self::Data(frame) => &frame.header,
            Self::Ack(frame) => &frame.header,
            Self::Command(frame) => &frame.header,
        }
    }

    pub const fn fcs(&self) -> u16 {
        match self {
            Self::Beacon(frame) => frame.fcs,
            Self::Data(frame) => frame.fcs,
            Self::Ack(frame) => frame.fcs,
            Self::Command(frame) => frame.fcs,
        }
    }

    fn serialize_command_payload(payload: &Ieee802154CommandPayload) -> Vec<u8> {
        match payload {
            Ieee802154CommandPayload::AssociationRequest(cmd) => cmd
                .serialize()
                .unwrap_or_default()
                .get(1..)
                .unwrap_or_default()
                .to_vec(),
            Ieee802154CommandPayload::AssociationResponse(cmd) => cmd
                .serialize()
                .unwrap_or_default()
                .get(1..)
                .unwrap_or_default()
                .to_vec(),
            Ieee802154CommandPayload::DisassociationNotification(cmd) => cmd
                .serialize()
                .unwrap_or_default()
                .get(1..)
                .unwrap_or_default()
                .to_vec(),
            Ieee802154CommandPayload::DataRequest(cmd) => cmd
                .serialize()
                .unwrap_or_default()
                .get(1..)
                .unwrap_or_default()
                .to_vec(),
            Ieee802154CommandPayload::BeaconRequest(cmd) => cmd
                .serialize()
                .unwrap_or_default()
                .get(1..)
                .unwrap_or_default()
                .to_vec(),
            Ieee802154CommandPayload::Unknown(data) => data.clone(),
        }
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

        if let Ieee802154Frame::Data(data_frame) = frame {
            assert_eq!(
                data_frame.header.frame_control.frame_type,
                Ieee802154FrameType::Data
            );
            assert!(!data_frame.header.frame_control.security_enabled);
            assert!(!data_frame.header.frame_control.frame_pending);
            assert!(data_frame.header.frame_control.ack_request);
            assert!(data_frame.header.frame_control.pan_id_compression);
            assert!(!data_frame.header.frame_control.sequence_number_suppression);
            assert!(!data_frame.header.frame_control.information_elements_present);
            assert_eq!(
                data_frame.header.frame_control.dest_addr_mode,
                Ieee802154AddressingMode::Short
            );
            assert_eq!(data_frame.header.frame_control.frame_version, 0);
            assert_eq!(
                data_frame.header.frame_control.src_addr_mode,
                Ieee802154AddressingMode::Short
            );

            assert_eq!(data_frame.header.sequence_number, Some(163));
            assert_eq!(data_frame.header.dest_pan_id, Some(PanId(0x3EF5)));
            assert_eq!(
                data_frame.header.dest_address,
                Some(Ieee802154Address::Nwk(Nwk(0x5234)))
            );
            assert_eq!(data_frame.header.src_pan_id, Some(PanId(0x3EF5)));
            assert_eq!(
                data_frame.header.src_address,
                Some(Ieee802154Address::Nwk(Nwk(0xF663)))
            );

            assert_eq!(data_frame.payload, bytes[9..bytes.len() - 2]);
            assert_eq!(data_frame.fcs, 0xEAC5);

            let frame_again = Ieee802154Frame::Data(data_frame);
            assert_eq!(frame_again.to_bytes(), bytes);
        } else {
            panic!("Expected Data frame");
        }
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

        if let Ieee802154Frame::Ack(ack_frame) = frame {
            assert_eq!(ack_frame.header.frame_control.frame_version, 0);
            assert_eq!(
                ack_frame.header.frame_control.src_addr_mode,
                Ieee802154AddressingMode::None
            );

            assert_eq!(ack_frame.header.sequence_number, Some(209));
            assert_eq!(ack_frame.header.dest_pan_id, None);
            assert_eq!(ack_frame.header.dest_address, None);
            assert_eq!(ack_frame.header.src_pan_id, None);
            assert_eq!(ack_frame.header.src_address, None);

            assert_eq!(ack_frame.fcs, 0x72BC);

            let frame_again = Ieee802154Frame::Ack(ack_frame);
            assert_eq!(frame_again.to_bytes(), bytes);
        } else {
            panic!("Expected Ack frame");
        }
    }

    #[test]
    fn test_frame_data2() {
        let bytes = hex!(
            "618834efbe909d443e48020000443e1eb4287cc54700e095dd0c018817000033a8fc4eb11941104ea261f13064f175f477d311e62736b708a6a390a4f8b120df6cd3ec5c244681"
        );
        let frame = Ieee802154Frame::from_bytes(&bytes).unwrap();

        let expected_frame = Ieee802154Frame::Data(Ieee802154DataFrame {
            header: Ieee802154FrameHeader{
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
            },
            payload: hex!("48020000443e1eb4287cc54700e095dd0c018817000033a8fc4eb11941104ea261f13064f175f477d311e62736b708a6a390a4f8b120df6cd3ec5c24").to_vec(),
            fcs: 0x8146,
        });

        assert_eq!(frame, expected_frame);
    }

    #[test]
    fn test_frame_ack2() {
        let bytes = hex!(
            "6188034072f42600000802f42600001e03284975922d90db24feff6e02bc00e1ddd9ffbbc3dadee840b61bf2ef2b 1c2e"
        );
        let frame = Ieee802154Frame::from_bytes(&bytes).unwrap();

        let expected_frame = Ieee802154Frame::Data(Ieee802154DataFrame {
            header: Ieee802154FrameHeader {
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
            },
            payload: hex!(
                "0802f42600001e03284975922d90db24feff6e02bc00e1ddd9ffbbc3dadee840b61bf2ef2b"
            )
            .to_vec(),
            fcs: 0x2e1c,
        });

        assert_eq!(frame, expected_frame);
        assert_eq!(frame.to_bytes(), bytes);
    }

    #[test]
    fn test_frame_ack3() {
        let bytes = hex!(
            "4188034072f42600000802f42600001e03284975922d90db24feff6e02bc00e1ddd9ffbbc3dadee840b61bf2ef2b"
        );
        let frame = Ieee802154Frame::from_bytes_without_fcs(&bytes).unwrap();

        let expected_frame = Ieee802154Frame::Data(Ieee802154DataFrame {
            header: Ieee802154FrameHeader {
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
            },
            payload: hex!(
                "0802f42600001e03284975922d90db24feff6e02bc00e1ddd9ffbbc3dadee840b61bf2ef2b"
            )
            .to_vec(),
            fcs: 0x4bdd,
        });

        assert_eq!(frame, expected_frame);
        assert_eq!(frame.to_bytes_without_fcs(), bytes);
    }

    #[test]
    fn test_beacon_request() {
        let bytes = hex!("03086dffffffff07");
        let frame = Ieee802154Frame::from_bytes_without_fcs(&bytes).unwrap();

        let expected_frame = Ieee802154Frame::Command(Ieee802154CommandFrame {
            header: Ieee802154FrameHeader {
                frame_control: Ieee802154FrameControl {
                    frame_type: Ieee802154FrameType::Command,
                    security_enabled: false,
                    frame_pending: false,
                    ack_request: false,
                    pan_id_compression: false,
                    reserved1: false,
                    sequence_number_suppression: false,
                    information_elements_present: false,
                    dest_addr_mode: Ieee802154AddressingMode::Short,
                    frame_version: 0,
                    src_addr_mode: Ieee802154AddressingMode::None,
                },
                sequence_number: Some(109),
                dest_pan_id: Some(PanId(0xFFFF)),
                dest_address: Some(Ieee802154Address::Nwk(Nwk(0xFFFF))),
                src_pan_id: None,
                src_address: None,
            },
            command_id: Ieee802154CommandId::BeaconRequest,
            command_payload: Ieee802154CommandPayload::BeaconRequest(
                commands::Ieee802154BeaconRequestCommand {},
            ),
            fcs: 0x9b56,
        });

        assert_eq!(frame, expected_frame);
        assert_eq!(frame.to_bytes_without_fcs(), bytes);
    }

    #[test]
    fn test_association_request() {
        let bytes = hex!("23c813261c0000ffff314a49feff6e02bc018e");
        let frame = Ieee802154Frame::from_bytes_without_fcs(&bytes).unwrap();

        let expected_frame = Ieee802154Frame::Command(Ieee802154CommandFrame {
            header: Ieee802154FrameHeader {
                frame_control: Ieee802154FrameControl {
                    frame_type: Ieee802154FrameType::Command,
                    security_enabled: false,
                    frame_pending: false,
                    ack_request: true,
                    pan_id_compression: false,
                    reserved1: false,
                    sequence_number_suppression: false,
                    information_elements_present: false,
                    dest_addr_mode: Ieee802154AddressingMode::Short,
                    frame_version: 0,
                    src_addr_mode: Ieee802154AddressingMode::Long,
                },
                sequence_number: Some(19),
                dest_pan_id: Some(PanId(0x1c26)),
                dest_address: Some(Ieee802154Address::Nwk(Nwk(0x0000))),
                src_pan_id: Some(PanId(0xffff)),
                src_address: Some(Ieee802154Address::Eui64(Eui64::from_hex(
                    "bc:02:6e:ff:fe:49:4a:31",
                ))),
            },
            command_id: Ieee802154CommandId::AssociationRequest,
            command_payload: Ieee802154CommandPayload::AssociationRequest(
                commands::Ieee802154AssociationRequestCommand {
                    alternate_pan_coordinator: false,
                    device_type: commands::AssociationRequestDeviceType::FullFunctionDevice,
                    power_source: commands::AssociationRequestPowerSource::MainsPower,
                    receive_on_when_idle: true,
                    reserved1: 0b00,
                    security_capable: false,
                    allocate_address: true,
                },
            ),
            fcs: 0x2832,
        });

        assert_eq!(frame, expected_frame);
        assert_eq!(frame.to_bytes_without_fcs(), bytes);
    }

    #[test]
    fn test_command_serialization() {
        use crate::commands::*;

        // Test BeaconRequest command (no payload)
        let beacon_req = Ieee802154BeaconRequestCommand;
        let serialized = beacon_req.serialize().unwrap();
        assert_eq!(serialized, vec![0x07]); // Command ID only

        let deserialized = Ieee802154BeaconRequestCommand::deserialize(&serialized).unwrap();
        assert_eq!(beacon_req, deserialized);

        // Test DataRequest command (no payload)
        let data_req = Ieee802154DataRequestCommand;
        let serialized = data_req.serialize().unwrap();
        assert_eq!(serialized, vec![0x04]); // Command ID only

        let deserialized = Ieee802154DataRequestCommand::deserialize(&serialized).unwrap();
        assert_eq!(data_req, deserialized);

        // Test DisassociationNotification command with typed reason
        let disassoc_notif = commands::Ieee802154DisassociationNotificationCommand {
            disassociation_reason: Ieee802154DisassociationReason::CoordinatorWishesToLeave,
        };
        let serialized = disassoc_notif.serialize().unwrap();
        assert_eq!(serialized, vec![0x03, 0x01]); // Command ID + reason code

        let deserialized =
            commands::Ieee802154DisassociationNotificationCommand::deserialize(&serialized)
                .unwrap();
        assert_eq!(disassoc_notif, deserialized);

        // Test the other reason code
        let disassoc_notif2 = commands::Ieee802154DisassociationNotificationCommand {
            disassociation_reason: Ieee802154DisassociationReason::DeviceWishesToLeave,
        };
        let serialized2 = disassoc_notif2.serialize().unwrap();
        assert_eq!(serialized2, vec![0x03, 0x02]); // Command ID + reason code

        let deserialized2 =
            commands::Ieee802154DisassociationNotificationCommand::deserialize(&serialized2)
                .unwrap();
        assert_eq!(disassoc_notif2, deserialized2);
    }
}
