#![no_std]

pub mod commands;
pub mod types;

use crate::types::{Eui64, Nwk, PanId, format_hex};
use abstract_bits::{AbstractBits, BitReader, BitWriter, abstract_bits};
use num_enum::TryFromPrimitive;

/// `aMaxPhyPacketSize`: a full 802.15.4 frame, FCS included, fits in 127 bytes
pub const MAX_PHY_PACKET_SIZE: usize = 127;

pub const FCS_LENGTH: usize = 2;

/// `aMaxMACPayloadSize`: the payload of a frame with the smallest MAC header
pub const MAX_MAC_PAYLOAD_SIZE: usize = 118;

/// A whole 802.15.4 frame. Frames are built in one of these and handed to the radio.
pub type Psdu = heapless::Vec<u8, MAX_PHY_PACKET_SIZE>;

/// Frame-bounded byte storage: an owned, inline buffer for payloads and ciphertexts.
///
/// Nothing carried within a single 802.15.4 frame can exceed its capacity. Fragmentation
/// is ignored for now.
pub type FrameBytes = heapless::Vec<u8, MAX_PHY_PACKET_SIZE>;

/// The frame does not fit in the room its layer has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("frame is too long")]
pub struct TooLong;

/// Write a frame, or a part of one, into a new buffer.
pub fn write_frame(
    serialize: impl FnOnce(&mut FrameWriter) -> Result<(), TooLong>,
) -> Result<Psdu, TooLong> {
    let mut psdu = Psdu::new();
    serialize(&mut FrameWriter::new(&mut psdu, MAX_PHY_PACKET_SIZE))?;
    Ok(psdu)
}

/// Appends one layer of a frame to a [`Psdu`].
///
/// Each layer gets a writer that starts where the layer starts and refuses to write
/// past the layer's size limit, so a layer can read back and encrypt its own bytes.
pub struct FrameWriter<'a> {
    psdu: &'a mut Psdu,
    start: usize,
    end: usize,
}

impl<'a> FrameWriter<'a> {
    /// A writer that appends to `psdu` and writes at most `max` bytes.
    pub fn new(psdu: &'a mut Psdu, max: usize) -> Self {
        let start = psdu.len();
        let end = (start + max).min(MAX_PHY_PACKET_SIZE);
        Self { psdu, start, end }
    }

    /// A writer for the next layer, which starts here and writes at most `max` bytes.
    pub fn nested(&mut self, max: usize) -> FrameWriter<'_> {
        let start = self.psdu.len();
        let end = (start + max).min(self.end);
        FrameWriter {
            psdu: self.psdu,
            start,
            end,
        }
    }

    pub fn len(&self) -> usize {
        self.psdu.len() - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn extend(&mut self, bytes: &[u8]) -> Result<(), TooLong> {
        if self.psdu.len() + bytes.len() > self.end {
            return Err(TooLong);
        }

        self.psdu
            .extend_from_slice(bytes)
            .expect("the end is within the PSDU");
        Ok(())
    }

    pub fn push(&mut self, byte: u8) -> Result<(), TooLong> {
        self.extend(&[byte])
    }

    pub fn bits<T: AbstractBits>(&mut self, value: &T) -> Result<(), TooLong> {
        let start = self.psdu.len();
        self.psdu
            .resize(self.end, 0)
            .expect("the end is within the PSDU");

        let mut writer = BitWriter::from(&mut self.psdu[start..]);
        let result = value.write_abstract_bits(&mut writer);
        let written = writer.bytes_written();

        self.psdu.truncate(start + written);
        result.map_err(|_| TooLong)
    }

    /// The bytes this writer has written.
    pub fn written(&self) -> &[u8] {
        &self.psdu[self.start..]
    }

    pub fn written_mut(&mut self) -> &mut [u8] {
        &mut self.psdu[self.start..]
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone, PartialOrd, Ord)]
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

/// Frame Version field (IEEE Std 802.15.4-2020, Table 7-4).
#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum Ieee802154FrameVersion {
    /// IEEE Std 802.15.4-2003
    Ieee2003 = 0b00,
    /// IEEE Std 802.15.4-2006
    Ieee2006 = 0b01,
    /// IEEE Std 802.15.4-2015 and later; enables IEs, enhanced beacons/acks
    Ieee2015 = 0b10,
    Reserved = 0b11,
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
    pub frame_version: Ieee802154FrameVersion,
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

#[derive(Clone, Eq, PartialEq)]
pub enum Ieee802154Frame<P = FrameBytes> {
    Beacon(Ieee802154BeaconFrame),
    Data(Ieee802154DataFrame<P>),
    Ack(Ieee802154AckFrame),
    Command(Ieee802154CommandFrame),
}

impl<P: FramePayload> core::fmt::Debug for Ieee802154Frame<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Beacon(frame) => f.debug_tuple("Beacon").field(frame).finish(),
            Self::Data(frame) => f.debug_tuple("Data").field(frame).finish(),
            Self::Ack(frame) => f.debug_tuple("Ack").field(frame).finish(),
            Self::Command(frame) => f.debug_tuple("Command").field(frame).finish(),
        }
    }
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
    pub beacon_payload: FrameBytes,
    pub fcs: u16,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Ieee802154DataFrame<P = FrameBytes> {
    pub header: Ieee802154FrameHeader,
    pub payload: P,
    pub fcs: u16,
}

impl<P: FramePayload> core::fmt::Debug for Ieee802154DataFrame<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ieee802154DataFrame")
            .field("header", &self.header)
            .field("payload", &PayloadDebug(&self.payload))
            .field("fcs", &self.fcs)
            .finish()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ieee802154AckFrame {
    pub header: Ieee802154FrameHeader,
    pub fcs: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ieee802154CommandFrame {
    pub header: Ieee802154FrameHeader,
    pub command_payload: Ieee802154CommandPayload,
    pub fcs: u16,
}

/// A payload carried inside an 802.15.4 data frame.
pub trait FramePayload {
    fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong>;
    /// Render the payload for `Debug`: hex for raw bytes, structured for frames.
    fn fmt_payload(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result;
}

impl FramePayload for FrameBytes {
    fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        writer.extend(self)
    }

    fn fmt_payload(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        format_hex(self.as_slice(), f)
    }
}

/// `Debug` adapter that routes a frame payload through [`FramePayload::fmt_payload`].
struct PayloadDebug<'a, P>(&'a P);

impl<P: FramePayload> core::fmt::Debug for PayloadDebug<'_, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt_payload(f)
    }
}

/// Failure to parse a frame or one of its fields off the wire.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("not enough data to parse {ty}")]
    UnexpectedEnd { ty: &'static str },
    #[error("{ty} has an invalid length")]
    InvalidLength { ty: &'static str },
    #[error("invalid discriminant {got} for {ty}")]
    InvalidDiscriminant { ty: &'static str, got: u8 },
    #[error("invalid frame check sequence")]
    InvalidFcs,
    #[error("{0} is not supported")]
    Unsupported(&'static str),
    #[error(transparent)]
    Bits(#[from] abstract_bits::FromBytesError),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Ieee802154CommandPayload {
    AssociationRequest(commands::Ieee802154AssociationRequestCommand),
    AssociationResponse(commands::Ieee802154AssociationResponseCommand),
    DisassociationNotification(commands::Ieee802154DisassociationNotificationCommand),
    DataRequest(commands::Ieee802154DataRequestCommand),
    BeaconRequest(commands::Ieee802154BeaconRequestCommand),
    /// A command we could not decode (unknown id, or a body that failed to parse), kept
    /// verbatim (command id byte included) so it round-trips.
    Unknown(FrameBytes),
}

impl Ieee802154CommandPayload {
    /// The command identifier, or `None` for an [`Ieee802154CommandPayload::Unknown`]
    /// payload whose leading byte is not a recognized command id.
    pub fn command_id(&self) -> Option<Ieee802154CommandId> {
        Some(match self {
            Self::AssociationRequest(_) => Ieee802154CommandId::AssociationRequest,
            Self::AssociationResponse(_) => Ieee802154CommandId::AssociationResponse,
            Self::DisassociationNotification(_) => Ieee802154CommandId::DisassociationNotification,
            Self::DataRequest(_) => Ieee802154CommandId::DataRequest,
            Self::BeaconRequest(_) => Ieee802154CommandId::BeaconRequest,
            Self::Unknown(raw) => {
                return raw
                    .first()
                    .and_then(|&b| Ieee802154CommandId::try_from(b).ok());
            }
        })
    }

    /// Decode a MAC command frame payload (the command id byte followed by the command
    /// body). An unknown id or a body that fails to parse is preserved verbatim as
    /// [`Ieee802154CommandPayload::Unknown`].
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::try_parse(bytes).unwrap_or_else(|| {
            Self::Unknown(FrameBytes::from_slice(bytes).expect("a MAC command is frame-bounded"))
        })
    }

    fn try_parse(bytes: &[u8]) -> Option<Self> {
        let (&id_byte, body) = bytes.split_first()?;
        let id = Ieee802154CommandId::try_from(id_byte).ok()?;

        Some(match id {
            Ieee802154CommandId::AssociationRequest => {
                Self::AssociationRequest(AbstractBits::from_abstract_bytes(body).ok()?)
            }
            Ieee802154CommandId::AssociationResponse => {
                Self::AssociationResponse(AbstractBits::from_abstract_bytes(body).ok()?)
            }
            Ieee802154CommandId::DisassociationNotification => {
                Self::DisassociationNotification(AbstractBits::from_abstract_bytes(body).ok()?)
            }
            Ieee802154CommandId::DataRequest => {
                Self::DataRequest(AbstractBits::from_abstract_bytes(body).ok()?)
            }
            Ieee802154CommandId::BeaconRequest => {
                Self::BeaconRequest(AbstractBits::from_abstract_bytes(body).ok()?)
            }
            // Known command ids the stack does not implement are kept verbatim
            _ => return None,
        })
    }

    /// Encode into a MAC command frame payload: the command id byte followed by the body.
    pub fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        match self {
            Self::AssociationRequest(c) => {
                writer.push(Ieee802154CommandId::AssociationRequest as u8)?;
                writer.bits(c)
            }
            Self::AssociationResponse(c) => {
                writer.push(Ieee802154CommandId::AssociationResponse as u8)?;
                writer.bits(c)
            }
            Self::DisassociationNotification(c) => {
                writer.push(Ieee802154CommandId::DisassociationNotification as u8)?;
                writer.bits(c)
            }
            Self::DataRequest(c) => {
                writer.push(Ieee802154CommandId::DataRequest as u8)?;
                writer.bits(c)
            }
            Self::BeaconRequest(c) => {
                writer.push(Ieee802154CommandId::BeaconRequest as u8)?;
                writer.bits(c)
            }
            Self::Unknown(raw) => writer.extend(raw),
        }
    }

    pub fn to_bytes(&self) -> FrameBytes {
        let mut bytes = FrameBytes::new();
        self.serialize(&mut FrameWriter::new(&mut bytes, MAX_PHY_PACKET_SIZE))
            .expect("a MAC command is frame-bounded");
        bytes
    }
}

impl Ieee802154Frame<FrameBytes> {
    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 2 + 2 {
            return Err(ParseError::UnexpectedEnd {
                ty: "Ieee802154Frame",
            });
        }

        // No 802.15.4 frame exceeds the PHY packet size; a longer input parses
        // into a frame that cannot be re-serialized into the fixed scratch buffer
        if data.len() > MAX_PHY_PACKET_SIZE {
            return Err(ParseError::InvalidLength {
                ty: "Ieee802154Frame",
            });
        }

        let fcs = u16::from_le_bytes([data[data.len() - 2], data[data.len() - 1]]);
        let mut remaining = &data[..data.len() - 2];

        if Self::compute_fcs(remaining) != fcs {
            return Err(ParseError::InvalidFcs);
        }

        // Parse frame control
        let mut reader = BitReader::from(remaining);
        let frame_control = Ieee802154FrameControl::read_abstract_bits(&mut reader)?;
        remaining = &remaining[reader.bytes_read()..];

        // Parse sequence number
        let sequence_number = if frame_control.sequence_number_suppression {
            None
        } else {
            if remaining.is_empty() {
                return Err(ParseError::UnexpectedEnd {
                    ty: "Ieee802154 sequence number",
                });
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
                if !matches!(
                    header.frame_control.frame_version,
                    Ieee802154FrameVersion::Ieee2003 | Ieee802154FrameVersion::Ieee2006
                ) {
                    return Err(ParseError::Unsupported("Enhanced Beacon frame"));
                }

                if remaining.len() < 4 {
                    return Err(ParseError::UnexpectedEnd {
                        ty: "Ieee802154BeaconFrame",
                    });
                }
                let superframe_specification =
                    SuperframeSpecification::from_abstract_bytes(&remaining[..4])?;
                let gts_specification = remaining[2];
                let pending_address_specification = remaining[3];
                let beacon_payload =
                    FrameBytes::from_slice(&remaining[4..]).expect("the frame length was checked");

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
                let payload =
                    FrameBytes::from_slice(remaining).map_err(|_| ParseError::InvalidLength {
                        ty: "Ieee802154DataFrame payload",
                    })?;
                Ok(Self::Data(Ieee802154DataFrame {
                    header,
                    payload,
                    fcs,
                }))
            }
            Ieee802154FrameType::Ack => Ok(Self::Ack(Ieee802154AckFrame { header, fcs })),
            Ieee802154FrameType::Command => {
                if remaining.is_empty() {
                    return Err(ParseError::UnexpectedEnd {
                        ty: "Ieee802154 command ID",
                    });
                }

                Ok(Self::Command(Ieee802154CommandFrame {
                    header,
                    command_payload: Ieee802154CommandPayload::from_bytes(remaining),
                    fcs,
                }))
            }
        }
    }

    pub fn from_bytes_without_fcs(data: &[u8]) -> Result<Self, ParseError> {
        let mut data_with_fcs = Psdu::new();
        data_with_fcs
            .extend_from_slice(data)
            .and_then(|()| data_with_fcs.extend_from_slice(&Self::compute_fcs(data).to_le_bytes()))
            .map_err(|_| ParseError::InvalidLength {
                ty: "Ieee802154Frame",
            })?;

        Self::from_bytes(&data_with_fcs)
    }
}

impl<P: FramePayload> Ieee802154Frame<P> {
    /// Write the frame without its FCS, which the radio appends.
    pub fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        let header = self.header();

        writer.bits(&header.frame_control)?;

        if let Some(seq) = header.sequence_number {
            writer.push(seq)?;
        }

        if let Some(pan_id) = header.dest_pan_id {
            writer.extend(&pan_id.to_bytes())?;
        }
        if let Some(address) = &header.dest_address {
            match address {
                Ieee802154Address::Nwk(addr) => writer.extend(&addr.to_bytes())?,
                Ieee802154Address::Eui64(addr) => writer.extend(&addr.to_bytes())?,
            }
        }

        if !header.frame_control.pan_id_compression
            && let Some(pan_id) = header.src_pan_id
        {
            writer.extend(&pan_id.to_bytes())?;
        }

        if let Some(address) = &header.src_address {
            match address {
                Ieee802154Address::Nwk(addr) => writer.extend(&addr.to_bytes())?,
                Ieee802154Address::Eui64(addr) => writer.extend(&addr.to_bytes())?,
            }
        }

        match self {
            Self::Beacon(frame) => {
                writer.bits(&frame.superframe_specification)?;
                writer.push(frame.gts_specification)?;
                writer.push(frame.pending_address_specification)?;
                writer.extend(&frame.beacon_payload)
            }
            Self::Data(frame) => frame
                .payload
                .serialize(&mut writer.nested(MAX_MAC_PAYLOAD_SIZE)),
            Self::Ack(_) => Ok(()),
            Self::Command(frame) => frame.command_payload.serialize(writer),
        }
    }

    pub fn to_bytes_without_fcs(&self) -> Psdu {
        let mut psdu = Psdu::new();
        self.serialize(&mut FrameWriter::new(
            &mut psdu,
            MAX_PHY_PACKET_SIZE - FCS_LENGTH,
        ))
        .expect("the frame fits in a PSDU");
        psdu
    }

    pub fn to_bytes(&self) -> Psdu {
        let mut psdu = self.to_bytes_without_fcs();
        let fcs = Self::compute_fcs(&psdu).to_le_bytes();
        psdu.extend_from_slice(&fcs)
            .expect("room for the FCS was left");
        psdu
    }

    pub const fn header(&self) -> &Ieee802154FrameHeader {
        match self {
            Self::Beacon(frame) => &frame.header,
            Self::Data(frame) => &frame.header,
            Self::Ack(frame) => &frame.header,
            Self::Command(frame) => &frame.header,
        }
    }

    pub const fn header_mut(&mut self) -> &mut Ieee802154FrameHeader {
        match self {
            Self::Beacon(frame) => &mut frame.header,
            Self::Data(frame) => &mut frame.header,
            Self::Ack(frame) => &mut frame.header,
            Self::Command(frame) => &mut frame.header,
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
        let frame_control = Ieee802154FrameControl::from_abstract_bytes(&bytes).unwrap();
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
        assert_eq!(
            frame_control.frame_version,
            Ieee802154FrameVersion::Ieee2003
        );
        assert_eq!(frame_control.src_addr_mode, Ieee802154AddressingMode::Short);

        assert_eq!(remaining, [0xFF]);
        assert_eq!(frame_control.to_abstract_bytes().unwrap(), bytes[..2]);
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
            assert_eq!(
                data_frame.header.frame_control.frame_version,
                Ieee802154FrameVersion::Ieee2003
            );
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
        assert_eq!(err, ParseError::InvalidFcs);
    }

    #[test]
    fn test_frame_ack() {
        let bytes = [0x02, 0x00, 0xd1, 0xbc, 0x72];

        let frame = Ieee802154Frame::from_bytes(&bytes).unwrap();

        if let Ieee802154Frame::Ack(ack_frame) = frame {
            assert_eq!(
                ack_frame.header.frame_control.frame_version,
                Ieee802154FrameVersion::Ieee2003
            );
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

            let frame_again: Ieee802154Frame = Ieee802154Frame::Ack(ack_frame);
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
                    frame_version: Ieee802154FrameVersion::Ieee2003,
                    src_addr_mode: Ieee802154AddressingMode::Short,
                },
                sequence_number: Some(52),
                dest_pan_id: Some(PanId(0xBEEF)),
                dest_address: Some(Ieee802154Address::Nwk(Nwk(0x9D90))),
                src_pan_id: Some(PanId(0xBEEF)),
                src_address: Some(Ieee802154Address::Nwk(Nwk(0x3E44))),
            },
            payload: FrameBytes::from_slice(&hex!("48020000443e1eb4287cc54700e095dd0c018817000033a8fc4eb11941104ea261f13064f175f477d311e62736b708a6a390a4f8b120df6cd3ec5c24")).unwrap(),
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
                    frame_version: Ieee802154FrameVersion::Ieee2003,
                    src_addr_mode: Ieee802154AddressingMode::Short,
                },
                sequence_number: Some(3),
                dest_pan_id: Some(PanId(0x7240)),
                dest_address: Some(Ieee802154Address::Nwk(Nwk(0x26F4))),
                src_pan_id: Some(PanId(0x7240)),
                src_address: Some(Ieee802154Address::Nwk(Nwk(0x0000))),
            },
            payload: FrameBytes::from_slice(&hex!(
                "0802f42600001e03284975922d90db24feff6e02bc00e1ddd9ffbbc3dadee840b61bf2ef2b"
            ))
            .unwrap(),
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
                    frame_version: Ieee802154FrameVersion::Ieee2003,
                    src_addr_mode: Ieee802154AddressingMode::Short,
                },
                sequence_number: Some(3),
                dest_pan_id: Some(PanId(0x7240)),
                dest_address: Some(Ieee802154Address::Nwk(Nwk(0x26F4))),
                src_pan_id: Some(PanId(0x7240)),
                src_address: Some(Ieee802154Address::Nwk(Nwk(0x0000))),
            },
            payload: FrameBytes::from_slice(&hex!(
                "0802f42600001e03284975922d90db24feff6e02bc00e1ddd9ffbbc3dadee840b61bf2ef2b"
            ))
            .unwrap(),
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
                    frame_version: Ieee802154FrameVersion::Ieee2003,
                    src_addr_mode: Ieee802154AddressingMode::None,
                },
                sequence_number: Some(109),
                dest_pan_id: Some(PanId(0xFFFF)),
                dest_address: Some(Ieee802154Address::Nwk(Nwk(0xFFFF))),
                src_pan_id: None,
                src_address: None,
            },
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
                    frame_version: Ieee802154FrameVersion::Ieee2003,
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

        // BeaconRequest command (no payload)
        let beacon_req = Ieee802154CommandPayload::BeaconRequest(Ieee802154BeaconRequestCommand);
        assert_eq!(beacon_req.to_bytes(), [0x07]); // Command ID only
        assert_eq!(Ieee802154CommandPayload::from_bytes(&[0x07]), beacon_req);

        // DataRequest command (no payload)
        let data_req = Ieee802154CommandPayload::DataRequest(Ieee802154DataRequestCommand);
        assert_eq!(data_req.to_bytes(), [0x04]); // Command ID only
        assert_eq!(Ieee802154CommandPayload::from_bytes(&[0x04]), data_req);

        // DisassociationNotification command with typed reason
        let disassoc_notif = Ieee802154CommandPayload::DisassociationNotification(
            Ieee802154DisassociationNotificationCommand {
                disassociation_reason: Ieee802154DisassociationReason::CoordinatorWishesToLeave,
            },
        );
        assert_eq!(disassoc_notif.to_bytes(), [0x03, 0x01]); // Command ID + reason code
        assert_eq!(
            Ieee802154CommandPayload::from_bytes(&[0x03, 0x01]),
            disassoc_notif
        );

        // The other reason code
        let disassoc_notif2 = Ieee802154CommandPayload::DisassociationNotification(
            Ieee802154DisassociationNotificationCommand {
                disassociation_reason: Ieee802154DisassociationReason::DeviceWishesToLeave,
            },
        );
        assert_eq!(disassoc_notif2.to_bytes(), [0x03, 0x02]); // Command ID + reason code
        assert_eq!(
            Ieee802154CommandPayload::from_bytes(&[0x03, 0x02]),
            disassoc_notif2
        );

        // An unrecognized command id round-trips verbatim
        let unknown = Ieee802154CommandPayload::from_bytes(&[0xFF, 0xAA]);
        assert_eq!(
            unknown,
            Ieee802154CommandPayload::Unknown(FrameBytes::from_slice(&[0xFF, 0xAA]).unwrap())
        );
        assert_eq!(unknown.command_id(), None);
        assert_eq!(unknown.to_bytes(), [0xFF, 0xAA]);
    }
}
