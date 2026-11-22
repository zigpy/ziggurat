//! The ZCL general frame (ZCL 2.4): a header naming the command and how it was sent,
//! followed by the command's payload.

use abstract_bits::{AbstractBits, BitReader, abstract_bits};
use ziggurat_ieee_802154::{FrameWriter, TooLong};

use crate::ParseError;

/// ZCL 2.4.1.1.1: whether the command is one of the global commands or one specific
/// to the cluster.
#[abstract_bits(bits = 2)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Global = 0b00,
    ClusterSpecific = 0b01,
}

/// ZCL 2.4.1.1.3: which side of the cluster sent the command.
#[abstract_bits(bits = 1)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    ClientToServer = 0,
    ServerToClient = 1,
}

/// ZCL 2.4.1: the frame control field, the manufacturer code of a manufacturer
/// specific command, the transaction sequence number, and the command identifier.
/// Reserved frame control bits are ignored on receipt (ZCL 2.3.2).
#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZclHeader {
    pub frame_type: FrameType,
    manufacturer_specific: bool,
    pub direction: Direction,
    pub disable_default_response: bool,
    reserved: u3,
    #[abstract_bits(presence_from = manufacturer_specific)]
    pub manufacturer_code: Option<u16>,
    pub tsn: u8,
    pub command_id: u8,
}

impl ZclHeader {
    /// Split a ZCL frame into its header and payload. Bytes past the payload a
    /// command defines are left in the payload, for the command parser to ignore.
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        let mut reader = BitReader::from(bytes);
        let header = Self::read_abstract_bits(&mut reader)?;
        Ok((header, &bytes[reader.bytes_read()..]))
    }

    /// The header of a frame sent as the immediate effect of this one: the same
    /// transaction and manufacturer, the opposite direction, and no Default Response
    /// asked for (ZCL 2.4.1.1.4, 2.4.1.3).
    pub const fn response(&self, frame_type: FrameType, command_id: u8) -> Self {
        Self {
            frame_type,
            direction: match self.direction {
                Direction::ClientToServer => Direction::ServerToClient,
                Direction::ServerToClient => Direction::ClientToServer,
            },
            disable_default_response: true,
            manufacturer_code: self.manufacturer_code,
            tsn: self.tsn,
            command_id,
        }
    }

    pub fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        writer.bits(self)
    }
}
