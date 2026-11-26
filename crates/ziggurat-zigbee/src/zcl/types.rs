//! ZCL data types (ZCL 2.6.2): the type identifiers carried next to attribute values,
//! and the values themselves. Only the types local attributes use are listed.

use abstract_bits::abstract_bits;
use alloc::vec::Vec;
use num_enum::TryFromPrimitive;
use ziggurat_ieee_802154::{FrameWriter, TooLong};

use crate::ParseError;

/// ZCL Table 2-11: data type identifiers.
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum DataType {
    Bool = 0x10,
    Map8 = 0x18,
    Map16 = 0x19,
    Uint8 = 0x20,
    Uint16 = 0x21,
    Uint32 = 0x23,
    Int8 = 0x28,
    Int16 = 0x29,
    Enum8 = 0x30,
    Enum16 = 0x31,
    OctetString = 0x41,
    CharacterString = 0x42,
}

/// An attribute value, tagged with its data type. Multi-byte values are little
/// endian; strings carry a one-byte length (ZCL 2.6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeValue {
    Bool(bool),
    Map8(u8),
    Map16(u16),
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Int8(i8),
    Int16(i16),
    Enum8(u8),
    Enum16(u16),
    /// `None` is the non-value.
    OctetString(Option<Vec<u8>>),
    /// The encoded characters, UTF-8 unless stated otherwise. `None` is the non-value.
    CharacterString(Option<Vec<u8>>),
}

/// ZCL 2.6.2.13, 2.6.2.14: a string length of 0xFF is the non-value, with no data.
const NON_VALUE_LENGTH: u8 = 0xFF;

impl AttributeValue {
    pub const fn data_type(&self) -> DataType {
        match self {
            Self::Bool(_) => DataType::Bool,
            Self::Map8(_) => DataType::Map8,
            Self::Map16(_) => DataType::Map16,
            Self::Uint8(_) => DataType::Uint8,
            Self::Uint16(_) => DataType::Uint16,
            Self::Uint32(_) => DataType::Uint32,
            Self::Int8(_) => DataType::Int8,
            Self::Int16(_) => DataType::Int16,
            Self::Enum8(_) => DataType::Enum8,
            Self::Enum16(_) => DataType::Enum16,
            Self::OctetString(_) => DataType::OctetString,
            Self::CharacterString(_) => DataType::CharacterString,
        }
    }

    /// Write the value alone, without its data type.
    pub fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        match self {
            Self::Bool(value) => writer.push(u8::from(*value)),
            Self::Map8(value) | Self::Uint8(value) | Self::Enum8(value) => writer.push(*value),
            Self::Map16(value) | Self::Uint16(value) | Self::Enum16(value) => {
                writer.extend(&value.to_le_bytes())
            }
            Self::Uint32(value) => writer.extend(&value.to_le_bytes()),
            Self::Int8(value) => writer.extend(&value.to_le_bytes()),
            Self::Int16(value) => writer.extend(&value.to_le_bytes()),
            Self::OctetString(None) | Self::CharacterString(None) => writer.push(NON_VALUE_LENGTH),
            Self::OctetString(Some(bytes)) | Self::CharacterString(Some(bytes)) => {
                let length = u8::try_from(bytes.len())
                    .ok()
                    .filter(|&length| length != NON_VALUE_LENGTH)
                    .ok_or(TooLong)?;
                writer.push(length)?;
                writer.extend(bytes)
            }
        }
    }

    /// Read a value of the given type off the front of `bytes`, returning it and the
    /// bytes after it.
    pub fn parse(data_type: DataType, bytes: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        Ok(match data_type {
            DataType::Bool => {
                let ([value], rest) = take(bytes)?;
                (Self::Bool(value != 0), rest)
            }
            DataType::Map8 => {
                let ([value], rest) = take(bytes)?;
                (Self::Map8(value), rest)
            }
            DataType::Uint8 => {
                let ([value], rest) = take(bytes)?;
                (Self::Uint8(value), rest)
            }
            DataType::Enum8 => {
                let ([value], rest) = take(bytes)?;
                (Self::Enum8(value), rest)
            }
            DataType::Int8 => {
                let (value, rest) = take(bytes)?;
                (Self::Int8(i8::from_le_bytes(value)), rest)
            }
            DataType::Map16 => {
                let (value, rest) = take(bytes)?;
                (Self::Map16(u16::from_le_bytes(value)), rest)
            }
            DataType::Uint16 => {
                let (value, rest) = take(bytes)?;
                (Self::Uint16(u16::from_le_bytes(value)), rest)
            }
            DataType::Enum16 => {
                let (value, rest) = take(bytes)?;
                (Self::Enum16(u16::from_le_bytes(value)), rest)
            }
            DataType::Int16 => {
                let (value, rest) = take(bytes)?;
                (Self::Int16(i16::from_le_bytes(value)), rest)
            }
            DataType::Uint32 => {
                let (value, rest) = take(bytes)?;
                (Self::Uint32(u32::from_le_bytes(value)), rest)
            }
            DataType::OctetString => {
                let (value, rest) = take_string(bytes)?;
                (Self::OctetString(value), rest)
            }
            DataType::CharacterString => {
                let (value, rest) = take_string(bytes)?;
                (Self::CharacterString(value), rest)
            }
        })
    }
}

fn take<const N: usize>(bytes: &[u8]) -> Result<([u8; N], &[u8]), ParseError> {
    let (value, rest) = bytes
        .split_first_chunk::<N>()
        .ok_or(ParseError::UnexpectedEnd {
            ty: "AttributeValue",
        })?;
    Ok((*value, rest))
}

/// A string with a one-byte length, or the non-value.
fn take_string(bytes: &[u8]) -> Result<(Option<Vec<u8>>, &[u8]), ParseError> {
    let ([length], rest) = take(bytes)?;

    if length == NON_VALUE_LENGTH {
        return Ok((None, rest));
    }

    let (value, rest) =
        rest.split_at_checked(usize::from(length))
            .ok_or(ParseError::UnexpectedEnd {
                ty: "AttributeValue",
            })?;
    Ok((Some(value.to_vec()), rest))
}
