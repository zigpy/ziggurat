//! The ZCL global commands (ZCL 2.5) that a cluster with attributes must support:
//! reading, writing and discovering attributes, and the Default Response.

use abstract_bits::{AbstractBits, BitReader, abstract_bits};
use alloc::vec::Vec;
use num_enum::TryFromPrimitive;
use ziggurat_ieee_802154::{FrameWriter, TooLong};

use super::types::{AttributeValue, DataType};
use crate::ParseError;

/// ZCL Table 2-3: global command identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum GlobalCommandId {
    ReadAttributes = 0x00,
    ReadAttributesResponse = 0x01,
    WriteAttributes = 0x02,
    WriteAttributesUndivided = 0x03,
    WriteAttributesResponse = 0x04,
    WriteAttributesNoResponse = 0x05,
    ConfigureReporting = 0x06,
    ConfigureReportingResponse = 0x07,
    ReadReportingConfiguration = 0x08,
    ReadReportingConfigurationResponse = 0x09,
    ReportAttributes = 0x0A,
    DefaultResponse = 0x0B,
    DiscoverAttributes = 0x0C,
    DiscoverAttributesResponse = 0x0D,
    ReadAttributesStructured = 0x0E,
    WriteAttributesStructured = 0x0F,
    WriteAttributesStructuredResponse = 0x10,
    DiscoverCommandsReceived = 0x11,
    DiscoverCommandsReceivedResponse = 0x12,
    DiscoverCommandsGenerated = 0x13,
    DiscoverCommandsGeneratedResponse = 0x14,
    DiscoverAttributesExtended = 0x15,
    DiscoverAttributesExtendedResponse = 0x16,
}

/// ZCL Table 2-12 (partial): the status codes that are not deprecated.
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Success = 0x00,
    Failure = 0x01,
    NotAuthorized = 0x7E,
    MalformedCommand = 0x80,
    UnsupCommand = 0x81,
    InvalidField = 0x85,
    UnsupportedAttribute = 0x86,
    InvalidValue = 0x87,
    ReadOnly = 0x88,
    InsufficientSpace = 0x89,
    NotFound = 0x8B,
    UnreportableAttribute = 0x8C,
    InvalidDataType = 0x8D,
    InvalidSelector = 0x8E,
    Timeout = 0x94,
    UnsupportedCluster = 0xC3,
}

/// ZCL 2.5.1: the attribute identifiers to read. Each takes two bytes; a trailing
/// odd byte is ignored like any appended octets (ZCL 2.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadAttributes {
    pub attribute_ids: Vec<u16>,
}

impl ReadAttributes {
    pub fn parse(payload: &[u8]) -> Self {
        Self {
            attribute_ids: payload
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&id| u16::from_le_bytes(id))
                .collect(),
        }
    }
}

/// ZCL 2.5.2.1: one read attribute status record. The data type and value follow
/// only on success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadAttributeStatusRecord {
    pub attribute_id: u16,
    pub result: Result<AttributeValue, Status>,
}

impl ReadAttributeStatusRecord {
    pub fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        writer.extend(&self.attribute_id.to_le_bytes())?;

        match &self.result {
            Ok(value) => {
                writer.bits(&Status::Success)?;
                writer.bits(&value.data_type())?;
                value.serialize(writer)
            }
            Err(status) => writer.bits(status),
        }
    }
}

/// ZCL 2.5.3: one write attribute record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteAttributeRecord {
    pub attribute_id: u16,
    pub value: AttributeValue,
}

/// ZCL 2.5.3, 2.5.4, 2.5.6: the records of a Write Attributes command, in any variant.
///
/// A record of a data type we cannot parse makes the rest of the frame unreadable, so
/// the whole command fails to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteAttributes {
    pub records: Vec<WriteAttributeRecord>,
}

impl WriteAttributes {
    pub fn parse(mut payload: &[u8]) -> Result<Self, ParseError> {
        let mut records = Vec::new();

        while let Some(([id_low, id_high, data_type], rest)) = payload.split_first_chunk::<3>() {
            let data_type =
                DataType::try_from(*data_type).map_err(|_| ParseError::InvalidDiscriminant {
                    ty: "DataType",
                    got: *data_type,
                })?;
            let (value, rest) = AttributeValue::parse(data_type, rest)?;

            records.push(WriteAttributeRecord {
                attribute_id: u16::from_le_bytes([*id_low, *id_high]),
                value,
            });
            payload = rest;
        }

        Ok(Self { records })
    }
}

/// ZCL 2.5.5.1: one write attribute status record.
#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteAttributeStatusRecord {
    pub status: Status,
    pub attribute_id: u16,
}

/// ZCL 2.5.5: the failed writes. When every write succeeded the response carries a
/// single SUCCESS status without an attribute identifier (ZCL 2.5.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteAttributesResponse {
    pub failures: Vec<WriteAttributeStatusRecord>,
}

impl WriteAttributesResponse {
    pub fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        if self.failures.is_empty() {
            return writer.bits(&Status::Success);
        }

        for record in &self.failures {
            writer.bits(record)?;
        }

        Ok(())
    }
}

/// ZCL 2.5.13.
#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverAttributes {
    pub start_attribute_id: u16,
    pub maximum_attribute_ids: u8,
}

impl DiscoverAttributes {
    pub fn parse(payload: &[u8]) -> Result<Self, ParseError> {
        Ok(Self::read_abstract_bits(&mut BitReader::from(payload))?)
    }
}

/// ZCL 2.5.14.1: one discovered attribute.
#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeInformation {
    pub attribute_id: u16,
    pub data_type: DataType,
}

/// ZCL 2.5.14.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverAttributesResponse {
    pub discovery_complete: bool,
    pub attributes: Vec<AttributeInformation>,
}

impl DiscoverAttributesResponse {
    pub fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        writer.push(u8::from(self.discovery_complete))?;

        for attribute in &self.attributes {
            writer.bits(attribute)?;
        }

        Ok(())
    }
}

/// ZCL 2.5.12.
#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultResponse {
    pub command_id: u8,
    pub status: Status,
}

impl DefaultResponse {
    pub fn parse(payload: &[u8]) -> Result<Self, ParseError> {
        Ok(Self::read_abstract_bits(&mut BitReader::from(payload))?)
    }
}
