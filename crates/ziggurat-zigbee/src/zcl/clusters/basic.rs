//! The Basic cluster server (ZCL 3.2): what the device is and how it is powered.

use alloc::vec::Vec;

use crate::Instant;
use crate::zcl::cluster::{Access, AttributeSpec, ClusterServer};
use crate::zcl::types::{AttributeValue, DataType};

pub const CLUSTER_ID: u16 = 0x0000;

/// ZCL 3.2.1.1: the newest revision in the cluster's revision history.
const CLUSTER_REVISION: u16 = 3;

/// The revision of the ZCL this implementation follows.
const ZCL_VERSION: u8 = 8;

const ZCL_VERSION_ATTRIBUTE_ID: u16 = 0x0000;
const MANUFACTURER_NAME_ATTRIBUTE_ID: u16 = 0x0004;
const MODEL_IDENTIFIER_ATTRIBUTE_ID: u16 = 0x0005;
const DATE_CODE_ATTRIBUTE_ID: u16 = 0x0006;
const POWER_SOURCE_ATTRIBUTE_ID: u16 = 0x0007;
const SW_BUILD_ID_ATTRIBUTE_ID: u16 = 0x4000;

/// ZCL Table 3-8: the primary power source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PowerSource {
    Unknown = 0x00,
    MainsSinglePhase = 0x01,
    MainsThreePhase = 0x02,
    Battery = 0x03,
    DcSource = 0x04,
    EmergencyMainsConstantlyPowered = 0x05,
    EmergencyMainsAndTransferSwitch = 0x06,
}

/// What a device reports about itself. The strings are optional attributes: one left
/// out is not supported, rather than reported empty.
#[derive(Debug, Clone)]
pub struct BasicInfo<'a> {
    pub power_source: PowerSource,
    /// ZCL 3.2.2.2.8: bit 7 of PowerSource, a battery backing the primary source.
    pub battery_backup: bool,
    /// At most 32 bytes.
    pub manufacturer_name: Option<&'a str>,
    /// At most 32 bytes.
    pub model_identifier: Option<&'a str>,
    /// At most 16 bytes.
    pub date_code: Option<&'a str>,
    /// At most 16 bytes.
    pub sw_build_id: Option<&'a str>,
}

#[derive(Debug)]
pub struct Basic {
    power_source: u8,
    /// The string attributes the device reports, by attribute identifier.
    strings: Vec<(u16, Vec<u8>)>,
    attributes: Vec<AttributeSpec>,
}

impl Basic {
    pub fn new(info: &BasicInfo) -> Self {
        let strings: Vec<(u16, Vec<u8>)> = [
            (MANUFACTURER_NAME_ATTRIBUTE_ID, info.manufacturer_name, 32),
            (MODEL_IDENTIFIER_ATTRIBUTE_ID, info.model_identifier, 32),
            (DATE_CODE_ATTRIBUTE_ID, info.date_code, 16),
            (SW_BUILD_ID_ATTRIBUTE_ID, info.sw_build_id, 16),
        ]
        .into_iter()
        .filter_map(|(id, value, max_length)| {
            value.map(|value| {
                assert!(
                    value.len() <= max_length,
                    "attribute {id:#06x} is longer than {max_length} bytes: {value:?}"
                );
                (id, value.as_bytes().to_vec())
            })
        })
        .collect();

        let mut attributes = Vec::from([
            AttributeSpec {
                id: ZCL_VERSION_ATTRIBUTE_ID,
                data_type: DataType::Uint8,
                access: Access::Read,
            },
            AttributeSpec {
                id: POWER_SOURCE_ATTRIBUTE_ID,
                data_type: DataType::Enum8,
                access: Access::Read,
            },
        ]);
        attributes.extend(strings.iter().map(|&(id, _)| AttributeSpec {
            id,
            data_type: DataType::CharacterString,
            access: Access::Read,
        }));

        Self {
            power_source: info.power_source as u8 | (u8::from(info.battery_backup) << 7),
            strings,
            attributes,
        }
    }
}

impl ClusterServer for Basic {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }

    fn revision(&self) -> u16 {
        CLUSTER_REVISION
    }

    fn attributes(&self) -> &[AttributeSpec] {
        &self.attributes
    }

    fn read(&self, attribute_id: u16, _now: Instant) -> AttributeValue {
        match attribute_id {
            ZCL_VERSION_ATTRIBUTE_ID => AttributeValue::Uint8(ZCL_VERSION),
            POWER_SOURCE_ATTRIBUTE_ID => AttributeValue::Enum8(self.power_source),
            _ => {
                let (_, value) = self
                    .strings
                    .iter()
                    .find(|(id, _)| *id == attribute_id)
                    .expect("only declared attributes are read");
                AttributeValue::CharacterString(Some(value.clone()))
            }
        }
    }
}
