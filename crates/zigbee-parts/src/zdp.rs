#![allow(clippy::useless_conversion)]

use crate::commands::NwkRejoinCapabilityInformation;
use crate::{DeserializeError, MAC_PAYLOAD_MAX_LEN, SerializeError};
use abstract_bits::{AbstractBits, BitReader, abstract_bits};
use ieee_802154::types::{Eui64, Nwk};
use num_enum::TryFromPrimitive;

/// The Zigbee Device Profile: ZDP commands are APS data frames exchanged between
/// endpoints 0 under this profile, with a transaction sequence number prefix.
pub const ZDP_PROFILE_ID: u16 = 0x0000;

/// Zigbee spec 2.4.3/2.4.4: ZDP cluster identifiers. Only the clusters the stack
/// itself consumes are listed; everything else is the client's business.
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u16)]
pub enum ZdpClusterId {
    DeviceAnnce = 0x0013,
    ParentAnnce = 0x001F,
    ParentAnnceRsp = 0x801F,
}

/// Zigbee spec Table 2-129 (partial): ZDP response status values.
#[abstract_bits(bits = 8)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum ZdpStatus {
    Success = 0x00,
    NotSupported = 0x84,
}

pub trait ZdpCommand: AbstractBits + Sized {
    const CLUSTER_ID: ZdpClusterId;

    fn serialize(&self, tsn: u8) -> Result<Vec<u8>, SerializeError> {
        serialize(self, tsn)
    }

    fn deserialize(bytes: &[u8]) -> Result<(u8, Self), DeserializeError> {
        deserialize(bytes)
    }
}

/// Zigbee spec 2.4.3.1.11: a device announces that it joined or rejoined, carrying
/// its address pair so the network can refresh stale address mappings.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeviceAnnce {
    pub nwk_addr: Nwk,
    pub ieee_addr: Eui64,
    pub capability: NwkRejoinCapabilityInformation,
}

impl ZdpCommand for DeviceAnnce {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::DeviceAnnce;
}

/// Zigbee spec 2.4.3.1.12: a router announces the end devices it parents, so other
/// routers can resolve conflicting child entries faster than by aging them out.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParentAnnce {
    #[abstract_bits(length_of = children)]
    number_of_children: u8,
    pub children: Vec<Eui64>,
}

impl ZdpCommand for ParentAnnce {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::ParentAnnce;
}

/// Zigbee spec 2.4.4.2.22: claims back announced children that the responder has
/// heard a keepalive from since its reboot.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParentAnnceRsp {
    pub status: ZdpStatus,
    #[abstract_bits(length_of = children)]
    number_of_children: u8,
    pub children: Vec<Eui64>,
}

impl ZdpCommand for ParentAnnceRsp {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::ParentAnnceRsp;
}

fn serialize<T: AbstractBits>(thing: &T, tsn: u8) -> Result<Vec<u8>, SerializeError> {
    let mut bytes = vec![0u8; MAC_PAYLOAD_MAX_LEN];
    bytes[0] = tsn;
    let mut writer = abstract_bits::BitWriter::from(&mut bytes[1..]);
    thing
        .write_abstract_bits(&mut writer)
        .map_err(|cause| SerializeError {
            ty: core::any::type_name::<T>(),
            cause,
        })?;
    let len = writer.bytes_written();
    bytes.truncate(len + 1); // +1 for the transaction sequence number
    Ok(bytes)
}

fn deserialize<T: AbstractBits>(bytes: &[u8]) -> Result<(u8, T), DeserializeError> {
    let [tsn, payload @ ..] = bytes else {
        return Err(DeserializeError::ZeroBytes);
    };

    let mut reader = BitReader::from(payload);
    let command =
        T::read_abstract_bits(&mut reader).map_err(|cause| DeserializeError::Payload {
            ty: core::any::type_name::<T>(),
            cause,
        })?;

    Ok((*tsn, command))
}
