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
    MgmtLqiReq = 0x0031,
    MgmtRtgReq = 0x0032,
    ParentAnnceRsp = 0x801F,
    MgmtLqiRsp = 0x8031,
    MgmtRtgRsp = 0x8032,
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

/// Zigbee spec 2.4.3.3.2: request a slice of the remote device's neighbor table.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MgmtLqiReq {
    pub start_index: u8,
}

impl ZdpCommand for MgmtLqiReq {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::MgmtLqiReq;
}

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum ZdpDeviceType {
    Coordinator = 0x00,
    Router = 0x01,
    EndDevice = 0x02,
    Unknown = 0x03,
}

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum ZdpRxOnWhenIdle {
    Off = 0x00,
    On = 0x01,
    Unknown = 0x02,
}

/// The neighbor relationship as reported over ZDP: any relationship past Sibling is
/// reported as NoneOfTheAbove (spec 2.4.4.3.2.1).
#[abstract_bits(bits = 3)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum ZdpAffinity {
    Parent = 0x00,
    Child = 0x01,
    Sibling = 0x02,
    NoneOfTheAbove = 0x03,
}

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum ZdpPermitJoining {
    NotAccepting = 0x00,
    Accepting = 0x01,
    Unknown = 0x02,
}

/// Zigbee spec Table 2-102: one neighbor table record of a Mgmt_Lqi_rsp.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NeighborDescriptor {
    pub extended_pan_id: Eui64,
    pub extended_address: Eui64,
    pub network_address: Nwk,
    pub device_type: ZdpDeviceType,
    pub rx_on_when_idle: ZdpRxOnWhenIdle,
    pub affinity: ZdpAffinity,
    reserved: u1,
    pub permit_joining: ZdpPermitJoining,
    reserved: u6,
    pub depth: u8,
    pub lqa: u8,
}

/// Zigbee spec 2.4.4.3.2: a slice of our neighbor table.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MgmtLqiRsp {
    pub status: ZdpStatus,
    pub neighbor_table_entries: u8,
    pub start_index: u8,
    #[abstract_bits(length_of = neighbor_table_list)]
    neighbor_table_list_count: u8,
    pub neighbor_table_list: Vec<NeighborDescriptor>,
}

impl ZdpCommand for MgmtLqiRsp {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::MgmtLqiRsp;
}

/// Zigbee spec 2.4.3.3.3: request a slice of the remote device's routing table.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MgmtRtgReq {
    pub start_index: u8,
}

impl ZdpCommand for MgmtRtgReq {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::MgmtRtgReq;
}

#[abstract_bits(bits = 3)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum ZdpRouteStatus {
    Active = 0x00,
    DiscoveryUnderway = 0x01,
    DiscoveryFailed = 0x02,
    Inactive = 0x03,
}

/// Zigbee spec Table 2-104: one routing table record of a Mgmt_Rtg_rsp.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RoutingDescriptor {
    pub destination_address: Nwk,
    pub status: ZdpRouteStatus,
    pub memory_constrained: bool,
    pub many_to_one: bool,
    pub route_record_required: bool,
    reserved: u2,
    pub next_hop_address: Nwk,
}

/// Zigbee spec 2.4.4.3.3: a slice of our routing table.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MgmtRtgRsp {
    pub status: ZdpStatus,
    pub routing_table_entries: u8,
    pub start_index: u8,
    #[abstract_bits(length_of = routing_table_list)]
    routing_table_list_count: u8,
    pub routing_table_list: Vec<RoutingDescriptor>,
}

impl ZdpCommand for MgmtRtgRsp {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::MgmtRtgRsp;
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
