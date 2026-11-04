#![allow(clippy::useless_conversion)]
use alloc::vec;
use alloc::vec::Vec;

use crate::nwk::commands::NwkRejoinCapabilityInformation;
use abstract_bits::{AbstractBits, BitReader, abstract_bits};
use num_enum::TryFromPrimitive;
use ziggurat_ieee_802154::types::{Eui64, Nwk};

/// 802.15.4 mac layer has a maximum payload length of 104 bytes
const MAC_PAYLOAD_MAX_LEN: usize = 104;

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
    #[error("Got zero bytes, no valid command/request/response is zero bytes")]
    ZeroBytes,
}

/// The Zigbee Device Profile: ZDP commands are APS data frames exchanged between
/// endpoints 0 under this profile, with a transaction sequence number prefix.
pub const ZDP_PROFILE_ID: u16 = 0x0000;

/// Zigbee spec 2.4.3/2.4.4: ZDP cluster identifiers. Only the clusters the stack
/// itself consumes are listed; everything else is the client's business.
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u16)]
pub enum ZdpClusterId {
    NodeDescReq = 0x0002,
    DeviceAnnce = 0x0013,
    ParentAnnce = 0x001F,
    MgmtLqiReq = 0x0031,
    MgmtRtgReq = 0x0032,
    NodeDescRsp = 0x8002,
    ParentAnnceRsp = 0x801F,
    MgmtLqiRsp = 0x8031,
    MgmtRtgRsp = 0x8032,
}

/// Zigbee spec 2.4.3.1.2: request the node descriptor for a network address.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NodeDescReq {
    pub nwk_addr_of_interest: Nwk,
}

impl ZdpCommand for NodeDescReq {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::NodeDescReq;
}

/// Stack-compliance revision advertised by this implementation.
pub const STACK_COMPLIANCE_REVISION: u8 = 22;

/// Zigbee spec 2.3.2.3: the coordinator's node descriptor.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NodeDescriptor {
    logical_type_and_flags: u8,
    aps_flags_and_frequency_band: u8,
    mac_capability_flags: u8,
    manufacturer_code: u16,
    maximum_buffer_size: u8,
    maximum_incoming_transfer_size: u16,
    server_mask: u16,
    maximum_outgoing_transfer_size: u16,
    descriptor_capability_field: u8,
}

impl NodeDescriptor {
    /// Describe a 2.4 GHz coordinator that owns the primary Trust Center.
    pub const fn coordinator() -> Self {
        Self {
            // Logical type Coordinator; no complex or user descriptor.
            logical_type_and_flags: 0x00,
            // APS flags 0; 2.4 GHz frequency band.
            aps_flags_and_frequency_band: 0x40,
            // Alternate PAN coordinator, FFD, mains powered, receiver on while idle,
            // security capable, and able to allocate addresses.
            mac_capability_flags: 0x8f,
            manufacturer_code: 0x0000,
            maximum_buffer_size: 82,
            maximum_incoming_transfer_size: 82,
            // Primary Trust Center (bit 0); stack compliance revision in bits 9..15.
            server_mask: 0x0001 | ((STACK_COMPLIANCE_REVISION as u16) << 9),
            maximum_outgoing_transfer_size: 82,
            descriptor_capability_field: 0x00,
        }
    }
}

/// Zigbee spec 2.4.4.1.2: successful node descriptor response.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NodeDescRsp {
    pub status: ZdpStatus,
    pub nwk_addr_of_interest: Nwk,
    pub node_descriptor: NodeDescriptor,
}

impl ZdpCommand for NodeDescRsp {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::NodeDescRsp;
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
    number_of_children: u8,
    #[abstract_bits(length_from = number_of_children)]
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
    number_of_children: u8,
    #[abstract_bits(length_from = number_of_children)]
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
    neighbor_table_list_count: u8,
    #[abstract_bits(length_from = neighbor_table_list_count)]
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
    routing_table_list_count: u8,
    #[abstract_bits(length_from = routing_table_list_count)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_descriptor_request_round_trips() {
        let request = NodeDescReq {
            nwk_addr_of_interest: Nwk(0x0000),
        };

        let encoded = request.serialize(0x27).unwrap();
        assert_eq!(encoded, [0x27, 0x00, 0x00]);
        assert_eq!(NodeDescReq::deserialize(&encoded).unwrap(), (0x27, request));
    }

    #[test]
    fn coordinator_node_descriptor_advertises_r22_trust_center() {
        let response = NodeDescRsp {
            status: ZdpStatus::Success,
            nwk_addr_of_interest: Nwk(0x0000),
            node_descriptor: NodeDescriptor::coordinator(),
        };

        assert_eq!(
            response.serialize(0x27).unwrap(),
            [
                0x27, 0x00, 0x00, 0x00, 0x00, 0x40, 0x8f, 0x00, 0x00, 0x52, 0x52, 0x00, 0x01, 0x2c,
                0x52, 0x00, 0x00,
            ]
        );
    }
}
