#![allow(clippy::useless_conversion)]
use alloc::vec::Vec;

use crate::nwk::commands::NwkRejoinCapabilityInformation;
use abstract_bits::{AbstractBits, BitReader, abstract_bits};
use num_enum::TryFromPrimitive;
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_ieee_802154::{FrameWriter, TooLong};

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

    fn serialize(&self, tsn: u8, writer: &mut FrameWriter) -> Result<(), TooLong> {
        writer.push(tsn)?;
        writer.bits(self)
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

/// Spec 2.4.4.3.2 / 2.4.4.3.3: one page of a Mgmt_Lqi_rsp or Mgmt_Rtg_rsp table.
///
/// Returns the table size to report and at most `per_frame` records from
/// `start_index`. The size field is a byte wide and describes at most 255 entries, so
/// a larger table is reported as its first 255: the size saturates instead of
/// wrapping, and no page reaches past the size it reports.
pub fn mgmt_table_page<T>(entries: &[T], start_index: u8, per_frame: usize) -> (u8, &[T]) {
    let total = u8::try_from(entries.len()).unwrap_or(u8::MAX);
    let reported = &entries[..usize::from(total)];
    let rest = reported.get(usize::from(start_index)..).unwrap_or(&[]);

    (total, &rest[..rest.len().min(per_frame)])
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
    fn mgmt_table_page_slices_from_the_start_index() {
        let entries: Vec<u16> = (0..5).collect();

        assert_eq!(mgmt_table_page(&entries, 0, 2), (5, &entries[0..2]));
        assert_eq!(mgmt_table_page(&entries, 4, 2), (5, &entries[4..5]));
        // A start index at or past the end is an empty page, not an error
        assert_eq!(mgmt_table_page(&entries, 5, 2), (5, &entries[5..5]));
        assert_eq!(mgmt_table_page(&entries, 200, 2), (5, &entries[5..5]));
    }

    #[test]
    fn mgmt_table_page_keeps_a_255_entry_table_whole() {
        let entries: Vec<u16> = (0..255).collect();

        assert_eq!(
            mgmt_table_page(&entries, 250, 10),
            (255, &entries[250..255])
        );
        assert_eq!(mgmt_table_page(&entries, 255, 10), (255, &entries[255..]));
    }

    #[test]
    fn mgmt_table_page_saturates_a_table_past_255_entries() {
        // 256 entries would wrap to 0 in a byte: an empty table to the client
        let entries: Vec<u16> = (0..256).collect();
        assert_eq!(mgmt_table_page(&entries, 0, 2), (255, &entries[0..2]));
        assert_eq!(mgmt_table_page(&entries, 254, 2), (255, &entries[254..255]));

        let entries: Vec<u16> = (0..260).collect();

        // 260 entries would wrap to 4 in a byte, ending a paging client's scan early
        assert_eq!(mgmt_table_page(&entries, 0, 10), (255, &entries[0..10]));
        // No page reaches past the reported size
        assert_eq!(
            mgmt_table_page(&entries, 250, 10),
            (255, &entries[250..255])
        );
        assert_eq!(
            mgmt_table_page(&entries, 255, 10),
            (255, &entries[255..255])
        );
    }
}
