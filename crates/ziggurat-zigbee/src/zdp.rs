#![allow(clippy::useless_conversion)]
use alloc::vec::Vec;

use crate::nwk::commands::NwkRejoinCapabilityInformation;
use abstract_bits::{
    AbstractBits, BitReader, BitWriter, FromBytesError, ToBytesError, abstract_bits,
};
use num_enum::TryFromPrimitive;
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_ieee_802154::{FrameWriter, TooLong};

pub mod descriptors;

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

/// Zigbee spec 2.4.3/2.4.4: ZDP cluster identifiers
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u16)]
pub enum ZdpClusterId {
    NwkAddrReq = 0x0000,
    IeeeAddrReq = 0x0001,
    NodeDescReq = 0x0002,
    PowerDescReq = 0x0003,
    SimpleDescReq = 0x0004,
    ActiveEpReq = 0x0005,
    MatchDescReq = 0x0006,
    DeviceAnnce = 0x0013,
    ParentAnnce = 0x001F,
    MgmtLqiReq = 0x0031,
    MgmtRtgReq = 0x0032,
    MgmtBindReq = 0x0033,
    NwkAddrRsp = 0x8000,
    IeeeAddrRsp = 0x8001,
    NodeDescRsp = 0x8002,
    PowerDescRsp = 0x8003,
    SimpleDescRsp = 0x8004,
    ActiveEpRsp = 0x8005,
    MatchDescRsp = 0x8006,
    ParentAnnceRsp = 0x801F,
    MgmtLqiRsp = 0x8031,
    MgmtRtgRsp = 0x8032,
    MgmtBindRsp = 0x8033,
}

/// Zigbee spec Table 2-129 (partial): ZDP response status values.
#[abstract_bits(bits = 8)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum ZdpStatus {
    Success = 0x00,
    InvRequestType = 0x80,
    DeviceNotFound = 0x81,
    InvalidEp = 0x82,
    NotActive = 0x83,
    NotSupported = 0x84,
    NoDescriptor = 0x89,
}

/// The RequestType of a NWK_addr_req or IEEE_addr_req (spec Table 2-47).
pub const ADDR_REQUEST_SINGLE: u8 = 0x00;
pub const ADDR_REQUEST_EXTENDED: u8 = 0x01;

/// Zigbee spec 2.4.3.1.1: find the network address of a device by its IEEE address.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NwkAddrReq {
    pub ieee_addr: Eui64,
    pub request_type: u8,
    pub start_index: u8,
}

impl ZdpCommand for NwkAddrReq {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::NwkAddrReq;
}

/// Zigbee spec 2.4.3.1.2: find the IEEE address of a device by its network address.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IeeeAddrReq {
    pub nwk_addr_of_interest: Nwk,
    pub request_type: u8,
    pub start_index: u8,
}

impl ZdpCommand for IeeeAddrReq {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::IeeeAddrReq;
}

/// The tail of an extended address response: a page of the network addresses of the
/// responder's end device children.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AssociatedDevices {
    num_assoc_dev: u8,
    pub start_index: u8,
    #[abstract_bits(length_from = num_assoc_dev)]
    pub nwk_addr_assoc_dev_list: Vec<Nwk>,
}

/// The two address responses share one layout. The associated devices are present
/// only in an extended response, and no field says so: they are present when bytes
/// remain after the addresses. `abstract_bits` cannot express that, so the
/// serialization is written by hand.
macro_rules! address_response {
    ($(#[$doc:meta])* $name:ident, $cluster:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct $name {
            pub status: ZdpStatus,
            pub ieee_addr_remote_dev: Eui64,
            pub nwk_addr_remote_dev: Nwk,
            pub associated_devices: Option<AssociatedDevices>,
        }

        impl AbstractBits for $name {
            const MIN_BITS: usize = ZdpStatus::MIN_BITS + Eui64::MIN_BITS + Nwk::MIN_BITS;
            const MAX_BITS: usize = Self::MIN_BITS + AssociatedDevices::MAX_BITS;

            fn write_abstract_bits(&self, writer: &mut BitWriter) -> Result<(), ToBytesError> {
                self.status.write_abstract_bits(writer)?;
                self.ieee_addr_remote_dev.write_abstract_bits(writer)?;
                self.nwk_addr_remote_dev.write_abstract_bits(writer)?;
                if let Some(associated_devices) = &self.associated_devices {
                    associated_devices.write_abstract_bits(writer)?;
                }
                Ok(())
            }

            fn read_abstract_bits(reader: &mut BitReader) -> Result<Self, FromBytesError> {
                let status = ZdpStatus::read_abstract_bits(reader)?;
                let ieee_addr_remote_dev = Eui64::read_abstract_bits(reader)?;
                let nwk_addr_remote_dev = Nwk::read_abstract_bits(reader)?;
                let associated_devices = if reader.remaining_bits() > 0 {
                    Some(AssociatedDevices::read_abstract_bits(reader)?)
                } else {
                    None
                };

                Ok(Self {
                    status,
                    ieee_addr_remote_dev,
                    nwk_addr_remote_dev,
                    associated_devices,
                })
            }
        }

        impl ZdpCommand for $name {
            const CLUSTER_ID: ZdpClusterId = $cluster;
        }
    };
}

address_response!(
    /// Zigbee spec 2.4.4.2.1: the answer to a NWK_addr_req.
    NwkAddrRsp,
    ZdpClusterId::NwkAddrRsp
);

address_response!(
    /// Zigbee spec 2.4.4.2.2: the answer to an IEEE_addr_req.
    IeeeAddrRsp,
    ZdpClusterId::IeeeAddrRsp
);

/// Zigbee spec 2.4.3.1.3. An R23 sender appends TLVs, which are ignored.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NodeDescReq {
    pub nwk_addr_of_interest: Nwk,
}

impl ZdpCommand for NodeDescReq {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::NodeDescReq;
}

/// Zigbee spec 2.4.3.1.4.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PowerDescReq {
    pub nwk_addr_of_interest: Nwk,
}

impl ZdpCommand for PowerDescReq {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::PowerDescReq;
}

/// Zigbee spec 2.4.3.1.5.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SimpleDescReq {
    pub nwk_addr_of_interest: Nwk,
    pub endpoint: u8,
}

impl ZdpCommand for SimpleDescReq {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::SimpleDescReq;
}

/// Zigbee spec 2.4.3.1.6.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ActiveEpReq {
    pub nwk_addr_of_interest: Nwk,
}

impl ZdpCommand for ActiveEpReq {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::ActiveEpReq;
}

/// Zigbee spec 2.4.3.1.7: find the endpoints that serve or use any of the clusters.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MatchDescReq {
    pub nwk_addr_of_interest: Nwk,
    pub profile_id: u16,
    num_in_clusters: u8,
    #[abstract_bits(length_from = num_in_clusters)]
    pub in_cluster_list: Vec<u16>,
    num_out_clusters: u8,
    #[abstract_bits(length_from = num_out_clusters)]
    pub out_cluster_list: Vec<u16>,
}

impl ZdpCommand for MatchDescReq {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::MatchDescReq;
}

/// Zigbee spec Table 2-34: the logical type field of the node descriptor.
#[abstract_bits(bits = 3)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum LogicalType {
    Coordinator = 0b000,
    Router = 0b001,
    EndDevice = 0b010,
}

/// Zigbee spec Table 2-35: the frequency band field holds one bit per band.
pub const FREQUENCY_BAND_2400_MHZ: u8 = 0b01000;

/// Zigbee spec 2.3.2.3.10: the server mask of the node descriptor.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServerMask {
    pub primary_trust_center: bool,
    pub backup_trust_center: bool,
    reserved: u4,
    pub network_manager: bool,
    reserved: u2,
    pub stack_compliance_revision: u7,
}

/// Zigbee spec 2.3.2.3: the node descriptor.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NodeDescriptor {
    pub logical_type: LogicalType,
    pub complex_descriptor_available: bool,
    pub user_descriptor_available: bool,
    reserved: u3,
    pub aps_flags: u3,
    pub frequency_band: u5,
    pub mac_capability_flags: NwkRejoinCapabilityInformation,
    pub manufacturer_code: u16,
    pub maximum_buffer_size: u8,
    pub maximum_incoming_transfer_size: u16,
    pub server_mask: ServerMask,
    pub maximum_outgoing_transfer_size: u16,
    pub descriptor_capability_field: u8,
}

/// Zigbee spec 2.4.4.2.3. The descriptor is present only on success.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NodeDescRsp {
    pub status: ZdpStatus,
    pub nwk_addr_of_interest: Nwk,
    #[abstract_bits(presence_from = matches!(status, ZdpStatus::Success))]
    pub node_descriptor: Option<NodeDescriptor>,
}

impl ZdpCommand for NodeDescRsp {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::NodeDescRsp;
}

/// Zigbee spec 2.3.2.4: the power descriptor. Each field is a small enumeration or
/// bitmap; see Tables 2-36 to 2-39 for the values.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PowerDescriptor {
    pub current_power_mode: u4,
    pub available_power_sources: u4,
    pub current_power_source: u4,
    pub current_power_source_level: u4,
}

/// Zigbee spec 2.4.4.2.4. The descriptor is present only on success.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PowerDescRsp {
    pub status: ZdpStatus,
    pub nwk_addr_of_interest: Nwk,
    #[abstract_bits(presence_from = matches!(status, ZdpStatus::Success))]
    pub power_descriptor: Option<PowerDescriptor>,
}

impl ZdpCommand for PowerDescRsp {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::PowerDescRsp;
}

/// Zigbee spec 2.3.2.5: the simple descriptor of one endpoint.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SimpleDescriptor {
    pub endpoint: u8,
    pub profile_id: u16,
    pub device_id: u16,
    pub device_version: u4,
    reserved: u4,
    input_cluster_count: u8,
    #[abstract_bits(length_from = input_cluster_count)]
    pub input_clusters: Vec<u16>,
    output_cluster_count: u8,
    #[abstract_bits(length_from = output_cluster_count)]
    pub output_clusters: Vec<u16>,
}

impl SimpleDescriptor {
    /// The serialized length in bytes: the fixed fields, two count bytes, and two
    /// bytes per cluster.
    pub const fn length(&self) -> u8 {
        (8 + 2 * (self.input_clusters.len() + self.output_clusters.len())) as u8
    }
}

/// Zigbee spec 2.4.4.2.5. `length` is the descriptor's byte length, 0 when absent.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SimpleDescRsp {
    pub status: ZdpStatus,
    pub nwk_addr_of_interest: Nwk,
    pub length: u8,
    #[abstract_bits(presence_from = matches!(status, ZdpStatus::Success))]
    pub simple_descriptor: Option<SimpleDescriptor>,
}

impl ZdpCommand for SimpleDescRsp {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::SimpleDescRsp;
}

/// Zigbee spec 2.4.4.2.6.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ActiveEpRsp {
    pub status: ZdpStatus,
    pub nwk_addr_of_interest: Nwk,
    active_ep_count: u8,
    #[abstract_bits(length_from = active_ep_count)]
    pub active_ep_list: Vec<u8>,
}

impl ZdpCommand for ActiveEpRsp {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::ActiveEpRsp;
}

/// Zigbee spec 2.4.4.2.7.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MatchDescRsp {
    pub status: ZdpStatus,
    pub nwk_addr_of_interest: Nwk,
    match_length: u8,
    #[abstract_bits(length_from = match_length)]
    pub match_list: Vec<u8>,
}

impl ZdpCommand for MatchDescRsp {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::MatchDescRsp;
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

/// Zigbee spec 2.4.3.3.4: request a slice of the remote device's binding table.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MgmtBindReq {
    pub start_index: u8,
}

impl ZdpCommand for MgmtBindReq {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::MgmtBindReq;
}

/// Zigbee spec 2.4.4.3.4: a slice of our binding table. We keep no binding table, so
/// the binding descriptor list is always empty and left out.
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MgmtBindRsp {
    pub status: ZdpStatus,
    pub binding_table_entries: u8,
    pub start_index: u8,
    pub binding_table_list_count: u8,
}

impl ZdpCommand for MgmtBindRsp {
    const CLUSTER_ID: ZdpClusterId = ZdpClusterId::MgmtBindRsp;
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
