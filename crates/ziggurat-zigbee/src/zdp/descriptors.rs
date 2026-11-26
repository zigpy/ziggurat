//! The local node's descriptors (spec 2.3.2), read by ZDP requests from other devices,
//! and the answers to those requests.
//!
//! Each answer is `None` when the request gets no response. A request about a device
//! we know nothing of gets an error status only when it was unicast to us; answering
//! a broadcast with an error would have every router respond.

use alloc::vec::Vec;

use ziggurat_ieee_802154::types::{Eui64, Nwk};

use super::{
    ADDR_REQUEST_EXTENDED, ADDR_REQUEST_SINGLE, ActiveEpReq, ActiveEpRsp, AssociatedDevices,
    FREQUENCY_BAND_2400_MHZ, IeeeAddrReq, IeeeAddrRsp, LogicalType, MatchDescReq, MatchDescRsp,
    NodeDescReq, NodeDescRsp, NodeDescriptor, NwkAddrReq, NwkAddrRsp, PowerDescReq, PowerDescRsp,
    PowerDescriptor, ServerMask, SimpleDescReq, SimpleDescRsp, SimpleDescriptor, ZdpStatus,
};
use crate::nwk::NwkDeviceType;
use crate::nwk::commands::{
    NwkRejoinCapabilityInformation, NwkRejoinCapabilityInformationDeviceType,
    NwkRejoinCapabilityInformationPowerSource,
};
use crate::nwk::frame::is_broadcast;
use crate::nwk::neighbors::Neighbors;

/// The manufacturer code reported when no table entry matches: the Open Home
/// Foundation's.
pub const DEFAULT_MANUFACTURER_CODE: u16 = 0x134B;

/// The stack compliance revision in our server mask. Joiners read it to decide on the
/// trust center link key exchange (BDB 9.3).
const STACK_COMPLIANCE_REVISION: u8 = 22;

/// End device child addresses per extended address response, keeping the ASDU within
/// the NWK payload budget.
const ASSOCIATED_DEVICES_PER_FRAME: usize = 30;

/// Profile ID 0xFFFF in a Match_Desc_req matches every profile (spec 2.4.3.1.7.1).
const WILDCARD_PROFILE_ID: u16 = 0xFFFF;

/// Spec 2.3.2.4: mains powered, receiver on as the node descriptor says.
const POWER_DESCRIPTOR: PowerDescriptor = PowerDescriptor {
    current_power_mode: 0b0000,
    available_power_sources: 0b0001,
    current_power_source: 0b0001,
    current_power_source_level: 0b1100,
};

/// A manufacturer code reported to the devices whose EUI64 starts with `prefix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManufacturerCode {
    /// The leading EUI64 bytes, most significant first, as in `54:EF:44`. An empty
    /// prefix matches every device.
    pub prefix: Vec<u8>,
    pub code: u16,
}

/// The local node as ZDP describes it: its addresses and role, its endpoints, and the
/// manufacturer codes it reports.
#[derive(Debug)]
pub struct Descriptors {
    nwk: Nwk,
    ieee: Eui64,
    role: NwkDeviceType,
    /// Sorted by endpoint.
    endpoints: Vec<SimpleDescriptor>,
    manufacturer_codes: Vec<ManufacturerCode>,
}

impl Descriptors {
    pub const fn new(nwk: Nwk, ieee: Eui64, role: NwkDeviceType) -> Self {
        Self {
            nwk,
            ieee,
            role,
            endpoints: Vec::new(),
            manufacturer_codes: Vec::new(),
        }
    }

    /// Register an endpoint, replacing an earlier descriptor for the same endpoint.
    pub fn add_endpoint(&mut self, descriptor: SimpleDescriptor) {
        match self
            .endpoints
            .binary_search_by_key(&descriptor.endpoint, |existing| existing.endpoint)
        {
            Ok(index) => self.endpoints[index] = descriptor,
            Err(index) => self.endpoints.insert(index, descriptor),
        }
    }

    /// Replace the whole manufacturer code table.
    pub fn set_manufacturer_codes(&mut self, codes: Vec<ManufacturerCode>) {
        self.manufacturer_codes = codes;
    }

    /// The manufacturer code to report to a device: the entry with the longest prefix
    /// of its EUI64. A device whose EUI64 is unknown matches only an empty prefix.
    #[allow(clippy::option_if_let_else)]
    pub fn manufacturer_code(&self, requester: Option<Eui64>) -> u16 {
        let requester = requester.map(|eui64| {
            let mut bytes = eui64.0;
            bytes.reverse();
            bytes
        });

        self.manufacturer_codes
            .iter()
            .filter(|entry| match requester {
                Some(bytes) => bytes.starts_with(&entry.prefix),
                None => entry.prefix.is_empty(),
            })
            .max_by_key(|entry| entry.prefix.len())
            .map_or(DEFAULT_MANUFACTURER_CODE, |entry| entry.code)
    }

    /// Spec 2.3.2.3: our node descriptor. The buffer sizes describe no APS
    /// fragmentation.
    pub fn node_descriptor(&self, manufacturer_code: u16) -> NodeDescriptor {
        NodeDescriptor {
            logical_type: match self.role {
                NwkDeviceType::Coordinator => LogicalType::Coordinator,
                NwkDeviceType::Router => LogicalType::Router,
                NwkDeviceType::EndDevice => LogicalType::EndDevice,
            },
            complex_descriptor_available: false,
            user_descriptor_available: false,
            aps_flags: 0,
            frequency_band: FREQUENCY_BAND_2400_MHZ,
            mac_capability_flags: NwkRejoinCapabilityInformation {
                alternate_pan_coordinator: false,
                device_type: match self.role {
                    NwkDeviceType::EndDevice => NwkRejoinCapabilityInformationDeviceType::EndDevice,
                    NwkDeviceType::Coordinator | NwkDeviceType::Router => {
                        NwkRejoinCapabilityInformationDeviceType::Router
                    }
                },
                power_source: NwkRejoinCapabilityInformationPowerSource::MainsPowered,
                receiver_on_when_idle: true,
                reserved1: 0,
                reserved2: 0,
                security_capability: false,
                allocate_address: true,
            },
            manufacturer_code,
            maximum_buffer_size: 82,
            maximum_incoming_transfer_size: 128,
            server_mask: ServerMask {
                primary_trust_center: self.role == NwkDeviceType::Coordinator,
                backup_trust_center: false,
                network_manager: false,
                stack_compliance_revision: STACK_COMPLIANCE_REVISION,
            },
            maximum_outgoing_transfer_size: 128,
            descriptor_capability_field: 0,
        }
    }

    /// Spec 2.4.3.1.1.2: answer for ourselves or for one of our end device children.
    pub fn nwk_addr_rsp(
        &self,
        request: &NwkAddrReq,
        neighbors: &Neighbors,
        broadcast: bool,
    ) -> Option<NwkAddrRsp> {
        let (nwk, is_local) = if request.ieee_addr == self.ieee {
            (self.nwk, true)
        } else if let Some(nwk) = neighbors.end_device_child_nwk(request.ieee_addr) {
            (nwk, false)
        } else if broadcast {
            return None;
        } else {
            return Some(NwkAddrRsp {
                status: ZdpStatus::DeviceNotFound,
                ieee_addr_remote_dev: request.ieee_addr,
                nwk_addr_remote_dev: Nwk(0xFFFF),
                associated_devices: None,
            });
        };

        if !matches!(
            request.request_type,
            ADDR_REQUEST_SINGLE | ADDR_REQUEST_EXTENDED
        ) {
            if broadcast {
                return None;
            }

            return Some(NwkAddrRsp {
                status: ZdpStatus::InvRequestType,
                ieee_addr_remote_dev: request.ieee_addr,
                nwk_addr_remote_dev: nwk,
                associated_devices: None,
            });
        }

        Some(NwkAddrRsp {
            status: ZdpStatus::Success,
            ieee_addr_remote_dev: request.ieee_addr,
            nwk_addr_remote_dev: nwk,
            associated_devices: address_tail(
                neighbors,
                request.request_type,
                request.start_index,
                is_local,
            ),
        })
    }

    /// Spec 2.4.3.1.2.2: answer for ourselves or for one of our end device children.
    pub fn ieee_addr_rsp(
        &self,
        request: &IeeeAddrReq,
        neighbors: &Neighbors,
        broadcast: bool,
    ) -> Option<IeeeAddrRsp> {
        let nwk = request.nwk_addr_of_interest;

        let (ieee, is_local) = if nwk == self.nwk {
            (self.ieee, true)
        } else if let Some(ieee) = neighbors.end_device_child_eui64(nwk) {
            (ieee, false)
        } else if broadcast {
            return None;
        } else {
            return Some(IeeeAddrRsp {
                status: ZdpStatus::DeviceNotFound,
                ieee_addr_remote_dev: Eui64([0xFF; 8]),
                nwk_addr_remote_dev: nwk,
                associated_devices: None,
            });
        };

        if !matches!(
            request.request_type,
            ADDR_REQUEST_SINGLE | ADDR_REQUEST_EXTENDED
        ) {
            if broadcast {
                return None;
            }

            return Some(IeeeAddrRsp {
                status: ZdpStatus::InvRequestType,
                ieee_addr_remote_dev: self.ieee,
                nwk_addr_remote_dev: self.nwk,
                associated_devices: None,
            });
        }

        Some(IeeeAddrRsp {
            status: ZdpStatus::Success,
            ieee_addr_remote_dev: ieee,
            nwk_addr_remote_dev: nwk,
            associated_devices: address_tail(
                neighbors,
                request.request_type,
                request.start_index,
                is_local,
            ),
        })
    }

    /// Spec 2.4.4.2.3. The manufacturer code depends on the requester (`requester` is
    /// its EUI64, if known): some devices finish joining only if they see their own
    /// vendor's.
    pub fn node_desc_rsp(
        &self,
        request: &NodeDescReq,
        neighbors: &Neighbors,
        broadcast: bool,
        requester: Option<Eui64>,
    ) -> Option<NodeDescRsp> {
        let nwk = request.nwk_addr_of_interest;

        if nwk == self.nwk {
            return Some(NodeDescRsp {
                status: ZdpStatus::Success,
                nwk_addr_of_interest: nwk,
                node_descriptor: Some(self.node_descriptor(self.manufacturer_code(requester))),
            });
        }

        (!broadcast).then(|| NodeDescRsp {
            status: self.other_device_status(nwk, neighbors),
            nwk_addr_of_interest: nwk,
            node_descriptor: None,
        })
    }

    /// Spec 2.4.4.2.4.1.
    pub fn power_desc_rsp(
        &self,
        request: &PowerDescReq,
        neighbors: &Neighbors,
        broadcast: bool,
    ) -> Option<PowerDescRsp> {
        let nwk = request.nwk_addr_of_interest;

        if nwk == self.nwk {
            return Some(PowerDescRsp {
                status: ZdpStatus::Success,
                nwk_addr_of_interest: nwk,
                power_descriptor: Some(POWER_DESCRIPTOR),
            });
        }

        (!broadcast).then(|| PowerDescRsp {
            status: self.other_device_status(nwk, neighbors),
            nwk_addr_of_interest: nwk,
            power_descriptor: None,
        })
    }

    /// Spec 2.4.4.2.6.1. We keep no discovery cache, so other devices are not found.
    pub fn active_ep_rsp(&self, request: &ActiveEpReq, broadcast: bool) -> Option<ActiveEpRsp> {
        let nwk = request.nwk_addr_of_interest;

        if nwk == self.nwk {
            return Some(ActiveEpRsp {
                status: ZdpStatus::Success,
                nwk_addr_of_interest: nwk,
                active_ep_list: self
                    .endpoints
                    .iter()
                    .map(|descriptor| descriptor.endpoint)
                    .collect(),
            });
        }

        (!broadcast).then(|| ActiveEpRsp {
            status: if self.role == NwkDeviceType::EndDevice {
                ZdpStatus::InvRequestType
            } else {
                ZdpStatus::DeviceNotFound
            },
            nwk_addr_of_interest: nwk,
            active_ep_list: Vec::new(),
        })
    }

    /// Spec 2.4.4.2.5.1.
    #[allow(clippy::option_if_let_else)]
    pub fn simple_desc_rsp(
        &self,
        request: &SimpleDescReq,
        neighbors: &Neighbors,
        broadcast: bool,
    ) -> Option<SimpleDescRsp> {
        let nwk = request.nwk_addr_of_interest;
        let failure = |status| SimpleDescRsp {
            status,
            nwk_addr_of_interest: nwk,
            length: 0,
            simple_descriptor: None,
        };

        if nwk != self.nwk {
            return (!broadcast).then(|| failure(self.other_device_status(nwk, neighbors)));
        }

        if !(1..=254).contains(&request.endpoint) {
            return Some(failure(ZdpStatus::InvalidEp));
        }

        let descriptor = self
            .endpoints
            .iter()
            .find(|descriptor| descriptor.endpoint == request.endpoint);

        Some(match descriptor {
            Some(descriptor) => SimpleDescRsp {
                status: ZdpStatus::Success,
                nwk_addr_of_interest: nwk,
                length: descriptor.length(),
                simple_descriptor: Some(descriptor.clone()),
            },
            None => failure(ZdpStatus::NotActive),
        })
    }

    /// Spec 2.4.4.2.7.1.
    pub fn match_desc_rsp(
        &self,
        request: &MatchDescReq,
        neighbors: &Neighbors,
        broadcast: bool,
    ) -> Option<MatchDescRsp> {
        let nwk = request.nwk_addr_of_interest;

        if nwk != self.nwk && !is_broadcast(nwk) {
            // We keep no descriptors of our children, so nothing of theirs can match
            return (!broadcast).then(|| MatchDescRsp {
                status: self.other_device_status(nwk, neighbors),
                nwk_addr_of_interest: nwk,
                match_list: Vec::new(),
            });
        }

        let match_list: Vec<u8> = self
            .endpoints
            .iter()
            .filter(|descriptor| descriptor_matches(descriptor, request))
            .map(|descriptor| descriptor.endpoint)
            .collect();

        if match_list.is_empty() && broadcast {
            return None;
        }

        Some(MatchDescRsp {
            status: ZdpStatus::Success,
            nwk_addr_of_interest: self.nwk,
            match_list,
        })
    }

    /// The status for a descriptor request about another device (spec 2.4.4.2.4.1). We
    /// keep no descriptors of our children.
    fn other_device_status(&self, nwk: Nwk, neighbors: &Neighbors) -> ZdpStatus {
        if self.role == NwkDeviceType::EndDevice {
            ZdpStatus::InvRequestType
        } else if neighbors.end_device_child_eui64(nwk).is_some() {
            ZdpStatus::NoDescriptor
        } else {
            ZdpStatus::DeviceNotFound
        }
    }
}

/// The associated devices of an address response, if extended: a page of our end
/// device children's addresses. An end device child has none of its own.
fn address_tail(
    neighbors: &Neighbors,
    request_type: u8,
    start_index: u8,
    is_local: bool,
) -> Option<AssociatedDevices> {
    if request_type != ADDR_REQUEST_EXTENDED {
        return None;
    }

    let page = if is_local {
        neighbors
            .end_device_child_addresses()
            .into_iter()
            .skip(usize::from(start_index))
            .take(ASSOCIATED_DEVICES_PER_FRAME)
            .collect()
    } else {
        Vec::new()
    };

    Some(AssociatedDevices {
        start_index,
        nwk_addr_assoc_dev_list: page,
    })
}

/// Spec 2.4.4.2.7.2: the profile matches, and any requested input or output cluster
/// is one the endpoint has on the same side.
fn descriptor_matches(descriptor: &SimpleDescriptor, request: &MatchDescReq) -> bool {
    (request.profile_id == WILDCARD_PROFILE_ID || request.profile_id == descriptor.profile_id)
        && (request
            .in_cluster_list
            .iter()
            .any(|cluster| descriptor.input_clusters.contains(cluster))
            || request
                .out_cluster_list
                .iter()
                .any(|cluster| descriptor.output_clusters.contains(cluster)))
}
