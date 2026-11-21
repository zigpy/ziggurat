//! ZDP device and service discovery (spec 2.4.3.1): the descriptors of the local node
//! that requests from other devices read.

use alloc::vec::Vec;

use ziggurat_ieee_802154::types::Eui64;

use crate::zdp::SimpleDescriptor;

/// The manufacturer code reported when no table entry matches: the Open Home
/// Foundation's.
pub const DEFAULT_MANUFACTURER_CODE: u16 = 0x134B;

/// A manufacturer code reported to the devices whose EUI64 starts with `prefix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManufacturerCode {
    /// The leading EUI64 bytes, most significant first, as in `54:EF:44`. An empty
    /// prefix matches every device.
    pub prefix: Vec<u8>,
    pub code: u16,
}

/// The local node's endpoints and the manufacturer codes it reports.
#[derive(Debug, Default)]
pub struct Descriptors {
    /// Sorted by endpoint.
    endpoints: Vec<SimpleDescriptor>,
    manufacturer_codes: Vec<ManufacturerCode>,
}

impl Descriptors {
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

    /// The registered endpoints, in ascending order.
    pub fn endpoints(&self) -> impl Iterator<Item = &SimpleDescriptor> {
        self.endpoints.iter()
    }

    pub fn endpoint(&self, endpoint: u8) -> Option<&SimpleDescriptor> {
        self.endpoints
            .iter()
            .find(|descriptor| descriptor.endpoint == endpoint)
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
}
