use std::collections::VecDeque;
use tokio::time::Instant;

use ieee_802154::types::{Eui64, Nwk};

use super::{LINK_QUALITY_SAMPLES, NwkDeviceType, lqi_to_link_cost};

#[derive(Debug)]
pub struct TableEntry {
    pub extended_address: Eui64,
    pub network_address: Nwk,
    pub device_type: NwkDeviceType,
    pub rx_on_when_idle: bool,
    pub end_device_configuration: u16,

    /// The current time remaining, in seconds, for the end device
    pub timeout_at: Instant,
    /// max: 15728640 seconds, ~182 days

    /// This field indicates the timeout, in seconds, for the end device child
    pub device_timeout_at: Instant,
    /// max: 129600 seconds, 36 hours
    pub relationship: Relationship,

    /// A value indicating if previous transmissions to the device were successful or
    /// not. Higher values indicate more failures.
    pub transmit_failure: u8,
    pub lqas: VecDeque<u8>,
    /// TODO: replace with a fixed-size ring buffer

    /// The outgoing cost field contains the cost of the link as measured by the
    /// neighbor. The value is obtained from the most recent link status command frame
    /// received from the neighbor. A value of 0 indicates that no link status command
    /// listing this device has been received.
    pub outgoing_cost: u8,

    /// The number of [`nwkLinkStatusPeriod`] intervals that have passed since
    /// the last link status command frame was received, up to a maximum value
    /// of [`nwkRouterAgeLimit`]
    // Spec-expected field: `pub age: u8`, we instead keep track of a timestamp
    pub last_link_status_timestamp: Instant,

    pub incoming_beacon_timestamp: u32,
    pub beacon_transmission_time_offset: u32,

    /// This value indicates at least one keepalive has been received from the end device
    /// since the router has rebooted.
    pub keepalive_received: bool,
    /// pub mac_interface_index: u8,
    pub mac_unicast_bytes_transmitted: u32,
    pub mac_unicast_bytes_received: u32,

    /// The number of [`nwkLinkStatusPeriod`] intervals, which elapsed since this router
    /// neighbor was added to the neighbor table. This value is only maintained on
    /// routers and the coordinator and is only valid for entries with a relationship
    /// of ‘parent’, ‘sibling’ or ‘backbone mesh sibling’. This is a saturating
    /// up-counter, which does not roll-over.
    // Spec-expected field: `pub router_age: u16`, we instead keep track of a timestamp
    pub router_added_timestamp: Instant,

    pub router_connectivity: u8,
    pub router_neighbor_set_diversity: u8,
    pub router_outbound_activity: u8,
    pub router_inbound_activity: u8,
    pub security_timer: u8,
}

impl TableEntry {
    pub fn lqa(&self) -> Option<u8> {
        let num_samples = self.lqas.len();
        if num_samples < LINK_QUALITY_SAMPLES {
            return None;
        }

        let mut sorted_lqas = Vec::from(self.lqas.clone());
        sorted_lqas.sort_unstable();

        // Calculate median
        if num_samples % 2 == 1 {
            return Some(sorted_lqas[num_samples / 2]);
        } else {
            // Average of the two middle elements for even number of samples
            let mid1 = sorted_lqas[num_samples / 2 - 1];
            let mid2 = sorted_lqas[num_samples / 2];
            return Some(((mid1 as u16 + mid2 as u16) / 2) as u8);
        };
    }

    pub fn incoming_link_cost(&self) -> u8 {
        self.lqa().map_or(0, |lqa| lqi_to_link_cost(lqa))
    }
}

#[derive(Debug)]
pub enum Relationship {
    Parent = 0x00,
    Child = 0x01,
    Sibling = 0x02,
    NoneOfTheAbove = 0x03, // NotParentChildOrSibling?
    PreviousChild = 0x04,
    UnauthenticatedChild = 0x05,
    UnauthorizedChildWithRelayAllowed = 0x06,
    LostChild = 0x07,
    AddressConflictChild = 0x08,
    BackboneMeshSibling = 0x09,
}
