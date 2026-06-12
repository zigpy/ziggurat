use std::cmp;
use std::collections::{HashMap, HashSet, VecDeque};

use ieee_802154::types::{Eui64, Nwk};
use tokio::time::{Duration, Instant};
use zigbee::nwk::commands::{NwkLinkStatus, NwkLinkStatusCommand};

use super::NwkDeviceType;

// The number of the most recent samples taken into consideration SHOULD be n = 3, which
// eliminates single outliers maintains a fast response to real changes in link quality,
// and keeps memory requirements to a minimum.
const LINK_QUALITY_SAMPLES: usize = 3;

/// Compute the link cost (1-7) based on the LQI (0-255).
const fn lqi_to_link_cost(lqi: u8) -> u8 {
    match lqi {
        0..=16 => 7,
        17..=32 => 6,
        33..=64 => 5,
        65..=96 => 4,
        97..=128 => 3,
        129..=192 => 2,
        193..=255 => 1,
        // 0 corresponds to "unknown LQI"
    }
}

#[derive(Debug)]
pub struct TableEntry {
    pub extended_address: Eui64,
    pub network_address: Nwk,
    pub device_type: NwkDeviceType,
    pub rx_on_when_idle: bool,
    pub end_device_configuration: u16,

    /// The end device child is evicted once this deadline passes without a keepalive
    /// (the spec's "Timeout Counter", kept as a deadline instead of a countdown)
    pub timeout_at: Instant,

    /// The keepalive period that refreshes `timeout_at`, defaulted from
    /// `nwkEndDeviceTimeoutDefault` and renegotiable via the End Device Timeout
    /// Request command (the spec's "Device Timeout")
    pub device_timeout: Duration,
    pub relationship: Relationship,

    /// A value indicating if previous transmissions to the device were successful or
    /// not. Higher values indicate more failures.
    pub transmit_failure: u8,
    /// TODO: replace with a fixed-size ring buffer
    pub lqas: VecDeque<u8>,

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
            Some(sorted_lqas[num_samples / 2])
        } else {
            // Average of the two middle elements for even number of samples
            let mid1 = sorted_lqas[num_samples / 2 - 1];
            let mid2 = sorted_lqas[num_samples / 2];
            Some(((mid1 as u16 + mid2 as u16) / 2) as u8)
        }
    }

    pub fn incoming_link_cost(&self) -> u8 {
        self.lqa().map_or(0, lqi_to_link_cost)
    }

    pub const fn is_child(&self) -> bool {
        matches!(
            self.relationship,
            Relationship::Child | Relationship::UnauthenticatedChild
        )
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

/// A snapshot of the radio link to one neighbor, for routing cost computations.
#[derive(Debug, Clone, Copy)]
pub struct NeighborLink {
    pub eui64: Eui64,
    /// The cost of the link as measured by the neighbor
    pub outgoing_cost: u8,
    /// The cost of the link as measured by us, from received LQI samples
    pub incoming_cost: u8,
}

/// The neighbor table: link quality accounting, link status digestion, and aging.
///
/// IO-free by design: pure state and computation — no locks, no async, no radio. The
/// async shell parses frames and acts on the returned values (e.g. invalidating routes
/// through neighbors this manager reports as lost). Child management (keepalives, end
/// device timeouts) will land here.
#[derive(Debug)]
pub struct Neighbors {
    network_address: Nwk,
    /// Neighbors silent for this long get their link costs reset
    max_age: Duration,
    table: HashMap<Eui64, TableEntry>,
}

impl Neighbors {
    pub fn new(network_address: Nwk, max_age: Duration) -> Self {
        Self {
            network_address,
            max_age,
            table: HashMap::new(),
        }
    }

    /// Record an LQI sample for the device that transmitted a frame to us. LQA is a
    /// property of the radio link to the MAC transmitter; the frame's NWK originator
    /// may be several hops away.
    pub fn record_lqa(&mut self, sender_nwk: Nwk, lqi: u8) {
        if let Some(entry) = self
            .table
            .values_mut()
            .find(|entry| entry.network_address == sender_nwk)
        {
            entry.lqas.push_back(lqi);

            if entry.lqas.len() > LINK_QUALITY_SAMPLES {
                entry.lqas.pop_front();
            }
        }
    }

    /// The radio link to a neighbor, if the device is one.
    pub fn link(&self, nwk: Nwk) -> Option<NeighborLink> {
        self.table
            .values()
            .find(|entry| entry.network_address == nwk)
            .map(|entry| NeighborLink {
                eui64: entry.extended_address,
                outgoing_cost: entry.outgoing_cost,
                incoming_cost: entry.incoming_link_cost(),
            })
    }

    pub fn entries(&self) -> impl Iterator<Item = &TableEntry> {
        self.table.values()
    }

    pub fn has_network_address(&self, nwk: Nwk) -> bool {
        self.table
            .values()
            .any(|entry| entry.network_address == nwk)
    }

    /// The EUI64 of the end device child with the given network address, if one
    /// exists. End devices do not participate in route discovery, so their parent acts
    /// on their behalf.
    pub fn end_device_child_eui64(&self, nwk: Nwk) -> Option<Eui64> {
        self.table.values().find_map(|entry| {
            if entry.network_address == nwk
                && matches!(entry.device_type, NwkDeviceType::EndDevice)
                && matches!(
                    entry.relationship,
                    Relationship::Child | Relationship::UnauthenticatedChild
                )
            {
                Some(entry.extended_address)
            } else {
                None
            }
        })
    }

    /// The EUI64 of the sleepy (rx-off-when-idle) child with the given network
    /// address, if one exists. Frames to sleepy children cannot be transmitted
    /// directly and must go through the indirect transaction queue.
    pub fn sleepy_child_eui64(&self, nwk: Nwk) -> Option<Eui64> {
        self.table.values().find_map(|entry| {
            (entry.network_address == nwk && !entry.rx_on_when_idle && entry.is_child())
                .then_some(entry.extended_address)
        })
    }

    pub fn contains(&self, eui64: Eui64) -> bool {
        self.table.contains_key(&eui64)
    }

    /// The number of children, for join admission and beacon capacity decisions.
    pub fn child_count(&self) -> usize {
        self.table.values().filter(|entry| entry.is_child()).count()
    }

    /// Spec 3.6.10.4: a MAC data poll from a known device refreshes its keepalive
    /// deadline. Returns whether the device has a neighbor table entry at all.
    pub fn refresh_child_timeout(&mut self, eui64: Option<Eui64>, nwk: Option<Nwk>) -> bool {
        if let Some(eui64) = eui64
            && let Some(entry) = self.table.get_mut(&eui64)
        {
            entry.timeout_at = Instant::now() + entry.device_timeout;
            entry.keepalive_received = true;
            return true;
        }

        if let Some(nwk) = nwk
            && let Some(entry) = self
                .table
                .values_mut()
                .find(|entry| entry.network_address == nwk)
        {
            entry.timeout_at = Instant::now() + entry.device_timeout;
            entry.keepalive_received = true;
            return true;
        }

        false
    }

    /// Spec 3.6.10.2 steps 2, 4 and 5: store the keepalive timeout an end device
    /// child requested. Returns false if the device is not an end device child.
    pub fn set_child_timeout(&mut self, nwk: Nwk, timeout: Duration, configuration: u16) -> bool {
        let Some(entry) = self.table.values_mut().find(|entry| {
            entry.network_address == nwk
                && entry.is_child()
                && matches!(entry.device_type, NwkDeviceType::EndDevice)
        }) else {
            return false;
        };

        entry.device_timeout = timeout;
        entry.timeout_at = Instant::now() + timeout;
        entry.end_device_configuration = configuration;
        entry.keepalive_received = true;

        true
    }

    /// A known device announced a new network address (e.g. after address conflict
    /// resolution); keep its neighbor entry in sync.
    pub fn update_network_address(&mut self, eui64: Eui64, nwk: Nwk) {
        if let Some(entry) = self.table.get_mut(&eui64)
            && entry.network_address != nwk
        {
            log::info!(
                "Neighbor {eui64:?} changed its network address from {:?} to {nwk:?}",
                entry.network_address
            );
            entry.network_address = nwk;
        }
    }

    /// Remove the entry for a child that attached to a different parent, returning
    /// its network address for cleanup.
    pub fn take_child(&mut self, eui64: Eui64) -> Option<Nwk> {
        if !self.table.get(&eui64)?.is_child() {
            return None;
        }

        self.table.remove(&eui64).map(|entry| entry.network_address)
    }

    /// Every end device child, for the post-boot parent announcement
    /// (spec 2.4.3.1.12.1: keepalive state is intentionally not considered).
    pub fn end_device_children(&self) -> Vec<Eui64> {
        self.table
            .values()
            .filter(|entry| {
                entry.is_child() && matches!(entry.device_type, NwkDeviceType::EndDevice)
            })
            .map(|entry| entry.extended_address)
            .collect()
    }

    /// Whether the device is an end device child that has yet to confirm itself with
    /// a keepalive. Confirmed children are dropped from follow-up parent
    /// announcements (spec 2.4.3.1.12.1).
    pub fn is_unconfirmed_end_device_child(&self, eui64: Eui64) -> bool {
        self.table.get(&eui64).is_some_and(|entry| {
            entry.is_child()
                && matches!(entry.device_type, NwkDeviceType::EndDevice)
                && !entry.keepalive_received
        })
    }

    /// Spec 2.4.4.2.22.2: remove the entries for end devices that another router has
    /// claimed with keepalive-confirmed ownership.
    pub fn remove_claimed_children(&mut self, claimed: &[Eui64]) -> Vec<(Eui64, Nwk)> {
        let mut removed = Vec::new();

        for &eui64 in claimed {
            let Some(entry) = self.table.get(&eui64) else {
                continue;
            };

            if !matches!(entry.device_type, NwkDeviceType::EndDevice) {
                continue;
            }

            removed.push((eui64, entry.network_address));
            self.table.remove(&eui64);
        }

        removed
    }

    /// Spec 2.4.4.2.22.1: another router announced the end devices it believes are
    /// its children. Announced devices we have heard a keepalive from are kept and
    /// returned for claiming back; our entries for the rest are stale and removed.
    pub fn process_parent_annce(&mut self, announced: &[Eui64]) -> (Vec<Eui64>, Vec<(Eui64, Nwk)>) {
        let mut claimed = Vec::new();
        let mut removed = Vec::new();

        for &eui64 in announced {
            let Some(entry) = self.table.get(&eui64) else {
                continue;
            };

            if !matches!(entry.device_type, NwkDeviceType::EndDevice) {
                continue;
            }

            if entry.keepalive_received {
                claimed.push(eui64);
            } else {
                removed.push((eui64, entry.network_address));
                self.table.remove(&eui64);
            }
        }

        (claimed, removed)
    }

    /// Remove children whose keepalive deadline has passed (spec 3.6.10.1), returning
    /// their addresses for cleanup.
    pub fn evict_timed_out_children(&mut self) -> Vec<(Eui64, Nwk)> {
        let now = Instant::now();

        let evicted: Vec<(Eui64, Nwk)> = self
            .table
            .values()
            .filter(|entry| entry.is_child() && entry.timeout_at <= now)
            .map(|entry| (entry.extended_address, entry.network_address))
            .collect();

        for (eui64, _) in &evicted {
            self.table.remove(eui64);
        }

        evicted
    }

    /// Get-or-create an entry for a joining device, keeping any existing state so the
    /// table stays stable across association retries.
    pub fn upsert(&mut self, eui64: Eui64, create: impl FnOnce() -> TableEntry) -> &mut TableEntry {
        self.table.entry(eui64).or_insert_with(create)
    }

    pub fn remove(&mut self, eui64: Eui64) {
        self.table.remove(&eui64);
    }

    /// Whether any router neighbor has established a bidirectional link with us,
    /// i.e. a received link status lists us with a nonzero cost.
    pub fn any_live_router_link(&self) -> bool {
        self.table
            .values()
            .any(|entry| entry.device_type == NwkDeviceType::Router && entry.outgoing_cost > 0)
    }

    /// The earliest child keepalive deadline, for scheduling the eviction sweep.
    pub fn next_child_timeout(&self) -> Option<Instant> {
        self.table
            .values()
            .filter(|entry| entry.is_child())
            .map(|entry| entry.timeout_at)
            .min()
    }

    /// Router neighbors with a live link, which are expected to relay our broadcasts
    /// (passive acknowledgment, spec 3.6.6). Aging zeroes the outgoing cost, so a
    /// non-zero cost means the router is still exchanging link statuses with us.
    pub fn expected_broadcast_relayers(&self) -> Vec<Nwk> {
        self.table
            .values()
            .filter(|entry| entry.device_type == NwkDeviceType::Router && entry.outgoing_cost > 0)
            .map(|entry| entry.network_address)
            .collect()
    }

    /// Reset link costs of neighbors that have stopped sending link status frames,
    /// returning their addresses so routes through them can be invalidated.
    pub fn age(&mut self) -> Vec<Nwk> {
        let now = Instant::now();

        let mut stale_neighbors = Vec::new();

        for neighbor in self.table.values_mut() {
            if neighbor.outgoing_cost > 0
                && neighbor.last_link_status_timestamp + self.max_age <= now
            {
                neighbor.lqas.truncate(0);
                neighbor.outgoing_cost = 0;
                stale_neighbors.push(neighbor.network_address);

                log::warn!("Neighbor {neighbor:?} has ceased communicating, resetting link costs")
            }
        }

        stale_neighbors
    }

    /// Called once per `nwkLinkStatusPeriod`: decrement the inbound and outbound
    /// activity counters for every neighbor.
    pub fn decay_activity(&mut self) {
        for entry in self.table.values_mut() {
            entry.router_outbound_activity = entry.router_outbound_activity.saturating_sub(1);
            entry.router_inbound_activity = entry.router_inbound_activity.saturating_sub(1);
        }
    }

    /// A unicast was forwarded through this neighbor.
    pub fn record_outbound_activity(&mut self, eui64: Eui64) {
        if let Some(entry) = self.table.get_mut(&eui64) {
            entry.router_outbound_activity = entry.router_outbound_activity.saturating_add(1);
        }
    }

    /// A unicast from this neighbor was received for relaying.
    pub fn record_inbound_activity(&mut self, nwk: Nwk) {
        if let Some(entry) = self
            .table
            .values_mut()
            .find(|entry| entry.network_address == nwk)
        {
            entry.router_inbound_activity = entry.router_inbound_activity.saturating_add(1);
        }
    }

    /// `nwkTxTotal` wrapped: the spec requires every transmit failure counter to reset.
    pub fn reset_transmit_failures(&mut self) {
        for entry in self.table.values_mut() {
            entry.transmit_failure = 0;
        }
    }

    /// The link statuses we advertise: one per neighbor with enough LQI samples.
    pub fn link_status_entries(&self) -> Vec<NwkLinkStatus> {
        self.table
            .values()
            .filter_map(|neighbor| {
                // We only calculate link statuses for neighbors for which we have
                // seen more than a few packets
                neighbor.lqa().map(|lqa| NwkLinkStatus {
                    address: neighbor.network_address,
                    incoming_cost: lqi_to_link_cost(lqa),
                    outgoing_cost: neighbor.outgoing_cost,
                })
            })
            .collect()
    }

    /// Digest a received link status command, updating the sender's entry (creating a
    /// sibling entry for previously unseen routers). Returns the sender's address if
    /// its outgoing cost collapsed to zero, meaning the link is considered broken and
    /// routes through it must be invalidated (spec 3.6.4.4.2).
    pub fn on_link_status(
        &mut self,
        source_ieee: Eui64,
        source_nwk: Nwk,
        lqi: u8,
        link_status_cmd: &NwkLinkStatusCommand,
    ) -> Option<Nwk> {
        // Collect the set of already-connected neighbors before mutating the state, for
        // the neighbor set diversity computation
        let neighbors_with_nonzero_outgoing_cost = self
            .table
            .values()
            .filter_map(|neighbor_entry| {
                if neighbor_entry.outgoing_cost > 0 {
                    Some(neighbor_entry.network_address)
                } else {
                    None
                }
            })
            .collect::<HashSet<Nwk>>();

        let neighbor_entry = self.table.entry(source_ieee).or_insert_with(|| {
            log::info!("Creating new neighbor entry for {source_ieee:?}");

            let mut entry = TableEntry {
                extended_address: source_ieee,
                network_address: source_nwk,
                device_type: NwkDeviceType::Router,
                rx_on_when_idle: true,
                end_device_configuration: 0x0000,
                timeout_at: Instant::now() + Duration::from_secs(0xFFFFFFFF),
                device_timeout: Duration::from_secs(0xFFFFFFFF),
                relationship: Relationship::Sibling,
                transmit_failure: 0,
                lqas: VecDeque::new(),
                outgoing_cost: 0,
                last_link_status_timestamp: Instant::now(),
                incoming_beacon_timestamp: 0,
                beacon_transmission_time_offset: 0,
                keepalive_received: true,
                mac_unicast_bytes_transmitted: 0,
                mac_unicast_bytes_received: 0,
                router_added_timestamp: Instant::now(),
                router_connectivity: 0,
                router_neighbor_set_diversity: 0,
                router_outbound_activity: 0,
                router_inbound_activity: 0,
                security_timer: 0,
            };

            // Update the neighbor's LQI deque here, since we did not do so earlier
            // when receiving the packet (since the entry was missing)
            entry.lqas.push_back(lqi);

            entry
        });

        let previous_outgoing_cost = neighbor_entry.outgoing_cost;

        neighbor_entry.last_link_status_timestamp = Instant::now();

        if link_status_cmd.is_first_frame {
            neighbor_entry.router_connectivity = 0;
            neighbor_entry.router_neighbor_set_diversity = 0;
            neighbor_entry.outgoing_cost = 0; // If we do not find it in the list, it is 0
        }

        for link_status in link_status_cmd.link_statuses.iter() {
            if link_status.outgoing_cost > 0 {
                let connectivity =
                    7 - cmp::max(link_status.incoming_cost, link_status.outgoing_cost);

                neighbor_entry.router_connectivity = neighbor_entry
                    .router_connectivity
                    .saturating_add(connectivity);

                if !neighbors_with_nonzero_outgoing_cost.contains(&link_status.address) {
                    neighbor_entry.router_neighbor_set_diversity = neighbor_entry
                        .router_neighbor_set_diversity
                        .saturating_add(connectivity);
                }
            }

            if link_status.address == self.network_address {
                neighbor_entry.outgoing_cost = link_status.incoming_cost;
            }
        }

        if link_status_cmd.link_statuses.is_empty() {
            // TODO: Initiate a gratuitous link status broadcast, jittered by
            // nwkcMinRouterBootstrapJitter < nwkcMaxRouterBootstrapJitter
        }

        log::debug!("Updated neighbor table entry: {neighbor_entry:?}");

        let lost_link = previous_outgoing_cost > 0 && neighbor_entry.outgoing_cost == 0;

        lost_link.then_some(neighbor_entry.network_address)
    }
}
