use crate::flat_map::{FlatMap, FlatSet};
use alloc::vec::Vec;
use core::cmp;

use crate::Instant;
use crate::nwk::activity::{Activity, ActivityParams, take_decay_steps};
use crate::nwk::commands::{NwkLinkStatus, NwkLinkStatusCommand};
use crate::nwk::frame::NwkHeader;
use crate::ring_buffer::RingBuffer;
use core::time::Duration;
use ziggurat_ieee_802154::types::{Eui64, Nwk};

use super::NwkDeviceType;

// The number of the most recent samples taken into consideration SHOULD be n = 3, which
// eliminates single outliers maintains a fast response to real changes in link quality,
// and keeps memory requirements to a minimum.
const LINK_QUALITY_SAMPLES: usize = 3;

/// Cap on the buffer of LQI samples for senders without a neighbor entry: any device we
/// merely overhear (or a spoofed source address) creates an entry, so the map must not
/// grow with them. Sized above the ~30 routers a dense radio neighborhood can hold.
const PENDING_LQA_CAP: usize = 64;

/// The last [`LINK_QUALITY_SAMPLES`] LQI samples from one transmitter, stored inline:
/// a heap buffer per neighbor would fragment a small arena.
pub type LqaSamples = RingBuffer<u8, LINK_QUALITY_SAMPLES>;

impl LqaSamples {
    /// Spec 3.6.3: the link quality is the median of the samples held. A window that
    /// is not full yet still counts, down to a single sample. `None` when there is no
    /// sample.
    pub fn median(&self) -> Option<u8> {
        let samples = self.values();

        if samples.is_empty() {
            return None;
        }

        let mut sorted = [0; LINK_QUALITY_SAMPLES];
        let sorted = &mut sorted[..samples.len()];
        sorted.copy_from_slice(samples);
        sorted.sort_unstable();

        let middle = sorted.len() / 2;

        if sorted.len() % 2 == 1 {
            Some(sorted[middle])
        } else {
            // Average of the two middle elements for an even sample count
            Some(((sorted[middle - 1] as u16 + sorted[middle] as u16) / 2) as u8)
        }
    }
}

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
    /// (the spec's "Timeout Counter", kept as a deadline instead of a countdown).
    /// `None` for a router, which is not aged by keepalives.
    pub timeout_at: Option<Instant>,

    /// The keepalive period that refreshes `timeout_at`, defaulted from
    /// `nwkEndDeviceTimeoutDefault` and renegotiable via the End Device Timeout
    /// Request command (the spec's "Device Timeout"). `None` for a router.
    pub device_timeout: Option<Duration>,
    pub relationship: Relationship,

    /// A value indicating if previous transmissions to the device were successful or
    /// not. Higher values indicate more failures.
    pub transmit_failure: u8,
    pub lqas: LqaSamples,

    /// The outgoing cost field contains the cost of the link as measured by the
    /// neighbor. The value is obtained from the most recent link status command frame
    /// received from the neighbor. A value of 0 indicates that no link status command
    /// listing this device has been received.
    pub outgoing_cost: u8,

    /// The number of `nwkLinkStatusPeriod` intervals that have passed since
    /// the last link status command frame was received, up to a maximum value
    /// of `nwkRouterAgeLimit`
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

    /// The number of `nwkLinkStatusPeriod` intervals, which elapsed since this router
    /// neighbor was added to the neighbor table. This value is only maintained on
    /// routers and the coordinator and is only valid for entries with a relationship
    /// of ‘parent’, ‘sibling’ or ‘backbone mesh sibling’. This is a saturating
    /// up-counter, which does not roll-over.
    // Spec-expected field: `pub router_age: u16`, we instead keep track of a timestamp
    pub router_added_timestamp: Instant,

    /// When the device last associated or rejoined through us. `None` for neighbors that
    /// never attached to us.
    pub attached_at: Option<Instant>,

    pub router_connectivity: u8,
    pub router_neighbor_set_diversity: u8,
    pub router_outbound_activity: Activity,
    pub router_inbound_activity: Activity,
    pub security_timer: u8,
}

impl TableEntry {
    /// Whether our link status lists this neighbor: a router we have heard from. A
    /// neighbor without a sample has no cost to report.
    pub fn is_in_link_status(&self) -> bool {
        self.device_type == NwkDeviceType::Router && !self.lqas.is_empty()
    }

    pub fn incoming_link_cost(&self) -> u8 {
        self.lqas.median().map_or(0, lqi_to_link_cost)
    }

    pub const fn is_child(&self) -> bool {
        matches!(
            self.relationship,
            Relationship::Child | Relationship::UnauthenticatedChild
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// The attachment-time identity of a joining or rejoining child, for
/// [`Neighbors::upsert_child`].
#[derive(Debug)]
pub struct ChildDescriptor {
    pub eui64: Eui64,
    pub network_address: Nwk,
    pub device_type: NwkDeviceType,
    pub rx_on_when_idle: bool,
    pub device_timeout: Option<Duration>,
    pub relationship: Relationship,
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

impl NeighborLink {
    /// The cost of the link for routing: the worse of the two directions, so an
    /// asymmetric link is not preferred
    pub fn cost(&self) -> u8 {
        cmp::max(self.outgoing_cost, self.incoming_cost)
    }
}

/// What a received link status changed in the sender's entry, for route maintenance.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LinkStatusOutcome {
    /// The sender's address, if its outgoing cost collapsed to zero: the link is
    /// considered broken and routes through it must be invalidated (spec 3.6.4.4.2).
    pub lost_link: Option<Nwk>,
    /// The sender's previous network address, if the link status came from a new one.
    pub replaced_address: Option<Nwk>,
    /// Our link status lists the sender from now on and did not before, so the sender
    /// has yet to learn its cost from us.
    pub link_status_due: bool,
    /// The sender's list was empty: it just started and asks who its neighbors are.
    /// The spec owes an answer only to an unknown sender (3.6.4.4.2). We answer a
    /// known one too so a restarted neighbor hears us at once.
    pub link_status_answer_due: bool,
}

/// The neighbor table: link quality accounting, link status digestion, and aging.
#[derive(Debug, Default)]
pub struct Neighbors {
    table: FlatMap<Eui64, TableEntry>,
    /// LQI samples for senders that have no neighbor entry yet, capped at
    /// [`PENDING_LQA_CAP`] entries.
    pending_lqas: FlatMap<Nwk, LqaSamples>,
    /// Up to when the activity counters have been decayed
    activity_decayed_at: Instant,
}

impl Neighbors {
    /// Record an LQI sample for the device that transmitted a frame to us. LQA is a
    /// property of the radio link to the MAC transmitter; the frame's NWK originator
    /// may be several hops away. Returns whether a link status is due: ours lists the
    /// sender from now on and did not before.
    pub fn record_lqa(&mut self, sender_nwk: Nwk, lqi: u8) -> bool {
        if let Some(entry) = self
            .table
            .values_mut()
            .find(|entry| entry.network_address == sender_nwk)
        {
            let was_in_link_status = entry.is_in_link_status();
            entry.lqas.push(lqi);

            !was_in_link_status && entry.is_in_link_status()
        } else {
            // No neighbor entry yet (e.g. a sibling router that has not sent a link
            // status command). Buffer the sample so the entry starts with usable link
            // quality the moment it is created.
            if self.pending_lqas.len() >= PENDING_LQA_CAP
                && !self.pending_lqas.contains_key(&sender_nwk)
            {
                self.pending_lqas.pop_first();
            }

            self.pending_lqas.entry(sender_nwk).or_default().push(lqi);

            false
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

    /// Whether `nwk` is a router child that associated or rejoined through us within
    /// `window`.
    pub fn is_recently_attached_router_child(
        &self,
        nwk: Nwk,
        now: Instant,
        window: Duration,
    ) -> bool {
        self.table.values().any(|entry| {
            entry.network_address == nwk
                && entry.device_type == NwkDeviceType::Router
                && entry.is_child()
                && entry
                    .attached_at
                    .is_some_and(|attached_at| now < attached_at + window)
        })
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

    /// The network address of the end device child with the given EUI64, if one exists.
    pub fn end_device_child_nwk(&self, eui64: Eui64) -> Option<Nwk> {
        self.table
            .get(&eui64)
            .filter(|entry| entry.is_child() && entry.device_type == NwkDeviceType::EndDevice)
            .map(|entry| entry.network_address)
    }

    /// The network addresses of every end device child, in ascending order.
    pub fn end_device_child_addresses(&self) -> Vec<Nwk> {
        let mut addresses: Vec<Nwk> = self
            .table
            .values()
            .filter(|entry| entry.is_child() && entry.device_type == NwkDeviceType::EndDevice)
            .map(|entry| entry.network_address)
            .collect();
        addresses.sort_by_key(Nwk::as_u16);
        addresses
    }

    /// Spec 3.3.1.1.8: after validating the source (3.6.2.2), a router parent SHALL
    /// clear the End Device Initiator bit when relaying a frame sent by one of its end
    /// device children. Otherwise the next router searches its own neighbor table for
    /// the source, finds no end device there, and drops the frame (3.6.2.2). Frames
    /// from any other source are left untouched. Returns whether the bit was cleared.
    pub fn clear_end_device_initiator_for_relay(&self, header: &mut NwkHeader) -> bool {
        if !header.frame_control.end_device_initiator
            || self.end_device_child_eui64(header.source).is_none()
        {
            return false;
        }

        header.frame_control.end_device_initiator = false;
        true
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

    /// The (EUI64, network address) of every rx-off-when-idle end-device child. A
    /// 0xFFFF broadcast has to be delivered to each as a MAC unicast, since a sleeping
    /// radio never hears the broadcast itself (spec 3.6.6).
    pub fn sleepy_children(&self) -> impl Iterator<Item = (Eui64, Nwk)> {
        self.table
            .values()
            .filter(|entry| !entry.rx_on_when_idle && entry.is_child())
            .map(|entry| (entry.extended_address, entry.network_address))
    }

    pub fn contains(&self, eui64: Eui64) -> bool {
        self.table.contains_key(&eui64)
    }

    /// The device type and rx-on-when-idle of a table entry, for join notifications.
    pub fn device_capability(&self, eui64: Eui64) -> Option<(NwkDeviceType, bool)> {
        self.table
            .get(&eui64)
            .map(|entry| (entry.device_type, entry.rx_on_when_idle))
    }

    /// The number of end device children, for join admission and beacon capacity
    /// decisions.
    pub fn end_device_child_count(&self) -> usize {
        self.table
            .values()
            .filter(|entry| entry.is_child() && entry.device_type == NwkDeviceType::EndDevice)
            .count()
    }

    /// Spec 3.6.10.4: a MAC data poll from a known device refreshes its keepalive
    /// deadline. Returns whether the device has a neighbor table entry at all.
    pub fn refresh_child_timeout(
        &mut self,
        eui64: Option<Eui64>,
        nwk: Option<Nwk>,
        now: Instant,
    ) -> bool {
        if let Some(eui64) = eui64
            && let Some(entry) = self.table.get_mut(&eui64)
        {
            entry.timeout_at = entry.device_timeout.map(|timeout| now + timeout);
            entry.keepalive_received = true;
            return true;
        }

        if let Some(nwk) = nwk
            && let Some(entry) = self
                .table
                .values_mut()
                .find(|entry| entry.network_address == nwk)
        {
            entry.timeout_at = entry.device_timeout.map(|timeout| now + timeout);
            entry.keepalive_received = true;
            return true;
        }

        false
    }

    /// Spec 3.6.10.2 steps 2, 4 and 5: store the keepalive timeout an end device
    /// child requested. Returns false if the device is not an end device child.
    pub fn set_child_timeout(
        &mut self,
        nwk: Nwk,
        timeout: Duration,
        configuration: u16,
        now: Instant,
    ) -> bool {
        let Some(entry) = self.table.values_mut().find(|entry| {
            entry.network_address == nwk
                && entry.is_child()
                && matches!(entry.device_type, NwkDeviceType::EndDevice)
        }) else {
            return false;
        };

        entry.device_timeout = Some(timeout);
        entry.timeout_at = Some(now + timeout);
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
            tracing::info!(
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
    #[must_use = "the removed children must be cleaned up from dependent state; \
        dropping them leaves stale entries"]
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
    #[must_use = "the children to claim back and the removed stale entries must both be \
        acted on; dropping the result silently skips both"]
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

    /// Remove end device children whose keepalive deadline has passed (spec 3.6.10.1),
    /// returning their addresses for cleanup. Router children do not send keepalives;
    /// link status aging covers them instead.
    #[must_use = "evicted children must be cleaned up and announced; dropping them \
        leaves stale entries and silent losses"]
    pub fn evict_timed_out_children(&mut self, now: Instant) -> Vec<(Eui64, Nwk)> {
        let evicted: Vec<(Eui64, Nwk)> = self
            .table
            .values()
            .filter(|entry| {
                entry.is_child()
                    && entry.device_type == NwkDeviceType::EndDevice
                    && entry.timeout_at.is_some_and(|timeout_at| timeout_at <= now)
            })
            .map(|entry| (entry.extended_address, entry.network_address))
            .collect();

        for (eui64, _) in &evicted {
            self.table.remove(eui64);
        }

        evicted
    }

    /// Get-or-create the entry for a joining or rejoining child, keeping any existing
    /// state (e.g. LQI samples, keepalive confirmation) so the table stays stable
    /// across attachment retries. The fields a device may change between attachments
    /// are refreshed even on existing entries: a device may re-attach with different
    /// capabilities (e.g. re-flashed from router to end device).
    pub fn upsert_child(&mut self, child: ChildDescriptor, now: Instant, activity: ActivityParams) {
        self.upsert(child, now, Some(now), activity);
    }

    /// Seed a child entry restored by the client on startup. Unlike a device that
    /// associates or rejoins, a restored child did not just attach to us.
    pub fn restore_child(
        &mut self,
        child: ChildDescriptor,
        now: Instant,
        activity: ActivityParams,
    ) {
        self.upsert(child, now, None, activity);
    }

    fn upsert(
        &mut self,
        child: ChildDescriptor,
        now: Instant,
        attached_at: Option<Instant>,
        activity: ActivityParams,
    ) {
        self.decay_activity(now, activity.period);

        let entry = self.table.entry(child.eui64).or_insert_with(|| TableEntry {
            extended_address: child.eui64,
            network_address: child.network_address,
            device_type: child.device_type,
            rx_on_when_idle: child.rx_on_when_idle,
            end_device_configuration: 0x0000,
            timeout_at: child.device_timeout.map(|timeout| now + timeout),
            device_timeout: child.device_timeout,
            relationship: Relationship::Child,
            transmit_failure: 0,
            lqas: LqaSamples::default(),
            outgoing_cost: 0,
            last_link_status_timestamp: now,
            incoming_beacon_timestamp: 0,
            beacon_transmission_time_offset: 0,
            keepalive_received: false,
            mac_unicast_bytes_transmitted: 0,
            mac_unicast_bytes_received: 0,
            router_added_timestamp: now,
            attached_at,
            router_connectivity: 0,
            router_neighbor_set_diversity: 0,
            router_outbound_activity: Activity::new(activity.initial_count),
            router_inbound_activity: Activity::new(activity.initial_count),
            security_timer: 0,
        });

        entry.attached_at = attached_at;
        entry.network_address = child.network_address;
        entry.device_type = child.device_type;
        entry.rx_on_when_idle = child.rx_on_when_idle;
        entry.device_timeout = child.device_timeout;
        entry.timeout_at = child.device_timeout.map(|timeout| now + timeout);
        entry.relationship = child.relationship;
    }

    pub fn remove(&mut self, eui64: Eui64) {
        self.table.remove(&eui64);
    }

    /// Spec 4.3.1.2 step 8: a frame from `eui64` passed NWK security processing, so
    /// an unauthenticated child entry for it becomes a child. Returns whether the entry
    /// was promoted.
    pub fn note_nwk_secured_frame(&mut self, eui64: Eui64) -> bool {
        match self.table.get_mut(&eui64) {
            Some(entry) if entry.relationship == Relationship::UnauthenticatedChild => {
                entry.relationship = Relationship::Child;
                true
            }
            _ => false,
        }
    }

    /// Whether any router neighbor has established a bidirectional link with us,
    /// i.e. a received link status lists us with a nonzero cost.
    /// The routers and coordinator we have a working link to, in both directions.
    pub fn live_router_links(&self) -> Vec<Nwk> {
        self.table
            .values()
            .filter(|entry| {
                entry.device_type != NwkDeviceType::EndDevice && entry.outgoing_cost > 0
            })
            .map(|entry| entry.network_address)
            .collect()
    }

    pub fn any_live_router_link(&self) -> bool {
        self.table
            .values()
            .any(|entry| entry.device_type == NwkDeviceType::Router && entry.outgoing_cost > 0)
    }

    /// The earliest end device child keepalive deadline, for scheduling the eviction
    /// sweep.
    pub fn next_child_timeout(&self) -> Option<Instant> {
        self.table
            .values()
            .filter(|entry| entry.is_child() && entry.device_type == NwkDeviceType::EndDevice)
            .filter_map(|entry| entry.timeout_at)
            .min()
    }

    /// Router neighbors with a good live link, which are expected to relay our
    /// broadcasts (passive acknowledgment, spec 3.6.6).
    pub fn expected_broadcast_relayers(&self, max_link_cost: u8) -> Vec<Nwk> {
        self.table
            .values()
            .filter(|entry| Self::relays_broadcasts(entry, max_link_cost))
            .map(|entry| entry.network_address)
            .collect()
    }

    /// Whether `nwk` is one of the [`Self::expected_broadcast_relayers`].
    pub fn is_expected_broadcast_relayer(&self, nwk: Nwk, max_link_cost: u8) -> bool {
        self.table.values().any(|entry| {
            entry.network_address == nwk && Self::relays_broadcasts(entry, max_link_cost)
        })
    }

    fn relays_broadcasts(entry: &TableEntry, max_link_cost: u8) -> bool {
        entry.device_type == NwkDeviceType::Router
            && (1..=max_link_cost).contains(&entry.outgoing_cost)
            && (1..=max_link_cost).contains(&entry.incoming_link_cost())
    }

    /// Reset link costs of neighbors that have been silent for `max_age` (stopped
    /// sending link status frames), returning their addresses so routes through them
    /// can be invalidated.
    #[must_use = "routes through the returned aged-out neighbors must be invalidated; \
        dropping them leaves stale routes"]
    pub fn age(&mut self, now: Instant, max_age: Duration) -> Vec<Nwk> {
        let mut stale_neighbors = Vec::new();

        for neighbor in self.table.values_mut() {
            if neighbor.outgoing_cost > 0 && neighbor.last_link_status_timestamp + max_age <= now {
                neighbor.lqas.clear();
                neighbor.outgoing_cost = 0;
                stale_neighbors.push(neighbor.network_address);

                tracing::warn!(
                    "Neighbor {:?} ({:?}) has ceased communicating, resetting link costs",
                    neighbor.network_address,
                    neighbor.extended_address
                )
            }
        }

        stale_neighbors
    }

    /// Decay the inbound and outbound activity of every neighbor by the time passed
    /// since the last call, at one count per `period` (`nwkLinkStatusPeriod`).
    pub fn decay_activity(&mut self, now: Instant, period: Duration) {
        let steps = take_decay_steps(&mut self.activity_decayed_at, now, period);

        if steps == 0 {
            return;
        }

        for entry in self.table.values_mut() {
            entry.router_outbound_activity.decay(steps);
            entry.router_inbound_activity.decay(steps);
        }
    }

    /// A unicast was forwarded through this neighbor.
    pub fn record_outbound_activity(&mut self, eui64: Eui64, now: Instant, period: Duration) {
        self.decay_activity(now, period);

        if let Some(entry) = self.table.get_mut(&eui64) {
            entry.router_outbound_activity.record_use();
        }
    }

    /// A unicast from this neighbor was received for relaying.
    pub fn record_inbound_activity(&mut self, nwk: Nwk, now: Instant, period: Duration) {
        self.decay_activity(now, period);

        if let Some(entry) = self
            .table
            .values_mut()
            .find(|entry| entry.network_address == nwk)
        {
            entry.router_inbound_activity.record_use();
        }
    }

    /// A unicast to this neighbor went unacknowledged (spec Table 3-75).
    pub fn record_transmit_failure(&mut self, eui64: Eui64) {
        if let Some(entry) = self.table.get_mut(&eui64) {
            entry.transmit_failure = entry.transmit_failure.saturating_add(1);
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
            // Only include routers in the link status list. Otherwise, we advertise
            // sleepy end devices that cannot be routed through.
            .filter(|neighbor| neighbor.is_in_link_status())
            .map(|neighbor| NwkLinkStatus {
                address: neighbor.network_address,
                incoming_cost: neighbor.incoming_link_cost(),
                outgoing_cost: neighbor.outgoing_cost,
            })
            .collect()
    }

    /// Digest a received link status command, updating the sender's entry (creating a
    /// sibling entry for previously unseen routers).
    #[allow(clippy::too_many_arguments)]
    pub fn on_link_status(
        &mut self,
        own_address: Nwk,
        source_ieee: Eui64,
        source_nwk: Nwk,
        lqi: u8,
        link_status_cmd: &NwkLinkStatusCommand,
        now: Instant,
        activity: ActivityParams,
    ) -> LinkStatusOutcome {
        self.decay_activity(now, activity.period);

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
            .collect::<FlatSet<Nwk>>();

        // Fold any LQI samples buffered for this address before its entry existed.
        let mut buffered_lqas = self.pending_lqas.remove(&source_nwk).unwrap_or_default();

        // Spec 3.3.1.7: a frame carrying its source IEEE address, as every link status
        // does (3.4.8.2), SHOULD be checked against the neighbor table. A router that
        // changed its address (address conflict, rejoin) and whose Device_annce we
        // missed would otherwise keep its old address here. Our own address, or one
        // another neighbor still holds, is in conflict: the entry keeps its address
        // until the conflict resolves, rather than two devices sharing one.
        let replaced_address = self
            .table
            .get(&source_ieee)
            .map(|entry| entry.network_address)
            .filter(|&previous| previous != source_nwk)
            .filter(|_| source_nwk != own_address && !self.has_network_address(source_nwk));

        if replaced_address.is_some() {
            self.update_network_address(source_ieee, source_nwk);

            // The samples the receive path buffered under the new address are this
            // router's. A full buffer replaces the older samples outright, which also
            // keeps the ring's order.
            if let Some(entry) = self.table.get_mut(&source_ieee) {
                if buffered_lqas.is_full() {
                    entry.lqas = core::mem::take(&mut buffered_lqas);
                } else {
                    for &sample in buffered_lqas.values() {
                        entry.lqas.push(sample);
                    }
                }
            }
        }

        let was_in_link_status = self
            .table
            .get(&source_ieee)
            .is_some_and(TableEntry::is_in_link_status);

        let neighbor_entry = self.table.entry(source_ieee).or_insert_with(|| {
            tracing::info!("Creating new neighbor entry for {source_ieee:?}");

            let mut entry = TableEntry {
                extended_address: source_ieee,
                network_address: source_nwk,
                device_type: NwkDeviceType::Router,
                rx_on_when_idle: true,
                end_device_configuration: 0x0000,
                timeout_at: None,
                device_timeout: None,
                relationship: Relationship::Sibling,
                transmit_failure: 0,
                lqas: LqaSamples::default(),
                outgoing_cost: 0,
                last_link_status_timestamp: now,
                incoming_beacon_timestamp: 0,
                beacon_transmission_time_offset: 0,
                keepalive_received: true,
                mac_unicast_bytes_transmitted: 0,
                mac_unicast_bytes_received: 0,
                router_added_timestamp: now,
                attached_at: None,
                router_connectivity: 0,
                router_neighbor_set_diversity: 0,
                router_outbound_activity: Activity::new(activity.initial_count),
                router_inbound_activity: Activity::new(activity.initial_count),
                security_timer: 0,
            };

            // Seed with the samples buffered before the entry existed plus the current
            // one (the receive path could not record them without an entry).
            entry.lqas = buffered_lqas;
            entry.lqas.push(lqi);

            entry
        });

        // End devices do not send link status (spec 3.6.4.4). An entry restored without
        // its device type is loaded as an end device, so correct it here.
        if neighbor_entry.device_type == NwkDeviceType::EndDevice {
            tracing::info!("Neighbor {source_ieee:?} sent a link status, marking it as a router");
            neighbor_entry.device_type = NwkDeviceType::Router;
            neighbor_entry.rx_on_when_idle = true;
        }

        let previous_outgoing_cost = neighbor_entry.outgoing_cost;

        neighbor_entry.last_link_status_timestamp = now;

        if link_status_cmd.is_first_frame {
            neighbor_entry.router_connectivity = 0;
            neighbor_entry.router_neighbor_set_diversity = 0;
        }

        // The list is sorted by address. A frame says nothing about us if our address
        // is outside its range, or if its list is empty.
        if let (Some(first), Some(last)) = (
            link_status_cmd.link_statuses.first(),
            link_status_cmd.link_statuses.last(),
        ) {
            let own = own_address.as_u16();
            let covers_us = (link_status_cmd.is_first_frame || first.address.as_u16() <= own)
                && (link_status_cmd.is_last_frame || own <= last.address.as_u16());

            if covers_us {
                neighbor_entry.outgoing_cost = link_status_cmd
                    .link_statuses
                    .iter()
                    .find(|link_status| link_status.address == own_address)
                    .map_or(0, |link_status| link_status.incoming_cost);
            }
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
        }

        tracing::trace!("Updated neighbor table entry: {neighbor_entry:?}");

        let lost_link = previous_outgoing_cost > 0 && neighbor_entry.outgoing_cost == 0;

        LinkStatusOutcome {
            lost_link: lost_link.then_some(neighbor_entry.network_address),
            replaced_address,
            link_status_due: !was_in_link_status && neighbor_entry.is_in_link_status(),
            link_status_answer_due: link_status_cmd.link_statuses.is_empty(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use hex_literal::hex;

    const CHILD_NWK: Nwk = Nwk(0x1234);
    const ACTIVITY: ActivityParams = ActivityParams {
        initial_count: 3,
        period: Duration::from_secs(15),
    };

    fn neighbors_with(device_type: NwkDeviceType) -> Neighbors {
        let mut neighbors = Neighbors::default();
        neighbors.upsert_child(
            ChildDescriptor {
                eui64: Eui64::from_hex("00:11:22:33:44:55:66:77"),
                network_address: CHILD_NWK,
                device_type,
                rx_on_when_idle: false,
                device_timeout: Some(Duration::from_secs(60)),
                relationship: Relationship::Child,
            },
            Instant::from_micros(0),
            ACTIVITY,
        );
        neighbors
    }

    /// A group command broadcast to 0xFFFD by end device 0x1234: data frame, route
    /// discovery enabled, secured, End Device Initiator set (frame control 0x2248).
    fn end_device_broadcast_header() -> NwkHeader {
        let (header, rest) = NwkHeader::deserialize(&hex!("4822fdff34121e05")).unwrap();
        assert!(rest.is_empty());
        assert!(header.frame_control.end_device_initiator);
        header
    }

    #[test]
    fn test_relay_clears_end_device_initiator_of_end_device_child() {
        let neighbors = neighbors_with(NwkDeviceType::EndDevice);
        let mut header = end_device_broadcast_header();

        assert!(neighbors.clear_end_device_initiator_for_relay(&mut header));
        assert!(!header.frame_control.end_device_initiator);

        // Only the End Device Initiator bit changes: frame control 0x2248 -> 0x0248
        assert_eq!(header.to_bytes(), hex!("4802fdff34121e05"));
    }

    #[test]
    fn test_relay_keeps_end_device_initiator_of_other_sources() {
        // Not an end device in our table: the bit is not ours to clear
        for neighbors in [Neighbors::default(), neighbors_with(NwkDeviceType::Router)] {
            let mut header = end_device_broadcast_header();

            assert!(!neighbors.clear_end_device_initiator_for_relay(&mut header));
            assert!(header.frame_control.end_device_initiator);
        }
    }

    #[test]
    fn test_relay_without_end_device_initiator_is_unchanged() {
        let neighbors = neighbors_with(NwkDeviceType::EndDevice);
        let mut header = end_device_broadcast_header();
        header.frame_control.end_device_initiator = false;
        let expected = header.clone();

        assert!(!neighbors.clear_end_device_initiator_for_relay(&mut header));
        assert_eq!(header, expected);
    }

    fn link_status_listing(own: Nwk) -> NwkLinkStatusCommand {
        NwkLinkStatusCommand {
            is_first_frame: true,
            is_last_frame: true,
            link_statuses: vec![NwkLinkStatus {
                address: own,
                incoming_cost: 1,
                outgoing_cost: 1,
            }],
        }
    }

    #[test]
    fn test_link_status_refreshes_router_network_address() {
        let router = Eui64::from_hex("aa:bb:cc:dd:ee:ff:00:11");
        let own = Nwk(0x0000);
        let (old, new) = (Nwk(0x1111), Nwk(0x2222));
        let now = Instant::from_micros(0);
        let link_status = link_status_listing(own);
        let mut neighbors = Neighbors::default();

        neighbors.on_link_status(own, router, old, 200, &link_status, now, ACTIVITY);
        neighbors.record_lqa(old, 200);
        neighbors.record_lqa(old, 200);
        assert_eq!(neighbors.link(old).unwrap().eui64, router);

        // The router moved to a new address and we missed its Device_annce: the
        // receive path buffers the LQI of its frames under the new address, then its
        // link status carries the new address with the router's EUI64
        neighbors.record_lqa(new, 40);
        neighbors.record_lqa(new, 40);
        let outcome = neighbors.on_link_status(own, router, new, 40, &link_status, now, ACTIVITY);
        assert_eq!(
            outcome,
            LinkStatusOutcome {
                lost_link: None,
                replaced_address: Some(old),
                link_status_due: false,
                link_status_answer_due: false,
            }
        );

        assert!(!neighbors.has_network_address(old));
        assert!(neighbors.link(old).is_none());
        let link = neighbors.link(new).unwrap();
        assert_eq!(link.eui64, router);
        assert_eq!(link.outgoing_cost, 1);
        // The buffered samples joined the router's own: median of [200, 40, 40]
        assert_eq!(link.incoming_cost, lqi_to_link_cost(40));
        assert_eq!(neighbors.entries().count(), 1);

        let advertised: Vec<Nwk> = neighbors
            .link_status_entries()
            .iter()
            .map(|status| status.address)
            .collect();
        assert_eq!(advertised, vec![new]);

        // A later link status from the same address changes nothing
        let outcome = neighbors.on_link_status(own, router, new, 40, &link_status, now, ACTIVITY);
        assert_eq!(outcome, LinkStatusOutcome::default());
    }

    #[test]
    fn test_empty_link_status_keeps_outgoing_cost() {
        let router = Eui64::from_hex("aa:bb:cc:dd:ee:ff:00:11");
        let (own, router_nwk) = (Nwk(0x0000), Nwk(0x1111));
        let mut neighbors = Neighbors::default();

        let listing = link_status_listing(own);
        neighbors.on_link_status(
            own,
            router,
            router_nwk,
            200,
            &listing,
            Instant::from_micros(0),
            ACTIVITY,
        );

        let empty = NwkLinkStatusCommand {
            is_first_frame: true,
            is_last_frame: true,
            link_statuses: vec![],
        };
        let later = Instant::from_micros(1);
        let outcome =
            neighbors.on_link_status(own, router, router_nwk, 200, &empty, later, ACTIVITY);

        assert_eq!(outcome.lost_link, None);
        assert_eq!(neighbors.link(router_nwk).unwrap().outgoing_cost, 1);
    }

    #[test]
    fn test_link_status_from_unknown_router_makes_ours_due() {
        let router = Eui64::from_hex("aa:bb:cc:dd:ee:ff:00:11");
        let (own, router_nwk) = (Nwk(0x0000), Nwk(0x1111));
        let now = Instant::from_micros(0);
        let empty = link_status_frame(true, true, &[]);
        let mut neighbors = Neighbors::default();

        let outcome = neighbors.on_link_status(own, router, router_nwk, 200, &empty, now, ACTIVITY);
        assert_eq!(
            outcome,
            LinkStatusOutcome {
                lost_link: None,
                replaced_address: None,
                link_status_due: true,
                link_status_answer_due: true,
            }
        );

        // The router is known now: its empty list is still owed an answer
        let outcome = neighbors.on_link_status(own, router, router_nwk, 200, &empty, now, ACTIVITY);
        assert_eq!(
            outcome,
            LinkStatusOutcome {
                lost_link: None,
                replaced_address: None,
                link_status_due: false,
                link_status_answer_due: true,
            }
        );

        // Another unknown router makes one due too, whatever its list holds
        let other = Eui64::from_hex("aa:bb:cc:dd:ee:ff:00:22");
        let listing = link_status_listing(own);
        let outcome =
            neighbors.on_link_status(own, other, Nwk(0x2222), 200, &listing, now, ACTIVITY);
        assert!(outcome.link_status_due);
        assert!(!outcome.link_status_answer_due);
    }

    #[test]
    fn test_first_frame_from_a_router_without_samples_makes_our_link_status_due() {
        let mut neighbors = neighbors_with(NwkDeviceType::Router);

        assert!(neighbors.record_lqa(CHILD_NWK, 200));
        assert!(!neighbors.record_lqa(CHILD_NWK, 200));
    }

    #[test]
    fn test_frames_from_other_senders_do_not_make_our_link_status_due() {
        // An end device is never listed
        let mut neighbors = neighbors_with(NwkDeviceType::EndDevice);
        assert!(!neighbors.record_lqa(CHILD_NWK, 200));

        // Neither is a sender without a neighbor entry
        assert!(!neighbors.record_lqa(Nwk(0x2222), 200));
    }

    #[test]
    fn test_link_status_from_a_heard_end_device_makes_ours_due() {
        // A child restored without its device type is loaded as an end device
        let mut neighbors = neighbors_with(NwkDeviceType::EndDevice);
        neighbors.record_lqa(CHILD_NWK, 200);

        let outcome = neighbors.on_link_status(
            Nwk(0x0000),
            Eui64::from_hex("00:11:22:33:44:55:66:77"),
            CHILD_NWK,
            200,
            &link_status_listing(Nwk(0x0000)),
            Instant::from_micros(0),
            ACTIVITY,
        );
        assert!(outcome.link_status_due);
    }

    #[test]
    fn test_link_status_leaving_us_out_zeroes_outgoing_cost() {
        let router = Eui64::from_hex("aa:bb:cc:dd:ee:ff:00:11");
        let (own, router_nwk) = (Nwk(0x0000), Nwk(0x1111));
        let now = Instant::from_micros(0);
        let mut neighbors = Neighbors::default();

        let listing = link_status_listing(own);
        neighbors.on_link_status(own, router, router_nwk, 200, &listing, now, ACTIVITY);

        let without_us = link_status_listing(Nwk(0x2222));
        let outcome =
            neighbors.on_link_status(own, router, router_nwk, 200, &without_us, now, ACTIVITY);

        assert_eq!(
            outcome,
            LinkStatusOutcome {
                lost_link: Some(router_nwk),
                replaced_address: None,
                link_status_due: false,
                link_status_answer_due: false,
            }
        );
        assert_eq!(neighbors.link(router_nwk).unwrap().outgoing_cost, 0);
    }

    fn link_status_frame(
        is_first_frame: bool,
        is_last_frame: bool,
        addresses: &[u16],
    ) -> NwkLinkStatusCommand {
        NwkLinkStatusCommand {
            is_first_frame,
            is_last_frame,
            link_statuses: addresses
                .iter()
                .map(|&address| NwkLinkStatus {
                    address: Nwk(address),
                    incoming_cost: 3,
                    outgoing_cost: 3,
                })
                .collect(),
        }
    }

    /// Our outgoing cost to a router that listed us at cost 1, after it sends `frame`.
    fn outgoing_cost_after(own: Nwk, frame: &NwkLinkStatusCommand) -> u8 {
        let router = Eui64::from_hex("aa:bb:cc:dd:ee:ff:00:11");
        let router_nwk = Nwk(0x1111);
        let now = Instant::from_micros(0);
        let mut neighbors = Neighbors::default();

        let listing = link_status_listing(own);
        neighbors.on_link_status(own, router, router_nwk, 200, &listing, now, ACTIVITY);
        neighbors.on_link_status(own, router, router_nwk, 200, frame, now, ACTIVITY);

        neighbors.link(router_nwk).unwrap().outgoing_cost
    }

    #[test]
    fn test_link_status_frame_not_covering_us_keeps_outgoing_cost() {
        let own = Nwk(0x3000);

        // We sort after the last entry and more frames follow
        let first_of_many = link_status_frame(true, false, &[0x1000, 0x2000]);
        assert_eq!(outgoing_cost_after(own, &first_of_many), 1);

        // We sort before the first entry and frames came before
        let last_of_many = link_status_frame(false, true, &[0x4000, 0x5000]);
        assert_eq!(outgoing_cost_after(own, &last_of_many), 1);

        let middle_of_many = link_status_frame(false, false, &[0x4000, 0x5000]);
        assert_eq!(outgoing_cost_after(own, &middle_of_many), 1);
    }

    #[test]
    fn test_link_status_frame_covering_us_sets_outgoing_cost() {
        let own = Nwk(0x3000);

        // Between the first and the last entry
        let middle_of_many = link_status_frame(false, false, &[0x2000, 0x4000]);
        assert_eq!(outgoing_cost_after(own, &middle_of_many), 0);

        // Below the first entry of the first frame
        let first_of_many = link_status_frame(true, false, &[0x4000, 0x5000]);
        assert_eq!(outgoing_cost_after(own, &first_of_many), 0);

        // Above the last entry of the last frame
        let last_of_many = link_status_frame(false, true, &[0x1000, 0x2000]);
        assert_eq!(outgoing_cost_after(own, &last_of_many), 0);

        // Listed as the entry two frames share
        let listed = link_status_frame(false, false, &[0x3000, 0x4000]);
        assert_eq!(outgoing_cost_after(own, &listed), 3);
    }

    #[test]
    fn test_link_cost_uses_the_samples_held() {
        let router = Eui64::from_hex("aa:bb:cc:dd:ee:ff:00:11");
        let (own, router_nwk) = (Nwk(0x0000), Nwk(0x1111));
        let now = Instant::from_micros(0);
        let link_status = link_status_listing(own);
        let mut neighbors = Neighbors::default();

        let incoming_cost =
            |neighbors: &Neighbors| neighbors.link(router_nwk).unwrap().incoming_cost;

        // One sample is the link quality, and the router is listed at once
        neighbors.on_link_status(own, router, router_nwk, 200, &link_status, now, ACTIVITY);
        assert_eq!(incoming_cost(&neighbors), lqi_to_link_cost(200));
        assert_eq!(neighbors.link_status_entries().len(), 1);

        // Two samples: their average
        neighbors.record_lqa(router_nwk, 40);
        assert_eq!(incoming_cost(&neighbors), lqi_to_link_cost(120));

        // Three samples: the median
        neighbors.record_lqa(router_nwk, 40);
        assert_eq!(incoming_cost(&neighbors), lqi_to_link_cost(40));
    }

    #[test]
    fn test_restored_child_without_samples_has_no_link_cost() {
        let neighbors = neighbors_with(NwkDeviceType::Router);

        assert_eq!(neighbors.link(CHILD_NWK).unwrap().incoming_cost, 0);
        assert!(neighbors.link_status_entries().is_empty());
    }

    #[test]
    fn test_link_status_keeps_address_another_neighbor_holds() {
        let router = Eui64::from_hex("aa:bb:cc:dd:ee:ff:00:11");
        let other = Eui64::from_hex("aa:bb:cc:dd:ee:ff:00:22");
        let own = Nwk(0x0000);
        let (old, contested) = (Nwk(0x1111), Nwk(0x2222));
        let now = Instant::from_micros(0);
        let link_status = link_status_listing(own);
        let mut neighbors = Neighbors::default();

        neighbors.on_link_status(own, router, old, 200, &link_status, now, ACTIVITY);
        neighbors.on_link_status(own, other, contested, 200, &link_status, now, ACTIVITY);

        // The router's link status from an address the other neighbor holds, or from
        // our own address, is an address conflict: the router keeps its entry's address
        for conflicting in [contested, own] {
            let outcome = neighbors.on_link_status(
                own,
                router,
                conflicting,
                200,
                &link_status,
                now,
                ACTIVITY,
            );
            assert_eq!(outcome, LinkStatusOutcome::default());
            assert_eq!(neighbors.link(old).unwrap().eui64, router);
            assert_eq!(neighbors.link(contested).unwrap().eui64, other);
            assert!(!neighbors.has_network_address(own));
        }
    }

    #[test]
    fn test_link_status_address_refresh_keeps_ring_order() {
        let router = Eui64::from_hex("aa:bb:cc:dd:ee:ff:00:11");
        let own = Nwk(0x0000);
        let (old, new) = (Nwk(0x1111), Nwk(0x2222));
        let now = Instant::from_micros(0);
        let link_status = link_status_listing(own);
        let mut neighbors = Neighbors::default();

        neighbors.on_link_status(own, router, old, 10, &link_status, now, ACTIVITY);

        // More samples than the window buffered under the new address: the ring wraps
        for lqi in [10, 20, 200, 220] {
            neighbors.record_lqa(new, lqi);
        }
        neighbors.on_link_status(own, router, new, 220, &link_status, now, ACTIVITY);

        // The window is [20, 200, 220] and its oldest (20) is replaced next, giving
        // [200, 220, 30]: a scrambled order would replace 220 and drop the median to 30
        neighbors.record_lqa(new, 30);
        assert_eq!(
            neighbors.link(new).unwrap().incoming_cost,
            lqi_to_link_cost(200)
        );
    }

    fn inbound_activity(neighbors: &Neighbors) -> u8 {
        let entry = neighbors.entries().next().unwrap();
        entry.router_inbound_activity.count()
    }

    #[test]
    fn test_new_neighbor_is_not_charged_for_time_before_it_existed() {
        // Created a minute in: the minute before must not decay its counters
        let created = Instant::from_micros(0) + Duration::from_secs(60);
        let mut neighbors = Neighbors::default();
        neighbors.restore_child(
            ChildDescriptor {
                eui64: Eui64::from_hex("00:11:22:33:44:55:66:77"),
                network_address: CHILD_NWK,
                device_type: NwkDeviceType::Router,
                rx_on_when_idle: true,
                device_timeout: None,
                relationship: Relationship::Child,
            },
            created,
            ACTIVITY,
        );

        neighbors.decay_activity(created + Duration::from_secs(1), ACTIVITY.period);
        assert_eq!(inbound_activity(&neighbors), ACTIVITY.initial_count - 1);
    }

    #[test]
    fn test_use_is_not_charged_for_time_before_it() {
        // By a minute in, the count the neighbor started with has decayed away
        let used = Instant::from_micros(0) + Duration::from_secs(60);
        let mut neighbors = neighbors_with(NwkDeviceType::Router);
        neighbors.record_inbound_activity(CHILD_NWK, used, ACTIVITY.period);
        neighbors.record_inbound_activity(CHILD_NWK, used, ACTIVITY.period);

        // The two uses lose only the second that follows them
        neighbors.decay_activity(used + Duration::from_secs(1), ACTIVITY.period);
        assert_eq!(inbound_activity(&neighbors), 1);
    }

    #[test]
    fn test_only_end_device_children_time_out() {
        let mut neighbors = neighbors_with(NwkDeviceType::EndDevice);
        neighbors.upsert_child(
            ChildDescriptor {
                eui64: Eui64::from_hex("88:99:aa:bb:cc:dd:ee:ff"),
                network_address: Nwk(0x5678),
                device_type: NwkDeviceType::Router,
                rx_on_when_idle: true,
                device_timeout: Some(Duration::from_secs(30)),
                relationship: Relationship::Child,
            },
            Instant::from_micros(0),
            ACTIVITY,
        );

        assert_eq!(
            neighbors.next_child_timeout(),
            Some(Instant::from_micros(0) + Duration::from_secs(60))
        );

        let evicted =
            neighbors.evict_timed_out_children(Instant::from_micros(0) + Duration::from_secs(120));
        assert_eq!(
            evicted,
            vec![(Eui64::from_hex("00:11:22:33:44:55:66:77"), CHILD_NWK)]
        );
        assert_eq!(neighbors.next_child_timeout(), None);
    }

    fn relationship_of(neighbors: &Neighbors, eui64: Eui64) -> Relationship {
        neighbors
            .entries()
            .find(|entry| entry.extended_address == eui64)
            .unwrap()
            .relationship
    }

    #[test]
    fn test_nwk_secured_frame_authenticates_unauthenticated_child() {
        let eui64 = Eui64::from_hex("00:11:22:33:44:55:66:77");
        let mut neighbors = Neighbors::default();
        neighbors.upsert_child(
            ChildDescriptor {
                eui64,
                network_address: CHILD_NWK,
                device_type: NwkDeviceType::EndDevice,
                rx_on_when_idle: false,
                device_timeout: Some(Duration::from_secs(60)),
                relationship: Relationship::UnauthenticatedChild,
            },
            Instant::from_micros(0),
            ACTIVITY,
        );

        // Still a child for parent duties while unauthenticated
        assert_eq!(neighbors.end_device_child_eui64(CHILD_NWK), Some(eui64));
        assert_eq!(
            relationship_of(&neighbors, eui64),
            Relationship::UnauthenticatedChild
        );

        assert!(neighbors.note_nwk_secured_frame(eui64));
        assert_eq!(relationship_of(&neighbors, eui64), Relationship::Child);

        // Already authenticated: nothing left to promote
        assert!(!neighbors.note_nwk_secured_frame(eui64));
        assert_eq!(relationship_of(&neighbors, eui64), Relationship::Child);

        // Associating again makes it unauthenticated until its next secured frame
        neighbors.upsert_child(
            ChildDescriptor {
                eui64,
                network_address: CHILD_NWK,
                device_type: NwkDeviceType::EndDevice,
                rx_on_when_idle: false,
                device_timeout: Some(Duration::from_secs(60)),
                relationship: Relationship::UnauthenticatedChild,
            },
            Instant::from_micros(0),
            ACTIVITY,
        );
        assert_eq!(
            relationship_of(&neighbors, eui64),
            Relationship::UnauthenticatedChild
        );
        assert!(neighbors.note_nwk_secured_frame(eui64));
        assert_eq!(relationship_of(&neighbors, eui64), Relationship::Child);
    }

    #[test]
    fn test_nwk_secured_frame_leaves_other_neighbors_alone() {
        let child = Eui64::from_hex("00:11:22:33:44:55:66:77");
        let mut neighbors = neighbors_with(NwkDeviceType::Router);

        // Unknown senders gain no entry, and authenticated children stay children
        assert!(!neighbors.note_nwk_secured_frame(Eui64::from_hex("88:99:aa:bb:cc:dd:ee:ff")));
        assert!(!neighbors.note_nwk_secured_frame(child));
        assert_eq!(neighbors.entries().count(), 1);
        assert_eq!(relationship_of(&neighbors, child), Relationship::Child);
    }
}
