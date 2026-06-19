use std::collections::HashMap;

use crate::nwk::commands::NwkRouteRequestManyToOne;
use ieee_802154::types::Nwk;
use std::time::{Duration, Instant};

use crate::nwk::frame::BROADCAST_ALL_ROUTERS_AND_COORDINATOR;

pub type RequestId = u8;

const UNKNOWN_NEXT_HOP: Nwk = Nwk(0xFFFF);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Active = 0,
    DiscoveryUnderway = 1,
    DiscoveryFailed = 2,
    Inactive = 3,
}

#[derive(Debug)]
pub struct TableEntry {
    /// Destination address the routing table entry is for
    pub destination: Nwk,
    pub status: Status,

    /// A flag indicating that the destination indicated by this address does not store
    /// source routes.
    pub no_route_cache: bool,

    /// A flag indicating that the destination is a concentrator that issued a
    /// many-to-one route request.
    pub many_to_one: bool,

    /// A flag indicating that a route record command frame SHOULD be sent to the
    /// destination prior to the next data packet.
    pub route_record_required: bool,

    /// When set to TRUE, this flag indicates that an expected regular many-to-one route
    /// request was missed, i.e. the last many-to-one route request for this destination
    /// was received more than `nwkConcentratorDiscoveryTime` + `nwkRouteDiscoveryTime`
    /// seconds ago. When the entry is created, this field is initially set to FALSE.
    /// This flag only has meaning for entries, which have the many-to-one field set to
    /// TRUE.
    pub expired: bool,

    /// The 16-bit network address of the next hop on the way to the destination.
    /// This is the routing table entry's primary purpose.
    pub next_hop_address: Nwk,

    /// A 32-bit saturating counter, which is incremented whenever this routing table
    /// entry is used to forward a data packet towards its destination
    pub total_usage_count: u32,

    /// An 8-bit saturating counter, which is pre-loaded with `nwkRouterAgeLimit` when the
    /// routing table entry is created; incremented whenever this routing table entry is
    /// used to forward a state packet towards its destination; and decremented
    /// unconditionally once every `nwkLinkStatusPeriod`. A value of 0 indicates no
    /// packets have recently been forwarded along this route.
    pub recent_activity: u8,
}

impl TableEntry {
    const fn new(destination: Nwk, status: Status, next_hop_address: Nwk) -> Self {
        Self {
            destination,
            status,
            no_route_cache: false,
            many_to_one: false,
            route_record_required: false,
            expired: false,
            next_hop_address,
            total_usage_count: 0,
            recent_activity: 0,
        }
    }
}

#[derive(Debug)]
pub struct DiscoveryEntry {
    /// A sequence number for a route request command frame that is incremented each time
    /// a device initiates a route request. Notice that this 8-bit identifier is
    /// distinct from the 16-bit Routing Sequence Number. The former is used to discern
    /// route requests originating in a particular router; the latter is used to
    /// identify stale routing information.
    pub route_request_id: RequestId,
    /// The 16-bit network address of the route request’s initiator.
    pub source_address: Nwk,
    /// The 16-bit network address of the device that has sent the most recent lowest
    /// cost route request command frame corresponding to this entry’s route request
    /// identifier and source address. This field is used to determine the path that an
    /// eventual route reply command frame SHOULD follow.
    pub sender_address: Nwk,
    /// The accumulated path cost from the source of the route request to the current
    /// device.
    pub forward_cost: u8,
    /// The accumulated path cost from the current device to the destination device.
    pub residual_cost: u8,
    /// A countdown timer indicating the number of milliseconds until route discovery
    /// expires. The initial value is `nwkcRouteDiscoveryTime`.
    pub expiration_time: Instant,
    /// The 16-bit network address of the device this route discovery entry is
    /// identifying a route for. This isn't mentioned in the spec as being a required
    /// field.
    pub destination_address: Nwk,
}

/// An outbound routing decision for a frame we originate.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// Transmit to this next hop; intermediate routers handle the rest
    NextHop(Nwk),
    /// Embed a source route subframe; the MAC destination is the last relay
    SourceRouted(Vec<Nwk>),
}

/// What to do with an accepted route reply.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "the driver must act on the disposition (relay onward or mark the route \
    established); dropping it silently discards the route reply"]
pub enum RouteReplyDisposition {
    /// Stale, unsolicited, or no better than what we already have
    Drop,
    /// The reply answers our own request: the route to the responder is usable now
    Established,
    /// Relay the reply toward the request originator via `next_hop`, advertising
    /// `path_cost` (the next hop's own link cost still needs to be added)
    Relay { next_hop: Nwk, path_cost: u8 },
}

/// The NWK routing layer: route table, route discovery table, and route record table,
/// with the decision logic for route request/reply processing.
#[derive(Debug)]
pub struct Routing {
    network_address: Nwk,
    route_discovery_time: Duration,

    /// Route-repair signals counted since the last many-to-one route request
    /// (route-failure network statuses and locally failed unicast deliveries);
    /// crossing a threshold warrants advertising the concentrator early
    mtorr_route_errors: u8,
    mtorr_delivery_failures: u8,
    mtorr_route_error_threshold: u8,
    mtorr_delivery_failure_threshold: u8,

    route_table: HashMap<Nwk, TableEntry>,
    discovery_table: HashMap<(Nwk, RequestId), DiscoveryEntry>,
    route_record_table: HashMap<Nwk, Vec<Nwk>>,

    /// Implied from the spec: "notice that this 8-bit identifier is distinct from the
    /// 16-bit Routing Sequence Number. The former is used to discern route requests
    /// originating in a particular router; the latter is used to identify stale routing
    /// information."
    request_sequence_number: RequestId,
}

impl Routing {
    pub fn new(
        network_address: Nwk,
        route_discovery_time: Duration,
        mtorr_route_error_threshold: u8,
        mtorr_delivery_failure_threshold: u8,
    ) -> Self {
        Self {
            network_address,
            route_discovery_time,
            mtorr_route_errors: 0,
            mtorr_delivery_failures: 0,
            mtorr_route_error_threshold,
            mtorr_delivery_failure_threshold,
            route_table: HashMap::new(),
            discovery_table: HashMap::new(),
            route_record_table: HashMap::new(),
            request_sequence_number: 0,
        }
    }

    /// Count a received route-failure network status toward an early many-to-one
    /// route request. Returns whether the accumulated signals warrant one.
    pub const fn note_route_error(&mut self) -> bool {
        self.mtorr_route_errors = self.mtorr_route_errors.saturating_add(1);
        self.mtorr_route_errors >= self.mtorr_route_error_threshold
    }

    /// Count a locally failed unicast delivery toward an early many-to-one route
    /// request. Returns whether the accumulated signals warrant one.
    pub const fn note_delivery_failure(&mut self) -> bool {
        self.mtorr_delivery_failures = self.mtorr_delivery_failures.saturating_add(1);
        self.mtorr_delivery_failures >= self.mtorr_delivery_failure_threshold
    }

    /// A many-to-one route request went out: the accumulated route-repair signals
    /// are spent.
    pub const fn reset_mtorr_triggers(&mut self) {
        self.mtorr_route_errors = 0;
        self.mtorr_delivery_failures = 0;
    }

    pub fn route_status(&self, destination: Nwk) -> Option<Status> {
        self.route_table.get(&destination).map(|entry| entry.status)
    }

    pub fn entries(&self) -> impl Iterator<Item = &TableEntry> {
        self.route_table.values()
    }

    /// The next hop toward a destination with an active route.
    pub fn next_hop(&self, destination: Nwk) -> Option<Nwk> {
        self.route_table
            .get(&destination)
            .filter(|entry| entry.status == Status::Active)
            .map(|entry| {
                assert!(entry.next_hop_address != UNKNOWN_NEXT_HOP);
                entry.next_hop_address
            })
    }

    pub fn mark_discovery_failed(&mut self, destination: Nwk) {
        if let Some(entry) = self.route_table.get_mut(&destination) {
            entry.status = Status::DiscoveryFailed;
        }
    }

    /// A frame was forwarded along the route: bump its usage counters.
    pub fn record_usage(&mut self, destination: Nwk) {
        if let Some(entry) = self.route_table.get_mut(&destination) {
            entry.recent_activity = entry.recent_activity.saturating_add(1);
            entry.total_usage_count = entry.total_usage_count.saturating_add(1);
        }
    }

    /// Called once per `nwkLinkStatusPeriod`: decrement the `recent_activity` field of
    /// every active routing table entry.
    pub fn decay_activity(&mut self) {
        for entry in self.route_table.values_mut() {
            if entry.status == Status::Active {
                entry.recent_activity = entry.recent_activity.saturating_sub(1);
            }
        }
    }

    /// Mark every active route through the given next hop as inactive, forcing a fresh
    /// discovery on next use.
    pub fn invalidate_via(&mut self, next_hop: Nwk) {
        for entry in self.route_table.values_mut() {
            if entry.status == Status::Active && entry.next_hop_address == next_hop {
                tracing::info!(
                    "Invalidating route to {:?} via unreachable next hop {next_hop:?}",
                    entry.destination
                );
                entry.status = Status::Inactive;
            }
        }
    }

    pub fn remove_route(&mut self, destination: Nwk) -> bool {
        self.route_table.remove(&destination).is_some()
    }

    pub fn store_route_record(&mut self, source: Nwk, relays: Vec<Nwk>) {
        // Spec 3.6.4.5.5: the new route also replaces any existing source routes to
        // the intermediary relays. The relays between relay `i` and us form its own
        // route; the last relay delivered the record to us directly.
        for i in 1..relays.len() {
            self.route_record_table
                .insert(relays[i - 1], relays[i..].to_vec());
        }
        if let Some(&last) = relays.last() {
            self.route_record_table.insert(last, Vec::new());
        }

        self.route_record_table.insert(source, relays);
    }

    pub fn remove_route_record(&mut self, destination: Nwk) -> bool {
        self.route_record_table.remove(&destination).is_some()
    }

    /// Spec 3.6.4.3.2: relaying a source-routed frame proves the concentrator that
    /// originated it holds a route record for the frame's source; no route record
    /// has to precede the next frame toward it (unless it keeps no route cache).
    pub fn note_source_routed_frame(&mut self, concentrator: Nwk) {
        if let Some(entry) = self.route_table.get_mut(&concentrator)
            && !entry.no_route_cache
        {
            entry.route_record_required = false;
        }
    }

    /// The outbound route for a frame we originate. A stored source route wins over
    /// the routing table: it is self-contained, while a table entry relies on every
    /// intermediate router still holding state (and our entries toward devices are
    /// mostly reverse-route side effects of their discoveries). This deviates from
    /// the spec's table-first order (3.6.4.3).
    pub fn route_to(&self, destination: Nwk, max_source_route: u8) -> Option<Route> {
        match self.route_record_table.get(&destination) {
            // Spec 3.6.4.3.1: no intermediate relays means direct transmission
            Some(relays) if relays.is_empty() => Some(Route::NextHop(destination)),
            Some(relays) if relays.len() < max_source_route as usize => {
                Some(Route::SourceRouted(relays.clone()))
            }
            _ => self.next_hop(destination).map(Route::NextHop),
        }
    }

    /// Prepare table state for a route discovery we originate: the routing entry enters
    /// `DiscoveryUnderway` and a discovery entry keyed by our own address is created.
    /// Returns the request identifier to put in the route request command.
    pub fn begin_discovery(&mut self, destination: Nwk, now: Instant) -> RequestId {
        // Expire stale discoveries before establishing the new one. A just-expired
        // discovery toward this same destination would otherwise tear down the
        // `DiscoveryUnderway` route entry created below.
        self.expire_discoveries(now);

        let route_table_entry = self
            .route_table
            .entry(destination)
            .or_insert_with(|| TableEntry::new(destination, Status::Inactive, UNKNOWN_NEXT_HOP));
        route_table_entry.status = Status::DiscoveryUnderway;

        self.request_sequence_number = self.request_sequence_number.wrapping_add(1);
        let request_id = self.request_sequence_number;

        let key = (self.network_address, request_id);
        let discovery_entry = self
            .discovery_table
            .entry(key)
            .or_insert_with(|| DiscoveryEntry {
                route_request_id: request_id,
                source_address: self.network_address,
                sender_address: UNKNOWN_NEXT_HOP,
                forward_cost: 0,
                residual_cost: 0,
                expiration_time: now + self.route_discovery_time,
                destination_address: destination,
            });

        tracing::debug!("Route discovery entry: [{key:?}] = {discovery_entry:?}");

        request_id
    }

    /// Register the discovery entry backing a many-to-one route advertisement, which
    /// is addressed to a broadcast address and never answered with a reply.
    pub fn begin_many_to_one_advertisement(&mut self, now: Instant) -> RequestId {
        self.request_sequence_number = self.request_sequence_number.wrapping_add(1);
        let request_id = self.request_sequence_number;

        self.expire_discoveries(now);

        // The discovery entry exists purely for loop detection: relayed copies of our
        // own request will compare against the zero forward cost and be dropped
        self.discovery_table.insert(
            (self.network_address, request_id),
            DiscoveryEntry {
                route_request_id: request_id,
                source_address: self.network_address,
                sender_address: UNKNOWN_NEXT_HOP,
                forward_cost: 0,
                residual_cost: 0,
                expiration_time: now + self.route_discovery_time,
                destination_address: BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
            },
        );

        request_id
    }

    /// The expiration time of the live discovery toward a destination, if any.
    pub fn discovery_deadline(&self, destination: Nwk, now: Instant) -> Option<Instant> {
        self.discovery_table.values().find_map(|entry| {
            if entry.expiration_time >= now && entry.destination_address == destination {
                Some(entry.expiration_time)
            } else {
                None
            }
        })
    }

    /// Deduplicate a received route request and track the best path back to its
    /// originator. Returns false for duplicates without a strictly better forward
    /// cost (which also stops our own requests from echoing back at us); an accepted
    /// request establishes the route back to the originator through the sending
    /// device (spec 3.6.4.5.1.2).
    #[allow(clippy::too_many_arguments)]
    pub fn accept_route_request(
        &mut self,
        originator: Nwk,
        request_id: RequestId,
        destination: Nwk,
        sender: Nwk,
        updated_path_cost: u8,
        many_to_one: NwkRouteRequestManyToOne,
        now: Instant,
    ) -> bool {
        self.expire_discoveries(now);

        match self.discovery_table.get_mut(&(originator, request_id)) {
            Some(discovery_entry) => {
                if updated_path_cost >= discovery_entry.forward_cost {
                    tracing::debug!("Ignoring route request without a better cost");
                    return false;
                }

                discovery_entry.forward_cost = updated_path_cost;
                discovery_entry.sender_address = sender;
            }
            None => {
                self.discovery_table.insert(
                    (originator, request_id),
                    DiscoveryEntry {
                        route_request_id: request_id,
                        source_address: originator,
                        sender_address: sender,
                        forward_cost: updated_path_cost,
                        residual_cost: 0,
                        expiration_time: now + self.route_discovery_time,
                        destination_address: destination,
                    },
                );
            }
        }

        let originator_entry = self
            .route_table
            .entry(originator)
            .or_insert_with(|| TableEntry::new(originator, Status::Active, sender));
        originator_entry.status = Status::Active;
        originator_entry.next_hop_address = sender;

        // Spec 3.6.4.5.1.2: a many-to-one request marks its originator as a
        // concentrator; spec 3.6.4.5.1.8: a later plain request never clears it
        if many_to_one != NwkRouteRequestManyToOne::NotManyToOne {
            originator_entry.many_to_one = true;
            originator_entry.route_record_required = true;
            originator_entry.no_route_cache = many_to_one
                == NwkRouteRequestManyToOne::ManyToOneSenderDoesntSupportRouteRecordTable;
        }

        true
    }

    /// Before relaying a route request: track that discovery toward the destination is
    /// underway, so frames for it are held off until it completes.
    pub fn note_relayed_discovery(&mut self, destination: Nwk) {
        self.route_table
            .entry(destination)
            .and_modify(|entry| {
                if entry.status != Status::Active {
                    entry.status = Status::DiscoveryUnderway;
                }
            })
            .or_insert_with(|| {
                TableEntry::new(destination, Status::DiscoveryUnderway, UNKNOWN_NEXT_HOP)
            });
    }

    /// Process a received route reply against the discovery and route tables and
    /// decide whether to drop it, accept it for our own request, or relay it onward.
    /// `updated_path_cost` is the advertised cost plus the sender's outgoing link cost.
    pub fn accept_route_reply(
        &mut self,
        originator: Nwk,
        request_id: RequestId,
        responder: Nwk,
        sender: Nwk,
        updated_path_cost: u8,
    ) -> RouteReplyDisposition {
        let Some(discovery_entry) = self.discovery_table.get_mut(&(originator, request_id)) else {
            tracing::debug!("Route reply for unknown route discovery, ignoring");
            return RouteReplyDisposition::Drop;
        };

        let Some(routing_entry) = self.route_table.get_mut(&responder) else {
            tracing::debug!("Route reply with unknown responder, ignoring");
            return RouteReplyDisposition::Drop;
        };

        // If we are the originator, handling is simplified
        if originator == self.network_address {
            if routing_entry.status == Status::Active
                && updated_path_cost >= discovery_entry.residual_cost
            {
                tracing::debug!(
                    "Ignoring route reply for us with higher cost ({} > {})",
                    updated_path_cost,
                    discovery_entry.residual_cost
                );
                return RouteReplyDisposition::Drop;
            }

            tracing::debug!(
                "Updating routing entry for NWK {responder:?} ({:?}) to next hop {sender:?} (residual cost {updated_path_cost})",
                routing_entry.status,
            );

            routing_entry.status = Status::Active;
            routing_entry.next_hop_address = sender;
            discovery_entry.residual_cost = updated_path_cost;

            return RouteReplyDisposition::Established;
        }

        // Otherwise, we need to decide if we need to update our own routes and possibly
        // relay the frame
        if updated_path_cost >= discovery_entry.residual_cost {
            tracing::debug!(
                "Ignoring unsolicited route reply with higher cost ({} > {})",
                updated_path_cost,
                discovery_entry.residual_cost
            );
            return RouteReplyDisposition::Drop;
        }

        routing_entry.next_hop_address = sender;
        discovery_entry.residual_cost = updated_path_cost;

        // The reply travels back along the path the request came from
        let next_hop = discovery_entry.sender_address;

        // Spec 3.6.4.5.2.1: relaying the reply also establishes the reverse route
        // toward the originator of the route request
        let reverse_entry = self
            .route_table
            .entry(originator)
            .or_insert_with(|| TableEntry::new(originator, Status::Active, next_hop));
        reverse_entry.status = Status::Active;
        reverse_entry.next_hop_address = next_hop;

        RouteReplyDisposition::Relay {
            next_hop,
            path_cost: updated_path_cost,
        }
    }

    /// Clean expired entries from the route discovery table. Their lifetime is ~10s.
    /// Spec 3.6.4.5.1.7: a discovery that never completed must not leave the routing
    /// entry stuck in DISCOVERY_UNDERWAY, which would block future discoveries.
    fn expire_discoveries(&mut self, now: Instant) {
        let mut expired_destinations = Vec::new();

        self.discovery_table.retain(|_, entry| {
            if entry.expiration_time <= now {
                tracing::debug!("Removing expired route discovery entry: {entry:?}");
                expired_destinations.push(entry.destination_address);
                false
            } else {
                true
            }
        });

        for destination in expired_destinations {
            if self
                .discovery_table
                .values()
                .any(|entry| entry.destination_address == destination)
            {
                continue;
            }

            if self
                .route_table
                .get(&destination)
                .is_some_and(|entry| entry.status == Status::DiscoveryUnderway)
            {
                tracing::debug!(
                    "Removing routing entry for expired route discovery: {destination:?}"
                );
                self.route_table.remove(&destination);
            }
        }
    }
}
