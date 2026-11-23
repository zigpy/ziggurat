//! The MAC next hop of a unicast we originate or relay, and the route record due before
//! it is transmitted.
//!
//! A decision over the routing and neighbor tables that may rewrite the frame to carry
//! a source route (spec 3.6.4.3).

use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_ieee_802154::types::{Eui64, Nwk};

use crate::Instant;

use crate::nwk::frame::{NwkFrame, NwkFrameType, NwkRouteDiscovery, NwkSourceRoute};
use crate::nwk::neighbors::Neighbors;
use crate::nwk::routing::{Route, Routing};

/// How the MAC next hop for an outgoing unicast is chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendMode {
    /// The destination is its own next hop: transmit straight to it with no routing
    /// lookup (and route discovery suppressed). Used for frames to a one-hop neighbor,
    /// e.g. delivering the network key to a joining device.
    Direct,
    /// Resolve the next hop through the routing layer, subject to a host [`RouteDirective`]:
    /// the route table or an applicable source route, discovering a route first if none is
    /// known.
    Route(RouteDirective),
    /// Relay another device's frame: follow its source route, or route it like our own.
    /// Only a frame from our own end device child may wait for a route discovery.
    Relay,
}

/// How the host wants an originated unicast routed.
///
/// Hints and forces are per-frame: they steer a single send and are never written into
/// the routing tables (so they never echo back through the route-change notification
/// stream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDirective {
    /// The stack resolves the route entirely on its own (source route, route table, or
    /// discovery). What all stack-originated traffic passes.
    StackDecides,
    /// Use the supplied route only when the stack has no route of its own; it stands in
    /// for route discovery rather than triggering it. A known route still wins.
    Hint(HostRoute),
    /// Use the supplied route unconditionally, overriding even a known route and
    /// suppressing discovery.
    Force(HostRoute),
}

/// A route the host supplies alongside a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRoute {
    /// Hand the frame to this next hop and let it route onward.
    NextHop(Nwk),
    /// The ordered relay path to embed as a source route; the MAC destination is the
    /// last relay. An empty list means direct delivery to the destination.
    SourceRoute(Vec<Nwk>),
}

/// A route record to transmit just before a data frame to a concentrator (spec
/// 3.6.4.5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRecord {
    /// For a frame we originate: the path starts at us.
    Ours,
    /// For a frame we relay for our end device child: the path starts at the child.
    Child { nwk: Nwk, eui64: Eui64 },
}

/// The outcome of resolving a unicast's MAC next hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHop {
    /// Transmit to this next hop now.
    Resolved(Nwk),
    /// No route known; the frame must wait for route discovery.
    NeedDiscovery,
    /// No route known and the frame's `discover_route` flag forbids discovering one.
    Discard,
}

/// The stack settings next-hop resolution reads.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Our own network address.
    pub network_address: Nwk,
    /// We store route records and source-route through them.
    pub is_concentrator: bool,
    /// Ignore every known route and always discover, so routing logic is exercised.
    pub force_route_discovery: bool,
    /// The longest source route we embed.
    pub max_source_route: u8,
    /// The highest outgoing cost to a source route's first hop we send over.
    pub source_route_max_first_hop_cost: u8,
    /// How long after a router child associates or rejoins we send to it directly
    /// when no route is known.
    pub new_router_child_window: Duration,
    /// The highest link cost to a neighbor we send to directly, with no route.
    pub direct_max_link_cost: u8,
}

/// Whether `destination` is a neighbor we can send to directly, with no route (spec
/// 3.6.3.3).
///
/// A neighbor that has not listed us in a link status has no outgoing cost and is
/// excluded.
pub fn is_direct_neighbor(neighbors: &Neighbors, destination: Nwk, max_link_cost: u8) -> bool {
    neighbors.link(destination).is_some_and(|link| {
        link.outgoing_cost > 0 && link.incoming_cost > 0 && link.cost() <= max_link_cost
    })
}

/// Whether we send to `destination` directly, with no route: our end device child, a
/// neighbor over a good link, or a router child that just attached.
pub fn reaches_directly(
    neighbors: &Neighbors,
    destination: Nwk,
    policy: Policy,
    now: Instant,
) -> bool {
    neighbors.end_device_child_eui64(destination).is_some()
        || is_direct_neighbor(neighbors, destination, policy.direct_max_link_cost)
        || neighbors.is_recently_attached_router_child(
            destination,
            now,
            policy.new_router_child_window,
        )
}

/// Resolve the MAC next hop for a unicast.
///
/// Following or applying a source route rewrites `frame`'s header in place (spec
/// 3.6.4.3).
pub fn resolve(
    routing: &mut Routing,
    neighbors: &Neighbors,
    frame: &mut NwkFrame,
    mode: &SendMode,
    policy: Policy,
    now: Instant,
) -> NextHop {
    match mode {
        SendMode::Direct => NextHop::Resolved(frame.nwk_header.destination),
        SendMode::Route(directive) => route(routing, neighbors, frame, directive, policy, now),
        SendMode::Relay => relay(routing, neighbors, frame, policy, now),
    }
}

/// Spec 3.6.4.5.5: the route record to transmit just before a data frame from us or our
/// end device child toward a concentrator.
pub fn route_record_due(
    routing: &Routing,
    neighbors: &Neighbors,
    frame: &NwkFrame,
    network_address: Nwk,
) -> Option<RouteRecord> {
    if frame.nwk_header.frame_control.frame_type != NwkFrameType::Data {
        return None;
    }

    let source = frame.nwk_header.source;
    let destination = frame.nwk_header.destination;

    if source == network_address {
        return routing
            .route_record_required(destination, false)
            .then_some(RouteRecord::Ours);
    }

    // TODO: spec 3.6.4.5.5 allows skipping the route record for a child that already
    // received a frame the concentrator source-routed to it. We send one before every
    // relayed frame.
    let eui64 = neighbors.end_device_child_eui64(source)?;
    routing
        .route_record_required(destination, true)
        .then_some(RouteRecord::Child { nwk: source, eui64 })
}

/// Spec 3.6.4.3: the next hop of a frame we relay.
fn relay(
    routing: &mut Routing,
    neighbors: &Neighbors,
    frame: &mut NwkFrame,
    policy: Policy,
    now: Instant,
) -> NextHop {
    let source = frame.nwk_header.source;
    let destination = frame.nwk_header.destination;

    if let Some(source_route) = &mut frame.nwk_header.source_route {
        // Spec 3.6.4.3.2: a source-routed frame names its own path; the relay list is
        // followed instead of the routing table
        let index = usize::from(source_route.relay_index);

        let next_hop = if index == 0 {
            // The final relay forwards directly to the NWK destination
            destination
        } else {
            if source_route.relays.get(index) != Some(&policy.network_address) {
                tracing::debug!("Source routed frame is not addressed through us");
                return NextHop::Discard;
            }

            source_route.relay_index -= 1;
            source_route.relays[index - 1]
        };

        routing.note_source_routed_frame(source);

        // Delivery to our own end device child skips the rest of the relay list
        if neighbors.end_device_child_eui64(destination).is_some() {
            return NextHop::Resolved(destination);
        }

        return NextHop::Resolved(next_hop);
    }

    if reaches_directly(neighbors, destination, policy, now) {
        return NextHop::Resolved(destination);
    }

    if let Some(next_hop) = routing.next_hop(destination) {
        return NextHop::Resolved(next_hop);
    }

    // Spec 3.6.4.5.1: a relay discovers a route only for a frame from its own end device
    // child that allows discovery. End devices do not discover routes themselves, so
    // their parent does it for them. A relay never discovers on behalf of a router,
    // which recovers through its own discovery or APS retries
    if frame.nwk_header.frame_control.discover_route == NwkRouteDiscovery::Enable
        && neighbors.end_device_child_eui64(source).is_some()
    {
        NextHop::NeedDiscovery
    } else {
        NextHop::Discard
    }
}

/// The next hop of a frame we originate.
fn route(
    routing: &Routing,
    neighbors: &Neighbors,
    frame: &mut NwkFrame,
    directive: &RouteDirective,
    policy: Policy,
    now: Instant,
) -> NextHop {
    let destination = frame.nwk_header.destination;

    // A forced host route overrides everything, including a known route.
    if let RouteDirective::Force(route) = directive {
        return apply_host_route(frame, route);
    }

    // End device children never route-discover; their parent delivers directly. This
    // also keeps a stale route record from outliving a device rejoining as our child.
    if neighbors.end_device_child_eui64(destination).is_some() {
        return NextHop::Resolved(destination);
    }

    // A neighbor with a good link is reached directly. No route is cheaper
    if !policy.force_route_discovery
        && is_direct_neighbor(neighbors, destination, policy.direct_max_link_cost)
    {
        return NextHop::Resolved(destination);
    }

    // A stored source route (concentrator behavior) wins over the routing table.
    if policy.is_concentrator && !policy.force_route_discovery {
        // Our outgoing cost is the one the neighbor measured and reported; 0 means it
        // has not reported one yet
        let first_hop_usable = |hop| {
            neighbors.link(hop).is_some_and(|link| {
                (1..=policy.source_route_max_first_hop_cost).contains(&link.outgoing_cost)
            })
        };

        match routing.route_to(destination, policy.max_source_route, first_hop_usable) {
            Some(Route::NextHop(next_hop)) => {
                return NextHop::Resolved(next_hop);
            }
            Some(Route::SourceRouted(relays)) => return apply_source_route(frame, relays),
            None => {}
        }
    }

    // An active ad-hoc route, unless we are deliberately forcing rediscovery.
    if !policy.force_route_discovery
        && let Some(next_hop) = routing.next_hop(destination)
    {
        return NextHop::Resolved(next_hop);
    }

    // A router child that just attached has sent no link status yet, send to it
    // directly for a short time
    if !policy.force_route_discovery
        && neighbors.is_recently_attached_router_child(
            destination,
            now,
            policy.new_router_child_window,
        )
    {
        return NextHop::Resolved(destination);
    }

    // No usable route. A host hint stands in for discovery rather than triggering it.
    if let RouteDirective::Hint(route) = directive {
        return apply_host_route(frame, route);
    }

    // Spec 3.6.3.3: only initiate discovery if the frame allows it.
    if frame.nwk_header.frame_control.discover_route == NwkRouteDiscovery::Suppress {
        NextHop::Discard
    } else {
        NextHop::NeedDiscovery
    }
}

/// Apply a host-supplied route to a frame we originate, resolving its MAC next hop.
fn apply_host_route(frame: &mut NwkFrame, route: &HostRoute) -> NextHop {
    match route {
        // The next hop routes onward itself, so `discover_route` is left as built:
        // an intermediate hop still needs it to reach the final destination.
        HostRoute::NextHop(next_hop) => NextHop::Resolved(*next_hop),
        HostRoute::SourceRoute(relays) => apply_source_route(frame, relays.clone()),
    }
}

/// Rewrite `frame` to carry a source route.
fn apply_source_route(frame: &mut NwkFrame, relays: Vec<Nwk>) -> NextHop {
    let next_hop = *relays.last().unwrap();
    frame.nwk_header.frame_control.source_route = true;
    frame.nwk_header.frame_control.discover_route = NwkRouteDiscovery::Suppress;
    frame.nwk_header.source_route = Some(NwkSourceRoute {
        relay_index: relays.len() as u8 - 1,
        relays,
    });
    NextHop::Resolved(next_hop)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::nwk::NwkDeviceType;
    use crate::nwk::activity::ActivityParams;
    use crate::nwk::commands::{NwkCommand, NwkRouteRecordCommand, NwkRouteRequestManyToOne};
    use crate::nwk::frame::{Nsdu, NwkFrameControl, NwkHeader, NwkPayload};
    use crate::nwk::neighbors::{ChildDescriptor, Relationship};

    const OWN: Nwk = Nwk(0x0000);
    const CONCENTRATOR: Nwk = Nwk(0x1111);
    const RELAY: Nwk = Nwk(0x2222);
    const CHILD: Nwk = Nwk(0x3333);
    const CHILD_EUI64: Eui64 = Eui64([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    const NOW: Instant = Instant::from_micros(0);
    const ACTIVITY: ActivityParams = ActivityParams {
        initial_count: 3,
        period: Duration::from_secs(15),
    };

    /// A routing table with a many-to-one route to `CONCENTRATOR` through `RELAY`, from
    /// a request that asks for route records.
    fn routing_to_concentrator() -> Routing {
        let mut routing = Routing::default();
        routing.accept_route_request(
            CONCENTRATOR,
            1,
            Nwk(0xFFFC),
            RELAY,
            2,
            NwkRouteRequestManyToOne::ManyToOneSenderSupportsRouteRecordTable,
            NOW,
            Duration::from_secs(10),
            ACTIVITY,
        );
        routing
    }

    fn neighbors_with_child() -> Neighbors {
        let mut neighbors = Neighbors::default();
        neighbors.upsert_child(
            ChildDescriptor {
                eui64: CHILD_EUI64,
                network_address: CHILD,
                device_type: NwkDeviceType::EndDevice,
                rx_on_when_idle: false,
                device_timeout: Some(Duration::from_secs(60)),
                relationship: Relationship::Child,
            },
            NOW,
            ACTIVITY,
        );
        neighbors
    }

    fn frame(frame_type: NwkFrameType, source: Nwk, payload: NwkPayload) -> NwkFrame {
        NwkFrame {
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type,
                    protocol_version: 2,
                    discover_route: NwkRouteDiscovery::Enable,
                    multicast: false,
                    security: true,
                    source_route: false,
                    destination: false,
                    extended_source: false,
                    end_device_initiator: false,
                    reserved1: 0,
                },
                destination: CONCENTRATOR,
                source,
                radius: 30,
                sequence_number: 1,
                destination_ieee: None,
                source_ieee: None,
                multicast_control: None,
                source_route: None,
            },
            aux_header: None,
            payload,
        }
    }

    fn data_frame(source: Nwk) -> NwkFrame {
        frame(
            NwkFrameType::Data,
            source,
            NwkPayload::Opaque(Nsdu::from_slice(&[0x00]).unwrap()),
        )
    }

    // A concentrator that keeps a route record table needs our route record until it
    // source-routes a frame through us after we sent one
    #[test]
    fn test_our_data_frames_need_route_records_until_the_concentrator_has_our_route() {
        let mut routing = routing_to_concentrator();
        let neighbors = Neighbors::default();
        let due = |routing: &Routing| route_record_due(routing, &neighbors, &data_frame(OWN), OWN);

        // A source route built before the concentrator asked again is no proof
        routing.note_source_routed_frame(CONCENTRATOR);
        assert_eq!(due(&routing), Some(RouteRecord::Ours));

        // An acked one is no proof either
        routing.note_route_record_acked(CONCENTRATOR, RELAY);
        assert_eq!(due(&routing), Some(RouteRecord::Ours));

        routing.note_source_routed_frame(CONCENTRATOR);
        assert_eq!(due(&routing), None);
    }

    // A concentrator that is our neighbor needs no source route to reach us
    #[test]
    fn test_neighbor_concentrator_needs_one_route_record() {
        let mut routing = routing_to_concentrator();
        let neighbors = Neighbors::default();

        routing.note_route_record_acked(CONCENTRATOR, CONCENTRATOR);
        assert_eq!(
            route_record_due(&routing, &neighbors, &data_frame(OWN), OWN),
            None
        );
    }

    // Spec 3.6.4.5.5: every data frame from an end device child to a concentrator needs
    // a route record, even once the concentrator has our own route
    #[test]
    fn test_child_data_frames_always_need_a_route_record() {
        let mut routing = routing_to_concentrator();
        let neighbors = neighbors_with_child();

        routing.note_route_record_acked(CONCENTRATOR, RELAY);
        routing.note_source_routed_frame(CONCENTRATOR);

        for _ in 0..2 {
            assert_eq!(
                route_record_due(&routing, &neighbors, &data_frame(CHILD), OWN),
                Some(RouteRecord::Child {
                    nwk: CHILD,
                    eui64: CHILD_EUI64,
                })
            );
        }
    }

    // Only data frames need route records, and only from us or our end device child
    #[test]
    fn test_no_route_record_for_commands_or_other_sources() {
        let routing = routing_to_concentrator();
        let neighbors = neighbors_with_child();
        let command = frame(
            NwkFrameType::Command,
            OWN,
            NwkPayload::Command(NwkCommand::RouteRecord(NwkRouteRecordCommand {
                relays: Vec::new(),
            })),
        );

        assert_eq!(route_record_due(&routing, &neighbors, &command, OWN), None);
        assert_eq!(
            route_record_due(&routing, &neighbors, &data_frame(Nwk(0x4444)), OWN),
            None
        );
    }
}
