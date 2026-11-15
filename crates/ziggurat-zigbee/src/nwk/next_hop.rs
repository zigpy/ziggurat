//! The MAC next hop of a unicast we originate: a decision over the routing and
//! neighbor tables that may rewrite the frame to carry a source route (spec 3.6.4.3).

use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;

use crate::nwk::frame::{NwkFrame, NwkRouteDiscovery, NwkSourceRoute};
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
    /// for route discovery rather than triggering it. A known route still wins, and
    /// once a delivery toward the destination fails its hints are ignored.
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
    /// We store route records and source-route through them.
    pub is_concentrator: bool,
    /// Ignore every known route and always discover, so routing logic is exercised.
    pub force_route_discovery: bool,
    /// The longest source route we embed.
    pub max_source_route: u8,
    /// How long after a router child associates or rejoins we send to it directly
    /// when no route is known.
    pub new_router_child_window: Duration,
}

/// Resolve the MAC next hop for a unicast.
///
/// A source-routed result rewrites `frame`'s header in place (spec 3.6.4.3.1). When no
/// route is known the frame's `discover_route` flag decides between discovery and
/// discard.
pub fn resolve(
    routing: &Routing,
    neighbors: &Neighbors,
    frame: &mut NwkFrame,
    mode: &SendMode,
    policy: Policy,
    now: Instant,
) -> NextHop {
    let destination = frame.nwk_header.destination;

    let directive = match mode {
        SendMode::Direct => return NextHop::Resolved(destination),
        SendMode::Route(directive) => directive,
    };

    // A forced host route overrides everything, including a known route.
    if let RouteDirective::Force(route) = directive {
        return apply_host_route(frame, route);
    }

    // End device children never route-discover; their parent delivers directly. This
    // also keeps a stale route record from outliving a device rejoining as our child.
    if neighbors.end_device_child_eui64(destination).is_some() {
        return NextHop::Resolved(destination);
    }

    // A stored source route (concentrator behavior) wins over the routing table.
    if policy.is_concentrator && !policy.force_route_discovery {
        match routing.route_to(destination, policy.max_source_route) {
            Some(Route::NextHop(next_hop)) => return NextHop::Resolved(next_hop),
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

    // No usable route. A host hint stands in for discovery rather than triggering it,
    // unless a delivery toward the destination already failed: the hint may be the
    // path that failed, and a failed hint teaches the tables nothing.
    if let RouteDirective::Hint(route) = directive
        && routing.host_hints_trusted(destination)
    {
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
    use crate::nwk::frame::{NwkFrameControl, NwkFrameType, NwkHeader, NwkPayload};

    const OWN: Nwk = Nwk(0x0000);
    const DEVICE: Nwk = Nwk(0x1111);
    const OTHER_DEVICE: Nwk = Nwk(0x2222);
    const HINTED_HOP: Nwk = Nwk(0x3333);
    const NOW: Instant = Instant::from_micros(0);
    const POLICY: Policy = Policy {
        is_concentrator: true,
        force_route_discovery: false,
        max_source_route: 11,
        new_router_child_window: Duration::from_secs(30),
    };

    fn data_frame_to(destination: Nwk) -> NwkFrame {
        NwkFrame {
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Data,
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
                destination,
                source: OWN,
                radius: 30,
                sequence_number: 1,
                destination_ieee: None,
                source_ieee: None,
                multicast_control: None,
                source_route: None,
            },
            aux_header: None,
            payload: NwkPayload::Opaque(Default::default()),
        }
    }

    fn resolve_with(routing: &Routing, destination: Nwk, directive: RouteDirective) -> NextHop {
        resolve(
            routing,
            &Neighbors::default(),
            &mut data_frame_to(destination),
            &SendMode::Route(directive),
            POLICY,
            NOW,
        )
    }

    fn hint() -> RouteDirective {
        RouteDirective::Hint(HostRoute::NextHop(HINTED_HOP))
    }

    #[test]
    fn test_hint_stands_in_for_discovery_without_a_route() {
        let routing = Routing::default();
        assert_eq!(
            resolve_with(&routing, DEVICE, hint()),
            NextHop::Resolved(HINTED_HOP)
        );
    }

    // A host hint built from a stale topology (a device that moved) failed. Nothing
    // was written into the tables, so without distrust every hinted frame retried it.
    #[test]
    fn test_hint_ignored_after_a_delivery_failure() {
        let mut routing = Routing::default();
        routing.distrust_host_hints(DEVICE);
        assert_eq!(
            resolve_with(&routing, DEVICE, hint()),
            NextHop::NeedDiscovery
        );
    }

    #[test]
    fn test_hint_ignored_after_a_route_failure_status() {
        let mut routing = Routing::default();
        routing.forget_route_to(DEVICE);
        assert_eq!(
            resolve_with(&routing, DEVICE, hint()),
            NextHop::NeedDiscovery
        );
    }

    #[test]
    fn test_distrust_keeps_hints_for_other_destinations() {
        let mut routing = Routing::default();
        routing.distrust_host_hints(DEVICE);
        assert_eq!(
            resolve_with(&routing, OTHER_DEVICE, hint()),
            NextHop::Resolved(HINTED_HOP)
        );
    }

    #[test]
    fn test_hint_trusted_again_once_the_device_is_forgotten() {
        let mut routing = Routing::default();
        routing.distrust_host_hints(DEVICE);
        routing.forget(OWN, DEVICE);
        assert_eq!(
            resolve_with(&routing, DEVICE, hint()),
            NextHop::Resolved(HINTED_HOP)
        );
    }

    #[test]
    fn test_forced_route_still_applies_after_a_delivery_failure() {
        let mut routing = Routing::default();
        routing.distrust_host_hints(DEVICE);
        assert_eq!(
            resolve_with(
                &routing,
                DEVICE,
                RouteDirective::Force(HostRoute::NextHop(HINTED_HOP))
            ),
            NextHop::Resolved(HINTED_HOP)
        );
    }
}
