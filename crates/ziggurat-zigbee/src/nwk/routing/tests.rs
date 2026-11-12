use alloc::vec;
use core::time::Duration;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::nwk::commands::NwkRouteRequestManyToOne;

use super::*;

const OWN: Nwk = Nwk(0x0000);
const DEVICE: Nwk = Nwk(0x1111);
const OTHER_DEVICE: Nwk = Nwk(0x2222);
const ROUTER: Nwk = Nwk(0x3333);
const NEIGHBOR: Nwk = Nwk(0x4444);

const START: Instant = Instant::from_micros(0);
const ROUTE_DISCOVERY_TIME: Duration = Duration::from_secs(10);
const MAX_SOURCE_ROUTE: u8 = 11;

/// A route request relayed to us by `NEIGHBOR`.
#[derive(Clone, Copy)]
struct RouteRequest {
    originator: Nwk,
    destination: Nwk,
    path_cost: u8,
}

/// Receive a route request. Returns whether it was accepted as new or as a better path.
fn receive(routing: &mut Routing, request: RouteRequest, now: Instant) -> bool {
    routing
        .accept_route_request(
            request.originator,
            1,
            request.destination,
            NEIGHBOR,
            request.path_cost,
            NwkRouteRequestManyToOne::NotManyToOne,
            now,
            ROUTE_DISCOVERY_TIME,
        )
        .accepted
}

// Issue #88: a device that joins again never heard the route request we sent before it
// joined. Our discovery toward it must go, or it blocks a new one until it expires.
#[test]
fn test_forget_drops_our_discovery_toward_the_device() {
    let mut routing = Routing::default();
    routing.begin_discovery(OWN, DEVICE, START, ROUTE_DISCOVERY_TIME);
    assert_eq!(
        routing.discovery_deadline(DEVICE, START),
        Some(START + ROUTE_DISCOVERY_TIME)
    );
    assert_eq!(
        routing.route_status(DEVICE),
        Some(Status::DiscoveryUnderway)
    );

    routing.forget(OWN, DEVICE);

    assert_eq!(routing.discovery_deadline(DEVICE, START), None);
    assert_eq!(routing.route_status(DEVICE), None);
}

#[test]
fn test_forget_drops_the_route_and_the_route_record() {
    let mut routing = Routing::default();
    routing.restore_route(DEVICE, NEIGHBOR, 3);
    routing.store_route_record(DEVICE, vec![ROUTER]);
    assert!(routing.route_to(DEVICE, MAX_SOURCE_ROUTE).is_some());

    routing.forget(OWN, DEVICE);

    assert_eq!(routing.next_hop(DEVICE), None);
    assert_eq!(routing.route_to(DEVICE, MAX_SOURCE_ROUTE), None);
}

#[test]
fn test_forget_leaves_other_destinations_alone() {
    let mut routing = Routing::default();
    routing.restore_route(OTHER_DEVICE, NEIGHBOR, 3);
    routing.begin_discovery(OWN, ROUTER, START, ROUTE_DISCOVERY_TIME);

    routing.forget(OWN, DEVICE);

    assert_eq!(routing.next_hop(OTHER_DEVICE), Some(NEIGHBOR));
    assert_eq!(
        routing.discovery_deadline(ROUTER, START),
        Some(START + ROUTE_DISCOVERY_TIME)
    );
}

// Route requests bypass the broadcast transaction table, so the discovery entry is the
// only duplicate check for a relayed request. Forgetting its originator must not make
// a late copy look new, or we rebroadcast it.
#[test]
fn test_forget_keeps_the_duplicate_check_for_a_request_the_device_originated() {
    let mut routing = Routing::default();
    let request = RouteRequest {
        originator: DEVICE,
        destination: OTHER_DEVICE,
        path_cost: 5,
    };
    assert!(receive(&mut routing, request, START));

    routing.forget(OWN, DEVICE);

    let late_copy = RouteRequest {
        path_cost: 7,
        ..request
    };
    assert!(!receive(&mut routing, late_copy, START));
}

#[test]
fn test_forget_keeps_the_duplicate_check_for_a_request_toward_the_device() {
    let mut routing = Routing::default();
    let request = RouteRequest {
        originator: OTHER_DEVICE,
        destination: DEVICE,
        path_cost: 5,
    };
    assert!(receive(&mut routing, request, START));

    routing.forget(OWN, DEVICE);

    let late_copy = RouteRequest {
        path_cost: 7,
        ..request
    };
    assert!(!receive(&mut routing, late_copy, START));
}

// A relayed request marks its destination `DiscoveryUnderway`. Only the expiry of the
// discovery entry retires that mark, so the entry must survive forgetting the
// originator.
#[test]
fn test_relayed_discovery_still_expires_after_its_originator_is_forgotten() {
    let mut routing = Routing::default();
    let request = RouteRequest {
        originator: DEVICE,
        destination: OTHER_DEVICE,
        path_cost: 5,
    };
    assert!(receive(&mut routing, request, START));
    routing.note_relayed_discovery(OTHER_DEVICE);
    assert_eq!(
        routing.route_status(OTHER_DEVICE),
        Some(Status::DiscoveryUnderway)
    );

    routing.forget(OWN, DEVICE);

    // Any later request runs the expiry
    let unrelated = RouteRequest {
        originator: ROUTER,
        destination: NEIGHBOR,
        path_cost: 5,
    };
    let after_expiry = START + ROUTE_DISCOVERY_TIME + Duration::from_secs(1);
    receive(&mut routing, unrelated, after_expiry);

    assert_eq!(routing.route_status(OTHER_DEVICE), None);
}
