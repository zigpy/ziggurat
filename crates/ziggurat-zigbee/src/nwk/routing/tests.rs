use alloc::vec;
use alloc::vec::Vec;
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
        routing.own_discovery_lapse(OWN, DEVICE, START),
        Some(START + ROUTE_DISCOVERY_TIME)
    );
    assert_eq!(
        routing.route_status(DEVICE),
        Some(Status::DiscoveryUnderway)
    );

    routing.forget(OWN, DEVICE);

    assert_eq!(routing.own_discovery_lapse(OWN, DEVICE, START), None);
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
        routing.own_discovery_lapse(OWN, ROUTER, START),
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

// Most route records repeat what is stored. Only a changed one is reported.
#[test]
fn test_route_record_reports_only_a_changed_source_route() {
    let mut routing = Routing::default();
    let changed = RouteRecordChange {
        source: true,
        any: true,
    };
    let unchanged = RouteRecordChange {
        source: false,
        any: false,
    };

    let first = routing.store_route_record(DEVICE, vec![ROUTER, NEIGHBOR]);
    let repeat = routing.store_route_record(DEVICE, vec![ROUTER, NEIGHBOR]);
    let new_path = routing.store_route_record(DEVICE, vec![NEIGHBOR]);

    assert_eq!([first, repeat, new_path], [changed, unchanged, changed]);
}

// A record also carries the routes to its relays. An unchanged record restores a relay
// route that was dropped: the device's own route is the same, but a send held for the
// relay can be routed again.
#[test]
fn test_unchanged_route_record_reports_a_relay_route_it_restores() {
    let mut routing = Routing::default();
    routing.store_route_record(DEVICE, vec![ROUTER, NEIGHBOR]);
    assert!(routing.remove_route_record(ROUTER));

    let change = routing.store_route_record(DEVICE, vec![ROUTER, NEIGHBOR]);

    assert_eq!(
        change,
        RouteRecordChange {
            source: false,
            any: true,
        }
    );
    assert_eq!(
        routing.route_to(ROUTER, MAX_SOURCE_ROUTE),
        Some(Route::SourceRouted(vec![NEIGHBOR]))
    );
}

/// A frame of ours wants a route to `DEVICE`. Returns whether that starts a discovery.
fn want(routing: &mut Routing, now: Instant, attempts: u8) -> bool {
    routing
        .want_route(OWN, DEVICE, now, ROUTE_DISCOVERY_TIME, attempts)
        .is_some()
}

/// Run a timer pass, with a frame still waiting for the route or not.
fn tick(routing: &mut Routing, now: Instant, wanted: bool) -> DiscoveryTick {
    routing.tick_discoveries(OWN, now, ROUTE_DISCOVERY_TIME, |_| wanted)
}

#[test]
fn test_wanting_a_route_starts_one_discovery() {
    let mut routing = Routing::default();

    assert!(want(&mut routing, START, 1));
    assert!(!want(&mut routing, START, 1));

    assert_eq!(
        routing.route_status(DEVICE),
        Some(Status::DiscoveryUnderway)
    );
    assert_eq!(
        routing.next_discovery_lapse(OWN, START),
        Some(START + ROUTE_DISCOVERY_TIME)
    );
}

// Spec 3.6.4.5.1.7: an unanswered discovery deletes its routing entry.
#[test]
fn test_lapsed_discovery_without_a_restart_makes_the_destination_unreachable() {
    let mut routing = Routing::default();
    assert!(want(&mut routing, START, 1));

    let lapsed = START + ROUTE_DISCOVERY_TIME;
    assert_eq!(tick(&mut routing, lapsed, true).unreachable, vec![DEVICE]);

    assert_eq!(routing.route_status(DEVICE), None);
    // The next frame starts over
    assert!(want(&mut routing, lapsed, 1));
}

#[test]
fn test_lapsed_discovery_is_restarted_while_a_frame_waits() {
    let mut routing = Routing::default();
    assert!(want(&mut routing, START, 2));

    let lapsed = START + ROUTE_DISCOVERY_TIME;
    let restarted = tick(&mut routing, lapsed, true).restarted;

    assert_eq!(restarted.len(), 1);
    assert_eq!(restarted[0].0, DEVICE);
    assert_eq!(
        routing.next_discovery_lapse(OWN, lapsed),
        Some(lapsed + ROUTE_DISCOVERY_TIME)
    );

    // The restart was the last one
    let lapsed_again = lapsed + ROUTE_DISCOVERY_TIME;
    assert_eq!(
        tick(&mut routing, lapsed_again, true).unreachable,
        vec![DEVICE]
    );
}

// A discovery nothing waits on is over, not failed: it is neither restarted nor
// reported.
#[test]
fn test_lapsed_discovery_nothing_waits_on_ends_quietly() {
    let mut routing = Routing::default();
    assert!(want(&mut routing, START, 2));

    let lapsed = START + ROUTE_DISCOVERY_TIME;
    assert_eq!(tick(&mut routing, lapsed, false), DiscoveryTick::default());

    assert!(want(&mut routing, lapsed, 2));
}

#[test]
fn test_live_discovery_is_left_alone() {
    let mut routing = Routing::default();
    assert!(want(&mut routing, START, 1));

    let live = START + Duration::from_secs(1);
    assert_eq!(tick(&mut routing, live, true), DiscoveryTick::default());
    assert_eq!(tick(&mut routing, live, false), DiscoveryTick::default());
}

// The route request is on the network whatever became of the frames that wanted it.
// A later frame waits on it, and it is that frame's one attempt.
#[test]
fn test_new_frame_waits_on_a_discovery_whose_frames_are_gone() {
    let mut routing = Routing::default();
    assert!(want(&mut routing, START, 1));

    let live = START + Duration::from_secs(1);
    assert_eq!(tick(&mut routing, live, false), DiscoveryTick::default());
    assert!(!want(&mut routing, live, 1));

    let lapsed = START + ROUTE_DISCOVERY_TIME;
    assert_eq!(tick(&mut routing, lapsed, true).unreachable, vec![DEVICE]);
}

// Spec 3.6.4.3: relaying a route request also marks the destination's entry as
// `DiscoveryUnderway`. A frame of ours does not wait on another router's discovery.
#[test]
fn test_relayed_discovery_toward_the_destination_is_not_ours() {
    let mut routing = Routing::default();
    let request = RouteRequest {
        originator: ROUTER,
        destination: DEVICE,
        path_cost: 3,
    };
    assert!(receive(&mut routing, request, START));
    routing.note_relayed_discovery(DEVICE);

    assert!(want(&mut routing, START, 1));
}

#[test]
fn test_relayed_discovery_does_not_keep_ours_alive() {
    let mut routing = Routing::default();
    assert!(want(&mut routing, START, 1));

    let request = RouteRequest {
        originator: ROUTER,
        destination: DEVICE,
        path_cost: 3,
    };
    assert!(receive(
        &mut routing,
        request,
        START + Duration::from_secs(5)
    ));

    let lapsed = START + ROUTE_DISCOVERY_TIME;
    assert_eq!(routing.next_discovery_lapse(OWN, lapsed), None);
    assert_eq!(tick(&mut routing, lapsed, true).unreachable, vec![DEVICE]);
}

// A relay can report an earlier frame undeliverable after the next frame started a
// discovery. The report is about the old route. The discovery must still take its reply.
#[test]
fn test_removing_the_route_keeps_a_discovery_underway() {
    let mut routing = Routing::default();
    routing.restore_route(DEVICE, NEIGHBOR, 3);
    assert!(routing.remove_route(DEVICE));

    let request_id = routing
        .want_route(OWN, DEVICE, START, ROUTE_DISCOVERY_TIME, 1)
        .unwrap();
    assert!(!routing.remove_route(DEVICE));

    let reply = routing.accept_route_reply(OWN, OWN, request_id, DEVICE, NEIGHBOR, 3);
    assert_eq!(reply.disposition, RouteReplyDisposition::Established);
    assert_eq!(routing.next_hop(DEVICE), Some(NEIGHBOR));
}

/// Start a discovery toward `DEVICE` and have the device answer it.
fn answered_discovery(routing: &mut Routing, attempts: u8) {
    let request_id = routing
        .want_route(OWN, DEVICE, START, ROUTE_DISCOVERY_TIME, attempts)
        .unwrap();

    let reply = routing.accept_route_reply(OWN, OWN, request_id, DEVICE, NEIGHBOR, 3);
    assert_eq!(reply.disposition, RouteReplyDisposition::Established);
    assert_eq!(routing.next_hop(DEVICE), Some(NEIGHBOR));
}

// The reply makes the route active, so no discovery is underway any more. If the route
// is lost later, the next frame starts a new discovery instead of waiting on a request
// that was already answered.
#[test]
fn test_frame_after_an_answered_discovery_starts_a_new_one() {
    let mut routing = Routing::default();
    answered_discovery(&mut routing, 1);

    assert_eq!(tick(&mut routing, START, false), DiscoveryTick::default());

    routing.invalidate_via(NEIGHBOR);
    assert!(want(&mut routing, START, 1));
}

// The route can be lost between the reply and the pass that would have released the
// held frame. The frame must not be left waiting with no discovery behind it.
#[test]
fn test_answered_discovery_is_restarted_for_a_frame_its_route_did_not_release() {
    let mut routing = Routing::default();
    answered_discovery(&mut routing, 2);
    routing.invalidate_via(NEIGHBOR);

    assert_eq!(tick(&mut routing, START, true).restarted.len(), 1);

    // With no restart left the frame fails instead
    let mut routing = Routing::default();
    answered_discovery(&mut routing, 1);
    routing.invalidate_via(NEIGHBOR);

    assert_eq!(tick(&mut routing, START, true).unreachable, vec![DEVICE]);
}

#[test]
fn test_forget_ends_our_discovery_toward_the_device() {
    let mut routing = Routing::default();
    assert!(want(&mut routing, START, 1));

    routing.forget(OWN, DEVICE);

    assert_eq!(routing.next_discovery_lapse(OWN, START), None);
    assert!(want(&mut routing, START, 1));
}

/// One event in the life of our route discovery toward `DEVICE`.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// A frame is held for the route.
    Hold,
    /// The held frames are gone: cancelled, or past their deadline.
    Release,
    /// Time passes until every discovery has lapsed.
    Lapse,
    Tick,
    /// The device answers the latest discovery.
    Reply,
    /// The route to the device is lost.
    Break,
}

const STEPS: [Step; 6] = [
    Step::Hold,
    Step::Release,
    Step::Lapse,
    Step::Tick,
    Step::Reply,
    Step::Break,
];

/// What `Routing` should hold about `DEVICE`.
#[derive(Debug, Default)]
struct Model {
    /// A frame waits for the route.
    wanted: bool,
    /// How many more discoveries the waiting frames may get. Kept from the first frame
    /// that wants the route until a pass finds no frame waiting, or gives up.
    discoveries_left: Option<u8>,
    /// The status of the routing entry, if there is one.
    status: Option<Status>,
    /// A discovery we started has not lapsed.
    live: bool,
    /// The device answered the latest discovery.
    replied: bool,
}

impl Model {
    fn underway(&self) -> bool {
        self.live && self.status == Some(Status::DiscoveryUnderway)
    }

    /// Lapsed discoveries are only cleaned up by a pass or by the next discovery. An
    /// unanswered one takes its routing entry with it.
    fn expire(&mut self) {
        if !self.live && self.status == Some(Status::DiscoveryUnderway) {
            self.status = None;
        }
    }

    fn begin_discovery(&mut self) {
        self.expire();
        self.status = Some(Status::DiscoveryUnderway);
        self.live = true;
        self.replied = false;
    }
}

/// Run `steps` against `Routing` and the model, comparing them after each one.
fn check_own_discovery(steps: &[Step], attempts: u8) {
    let mut routing = Routing::default();
    let mut model = Model::default();
    let mut now = START;
    let mut request_id = None;

    for step in steps {
        match *step {
            // The driver only holds a frame when it has no route
            Step::Hold if routing.next_hop(DEVICE).is_some() => {}
            Step::Hold => {
                let started = routing.want_route(OWN, DEVICE, now, ROUTE_DISCOVERY_TIME, attempts);

                // Only the first frame to wait can start a discovery, and a discovery
                // of ours that is still underway serves it
                let starts = model.discoveries_left.is_none() && !model.underway();
                assert_eq!(started.is_some(), starts, "{steps:?}");

                if model.discoveries_left.is_none() {
                    model.discoveries_left = Some(attempts - 1);
                }
                if let Some(started) = started {
                    request_id = Some(started);
                    model.begin_discovery();
                }
                model.wanted = true;
            }
            Step::Release => model.wanted = false,
            Step::Lapse => {
                now = now + ROUTE_DISCOVERY_TIME;
                model.live = false;
            }
            Step::Tick => {
                // The send tables go first: a held frame leaves once it has a next hop
                if routing.next_hop(DEVICE).is_some() {
                    model.wanted = false;
                }

                let tick = tick(&mut routing, now, model.wanted);
                let mut restarted = false;
                let mut unreachable = false;

                model.expire();

                match model.discoveries_left {
                    None => {}
                    Some(_) if !model.wanted => model.discoveries_left = None,
                    Some(_) if model.underway() => {}
                    Some(0) => {
                        model.discoveries_left = None;
                        // The driver fails the frames held for the destination
                        model.wanted = false;
                        unreachable = true;
                    }
                    Some(left) => {
                        model.discoveries_left = Some(left - 1);
                        model.begin_discovery();
                        restarted = true;
                    }
                }

                let destinations: Vec<Nwk> = tick.restarted.iter().map(|r| r.0).collect();
                assert_eq!(
                    destinations,
                    [DEVICE][..usize::from(restarted)],
                    "{steps:?}"
                );
                assert_eq!(
                    tick.unreachable,
                    [DEVICE][..usize::from(unreachable)],
                    "{steps:?}"
                );

                if let Some(restart) = tick.restarted.first() {
                    request_id = Some(restart.1);
                }

                // A pass leaves every waiting frame with a discovery underway
                assert!(!model.wanted || model.underway(), "{steps:?}");
            }
            Step::Reply if model.live && !model.replied => {
                let reply =
                    routing.accept_route_reply(OWN, OWN, request_id.unwrap(), DEVICE, NEIGHBOR, 3);
                assert_eq!(
                    reply.disposition,
                    RouteReplyDisposition::Established,
                    "{steps:?}"
                );

                // The held frames leave at the next pass, if the route is still there
                model.status = Some(Status::Active);
                model.replied = true;
            }
            Step::Reply => {}
            Step::Break => {
                routing.invalidate_via(NEIGHBOR);

                if model.status == Some(Status::Active) {
                    model.status = Some(Status::Inactive);
                }
            }
        }

        assert_eq!(routing.route_status(DEVICE), model.status, "{steps:?}");
        assert_eq!(
            routing.next_discovery_lapse(OWN, now).is_some(),
            model.discoveries_left.is_some() && model.live,
            "{steps:?}"
        );

        // A frame that waits always has something that will release or fail it: a
        // route, or a count a later pass acts on
        assert!(
            !model.wanted || model.discoveries_left.is_some() || routing.next_hop(DEVICE).is_some(),
            "a frame waits with no route and nothing a pass acts on: {steps:?}"
        );
    }
}

// Every sequence of seven events, with one and with two discovery attempts.
#[test]
fn test_own_discovery_matches_the_model_over_every_short_sequence() {
    const LENGTH: u32 = 7;

    for attempts in [1, 2] {
        for mut sequence in 0..STEPS.len().pow(LENGTH) {
            let mut steps = Vec::new();
            for _ in 0..LENGTH {
                steps.push(STEPS[sequence % STEPS.len()]);
                sequence /= STEPS.len();
            }

            check_own_discovery(&steps, attempts);
        }
    }
}
