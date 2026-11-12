use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::constants::Tunables;

use super::*;

type TestSends = Sends<&'static str, u8, SendFailure>;
type TestActions = Actions<&'static str, u8, SendFailure>;

/// A send's waiter and how it settled.
type Verdict = (u8, Result<(), SendFailure>);

const DESTINATION: Nwk = Nwk(0x1234);
const NEXT_HOP: Nwk = Nwk(0x5678);

// The waiters of the sends a test enqueues
const HELD_UNICAST: u8 = 1;
const ROUTE_REQUEST: u8 = 2;
const SECOND_ROUTE_REQUEST: u8 = 3;

const HELD_TIMED_OUT: Verdict = (HELD_UNICAST, Err(SendFailure::RouteDiscoveryTimeout));
const REQUEST_CANCELLED: Verdict = (ROUTE_REQUEST, Err(SendFailure::Cancelled));

/// What the driver's routing table answers about `DESTINATION` during a timer pass.
#[derive(Clone, Copy)]
enum Tables {
    /// No route yet, and a discovery toward it is running.
    Discovering,
    /// No route, and no discovery is running: the last one lapsed.
    Lapsed,
    /// A route through `NEXT_HOP`.
    Routed,
}

/// What a timer pass did. The default is a pass that did nothing.
#[derive(Debug, Default, PartialEq)]
struct Pass {
    settled: Vec<Verdict>,
    /// The driver is asked to restart `DESTINATION`'s discovery.
    restarts_discovery: bool,
    /// `DESTINATION`'s discovery is reported as failed.
    fails_discovery: bool,
}

impl Pass {
    /// A pass that settled these sends and did nothing else.
    fn settling(settled: impl Into<Vec<Verdict>>) -> Self {
        Self {
            settled: settled.into(),
            ..Self::default()
        }
    }

    /// A pass that asked for the discovery to be restarted.
    fn restarting() -> Self {
        Self {
            restarts_discovery: true,
            ..Self::default()
        }
    }

    /// A pass that gave up on the discovery and failed the held unicast.
    fn failing() -> Self {
        Self {
            settled: vec![HELD_TIMED_OUT],
            fails_discovery: true,
            ..Self::default()
        }
    }
}

/// The send tables, with the tunables and the clock a test drives them with.
struct Fixture {
    sends: TestSends,
    tunables: Tunables,
    now: Instant,
}

impl Fixture {
    fn new() -> Self {
        Self {
            sends: TestSends::default(),
            tunables: Tunables::default(),
            now: Instant::from_micros(0),
        }
    }

    /// Tables that allow a route discovery to be restarted once.
    fn with_one_restart() -> Self {
        let fixture = Self::new();
        fixture
            .tunables
            .set("pending_route_discovery_attempts", 2)
            .unwrap();

        fixture
    }

    fn advance(&mut self, duration: Duration) {
        self.now = self.now + duration;
    }

    /// Hold a unicast to `DESTINATION` until a route to it is known.
    fn hold_unicast(&mut self) -> SendId {
        let (id, actions) = self.sends.enqueue_unrouted_unicast(
            UnroutedUnicast {
                frame: "held unicast",
                priority: TxPriority::UserNormal,
                waiter: HELD_UNICAST,
                confirm: Confirm::OnHandoff,
                destination: DESTINATION,
            },
            self.now,
            &self.tunables,
        );
        assert!(settled(actions).is_empty());

        id
    }

    /// Whether the tables still track a discovery toward `DESTINATION`.
    fn discovering(&self) -> bool {
        self.sends.has_unrouted(DESTINATION)
    }

    /// Fail every unicast held for `DESTINATION`, as the driver does when the device
    /// leaves or joins again.
    fn fail_held(&mut self) -> Vec<Verdict> {
        settled(self.sends.fail_unrouted(DESTINATION))
    }

    /// Broadcast the route request of `DESTINATION`'s discovery, as the driver does:
    /// four copies, the first due now. Returns what registering the request settles.
    fn broadcast_route_request(&mut self, waiter: u8) -> Vec<Verdict> {
        let (request, actions) = self.sends.enqueue_broadcast(
            Broadcast {
                frame: "route request",
                priority: TxPriority::UserNormal,
                waiter,
                schedule: Schedule::FixedInterval {
                    interval: Duration::from_millis(254),
                    copies_remaining: 4,
                    next_attempt: self.now,
                },
            },
            self.now,
            &self.tunables,
        );
        assert!(settled(actions).is_empty());

        settled(self.sends.route_request_sent(DESTINATION, request))
    }

    /// Run a timer pass.
    fn pass(&mut self, tables: Tables) -> Pass {
        let next_hop = matches!(tables, Tables::Routed).then_some(NEXT_HOP);
        let discovery_deadline =
            (!matches!(tables, Tables::Lapsed)).then_some(self.now + Duration::from_secs(10));

        let tick = self.sends.tick(
            self.now,
            &self.tunables,
            |_| next_hop.map(|next_hop| (next_hop, None)),
            |_| discovery_deadline,
        );

        Pass {
            settled: settled(tick.actions),
            restarts_discovery: tick.restart_discovery == [DESTINATION],
            fails_discovery: tick.failed_discovery == [DESTINATION],
        }
    }

    fn dequeue(&mut self) -> Option<InFlight<&'static str>> {
        self.sends.dequeue(self.now)
    }

    /// Report a successful transmit. Returns what it settles.
    fn transmitted(&mut self, in_flight: InFlight<&'static str>) -> Vec<Verdict> {
        settled(
            self.sends
                .transmitted(in_flight, Ok(()), self.now, Duration::ZERO, Duration::ZERO),
        )
    }

    /// Transmit the next frame that is due. Returns what that settles.
    fn transmit_next(&mut self) -> Vec<Verdict> {
        let in_flight = self.dequeue().unwrap();
        self.transmitted(in_flight)
    }
}

/// The waiter and verdict of every send the actions settle.
fn settled(actions: TestActions) -> Vec<Verdict> {
    actions
        .into_iter()
        .filter_map(|action| match action {
            Action::Settled { waiter, result, .. } => Some((waiter, result)),
            Action::HandedOff(_) => None,
        })
        .collect()
}

#[test]
fn test_held_unicast_waits_while_its_discovery_is_live() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();

    assert_eq!(fixture.pass(Tables::Discovering), Pass::default());
    assert!(fixture.discovering());
    assert!(fixture.dequeue().is_none());
}

// A held unicast is bound to its destination, not to one discovery: any pass that
// finds a next hop releases it, even while a discovery toward it is still live.
#[test]
fn test_held_unicast_is_routed_once_a_next_hop_is_found() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();

    assert_eq!(fixture.pass(Tables::Routed), Pass::default());
    assert!(!fixture.discovering());

    let in_flight = fixture.dequeue().unwrap();
    assert_eq!(in_flight.frame, "held unicast");
    assert!(matches!(
        in_flight.transmit(),
        Transmit::Unicast { next_hop, .. } if next_hop == NEXT_HOP
    ));
}

#[test]
fn test_lapsed_discovery_without_a_restart_fails_its_unicasts() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();

    assert_eq!(fixture.pass(Tables::Lapsed), Pass::failing());
    assert!(!fixture.discovering());
}

#[test]
fn test_lapsed_discovery_with_a_restart_left_is_restarted_once() {
    let mut fixture = Fixture::with_one_restart();
    fixture.hold_unicast();

    assert_eq!(fixture.pass(Tables::Lapsed), Pass::restarting());
    assert!(fixture.discovering());

    // The restarted discovery lapses too, and no restart is left
    assert_eq!(fixture.pass(Tables::Lapsed), Pass::failing());
}

// The route request is on the network whether or not anything still waits on it. A
// discovery whose sends are all gone stays tracked until it lapses, so a send that
// arrives meanwhile does not start a second one. Then it has nothing to fail, or to
// restart for: reporting it as failed makes the driver mark the route
// `DiscoveryFailed`, which discards a route the reply produced.
#[test]
fn test_discovery_ends_quietly_after_its_unicast_is_cancelled() {
    let mut fixture = Fixture::with_one_restart();
    let id = fixture.hold_unicast();

    let cancelled = settled(fixture.sends.cancel(id).unwrap());
    assert_eq!(cancelled, [(HELD_UNICAST, Err(SendFailure::Cancelled))]);

    assert_eq!(fixture.pass(Tables::Discovering), Pass::default());
    assert!(fixture.discovering());

    assert_eq!(fixture.pass(Tables::Lapsed), Pass::default());
    assert!(!fixture.discovering());
}

#[test]
fn test_discovery_ends_quietly_after_its_unicast_times_out() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();

    // The unicast passes its deadline in the same pass that finds the discovery lapsed
    fixture.advance(fixture.tunables.handoff_timeout());
    assert_eq!(
        fixture.pass(Tables::Lapsed),
        Pass::settling([(HELD_UNICAST, Err(SendFailure::HandoffTimeout))])
    );
    assert!(!fixture.discovering());
}

// Issue #88: a device that joins again never heard the route request sent before it
// joined. Failing the held unicasts must leave nothing behind that keeps the next send
// to the address from starting its own discovery.
#[test]
fn test_failing_held_unicasts_frees_the_destination_for_a_new_discovery() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();

    assert_eq!(fixture.fail_held(), [HELD_TIMED_OUT]);
    assert!(!fixture.discovering());
}

// An abandoned discovery must not keep broadcasting its route request.
#[test]
fn test_failing_held_unicasts_stops_their_route_request() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();
    assert!(fixture.broadcast_route_request(ROUTE_REQUEST).is_empty());

    // The first of the four copies goes out
    assert_eq!(fixture.pass(Tables::Discovering), Pass::default());
    assert!(fixture.transmit_next().is_empty());

    assert_eq!(fixture.fail_held(), [HELD_TIMED_OUT, REQUEST_CANCELLED]);

    // The other three copies are never queued
    fixture.advance(Duration::from_secs(1));
    assert_eq!(fixture.pass(Tables::Lapsed), Pass::default());
    assert!(fixture.dequeue().is_none());
}

// A copy in the radio cannot be recalled. It completes, and no copy follows it.
#[test]
fn test_stopped_route_request_in_the_radio_sends_no_further_copy() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();
    assert!(fixture.broadcast_route_request(ROUTE_REQUEST).is_empty());

    assert_eq!(fixture.pass(Tables::Discovering), Pass::default());
    let first_copy = fixture.dequeue().unwrap();

    // Only the held unicast settles: the route request is on loan to the radio
    assert_eq!(fixture.fail_held(), [HELD_TIMED_OUT]);
    assert!(fixture.transmitted(first_copy).is_empty());

    // One copy reached the air, which completes a route request
    fixture.advance(Duration::from_secs(1));
    assert_eq!(
        fixture.pass(Tables::Lapsed),
        Pass::settling([(ROUTE_REQUEST, Ok(()))])
    );
    assert!(fixture.dequeue().is_none());
}

// A restarted discovery broadcasts a new route request. The one it replaces stops.
#[test]
fn test_new_route_request_stops_the_one_it_replaces() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();
    assert!(fixture.broadcast_route_request(ROUTE_REQUEST).is_empty());

    assert_eq!(
        fixture.broadcast_route_request(SECOND_ROUTE_REQUEST),
        [REQUEST_CANCELLED]
    );

    // Only the new request has a copy to send
    assert_eq!(fixture.pass(Tables::Discovering), Pass::default());
    assert!(fixture.transmit_next().is_empty());
    assert!(fixture.dequeue().is_none());
}
