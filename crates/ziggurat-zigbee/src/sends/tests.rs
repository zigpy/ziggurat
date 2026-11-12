use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::constants::Tunables;

use super::*;

type TestSends = Sends<&'static str, u8, SendFailure>;
type TestActions = Actions<&'static str, u8, SendFailure>;
type TestTick = Tick<&'static str, u8, SendFailure>;

const DESTINATION: Nwk = Nwk(0x1234);
const NEXT_HOP: Nwk = Nwk(0x5678);

// The waiters of the sends a test enqueues
const HELD_UNICAST: u8 = 1;
const ROUTE_REQUEST: u8 = 2;
const SECOND_ROUTE_REQUEST: u8 = 3;

/// What the driver's routing table answers about `DESTINATION` during a timer pass.
struct DriverTables {
    next_hop: Option<Nwk>,
    discovery_live: bool,
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

    fn advance(&mut self, duration: Duration) {
        self.now = self.now + duration;
    }

    /// Hold a unicast to `DESTINATION` until a route to it is known.
    fn hold_unicast(&mut self) {
        let (_, actions) = self.sends.enqueue_unrouted_unicast(
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
    }

    /// Broadcast the route request of `DESTINATION`'s discovery, as the driver does:
    /// four copies, the first due now. Returns what registering the request settles.
    fn broadcast_route_request(&mut self, waiter: u8) -> Vec<(u8, Result<(), SendFailure>)> {
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
    fn tick(&mut self, tables: DriverTables) -> TestTick {
        let discovery_deadline = tables
            .discovery_live
            .then_some(self.now + Duration::from_secs(10));

        self.sends.tick(
            self.now,
            &self.tunables,
            |_| tables.next_hop.map(|next_hop| (next_hop, None)),
            |_| discovery_deadline,
        )
    }

    fn dequeue(&mut self) -> Option<InFlight<&'static str>> {
        self.sends.dequeue(self.now)
    }

    /// Report a successful transmit. Returns what it settles.
    fn transmitted(
        &mut self,
        in_flight: InFlight<&'static str>,
    ) -> Vec<(u8, Result<(), SendFailure>)> {
        settled(
            self.sends
                .transmitted(in_flight, Ok(()), self.now, Duration::ZERO, Duration::ZERO),
        )
    }
}

/// The waiter and verdict of every send the actions settle.
fn settled(actions: TestActions) -> Vec<(u8, Result<(), SendFailure>)> {
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

    let tick = fixture.tick(DriverTables {
        next_hop: None,
        discovery_live: true,
    });

    assert!(settled(tick.actions).is_empty());
    assert!(tick.restart_discovery.is_empty());
    assert!(tick.failed_discovery.is_empty());
    assert!(fixture.sends.has_unrouted(DESTINATION));
    assert!(fixture.dequeue().is_none());
}

// A held unicast is bound to its destination, not to one discovery: any pass that
// finds a next hop releases it, even while a discovery toward it is still live.
#[test]
fn test_held_unicast_is_routed_once_a_next_hop_is_found() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();

    let tick = fixture.tick(DriverTables {
        next_hop: Some(NEXT_HOP),
        discovery_live: true,
    });

    assert!(settled(tick.actions).is_empty());
    assert!(tick.restart_discovery.is_empty());
    assert!(tick.failed_discovery.is_empty());
    assert!(!fixture.sends.has_unrouted(DESTINATION));

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

    let tick = fixture.tick(DriverTables {
        next_hop: None,
        discovery_live: false,
    });

    assert_eq!(
        settled(tick.actions),
        [(HELD_UNICAST, Err(SendFailure::RouteDiscoveryTimeout))]
    );
    assert!(tick.restart_discovery.is_empty());
    assert_eq!(tick.failed_discovery, [DESTINATION]);
    assert!(!fixture.sends.has_unrouted(DESTINATION));
}

#[test]
fn test_lapsed_discovery_with_a_restart_left_is_restarted_once() {
    let mut fixture = Fixture::new();
    fixture
        .tunables
        .set("pending_route_discovery_attempts", 2)
        .unwrap();
    fixture.hold_unicast();

    let tick = fixture.tick(DriverTables {
        next_hop: None,
        discovery_live: false,
    });

    assert!(settled(tick.actions).is_empty());
    assert_eq!(tick.restart_discovery, [DESTINATION]);
    assert!(tick.failed_discovery.is_empty());
    assert!(fixture.sends.has_unrouted(DESTINATION));

    // The restarted discovery lapses too, and no restart is left
    let tick = fixture.tick(DriverTables {
        next_hop: None,
        discovery_live: false,
    });

    assert_eq!(
        settled(tick.actions),
        [(HELD_UNICAST, Err(SendFailure::RouteDiscoveryTimeout))]
    );
    assert!(tick.restart_discovery.is_empty());
    assert_eq!(tick.failed_discovery, [DESTINATION]);
}

// Issue #88: a device that joins again never heard the route request sent before it
// joined. Failing the held unicasts must leave nothing behind that keeps the next send
// to the address from starting its own discovery.
#[test]
fn test_failing_held_unicasts_frees_the_destination_for_a_new_discovery() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();

    let actions = fixture.sends.fail_unrouted(DESTINATION);

    assert_eq!(
        settled(actions),
        [(HELD_UNICAST, Err(SendFailure::RouteDiscoveryTimeout))]
    );
    assert!(!fixture.sends.has_unrouted(DESTINATION));
}

// An abandoned discovery must not keep broadcasting its route request.
#[test]
fn test_failing_held_unicasts_stops_their_route_request() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();
    assert!(fixture.broadcast_route_request(ROUTE_REQUEST).is_empty());

    // The first of the four copies goes out
    let tick = fixture.tick(DriverTables {
        next_hop: None,
        discovery_live: true,
    });
    assert!(settled(tick.actions).is_empty());
    let first_copy = fixture.dequeue().unwrap();
    assert!(fixture.transmitted(first_copy).is_empty());

    let actions = fixture.sends.fail_unrouted(DESTINATION);

    assert_eq!(
        settled(actions),
        [
            (HELD_UNICAST, Err(SendFailure::RouteDiscoveryTimeout)),
            (ROUTE_REQUEST, Err(SendFailure::Cancelled)),
        ]
    );

    // The other three copies are never queued
    fixture.advance(Duration::from_secs(1));
    let tick = fixture.tick(DriverTables {
        next_hop: None,
        discovery_live: false,
    });
    assert!(settled(tick.actions).is_empty());
    assert!(fixture.dequeue().is_none());
}

// A copy in the radio cannot be recalled. It completes, and no copy follows it.
#[test]
fn test_stopped_route_request_in_the_radio_sends_no_further_copy() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();
    assert!(fixture.broadcast_route_request(ROUTE_REQUEST).is_empty());

    let tick = fixture.tick(DriverTables {
        next_hop: None,
        discovery_live: true,
    });
    assert!(settled(tick.actions).is_empty());
    let first_copy = fixture.dequeue().unwrap();

    // Only the held unicast settles: the route request is on loan to the radio
    let actions = fixture.sends.fail_unrouted(DESTINATION);
    assert_eq!(
        settled(actions),
        [(HELD_UNICAST, Err(SendFailure::RouteDiscoveryTimeout))]
    );

    assert!(fixture.transmitted(first_copy).is_empty());

    // One copy reached the air, which completes a route request
    fixture.advance(Duration::from_secs(1));
    let tick = fixture.tick(DriverTables {
        next_hop: None,
        discovery_live: false,
    });
    assert_eq!(settled(tick.actions), [(ROUTE_REQUEST, Ok(()))]);
    assert!(fixture.dequeue().is_none());
}

// A restarted discovery broadcasts a new route request. The one it replaces stops.
#[test]
fn test_new_route_request_stops_the_one_it_replaces() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();
    assert!(fixture.broadcast_route_request(ROUTE_REQUEST).is_empty());

    let stopped = fixture.broadcast_route_request(SECOND_ROUTE_REQUEST);

    assert_eq!(stopped, [(ROUTE_REQUEST, Err(SendFailure::Cancelled))]);

    // Only the new request has a copy to send
    let tick = fixture.tick(DriverTables {
        next_hop: None,
        discovery_live: true,
    });
    assert!(settled(tick.actions).is_empty());
    let only_copy = fixture.dequeue().unwrap();
    assert!(fixture.transmitted(only_copy).is_empty());
    assert!(fixture.dequeue().is_none());
}
