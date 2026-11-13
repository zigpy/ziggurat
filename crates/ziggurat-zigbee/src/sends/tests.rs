use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::constants::Tunables;

use super::*;

impl SendFrame for &'static str {
    type Failure = ();

    fn failure(&self) {}
}

type TestSends = Sends<&'static str, u8, SendFailure>;

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
    fn hold_unicast(&mut self) -> SendId {
        let id = self.sends.enqueue_unrouted_unicast(
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
        assert!(self.settled().is_empty());

        id
    }

    /// Whether a unicast is still held for `DESTINATION`.
    fn holding(&self) -> bool {
        self.sends.has_unrouted(DESTINATION)
    }

    /// Fail every unicast held for `DESTINATION`, as the driver does when the device
    /// leaves or joins again.
    fn fail_held(&mut self) -> Vec<Verdict> {
        self.sends.fail_unrouted(DESTINATION);
        self.settled()
    }

    /// Broadcast the route request of `DESTINATION`'s discovery, as the driver does:
    /// four copies, the first due now. Returns what registering the request settles.
    fn broadcast_route_request(&mut self, waiter: u8) -> Vec<Verdict> {
        let request = self.sends.enqueue_broadcast(
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
        assert!(self.settled().is_empty());

        self.sends.route_request_sent(DESTINATION, request);
        self.settled()
    }

    /// Run a timer pass in which the routing table offers this next hop toward
    /// `DESTINATION`. Returns what the pass settles.
    fn pass(&mut self, next_hop: Option<Nwk>) -> Vec<Verdict> {
        self.sends.tick(self.now, &self.tunables, |_| {
            next_hop.map(|next_hop| (next_hop, None))
        });
        self.settled()
    }

    fn dequeue(&mut self) -> Option<InFlight<&'static str>> {
        self.sends.dequeue(self.now)
    }

    /// Report a successful transmit. Returns what it settles.
    fn transmitted(&mut self, in_flight: InFlight<&'static str>) -> Vec<Verdict> {
        self.sends
            .transmitted(in_flight, Ok(()), self.now, Duration::ZERO, Duration::ZERO);
        self.settled()
    }

    /// Transmit the next frame that is due. Returns what that settles.
    fn transmit_next(&mut self) -> Vec<Verdict> {
        let in_flight = self.dequeue().unwrap();
        self.transmitted(in_flight)
    }

    /// Take the queued actions. Returns the waiter and verdict of every send they
    /// settle.
    fn settled(&mut self) -> Vec<Verdict> {
        let mut verdicts = Vec::new();
        while let Some(action) = self.sends.next_action() {
            if let Action::Settled { waiter, result, .. } = action {
                verdicts.push((waiter, result));
            }
        }
        verdicts
    }
}

#[test]
fn test_held_unicast_waits_without_a_next_hop() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();

    assert!(fixture.pass(None).is_empty());
    assert!(fixture.holding());
    assert!(fixture.dequeue().is_none());
}

// A held unicast waits for a next hop, not for a discovery: any pass that finds one
// releases it.
#[test]
fn test_held_unicast_is_routed_once_a_next_hop_is_found() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();

    assert!(fixture.pass(Some(NEXT_HOP)).is_empty());
    assert!(!fixture.holding());

    let in_flight = fixture.dequeue().unwrap();
    assert_eq!(in_flight.frame, "held unicast");
    assert!(matches!(
        in_flight.transmit(),
        Transmit::Unicast { next_hop, .. } if next_hop == NEXT_HOP
    ));
}

#[test]
fn test_held_unicast_fails_at_its_deadline() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();

    fixture.advance(fixture.tunables.handoff_timeout());

    // The deadline comes first: a next hop does not revive a late send
    assert_eq!(
        fixture.pass(Some(NEXT_HOP)),
        [(HELD_UNICAST, Err(SendFailure::HandoffTimeout))]
    );
    assert!(!fixture.holding());
}

#[test]
fn test_held_unicast_can_be_cancelled() {
    let mut fixture = Fixture::new();
    let id = fixture.hold_unicast();

    assert!(fixture.sends.cancel(id));
    let cancelled = fixture.settled();

    assert_eq!(cancelled, [(HELD_UNICAST, Err(SendFailure::Cancelled))]);
    assert!(!fixture.holding());
}

// The routing table gave up on the destination, or the device left or joined again.
#[test]
fn test_failing_held_unicasts_leaves_nothing_held() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();

    assert_eq!(fixture.fail_held(), [HELD_TIMED_OUT]);
    assert!(!fixture.holding());
}

// An abandoned discovery must not keep broadcasting its route request.
#[test]
fn test_failing_held_unicasts_stops_their_route_request() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();
    assert!(fixture.broadcast_route_request(ROUTE_REQUEST).is_empty());

    // The first of the four copies goes out
    assert!(fixture.pass(None).is_empty());
    assert!(fixture.transmit_next().is_empty());

    assert_eq!(fixture.fail_held(), [HELD_TIMED_OUT, REQUEST_CANCELLED]);

    // The other three copies are never queued
    fixture.advance(Duration::from_secs(1));
    assert!(fixture.pass(None).is_empty());
    assert!(fixture.dequeue().is_none());
}

// A copy in the radio cannot be recalled. It completes, and no copy follows it.
#[test]
fn test_stopped_route_request_in_the_radio_sends_no_further_copy() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();
    assert!(fixture.broadcast_route_request(ROUTE_REQUEST).is_empty());

    assert!(fixture.pass(None).is_empty());
    let first_copy = fixture.dequeue().unwrap();

    // Only the held unicast settles: the route request is on loan to the radio
    assert_eq!(fixture.fail_held(), [HELD_TIMED_OUT]);
    assert!(fixture.transmitted(first_copy).is_empty());

    // One copy reached the air, which completes a route request
    fixture.advance(Duration::from_secs(1));
    assert_eq!(fixture.pass(None), [(ROUTE_REQUEST, Ok(()))]);
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
    assert!(fixture.pass(None).is_empty());
    assert!(fixture.transmit_next().is_empty());
    assert!(fixture.dequeue().is_none());
}
