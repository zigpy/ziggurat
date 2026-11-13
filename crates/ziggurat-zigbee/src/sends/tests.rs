use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::constants::Tunables;
use crate::gp::{GpdId, GpdfTarget};

use super::*;

impl SendFrame for &'static str {
    type Failure = ();

    fn failure(&self) {}
}

type TestSends = Sends<&'static str, SendFailure>;

/// A send and how it settled.
type Verdict = (SendId, Result<(), SendFailure>);

const DESTINATION: Nwk = Nwk(0x1234);
const NEXT_HOP: Nwk = Nwk(0x5678);
const GPD: GpdfTarget = GpdfTarget::Gpd(GpdId::SrcId(0x87654321));

/// How long a held GPDF waits for its GPD to listen.
const GPDF_LIFETIME: Duration = Duration::from_secs(1);

/// How long after its trigger a GPDF can still be handed to the radio.
const GPDF_WINDOW: Duration = Duration::from_millis(16);

const fn timed_out(held: SendId) -> Verdict {
    (held, Err(SendFailure::RouteDiscoveryTimeout))
}

const fn cancelled(request: SendId) -> Verdict {
    (request, Err(SendFailure::Cancelled))
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
    fn hold_unicast(&mut self) -> SendId {
        let id = self.sends.enqueue_unrouted_unicast(
            UnroutedUnicast {
                frame: "held unicast",
                priority: TxPriority::UserNormal,
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
    /// four copies, the first due now. Returns the request and what registering it
    /// settles.
    fn broadcast_route_request(&mut self) -> (SendId, Vec<Verdict>) {
        let request = self.sends.enqueue_broadcast(
            Broadcast {
                frame: "route request",
                priority: TxPriority::UserNormal,
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
        (request, self.settled())
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
        self.report(in_flight, Ok(()))
    }

    /// Report a transmit. Returns what it settles.
    fn report(
        &mut self,
        in_flight: InFlight<&'static str>,
        result: Result<(), TransmitError<SendFailure>>,
    ) -> Vec<Verdict> {
        self.sends
            .transmitted(in_flight, result, self.now, Duration::ZERO, Duration::ZERO);
        self.settled()
    }

    /// Hold a GPDF for `GPD` until it listens. Returns the send and what holding it
    /// settles.
    fn hold_gpdf(&mut self, frame: &'static str) -> (SendId, Vec<Verdict>) {
        let id = self.sends.enqueue_gpdf(
            Gpdf {
                frame,
                target: GPD,
                lifetime: GPDF_LIFETIME,
            },
            self.now,
        );
        (id, self.settled())
    }

    /// The trigger of a GPDF received now.
    fn gpdf_trigger(&self) -> GpdfTrigger {
        GpdfTrigger {
            rx_timestamp_us: 1234,
            send_by: self.now + GPDF_WINDOW,
        }
    }

    /// `target` sent a GPDF and now listens, and `accept` decides on the frame held for
    /// it. Returns what that settles.
    fn gpd_listens_with(
        &mut self,
        target: GpdfTarget,
        accept: impl FnOnce(&&'static str) -> Result<bool, SendFailure>,
    ) -> Vec<Verdict> {
        let trigger = self.gpdf_trigger();
        self.sends.gpdf_triggered(target, trigger, self.now, accept);
        self.settled()
    }

    /// `target` sent a GPDF and now listens. Returns what that settles.
    fn gpd_listens(&mut self, target: GpdfTarget) -> Vec<Verdict> {
        self.gpd_listens_with(target, |_| Ok(true))
    }

    /// Transmit the next frame that is due. Returns what that settles.
    fn transmit_next(&mut self) -> Vec<Verdict> {
        let in_flight = self.dequeue().unwrap();
        self.transmitted(in_flight)
    }

    /// Take the queued actions. Returns every send they settle and its verdict.
    fn settled(&mut self) -> Vec<Verdict> {
        let mut verdicts = Vec::new();
        while let Some(action) = self.sends.next_action() {
            if let Action::Settled { id, result, .. } = action {
                verdicts.push((id, result));
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
    let held = fixture.hold_unicast();

    fixture.advance(fixture.tunables.handoff_timeout());

    // The deadline comes first: a next hop does not revive a late send
    assert_eq!(
        fixture.pass(Some(NEXT_HOP)),
        [(held, Err(SendFailure::HandoffTimeout))]
    );
    assert!(!fixture.holding());
}

#[test]
fn test_held_unicast_can_be_cancelled() {
    let mut fixture = Fixture::new();
    let held = fixture.hold_unicast();

    assert!(fixture.sends.cancel(held));
    assert_eq!(fixture.settled(), [cancelled(held)]);
    assert!(!fixture.holding());
}

// The routing table gave up on the destination, or the device left or joined again.
#[test]
fn test_failing_held_unicasts_leaves_nothing_held() {
    let mut fixture = Fixture::new();
    let held = fixture.hold_unicast();

    assert_eq!(fixture.fail_held(), [timed_out(held)]);
    assert!(!fixture.holding());
}

// An abandoned discovery must not keep broadcasting its route request.
#[test]
fn test_failing_held_unicasts_stops_their_route_request() {
    let mut fixture = Fixture::new();
    let held = fixture.hold_unicast();
    let (request, settled) = fixture.broadcast_route_request();
    assert!(settled.is_empty());

    // The first of the four copies goes out
    assert!(fixture.pass(None).is_empty());
    assert!(fixture.transmit_next().is_empty());

    assert_eq!(fixture.fail_held(), [timed_out(held), cancelled(request)]);

    // The other three copies are never queued
    fixture.advance(Duration::from_secs(1));
    assert!(fixture.pass(None).is_empty());
    assert!(fixture.dequeue().is_none());
}

// A copy in the radio cannot be recalled. It completes, and no copy follows it.
#[test]
fn test_stopped_route_request_in_the_radio_sends_no_further_copy() {
    let mut fixture = Fixture::new();
    let held = fixture.hold_unicast();
    let (request, settled) = fixture.broadcast_route_request();
    assert!(settled.is_empty());

    assert!(fixture.pass(None).is_empty());
    let first_copy = fixture.dequeue().unwrap();

    // Only the held unicast settles: the route request is on loan to the radio
    assert_eq!(fixture.fail_held(), [timed_out(held)]);
    assert!(fixture.transmitted(first_copy).is_empty());

    // One copy reached the air, which completes a route request
    fixture.advance(Duration::from_secs(1));
    assert_eq!(fixture.pass(None), [(request, Ok(()))]);
    assert!(fixture.dequeue().is_none());
}

// A restarted discovery broadcasts a new route request. The one it replaces stops.
#[test]
fn test_new_route_request_stops_the_one_it_replaces() {
    let mut fixture = Fixture::new();
    fixture.hold_unicast();
    let (first_request, settled) = fixture.broadcast_route_request();
    assert!(settled.is_empty());

    let (_, settled) = fixture.broadcast_route_request();
    assert_eq!(settled, [cancelled(first_request)]);

    // Only the new request has a copy to send
    assert!(fixture.pass(None).is_empty());
    assert!(fixture.transmit_next().is_empty());
    assert!(fixture.dequeue().is_none());
}

// A GPDF waits until its GPD listens, then goes out once, timed from the trigger.
#[test]
fn test_gpdf_sent_after_trigger() {
    let mut fixture = Fixture::new();
    let (gpdf, settled) = fixture.hold_gpdf("gpdf");
    assert!(settled.is_empty());
    assert_eq!(fixture.sends.next_wake(), Some(fixture.now + GPDF_LIFETIME));
    assert!(fixture.dequeue().is_none());

    assert!(fixture.gpd_listens(GPD).is_empty());
    let trigger = fixture.gpdf_trigger();
    assert_eq!(fixture.sends.next_wake(), Some(trigger.send_by));

    let in_flight = fixture.dequeue().unwrap();
    assert!(matches!(in_flight.transmit(), Transmit::Gpdf(t) if t == trigger));
    assert_eq!(fixture.sends.next_wake(), None);

    // In the radio: not cancellable, and a repeated trigger changes nothing
    assert!(!fixture.sends.cancel(gpdf));
    assert!(fixture.gpd_listens(GPD).is_empty());

    assert_eq!(fixture.transmitted(in_flight), [(gpdf, Ok(()))]);
    assert!(fixture.dequeue().is_none());
}

// A triggered GPDF must go out before its window closes, so it goes ahead of every
// host frame, even an older one.
#[test]
fn test_gpdf_goes_ahead_of_host_frames() {
    let mut fixture = Fixture::new();
    fixture.sends.enqueue_broadcast(
        Broadcast {
            frame: "broadcast",
            priority: TxPriority::UserCritical,
            schedule: Schedule::Once,
        },
        fixture.now,
        &fixture.tunables,
    );
    fixture.hold_gpdf("gpdf");
    fixture.gpd_listens(GPD);

    assert_eq!(*fixture.dequeue().unwrap().frame_mut(), "gpdf");
}

// A trigger from another GPD, or a Maintenance frame, does not release the GPDF.
#[test]
fn test_gpdf_other_targets() {
    let mut fixture = Fixture::new();
    fixture.hold_gpdf("gpdf");

    assert!(
        fixture
            .gpd_listens(GpdfTarget::Gpd(GpdId::SrcId(1)))
            .is_empty()
    );
    assert!(fixture.gpd_listens(GpdfTarget::Maintenance).is_empty());
    assert!(fixture.dequeue().is_none());
}

// A GPD has at most one GPDF waiting: a new one replaces it.
#[test]
fn test_gpdf_replaced() {
    let mut fixture = Fixture::new();
    let (first, _) = fixture.hold_gpdf("first");

    let (second, settled) = fixture.hold_gpdf("second");
    assert_eq!(settled, [(first, Err(SendFailure::GpdfReplaced))]);

    fixture.gpd_listens(GPD);
    let in_flight = fixture.dequeue().unwrap();
    assert_eq!(fixture.transmitted(in_flight), [(second, Ok(()))]);
}

// The GPDF in the radio finishes on its own. The new one waits for the next trigger.
#[test]
fn test_gpdf_replaced_while_transmitting() {
    let mut fixture = Fixture::new();
    let (first, _) = fixture.hold_gpdf("first");
    fixture.gpd_listens(GPD);
    let in_flight = fixture.dequeue().unwrap();

    let (second, settled) = fixture.hold_gpdf("second");
    assert!(settled.is_empty());
    assert_eq!(fixture.transmitted(in_flight), [(first, Ok(()))]);
    assert!(fixture.dequeue().is_none());

    fixture.gpd_listens(GPD);
    let in_flight = fixture.dequeue().unwrap();
    assert_eq!(fixture.transmitted(in_flight), [(second, Ok(()))]);
}

// Past its window the sender no longer takes the GPDF, and the timer puts it back to
// wait for the next trigger.
#[test]
fn test_gpdf_window_missed() {
    let mut fixture = Fixture::new();
    let (gpdf, _) = fixture.hold_gpdf("gpdf");
    let deadline = fixture.now + GPDF_LIFETIME;
    fixture.gpd_listens(GPD);

    fixture.advance(GPDF_WINDOW);
    assert!(fixture.dequeue().is_none());
    assert!(fixture.pass(None).is_empty());
    assert_eq!(fixture.sends.next_wake(), Some(deadline));

    fixture.gpd_listens(GPD);
    let in_flight = fixture.dequeue().unwrap();
    assert_eq!(fixture.transmitted(in_flight), [(gpdf, Ok(()))]);
}

#[test]
fn test_gpdf_expired() {
    let mut fixture = Fixture::new();
    let (gpdf, _) = fixture.hold_gpdf("gpdf");

    fixture.advance(GPDF_LIFETIME - Duration::from_millis(1));
    assert!(fixture.pass(None).is_empty());
    fixture.advance(Duration::from_millis(1));
    assert_eq!(fixture.pass(None), [(gpdf, Err(SendFailure::GpdfExpired))]);
}

// The driver ignores a trigger it cannot answer, or fails the send.
#[test]
fn test_gpdf_trigger_accepted_or_not() {
    let mut fixture = Fixture::new();
    let (gpdf, _) = fixture.hold_gpdf("gpdf");

    assert!(fixture.gpd_listens_with(GPD, |_| Ok(false)).is_empty());
    assert!(fixture.dequeue().is_none());

    assert_eq!(
        fixture.gpd_listens_with(GPD, |_| Err(SendFailure::Cancelled)),
        [cancelled(gpdf)]
    );
}

// A failed transmit waits for the next trigger until the deadline. After it, the
// failure is the verdict.
#[test]
fn test_gpdf_transmit_failed() {
    let mut fixture = Fixture::new();
    let (gpdf, _) = fixture.hold_gpdf("gpdf");

    fixture.gpd_listens(GPD);
    let in_flight = fixture.dequeue().unwrap();
    let failed = Err(TransmitError::Failed(SendFailure::Cancelled));
    assert!(fixture.report(in_flight, failed).is_empty());

    fixture.advance(GPDF_LIFETIME - GPDF_WINDOW);
    fixture.gpd_listens(GPD);
    let in_flight = fixture.dequeue().unwrap();
    fixture.advance(GPDF_WINDOW);
    let failed = Err(TransmitError::Failed(SendFailure::Cancelled));
    assert_eq!(fixture.report(in_flight, failed), [cancelled(gpdf)]);
}

// A frame the radio can never send fails at once, even before the deadline.
#[test]
fn test_gpdf_transmit_rejected() {
    let mut fixture = Fixture::new();
    let (gpdf, _) = fixture.hold_gpdf("gpdf");

    fixture.gpd_listens(GPD);
    let in_flight = fixture.dequeue().unwrap();
    let rejected = Err(TransmitError::Rejected(SendFailure::Cancelled));
    assert_eq!(fixture.report(in_flight, rejected), [cancelled(gpdf)]);
}

#[test]
fn test_gpdf_cancel_and_abandon() {
    let mut fixture = Fixture::new();
    let (first, _) = fixture.hold_gpdf("first");

    assert!(fixture.sends.cancel(first));
    assert_eq!(fixture.settled(), [cancelled(first)]);
    assert!(!fixture.sends.cancel(first));

    let (second, _) = fixture.hold_gpdf("second");
    fixture.sends.abandon();
    assert_eq!(fixture.settled(), [cancelled(second)]);
}
