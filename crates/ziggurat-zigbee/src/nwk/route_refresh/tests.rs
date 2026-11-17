use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;

use super::*;

const DEVICE: Nwk = Nwk(0x1111);
const OTHER_DEVICE: Nwk = Nwk(0x2222);
const HOP: Nwk = Nwk(0x3333);
const OTHER_HOP: Nwk = Nwk(0x4444);

const START: Instant = Instant::from_micros(0);
const ROUTE_DISCOVERY_TIME: Duration = Duration::from_secs(10);

const POLICY: RouteRefreshPolicy = RouteRefreshPolicy {
    spacing: Duration::from_secs(2),
    backoff: Duration::from_secs(60),
    backoff_max: Duration::from_secs(30 * 60),
    displaced_retention: Duration::from_secs(10 * 60),
};

fn retry(backoff: Duration) -> Missed {
    Missed {
        destination: DEVICE,
        retry_in: Some(backoff),
    }
}

fn at(seconds: u64) -> Instant {
    START + Duration::from_secs(seconds)
}

/// Take the next due refresh and issue it, as the driver does.
fn issue(refresh: &mut RouteRefresh, now: Instant) -> Option<(Nwk, RefreshReason)> {
    let due = refresh.next_due(now, POLICY)?;
    refresh.issued(due.0, due.1, now, now + ROUTE_DISCOVERY_TIME);
    Some(due)
}

/// Issue the refresh of `DEVICE` at `now` and let it go unanswered. Returns what the
/// timer pass at its deadline reports.
fn miss(refresh: &mut RouteRefresh, now: Instant) -> Vec<Missed> {
    assert_eq!(issue(refresh, now).map(|due| due.0), Some(DEVICE));
    refresh.tick(now + ROUTE_DISCOVERY_TIME, POLICY)
}

// enqueue / next_due

#[test]
fn test_next_due_returns_the_oldest_first() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    refresh.enqueue(OTHER_DEVICE, RefreshReason::Hinted);

    assert_eq!(
        refresh.next_due(START, POLICY),
        Some((DEVICE, RefreshReason::Settled))
    );
    assert_eq!(
        refresh.next_due(START, POLICY),
        Some((OTHER_DEVICE, RefreshReason::Hinted))
    );
}

#[test]
fn test_destination_queued_twice_is_due_once() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    refresh.enqueue(DEVICE, RefreshReason::Hinted);

    assert!(refresh.next_due(START, POLICY).is_some());
    assert_eq!(refresh.next_due(START, POLICY), None);
}

#[test]
fn test_destination_queued_twice_keeps_the_first_reason() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    refresh.enqueue(DEVICE, RefreshReason::Hinted);

    assert_eq!(
        refresh.next_due(START, POLICY),
        Some((DEVICE, RefreshReason::Settled))
    );
}

#[test]
fn test_broadcast_address_is_not_queued() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(Nwk(0xFFFD), RefreshReason::Hinted);

    assert!(refresh.is_empty());
}

#[test]
fn test_destination_in_flight_is_not_queued_again() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    issue(&mut refresh, START);

    refresh.enqueue(DEVICE, RefreshReason::Hinted);

    assert_eq!(refresh.next_due(at(5), POLICY), None);
}

#[test]
fn test_due_respects_spacing() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    refresh.enqueue(OTHER_DEVICE, RefreshReason::Settled);
    issue(&mut refresh, START);

    assert_eq!(
        refresh.next_due(START + Duration::from_millis(1999), POLICY),
        None
    );
}

#[test]
fn test_due_after_spacing_returns_the_next_destination() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    refresh.enqueue(OTHER_DEVICE, RefreshReason::Settled);
    issue(&mut refresh, START);

    assert_eq!(
        refresh.next_due(at(2), POLICY),
        Some((OTHER_DEVICE, RefreshReason::Settled))
    );
}

// note_displaced / hop_recovered

#[test]
fn test_hop_recovery_queues_its_displaced_destinations() {
    let mut refresh = RouteRefresh::default();
    refresh.note_displaced(DEVICE, HOP, START);

    assert_eq!(refresh.hop_recovered(HOP, at(30), POLICY), 1);
    assert_eq!(
        refresh.next_due(at(30), POLICY),
        Some((DEVICE, RefreshReason::HopRecovered))
    );
}

#[test]
fn test_hop_recovery_empties_the_hops_displaced_list() {
    let mut refresh = RouteRefresh::default();
    refresh.note_displaced(DEVICE, HOP, START);
    refresh.hop_recovered(HOP, at(30), POLICY);

    assert_eq!(refresh.hop_recovered(HOP, at(31), POLICY), 0);
}

#[test]
fn test_displaced_entry_past_retention_is_not_queued() {
    let mut refresh = RouteRefresh::default();
    refresh.note_displaced(DEVICE, HOP, START);

    assert_eq!(refresh.hop_recovered(HOP, at(10 * 60 + 1), POLICY), 0);
    assert!(refresh.is_empty());
}

#[test]
fn test_displaced_list_drops_the_oldest_past_its_limit() {
    let mut refresh = RouteRefresh::default();
    for n in 0..=32 {
        refresh.note_displaced(Nwk(0x1000 + n), HOP, START);
    }

    assert_eq!(refresh.hop_recovered(HOP, START, POLICY), 32);
    let mut due = Vec::new();
    let mut now = START;
    while let Some((destination, _)) = issue(&mut refresh, now) {
        due.push(destination);
        now = now + POLICY.spacing;
    }
    assert!(!due.contains(&Nwk(0x1000)));
}

#[test]
fn test_displaced_again_counts_as_newest() {
    let mut refresh = RouteRefresh::default();
    refresh.note_displaced(DEVICE, HOP, START);
    for n in 0..31 {
        refresh.note_displaced(Nwk(0x1000 + n), HOP, START);
    }
    refresh.note_displaced(DEVICE, HOP, START);
    refresh.note_displaced(Nwk(0x2000), HOP, START);

    refresh.hop_recovered(HOP, START, POLICY);

    let mut due = Vec::new();
    let mut now = START;
    while let Some((destination, _)) = issue(&mut refresh, now) {
        due.push(destination);
        now = now + POLICY.spacing;
    }
    assert!(due.contains(&DEVICE));
    assert!(!due.contains(&Nwk(0x1000)));
}

#[test]
fn test_hop_recovery_makes_a_destination_in_back_off_due() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    miss(&mut refresh, START);
    refresh.note_displaced(DEVICE, HOP, at(10));

    refresh.hop_recovered(HOP, at(20), POLICY);

    assert_eq!(
        refresh.next_due(at(20), POLICY),
        Some((DEVICE, RefreshReason::Settled))
    );
}

#[test]
fn test_hop_recovery_restarts_the_back_off_of_a_destination() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    miss(&mut refresh, START);
    refresh.note_displaced(DEVICE, HOP, at(10));
    refresh.hop_recovered(HOP, at(20), POLICY);

    assert_eq!(miss(&mut refresh, at(20)), vec![retry(POLICY.backoff)]);
}

#[test]
fn test_hop_recovery_with_nothing_displaced_queues_nothing() {
    let mut refresh = RouteRefresh::default();
    refresh.note_displaced(DEVICE, OTHER_HOP, START);

    assert_eq!(refresh.hop_recovered(HOP, START, POLICY), 0);
    assert!(refresh.is_empty());
}

// issued / note_reply / tick

#[test]
fn test_reply_from_the_refreshed_destination_is_noted() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    issue(&mut refresh, START);

    assert!(refresh.note_reply(DEVICE));
}

#[test]
fn test_answered_refresh_is_not_reported_as_missed() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    issue(&mut refresh, START);
    refresh.note_reply(DEVICE);

    assert_eq!(refresh.tick(at(10), POLICY), Vec::new());
}

#[test]
fn test_reply_without_a_refresh_in_flight_is_not_noted() {
    let mut refresh = RouteRefresh::default();

    assert!(!refresh.note_reply(DEVICE));
}

#[test]
fn test_unanswered_refresh_gets_the_initial_back_off() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);

    assert_eq!(miss(&mut refresh, START), vec![retry(POLICY.backoff)]);
}

#[test]
fn test_refresh_in_flight_before_its_deadline_is_not_missed() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    issue(&mut refresh, START);

    assert_eq!(refresh.tick(at(9), POLICY), Vec::new());
}

#[test]
fn test_destination_in_back_off_is_not_due() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    miss(&mut refresh, START);

    assert_eq!(refresh.next_due(at(10 + 59), POLICY), None);
}

#[test]
fn test_destination_in_back_off_does_not_block_others() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    miss(&mut refresh, START);
    refresh.enqueue(OTHER_DEVICE, RefreshReason::Hinted);

    assert_eq!(
        refresh.next_due(at(11), POLICY),
        Some((OTHER_DEVICE, RefreshReason::Hinted))
    );
}

#[test]
fn test_destination_is_due_again_after_its_back_off() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::HopRecovered);
    miss(&mut refresh, START);

    assert_eq!(
        refresh.next_due(at(10 + 60), POLICY),
        Some((DEVICE, RefreshReason::HopRecovered))
    );
}

#[test]
fn test_second_miss_doubles_the_back_off() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    miss(&mut refresh, START);

    assert_eq!(miss(&mut refresh, at(70)), vec![retry(POLICY.backoff * 2)]);
}

/// Let the refresh of `DEVICE` go unanswered until route refresh gives up on it.
/// Returns each miss's back-off, `None` for the miss it gave up at.
fn miss_until_given_up(refresh: &mut RouteRefresh) -> Vec<Option<u64>> {
    let mut now = START;
    let mut retries = Vec::new();
    loop {
        let missed = miss(refresh, now)[0];
        retries.push(missed.retry_in.map(|backoff| backoff.as_secs()));
        let Some(backoff) = missed.retry_in else {
            return retries;
        };
        now = now + ROUTE_DISCOVERY_TIME + backoff;
    }
}

#[test]
fn test_back_off_doubles_up_to_the_cap() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);

    let retries = miss_until_given_up(&mut refresh);

    assert_eq!(
        &retries[..7],
        &[
            Some(60),
            Some(120),
            Some(240),
            Some(480),
            Some(960),
            Some(1800),
            Some(1800)
        ]
    );
}

#[test]
fn test_misses_at_the_cap_end_in_giving_up() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);

    let retries = miss_until_given_up(&mut refresh);

    assert_eq!(
        retries.iter().filter(|retry| **retry == Some(1800)).count(),
        usize::from(MAX_RETRIES_AT_CAP)
    );
}

#[test]
fn test_destination_given_up_on_is_not_queued_again() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);

    miss_until_given_up(&mut refresh);

    assert!(refresh.is_empty());
}

#[test]
fn test_reply_ends_the_back_off() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    miss(&mut refresh, START);
    miss(&mut refresh, at(70));
    issue(&mut refresh, at(200));
    refresh.note_reply(DEVICE);
    refresh.enqueue(DEVICE, RefreshReason::HopRecovered);

    assert_eq!(miss(&mut refresh, at(300)), vec![retry(POLICY.backoff)]);
}

// forget

#[test]
fn test_forget_drops_the_destination_everywhere() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    miss(&mut refresh, START);
    refresh.enqueue(OTHER_DEVICE, RefreshReason::Settled);
    issue(&mut refresh, at(11));
    refresh.note_displaced(DEVICE, HOP, at(11));
    refresh.note_displaced(OTHER_DEVICE, HOP, at(11));

    refresh.forget(DEVICE);
    refresh.forget(OTHER_DEVICE);

    assert!(refresh.is_empty());
    assert_eq!(refresh.tick(at(10_000), POLICY), Vec::new());
    assert_eq!(refresh.hop_recovered(HOP, at(12), POLICY), 0);
}

// A router that rejoins at its address is forgotten and comes back: the routes that
// failed through it are still worth refreshing when it works again.
#[test]
fn test_forget_keeps_the_hops_own_displaced_list() {
    let mut refresh = RouteRefresh::default();
    refresh.note_displaced(DEVICE, HOP, START);

    refresh.forget(HOP);

    assert_eq!(refresh.hop_recovered(HOP, at(30), POLICY), 1);
}

#[test]
fn test_forget_leaves_other_destinations_alone() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    refresh.enqueue(OTHER_DEVICE, RefreshReason::Settled);

    refresh.forget(DEVICE);

    assert_eq!(
        refresh.next_due(START, POLICY),
        Some((OTHER_DEVICE, RefreshReason::Settled))
    );
}

// next_wake

#[test]
fn test_next_wake_with_nothing_to_do_is_none() {
    let refresh = RouteRefresh::default();

    assert_eq!(refresh.next_wake(START, POLICY), None);
}

#[test]
fn test_next_wake_within_spacing_is_when_spacing_ends() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    refresh.enqueue(OTHER_DEVICE, RefreshReason::Settled);
    issue(&mut refresh, START);
    refresh.note_reply(DEVICE);

    assert_eq!(refresh.next_wake(START, POLICY), Some(at(2)));
}

#[test]
fn test_next_wake_with_a_refresh_in_flight_is_no_later_than_its_deadline() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    issue(&mut refresh, START);

    assert!(
        refresh
            .next_wake(START, POLICY)
            .is_some_and(|wake| wake <= at(10))
    );
}

#[test]
fn test_next_wake_in_back_off_is_when_the_back_off_ends() {
    let mut refresh = RouteRefresh::default();
    refresh.enqueue(DEVICE, RefreshReason::Settled);
    miss(&mut refresh, START);

    assert_eq!(refresh.next_wake(at(10), POLICY), Some(at(70)));
}
