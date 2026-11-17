//! Route refresh: a paced queue of destinations whose working routes are worth
//! looking at again.
//!
//! Ziggurat changes a route only when something fails, so a route found while the
//! network was still settling stays expensive for good. Route refresh re-discovers
//! routes in three cases (see `RefreshReason`) and backs off for destinations that do
//! not answer. This is the pure decision logic: the driver paces it, issues the
//! discoveries through `Routing::begin_refresh`, and reports replies.
//!
//! Deviation from the proposal: the rate is bounded by a fixed spacing between
//! refreshes only, with no separate per-minute cap; the spacing already bounds it.

use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_ieee_802154::types::Nwk;

use crate::Instant;
use crate::flat_map::FlatMap;

#[cfg(test)]
mod tests;

/// At most this many destinations are remembered as displaced from one hop. When the
/// list is full, the oldest is dropped.
pub const MAX_DISPLACED_PER_HOP: usize = 32;

/// How many tries at the longest back-off a destination that does not answer gets.
///
/// The next miss gives up on it: a device that is gone for good, or an address it no
/// longer holds, would otherwise draw a network-wide route request every back-off for
/// ever. A later trigger queues it again from the start.
pub const MAX_RETRIES_AT_CAP: u8 = 3;

/// Network addresses from here up are broadcast addresses: no route goes to them.
const FIRST_BROADCAST_ADDRESS: u16 = 0xFFF8;

/// Why a destination is due for a refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshReason {
    /// Its route was found before the neighbors settled after a start, while some of
    /// them may still have dropped our route requests.
    Settled,
    /// Only a host route hint reached it: a real route lets the hint expire.
    Hinted,
    /// Its route failed through a hop that works again.
    HopRecovered,
}

/// The tunables route refresh runs by. Passed in, never stored, so a changed tunable
/// takes effect on the next call.
#[derive(Debug, Clone, Copy)]
pub struct RouteRefreshPolicy {
    /// The least time between two refreshes.
    pub spacing: Duration,
    /// The wait before trying a destination again after its first unanswered refresh.
    /// Each later miss doubles it.
    pub backoff: Duration,
    /// The longest back-off.
    pub backoff_max: Duration,
    /// How long a destination displaced from a hop is worth refreshing when the hop
    /// recovers.
    pub displaced_retention: Duration,
}

/// An unanswered refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Missed {
    pub destination: Nwk,
    /// The back-off before the next try, or `None` when route refresh gave up on the
    /// destination.
    pub retry_in: Option<Duration>,
}

/// The back-off a destination's last unanswered refresh got.
#[derive(Debug, Clone, Copy)]
struct Backoff {
    duration: Duration,
    /// How many misses in a row got the longest back-off.
    at_cap: u8,
}

#[derive(Debug)]
struct Queued {
    destination: Nwk,
    reason: RefreshReason,
    /// Not due before this instant: the destination is in back-off.
    not_before: Option<Instant>,
}

#[derive(Debug)]
struct InFlight {
    reason: RefreshReason,
    deadline: Instant,
}

/// The queue of destinations to refresh, the destinations displaced from each hop,
/// the refreshes in flight, and a back-off per destination.
#[derive(Debug, Default)]
pub struct RouteRefresh {
    /// Oldest first, one entry per destination.
    queue: Vec<Queued>,
    /// Per hop, the destinations whose routes failed through it and when, oldest
    /// first.
    displaced: FlatMap<Nwk, Vec<(Nwk, Instant)>>,
    in_flight: FlatMap<Nwk, InFlight>,
    backoff: FlatMap<Nwk, Backoff>,
    /// When the last refresh went out, for the spacing.
    last_issued: Option<Instant>,
}

impl RouteRefresh {
    /// Queue `destination` for a refresh. A destination already queued keeps its
    /// place and first reason; one with a refresh in flight and broadcast addresses
    /// are not queued.
    pub fn enqueue(&mut self, destination: Nwk, reason: RefreshReason) {
        self.enqueue_new(destination, reason);
    }

    /// `enqueue`, returning whether the destination was newly queued.
    fn enqueue_new(&mut self, destination: Nwk, reason: RefreshReason) -> bool {
        if destination.as_u16() >= FIRST_BROADCAST_ADDRESS
            || self.in_flight.contains_key(&destination)
            || self.is_queued(destination)
        {
            return false;
        }

        self.queue.push(Queued {
            destination,
            reason,
            not_before: None,
        });
        true
    }

    fn is_queued(&self, destination: Nwk) -> bool {
        self.queue
            .iter()
            .any(|queued| queued.destination == destination)
    }

    /// The route to `destination` through `failed_next_hop` failed. Remembered so the
    /// destination is refreshed when the hop recovers.
    pub fn note_displaced(&mut self, destination: Nwk, failed_next_hop: Nwk, now: Instant) {
        let displaced = self.displaced.entry(failed_next_hop).or_default();

        displaced.retain(|&(other, _)| other != destination);
        displaced.push((destination, now));

        if displaced.len() > MAX_DISPLACED_PER_HOP {
            displaced.remove(0);
        }
    }

    /// `hop` works again: queue the destinations displaced from it within the
    /// retention, and forget its list. One already queued in back-off is due at once,
    /// with its back-off restarted: the hop recovering is news about its reachability.
    /// Returns how many were newly queued or made due.
    pub fn hop_recovered(&mut self, hop: Nwk, now: Instant, policy: RouteRefreshPolicy) -> usize {
        let Some(displaced) = self.displaced.remove(&hop) else {
            return 0;
        };

        displaced
            .into_iter()
            .filter(|&(_, at)| now.saturating_duration_since(at) <= policy.displaced_retention)
            .filter(|&(destination, _)| {
                if self.enqueue_new(destination, RefreshReason::HopRecovered) {
                    return true;
                }

                let Some(queued) = self
                    .queue
                    .iter_mut()
                    .find(|queued| queued.destination == destination)
                else {
                    return false;
                };

                self.backoff.remove(&destination);
                queued.not_before.take().is_some()
            })
            .count()
    }

    /// Take the oldest queued destination that is not in back-off, or `None` within
    /// `spacing` of the last refresh issued. Destinations in back-off stay queued.
    pub fn next_due(
        &mut self,
        now: Instant,
        policy: RouteRefreshPolicy,
    ) -> Option<(Nwk, RefreshReason)> {
        if self
            .last_issued
            .is_some_and(|last| now < last + policy.spacing)
        {
            return None;
        }

        let index = self
            .queue
            .iter()
            .position(|queued| queued.not_before.is_none_or(|not_before| not_before <= now))?;
        let queued = self.queue.remove(index);

        Some((queued.destination, queued.reason))
    }

    /// A refresh of `destination` went out: it is in flight until `deadline`, and the
    /// next one waits for the spacing.
    pub fn issued(
        &mut self,
        destination: Nwk,
        reason: RefreshReason,
        now: Instant,
        deadline: Instant,
    ) {
        self.in_flight
            .insert(destination, InFlight { reason, deadline });
        self.last_issued = Some(now);
    }

    /// A route reply from `responder` reached us. If it answers a refresh in flight,
    /// the refresh ends and the destination's back-off is cleared: a reply that does
    /// not replace the route still shows the destination answers.
    pub fn note_reply(&mut self, responder: Nwk) -> bool {
        if self.in_flight.remove(&responder).is_none() {
            return false;
        }

        self.backoff.remove(&responder);
        true
    }

    /// Refreshes past their deadline went unanswered. Each gets a back-off, the
    /// initial one or double its last up to the cap, and is queued again with its
    /// reason, not due before the back-off ends. After `MAX_RETRIES_AT_CAP` tries at
    /// the cap, the next miss gives up on the destination instead.
    pub fn tick(&mut self, now: Instant, policy: RouteRefreshPolicy) -> Vec<Missed> {
        self.in_flight
            .extract_if(|_, in_flight| in_flight.deadline <= now)
            .map(|(destination, in_flight)| {
                let reason = in_flight.reason;
                let duration = self
                    .backoff
                    .get(&destination)
                    .map_or(policy.backoff, |last| last.duration.saturating_mul(2))
                    .min(policy.backoff_max);
                let previous_at_cap = self.backoff.get(&destination).map_or(0, |b| b.at_cap);
                let at_cap = if duration >= policy.backoff_max {
                    previous_at_cap.saturating_add(1)
                } else {
                    0
                };

                self.queue
                    .retain(|queued| queued.destination != destination);

                if at_cap > MAX_RETRIES_AT_CAP {
                    self.backoff.remove(&destination);
                    return Missed {
                        destination,
                        retry_in: None,
                    };
                }

                self.backoff
                    .insert(destination, Backoff { duration, at_cap });
                self.queue.push(Queued {
                    destination,
                    reason,
                    not_before: Some(now + duration),
                });

                Missed {
                    destination,
                    retry_in: Some(duration),
                }
            })
            .collect()
    }

    /// When there is next something to do: a queued destination may go (after the
    /// spacing and its back-off), or a refresh in flight reaches its deadline. `None`
    /// when nothing is queued or in flight. Displaced entries expiring is not counted:
    /// they are only checked when their hop recovers.
    pub fn next_wake(&self, now: Instant, policy: RouteRefreshPolicy) -> Option<Instant> {
        let spacing_end = self.last_issued.map_or(now, |last| last + policy.spacing);

        let next_queued = self
            .queue
            .iter()
            .map(|queued| queued.not_before.unwrap_or(now).max(spacing_end))
            .min();

        let next_deadline = self
            .in_flight
            .values()
            .map(|in_flight| in_flight.deadline)
            .min();

        next_queued.into_iter().chain(next_deadline).min()
    }

    /// The device at `nwk` left or joined again: no refresh goes to it and no hop
    /// list names it as a destination. Its own list as a hop stays: a router that
    /// rejoins at its address comes back, and the routes that failed through it are
    /// worth refreshing when it works again. Deviation from the plan, which dropped it.
    pub fn forget(&mut self, nwk: Nwk) {
        self.queue.retain(|queued| queued.destination != nwk);
        self.in_flight.remove(&nwk);
        self.backoff.remove(&nwk);
        self.displaced.retain(|_, displaced| {
            displaced.retain(|&(destination, _)| destination != nwk);
            !displaced.is_empty()
        });
    }

    /// No refresh is queued or in flight.
    pub const fn is_empty(&self) -> bool {
        self.queue.is_empty() && self.in_flight.is_empty()
    }
}
