//! Route refresh in the driver: the wait for the neighbors to settle after a start,
//! and the task that paces the refresh discoveries `RouteRefresh` decides on.

use crate::runtime::Runtime;
use ziggurat_ieee_802154::types::Nwk;
use ziggurat_phy::RadioPhy;
use ziggurat_zigbee::nwk::route_refresh::{RefreshReason, RouteRefreshPolicy};
use ziggurat_zigbee::nwk::routing::RouteUpdate;

use super::{Nib, RouteDirective, SendMode, ZigbeeStack};

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    /// Wait for the neighbors to settle after a start, before route refresh looks at
    /// any route. Receivers drop route requests from senders with a zero outgoing
    /// cost, and the empty link status sent at startup has just zeroed it on every
    /// neighbor. Wait one link status period, so every router neighbor gets to send its
    /// link status, then tell them all their side with one of our own. A router that
    /// answers at once is not enough: the others would still drop our requests.
    async fn settle_after_start(&self) {
        self.sleep_until_core(self.core_now() + self.tunables.link_status_period())
            .await;

        if let Ok(link_status) = self.send_link_status_broadcast(false) {
            let _ = link_status.delivered().await;
        }
    }

    /// The route refresh tunables, read afresh so a change takes effect at once.
    fn route_refresh_policy(&self) -> RouteRefreshPolicy {
        RouteRefreshPolicy {
            spacing: self.tunables.route_refresh_spacing(),
            backoff: self.tunables.route_refresh_backoff(),
            backoff_max: self.tunables.route_refresh_backoff_max(),
            displaced_retention: self.tunables.displaced_route_retention(),
        }
    }

    /// Once the neighbors have settled after the start, look again, in the background,
    /// at the routes found before, then at whatever the triggers queue. One refresh
    /// discovery goes out per `route_refresh_spacing` at most, and none while a frame
    /// waits for a discovery: frames come first. A refresh keeps the route in use until
    /// a strictly cheaper reply arrives (`Routing::begin_refresh`).
    ///
    /// The `route_refresh` tunable is read on every pass: off, the task issues nothing
    /// and the triggers queue nothing. The settle step, and the settle trigger, only
    /// run if it is on at the start.
    pub async fn route_refresh_task(&self) {
        if self.tunables.route_refresh() {
            self.settle_after_start().await;

            let settled = {
                let mut guard = self.core();
                let nib = &mut guard.nib;
                let policy = self.next_hop_policy();
                let destinations = nib
                    .routing
                    .refreshable_destinations(policy.is_concentrator, policy.max_source_route);

                for &destination in &destinations {
                    nib.route_refresh
                        .enqueue(destination, RefreshReason::Settled);
                }

                drop(guard);
                destinations.len()
            };
            tracing::info!("Neighbors settled: refreshing {settled} routes found before");
        }

        loop {
            let wake = if self.tunables.route_refresh() {
                self.refresh_routes()
            } else {
                self.core_now() + self.tunables.route_discovery_time()
            };

            let _ = self
                .timeout_at_core(wake, self.route_refresh_kick.notified())
                .await;
        }
    }

    /// One pass of the route refresh task: note the refreshes that went unanswered,
    /// issue the next one that is due, and return when the next pass is due.
    fn refresh_routes(&self) -> ziggurat_zigbee::Instant {
        let policy = self.route_refresh_policy();
        let route_discovery_time = self.tunables.route_discovery_time();
        let own_address = self.state.network_address;
        let now = self.core_now();

        let mut guard = self.core();
        let core = &mut *guard;

        for missed in core.nib.route_refresh.tick(now, policy) {
            let destination = missed.destination;
            match missed.retry_in {
                Some(backoff) => tracing::info!(
                    "Route refresh: no reply from {destination:?}, next try in {backoff:?}"
                ),
                None => {
                    tracing::info!("Route refresh: no reply from {destination:?}, giving up on it");
                }
            }
        }

        let frames_wait = core.nib.routing.frames_await_discovery();
        let mut issued = false;

        if !frames_wait
            && let Some((destination, reason)) = core.nib.route_refresh.next_due(now, policy)
        {
            match core.nib.routing.begin_refresh(
                own_address,
                destination,
                now,
                route_discovery_time,
                self.activity_params(),
            ) {
                Some(request_id) => {
                    tracing::info!("Route refresh: refreshing {destination:?} ({reason:?})");
                    self.broadcast_discovery_request(core, destination, request_id);
                    core.nib.route_refresh.issued(
                        destination,
                        reason,
                        now,
                        now + route_discovery_time,
                    );
                    issued = true;
                }
                None => {
                    tracing::debug!(
                        "Route refresh: {destination:?} is already under discovery, skipping"
                    );
                }
            }
        }

        // Nothing pending: check back at the discovery time. While frames wait for a
        // discovery, check back no sooner than the spacing, or a due refresh would spin.
        let next_wake = core
            .nib
            .route_refresh
            .next_wake(now, policy)
            .unwrap_or(now + route_discovery_time);
        let next_wake = if frames_wait {
            next_wake.max(now + policy.spacing)
        } else {
            next_wake
        };

        if issued {
            self.commit_sends(guard);
        }

        next_wake
    }

    /// `hop` works again, as a link status shows or as the server learns another way
    /// (a backbone peer that answers again). The routes that failed through it are
    /// refreshed: they may be cheaper through it than on their detour.
    pub fn note_hop_recovered(&self, hop: Nwk) {
        if !self.tunables.route_refresh() {
            return;
        }

        let now = self.core_now();
        let policy = self.route_refresh_policy();
        let queued = self
            .core()
            .nib
            .route_refresh
            .hop_recovered(hop, now, policy);

        if queued > 0 {
            tracing::info!("Next hop {hop:?} works again: refreshing {queued} routes");
            self.route_refresh_kick.notify_one();
        }
    }

    /// A route reply to a discovery of ours from `responder`. If it answers a refresh,
    /// the refresh ends and the destination's back-off with it; `update` is the route
    /// it moved, if it did.
    pub(super) fn note_refresh_reply(&self, responder: Nwk, update: Option<RouteUpdate>) {
        if !self.core().nib.route_refresh.note_reply(responder) {
            return;
        }

        if let Some(update) = update {
            tracing::info!(
                "Route refresh: {:?} now via {:?} at cost {}",
                update.destination,
                update.next_hop,
                update.path_cost
            );
        }

        // The next refresh may be due now that this one is no longer in flight
        self.route_refresh_kick.notify_one();
    }

    /// Whether a send in `mode` to `destination` would go by a host route hint because
    /// the stack has no route of its own. Checked beside `next_hop::resolve`, which
    /// stays unaware of route refresh. End device children are reached directly and
    /// need no route.
    pub(super) fn hint_stands_in_for_a_route(
        &self,
        nib: &Nib,
        destination: Nwk,
        mode: &SendMode,
    ) -> bool {
        if !matches!(mode, SendMode::Route(RouteDirective::Hint(_)))
            || nib.neighbors.end_device_child_eui64(destination).is_some()
        {
            return false;
        }

        let policy = self.next_hop_policy();
        let stack_route = if policy.is_concentrator {
            nib.routing
                .route_to(destination, policy.max_source_route)
                .is_some()
        } else {
            nib.routing.next_hop(destination).is_some()
        };

        !stack_route
    }

    /// A host route hint stood in for a route to `destination`: refresh it, so a real
    /// route takes over before the host stops hinting.
    pub(super) fn queue_hinted_refresh(&self, nib: &mut Nib, destination: Nwk) {
        if !self.tunables.route_refresh() {
            return;
        }

        nib.route_refresh
            .enqueue(destination, RefreshReason::Hinted);
        self.route_refresh_kick.notify_one();
    }
}
