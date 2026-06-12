use std::cmp;
use tokio::sync::broadcast;
use tokio::time::{Duration, Instant, timeout, timeout_at};

use ieee_802154::types::Nwk;

use zigbee::Command;
use zigbee::nwk::commands::{
    NwkNetworkStatus, NwkNetworkStatusCommand, NwkRouteReplyCommand, NwkRouteRequestCommand,
    NwkRouteRequestManyToOne,
};
use zigbee::nwk::frame::{BROADCAST_ALL_ROUTERS_AND_COORDINATOR, NwkFrame};

use super::routing::{RouteReplyDisposition, Status};
use super::{MAX_LOCK_DURATION, NwkSecurityMode, ZigbeeStack, ZigbeeStackError};

impl ZigbeeStack {
    fn notify_routing_change(&self, nwk: &Nwk) {
        let tx = {
            let pending_route_notifications = self
                .state
                .pending_route_notifications
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            if !pending_route_notifications.contains_key(nwk) {
                return;
            }

            pending_route_notifications.get(nwk).unwrap().clone()
        };
        let _ = tx.send(());
    }

    #[allow(clippy::significant_drop_tightening)]
    pub(super) fn handle_route_reply(&self, nwk_frame: &NwkFrame) {
        let route_reply_cmd = match NwkRouteReplyCommand::deserialize(&nwk_frame.payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                log::warn!("Error parsing route reply command: {e:?}");
                return;
            }
        };

        log::debug!("Route reply command frame: {route_reply_cmd:?}");

        // Both `responder_eui64` and `originator_eui64` SHALL be set according to the
        // R23 spec but real devices do not do this

        let sender_link = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .link(nwk_frame.nwk_header.source);

        let Some(sender_link) = sender_link else {
            log::debug!("Ignoring route reply from unknown neighbor");
            return;
        };

        if sender_link.outgoing_cost == 0 {
            log::debug!("Ignoring route reply from neighbor with zero outgoing cost");
            return;
        }

        let updated_path_cost = route_reply_cmd
            .path_cost
            .saturating_add(sender_link.outgoing_cost);

        let disposition = self
            .state
            .routing
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .accept_route_reply(
                route_reply_cmd.originator_nwk,
                route_reply_cmd.route_request_identifier,
                route_reply_cmd.responder_nwk,
                nwk_frame.nwk_header.source,
                updated_path_cost,
            );

        let (next_hop_nwk, path_cost) = match disposition {
            RouteReplyDisposition::Drop => return,
            RouteReplyDisposition::Established => {
                self.notify_routing_change(&route_reply_cmd.responder_nwk);
                return;
            }
            RouteReplyDisposition::Relay {
                next_hop,
                path_cost,
            } => (next_hop, path_cost),
        };

        self.notify_routing_change(&route_reply_cmd.responder_nwk);

        let next_hop_link = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .link(next_hop_nwk);

        let Some(next_hop_link) = next_hop_link else {
            log::warn!("Next hop neighbor not found in neighbor table");
            return;
        };

        let relayed_route_reply_frame = self
            .nwk_command_frame(
                next_hop_nwk,
                NwkRouteReplyCommand {
                    route_request_identifier: route_reply_cmd.route_request_identifier,
                    originator_nwk: route_reply_cmd.originator_nwk,
                    responder_nwk: route_reply_cmd.responder_nwk,
                    // We increment the path cost
                    path_cost: path_cost.saturating_add(next_hop_link.incoming_cost),
                    originator_eui64: route_reply_cmd.originator_eui64,
                    responder_eui64: route_reply_cmd.responder_eui64,
                }
                .serialize()
                .unwrap(),
            )
            // Spec 3.4.2.2: relays decrement the radius, but a reply received with a
            // radius of 1 is still forwarded with a radius of 1
            .with_radius(cmp::max(nwk_frame.nwk_header.radius.saturating_sub(1), 1))
            .with_destination_ieee(Some(next_hop_link.eui64));

        // The next hop toward the originator is a direct radio neighbor
        self.background_send_nwk_frame(
            relayed_route_reply_frame,
            NwkSecurityMode::NetworkKey,
            true,
        );
    }

    #[allow(clippy::significant_drop_tightening)]
    pub(super) fn handle_route_request(&self, nwk_frame: &NwkFrame, sender_nwk: Nwk) {
        let route_request_cmd = match NwkRouteRequestCommand::deserialize(&nwk_frame.payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                log::warn!("Error parsing route request command: {e:?}");
                return;
            }
        };

        log::debug!("Route request command frame (sender {sender_nwk:?}): {route_request_cmd:?}");

        let network_address = self.state.network_address;
        let many_to_one = route_request_cmd.many_to_one != NwkRouteRequestManyToOne::NotManyToOne;

        // We need to know who sent the frame
        let sender_link = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .link(sender_nwk);

        let Some(sender_link) = sender_link else {
            // Can we do anything here? Broadcast an unsolicited link status?
            log::debug!("Route request relayer {sender_nwk:?} not found in neighbor table");
            return;
        };

        if sender_link.outgoing_cost == 0 {
            log::warn!("Path cost to neighbor is 0, not sending route reply");
            return;
        }

        let sender_ieee = sender_link.eui64;

        // The maximum of the incoming and outgoing costs is used for computations to
        // deprioritize asymmetric routes
        let contributing_path_cost = cmp::max(sender_link.outgoing_cost, sender_link.incoming_cost);
        let updated_path_cost = route_request_cmd
            .path_cost
            .saturating_add(contributing_path_cost);

        // Deduplicate route requests and track the best path back to the originator.
        // Only requests advertising a strictly better forward cost are processed
        // further; this also stops our own requests from echoing back at us.
        let accepted = self
            .state
            .routing
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .accept_route_request(
                nwk_frame.nwk_header.source,
                route_request_cmd.route_request_identifier,
                route_request_cmd.destination_address,
                sender_nwk,
                updated_path_cost,
                route_request_cmd.many_to_one,
                Instant::now().into_std(),
            );

        if !accepted {
            return;
        }

        self.notify_routing_change(&nwk_frame.nwk_header.source);

        // TODO: what do we do if the address and the EUI64 don't agree? This would be
        // an error, some device on the network is storing invalid information about
        // either us or a child.
        let responder_eui64 = if many_to_one {
            // Many-to-one requests are advertisements; nobody replies to them
            None
        } else if route_request_cmd.destination_address == network_address
            || route_request_cmd.destination_eui64 == Some(self.state.ieee_address)
        {
            Some(self.state.ieee_address)
        } else {
            // Spec 3.6.4.5.1.2: parents answer route requests for their end device
            // children, which do not participate in route discovery
            self.end_device_child_eui64(route_request_cmd.destination_address)
        };

        if let Some(responder_eui64) = responder_eui64 {
            // Spec 3.4.2.2: the reply is addressed hop-by-hop, starting with the
            // neighbor we accepted the request from, and accumulates its own path cost
            // on the way back
            let route_reply_frame = self
                .nwk_command_frame(
                    sender_nwk,
                    NwkRouteReplyCommand {
                        route_request_identifier: route_request_cmd.route_request_identifier,
                        originator_nwk: nwk_frame.nwk_header.source,
                        responder_nwk: route_request_cmd.destination_address,
                        path_cost: contributing_path_cost,
                        originator_eui64: nwk_frame.nwk_header.source_ieee,
                        responder_eui64: Some(responder_eui64),
                    }
                    .serialize()
                    .unwrap(),
                )
                .with_destination_ieee(Some(sender_ieee));

            // The next hop toward the originator is a direct radio neighbor
            self.background_send_nwk_frame(route_reply_frame, NwkSecurityMode::NetworkKey, true);
            return;
        }

        // We are relaying. Track that discovery toward the destination is underway;
        // many-to-one requests are addressed to a broadcast address, so there is no
        // destination to track for them.
        if !many_to_one {
            self.state
                .routing
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .note_relayed_discovery(route_request_cmd.destination_address);
        }

        let rebroadcast_radius = nwk_frame.nwk_header.radius.saturating_sub(1);

        if rebroadcast_radius == 0 {
            log::debug!("Not relaying route request, re-broadcast radius is 0");
            return;
        }

        // Relayed route requests are not new frames: the originator's source address
        // and sequence number are preserved, only the path cost and radius change
        let relayed_route_request_cmd = self
            .nwk_command_frame(
                nwk_frame.nwk_header.destination,
                NwkRouteRequestCommand {
                    many_to_one: route_request_cmd.many_to_one,
                    route_request_identifier: route_request_cmd.route_request_identifier,
                    destination_address: route_request_cmd.destination_address,
                    path_cost: updated_path_cost, // We update only the path cost
                    destination_eui64: route_request_cmd.destination_eui64,
                }
                .serialize()
                .unwrap(),
            )
            .with_source(nwk_frame.nwk_header.source)
            .with_source_ieee(nwk_frame.nwk_header.source_ieee)
            .with_radius(rebroadcast_radius)
            .with_sequence_number(nwk_frame.nwk_header.sequence_number);

        // Spec 3.6.4.5.1.4: relayed route requests are jittered and retried
        let jitter = (self.constants.min_rreq_jitter
            + (self.constants.max_rreq_jitter - self.constants.min_rreq_jitter)
                .mul_f32(rand::random::<f32>()))
            * 2;

        self.background_broadcast_route_request(
            relayed_route_request_cmd,
            self.constants.rreq_retries + 1,
            jitter,
        );
    }

    /// Broadcast a route request `attempts` times, separated by the RREQ retry
    /// interval. The frame's sequence number must already be assigned: route request
    /// retries and relays are not new frames.
    fn background_broadcast_route_request(
        &self,
        nwk_frame: NwkFrame,
        attempts: u8,
        initial_delay: Duration,
    ) {
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            tokio::time::sleep(initial_delay).await;

            for attempt in 0..attempts {
                if attempt > 0 {
                    tokio::time::sleep(arc_self.constants.rreq_retry_interval).await;
                }

                if let Err(err) = arc_self
                    .transmit_broadcast_nwk_frame(nwk_frame.clone(), NwkSecurityMode::NetworkKey)
                    .await
                {
                    log::warn!("Failed to broadcast route request: {err}");
                }
            }
        });
    }

    /// Zigbee spec 3.6.4.5.1: advertise a many-to-one route to ourselves so that every
    /// router records a path toward the concentrator. Devices can then reach us without
    /// per-device route discoveries, and respond with route record commands that we
    /// store for future source routing.
    pub async fn send_many_to_one_route_request(&self) {
        let route_request_identifier = self
            .state
            .routing
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .begin_many_to_one_advertisement(Instant::now().into_std());

        log::debug!("Sending many-to-one route request {route_request_identifier}");

        let many_to_one_request_frame = self
            .nwk_command_frame(
                BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
                NwkRouteRequestCommand {
                    many_to_one: NwkRouteRequestManyToOne::ManyToOneSenderSupportsRouteRecordTable,
                    route_request_identifier,
                    destination_address: BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
                    path_cost: 0,
                    destination_eui64: None,
                }
                .serialize()
                .unwrap(),
            )
            .with_radius(self.constants.concentrator_radius)
            // Sent via `transmit_*`, which does not assign sequence numbers
            .with_sequence_number(self.next_nwk_sequence_number());

        // Many-to-one route requests are not retried (spec 3.6.4.5.1)
        if let Err(err) = self
            .transmit_broadcast_nwk_frame(many_to_one_request_frame, NwkSecurityMode::NetworkKey)
            .await
        {
            log::warn!("Failed to broadcast many-to-one route request: {err}");
        }
    }

    pub async fn periodic_many_to_one_route_request_task(&self) {
        // Receivers drop route requests from senders with a zero outgoing cost, so
        // the first advertisement waits until link status exchanges establish a
        // neighbor link, bounded by a fixed ceiling in case the network is silent
        let startup_deadline = Instant::now() + 2 * self.constants.link_status_period;

        loop {
            if self
                .state
                .neighbors
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .any_live_router_link()
            {
                break;
            }

            if timeout_at(startup_deadline, self.link_status_received.notified())
                .await
                .is_err()
            {
                break;
            }
        }

        loop {
            self.send_many_to_one_route_request().await;

            self.state
                .routing
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .reset_mtorr_triggers();

            let min_deadline = Instant::now() + self.constants.mtorr_min_interval;
            let max_deadline = Instant::now() + self.constants.mtorr_max_interval;

            // Avertise every max interval, sooner when accumulated route errors or
            // delivery failures signal that routes toward us have gone bad, but never
            // within the min interval
            tokio::select! {
                () = tokio::time::sleep_until(max_deadline) => {}
                () = self.mtorr_kick.notified() => {
                    tokio::time::sleep_until(min_deadline).await;
                }
            }
        }
    }

    /// Count a received route-failure network status toward an early many-to-one
    /// route request.
    pub(super) fn note_route_error(&self) {
        if !self.state.is_concentrator {
            return;
        }

        let kick = self
            .state
            .routing
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .note_route_error();

        if kick {
            self.mtorr_kick.notify_one();
        }
    }

    /// Count a locally failed unicast delivery toward an early many-to-one route
    /// request.
    pub(super) fn note_delivery_failure(&self) {
        if !self.state.is_concentrator {
            return;
        }

        let kick = self
            .state
            .routing
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .note_delivery_failure();

        if kick {
            self.mtorr_kick.notify_one();
        }
    }

    pub(super) fn invalidate_routes_via(&self, next_hop: Nwk) {
        self.state
            .routing
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .invalidate_via(next_hop);
    }

    /// Zigbee spec 3.6.4.8.1: another router could not deliver a frame we originated;
    /// drop the route so the next transmission performs a fresh discovery.
    pub(super) fn handle_network_status(&self, nwk_frame: &NwkFrame) {
        let network_status_cmd = match NwkNetworkStatusCommand::deserialize(&nwk_frame.payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                log::warn!("Error parsing network status command: {e:?}");
                return;
            }
        };

        log::info!(
            "Network status from {:?}: {network_status_cmd:?}",
            nwk_frame.nwk_header.source
        );

        match network_status_cmd.status_code {
            NwkNetworkStatus::LegacyNoRouteAvailable
            | NwkNetworkStatus::LegacyLinkFailure
            | NwkNetworkStatus::LinkFailure
            | NwkNetworkStatus::SourceRouteFailure => {
                let mut routing = self.state.routing.try_lock_for(MAX_LOCK_DURATION).unwrap();

                let removed_route = routing.remove_route(network_status_cmd.network_address);

                // A relay reported the stored path broken; the next transmission
                // falls back to discovery until a fresh route record arrives
                let removed_record = network_status_cmd.status_code
                    == NwkNetworkStatus::SourceRouteFailure
                    && routing.remove_route_record(network_status_cmd.network_address);

                drop(routing);

                if removed_route {
                    log::info!(
                        "Removed failed route to {:?}",
                        network_status_cmd.network_address
                    );
                }
                if removed_record {
                    log::info!(
                        "Removed failed source route to {:?}",
                        network_status_cmd.network_address
                    );
                }

                self.note_route_error();
            }
            NwkNetworkStatus::ManyToOneRouteFailure => {
                // Spec 3.6.4.8.2: the concentrator repairs many-to-one routes by
                // advertising itself again; the scheduler throttles the repair
                self.note_route_error();
            }
            NwkNetworkStatus::AddressConflict => {
                self.handle_address_conflict(network_status_cmd.network_address, false);
            }
            _ => {
                log::warn!("Unhandled network status: {network_status_cmd:?}");
            }
        }
    }

    #[allow(clippy::significant_drop_tightening)]
    pub async fn discover_route(&self, destination: Nwk) -> Result<Nwk, ZigbeeStackError> {
        // End device children do not participate in route discovery (they could never
        // answer a route request); their parent always delivers directly
        if self.end_device_child_eui64(destination).is_some() {
            return Ok(destination);
        }

        if self.state.hack_force_route_discovery
            || self
                .state
                .routing
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .route_status(destination)
                .is_none()
        {
            log::debug!("Starting route discovery for NWK {destination:?}");
            self.send_route_discovery(destination).await;
        }

        // The entry just ensured above can be torn down concurrently (e.g. a
        // link-failure network status removing the route), so a missing entry is
        // treated like an inactive route and discovery starts over
        let route_entry_status = self
            .state
            .routing
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .route_status(destination)
            .unwrap_or(Status::Inactive);

        log::debug!("Routing table status for {destination:?}: {route_entry_status:?}");

        match route_entry_status {
            Status::Active => {
                let next_hop = self
                    .state
                    .routing
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .next_hop(destination);

                // The same concurrent teardown can strike between the two reads
                if let Some(next_hop) = next_hop {
                    log::debug!("Using existing next hop for NWK {destination:?}: {next_hop:?}");
                    return Ok(next_hop);
                }

                self.send_route_discovery(destination).await;
            }
            Status::DiscoveryUnderway => {
                // Do nothing
            }
            Status::DiscoveryFailed | Status::Inactive => {
                self.send_route_discovery(destination).await;
            }
        }

        // Create a pending route notification
        let mut rx = {
            let mut pending_route_notifications = self
                .state
                .pending_route_notifications
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            let tx = pending_route_notifications
                .entry(destination)
                .or_insert_with(|| {
                    let (tx, _) = broadcast::channel(1);
                    tx
                });

            tx.subscribe()
        };

        // Pull the current route discovery entry for the device to determine the timeout
        let discovery_timeout = {
            let deadline = self
                .state
                .routing
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .discovery_deadline(destination, Instant::now().into_std());

            // One should exist
            match deadline {
                Some(deadline) => deadline - Instant::now().into_std(),
                None => {
                    log::warn!("No route discovery entry found for {destination:?}");
                    return Err(ZigbeeStackError::RouteDiscoveryFailure(
                        "No discovery entry found".to_string(),
                    ));
                }
            }
        };

        log::debug!(
            "Waiting for route discovery notification for NWK {destination:?} with timeout {discovery_timeout:?}"
        );

        match timeout(discovery_timeout, rx.recv()).await {
            Ok(_) => {
                log::debug!("Route discovery completed for NWK {destination:#?}");
            }
            Err(err) => {
                log::debug!("Route discovery timed out");
                self.state
                    .routing
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .mark_discovery_failed(destination);
                return Err(ZigbeeStackError::RouteDiscoveryTimeout(err));
            }
        };

        self.state
            .routing
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .next_hop(destination)
            .ok_or_else(|| {
                ZigbeeStackError::RouteDiscoveryFailure(
                    "Route not active after discovery".to_string(),
                )
            })
    }

    #[allow(clippy::significant_drop_tightening)]
    pub async fn send_route_discovery(&self, destination: Nwk) {
        log::debug!("Sending route discovery for NWK {destination:?}");

        let route_request_identifier = self
            .state
            .routing
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .begin_discovery(destination, Instant::now().into_std());

        // If we know the EUI64 corresponding to the NWK, use it
        let destination_eui64 = self
            .state
            .address_map
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .eui64_for(destination);

        let route_request_frame = self
            .nwk_command_frame(
                BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
                NwkRouteRequestCommand {
                    many_to_one: NwkRouteRequestManyToOne::NotManyToOne,
                    route_request_identifier,
                    destination_address: destination,
                    path_cost: 0, // The path cost starts at 0, since we originate it
                    destination_eui64,
                }
                .serialize()
                .unwrap(),
            )
            // Retried broadcasts of a route request share one sequence number,
            // assigned now: `transmit_*` does not touch it
            .with_sequence_number(self.next_nwk_sequence_number());

        // Spec 3.6.4.5.1: the initial broadcast is repeated `nwkcInitialRREQRetries`
        // times, separated by the retry interval
        self.background_broadcast_route_request(
            route_request_frame,
            self.constants.initial_rreq_retries + 1,
            Duration::ZERO,
        );
    }
}
