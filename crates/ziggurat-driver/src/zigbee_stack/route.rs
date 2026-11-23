use crate::runtime::Runtime;
use core::cmp;
use core::time::Duration;

use alloc::vec::Vec;
use ziggurat_ieee_802154::types::Nwk;
use ziggurat_phy::{Phy, RadioPhy};

use ziggurat_zigbee::nwk::commands::{
    NwkCommand, NwkNetworkStatus, NwkNetworkStatusCommand, NwkRouteRecordCommand,
    NwkRouteReplyCommand, NwkRouteRequestCommand, NwkRouteRequestManyToOne,
};
use ziggurat_zigbee::nwk::frame::{BROADCAST_ALL_ROUTERS_AND_COORDINATOR, NwkFrame};
use ziggurat_zigbee::nwk::next_hop::{self, RouteRecord};

use super::TrafficClass;
use super::routing::RouteReplyDisposition;

use super::{
    AddrConflictSource, Broadcast, Confirm, Frame, NwkSecurityMode, PhyIndex, SendHandle, SendMode,
    TxPolicy, TxPriority, Unicast, ZigbeeCore, ZigbeeStack,
};

impl<P: RadioPhy, S: Phy, R: Runtime> ZigbeeStack<P, S, R> {
    #[allow(clippy::significant_drop_tightening)]
    pub(super) fn handle_route_reply(
        &self,
        nwk_frame: &NwkFrame,
        route_reply_cmd: NwkRouteReplyCommand,
    ) {
        tracing::trace!("Route reply command frame: {route_reply_cmd:?}");

        // Both `responder_eui64` and `originator_eui64` SHALL be set according to the
        // R23 spec but real devices do not do this

        // The path cost already accounts for every link the reply has traversed: the
        // responder seeds the first hop and each relay adds the link it forwards across.
        let updated_path_cost = route_reply_cmd.path_cost;

        let now = self.core_now();
        let outcome = self.core().nib.routing.accept_route_reply(
            self.state.network_address,
            route_reply_cmd.originator_nwk,
            route_reply_cmd.route_request_identifier,
            route_reply_cmd.responder_nwk,
            nwk_frame.nwk_header.source,
            updated_path_cost,
            now,
            self.activity_params(),
        );

        let (next_hop_nwk, path_cost) = match outcome.disposition {
            RouteReplyDisposition::Drop => return,
            RouteReplyDisposition::Established => {
                self.send_timer_wake.notify_one();
                return;
            }
            RouteReplyDisposition::Relay {
                next_hop,
                path_cost,
            } => (next_hop, path_cost),
        };

        self.send_timer_wake.notify_one();

        let next_hop_link = self.core().nib.neighbors.link(next_hop_nwk);

        let Some(next_hop_link) = next_hop_link else {
            tracing::warn!("Next hop neighbor not found in neighbor table");
            return;
        };

        let relayed_route_reply_frame = self
            .nwk_command_frame(
                next_hop_nwk,
                NwkCommand::RouteReply(NwkRouteReplyCommand {
                    route_request_identifier: route_reply_cmd.route_request_identifier,
                    originator_nwk: route_reply_cmd.originator_nwk,
                    responder_nwk: route_reply_cmd.responder_nwk,
                    // We increment the path cost
                    path_cost: path_cost.saturating_add(cmp::max(
                        next_hop_link.incoming_cost,
                        next_hop_link.outgoing_cost,
                    )),
                    originator_eui64: route_reply_cmd.originator_eui64,
                    responder_eui64: route_reply_cmd.responder_eui64,
                }),
            )
            // Spec 3.4.2.2: relays decrement the radius, but a reply received with a
            // radius of 1 is still forwarded with a radius of 1
            .with_radius(cmp::max(nwk_frame.nwk_header.radius.saturating_sub(1), 1))
            .with_destination_ieee(Some(next_hop_link.eui64));

        // The next hop toward the originator is a direct radio neighbor
        self.send_unicast(Unicast {
            frame: relayed_route_reply_frame,
            security: NwkSecurityMode::NetworkKey,
            mode: SendMode::Direct,
            policy: TxPolicy::STACK_CRITICAL,
            confirm: Confirm::OnHandoff,
        })
        .map_err(|err| tracing::warn!("Failed to relay route reply: {err}"))
        .ok();
    }

    #[allow(clippy::significant_drop_tightening)]
    pub(super) fn handle_route_request(
        &self,
        nwk_frame: &NwkFrame,
        route_request_cmd: NwkRouteRequestCommand,
        sender_nwk: Nwk,
        arrival: PhyIndex,
    ) {
        tracing::debug!(
            "Route request command frame (sender {sender_nwk:?}): {route_request_cmd:?}"
        );

        let network_address = self.state.network_address;
        let many_to_one = route_request_cmd.many_to_one != NwkRouteRequestManyToOne::NotManyToOne;

        // Neighbors relay our own route requests back to us. Our discovery entry may
        // already be gone, so it cannot be what filters them.
        if nwk_frame.nwk_header.source == network_address {
            tracing::debug!("Ignoring our own route request relayed by {sender_nwk:?}");
            return;
        }

        // We need to know who sent the frame
        let sender_link = self.core().nib.neighbors.link(sender_nwk);

        let Some(sender_link) = sender_link else {
            // Can we do anything here? Broadcast an unsolicited link status?
            tracing::debug!("Route request relayer {sender_nwk:?} not found in neighbor table");
            return;
        };

        if sender_link.outgoing_cost == 0 {
            tracing::debug!("Path cost to neighbor is 0, not sending route reply");
            return;
        }

        let sender_ieee = sender_link.eui64;

        let updated_path_cost = route_request_cmd
            .path_cost
            .saturating_add(sender_link.cost());

        // Deduplicate route requests and track the best path back to the originator.
        // Only the first copy, one advertising a strictly better forward cost, or an
        // equal-cost copy while no copy at that cost was relayed (the earlier ones had
        // no radius left) is replied to or relayed. Other equal-cost copies only
        // refresh that path.
        let outcome = self.core().nib.routing.accept_route_request(
            nwk_frame.nwk_header.source,
            route_request_cmd.route_request_identifier,
            route_request_cmd.destination_address,
            sender_nwk,
            updated_path_cost,
            route_request_cmd.many_to_one,
            self.core_now(),
            self.tunables.route_discovery_time(),
            self.activity_params(),
        );

        if !outcome.accepted {
            return;
        }

        // The route back to the originator may release frames held for it
        self.send_timer_wake.notify_one();

        if !outcome.fresh {
            tracing::debug!("Not relaying or replying to an equal-cost duplicate route request");
            return;
        }

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

        let originator = nwk_frame.nwk_header.source;
        let request_id = route_request_cmd.route_request_identifier;

        if let Some(responder_eui64) = responder_eui64 {
            // Mark it handled, so an equal-cost copy is never replied to again
            self.core()
                .nib
                .routing
                .note_route_request_handled(originator, request_id);

            // Spec 3.4.2.2: the reply is addressed hop-by-hop, starting with the
            // neighbor we accepted the request from, and accumulates its own path cost
            // on the way back
            let route_reply_frame = self
                .nwk_command_frame(
                    sender_nwk,
                    NwkCommand::RouteReply(NwkRouteReplyCommand {
                        route_request_identifier: route_request_cmd.route_request_identifier,
                        originator_nwk: nwk_frame.nwk_header.source,
                        responder_nwk: route_request_cmd.destination_address,
                        path_cost: sender_link.cost(),
                        originator_eui64: nwk_frame.nwk_header.source_ieee,
                        responder_eui64: Some(responder_eui64),
                    }),
                )
                .with_destination_ieee(Some(sender_ieee));

            // The next hop toward the originator is a direct radio neighbor
            self.send_unicast(Unicast {
                frame: route_reply_frame,
                security: NwkSecurityMode::NetworkKey,
                mode: SendMode::Direct,
                policy: TxPolicy::STACK_CRITICAL,
                confirm: Confirm::OnHandoff,
            })
            .map_err(|err| tracing::warn!("Failed to send route reply: {err}"))
            .ok();

            return;
        }

        // We are relaying. Track that discovery toward the destination is underway;
        // many-to-one requests are addressed to a broadcast address, so there is no
        // destination to track for them.
        if !many_to_one {
            self.core().nib.routing.note_relayed_discovery(
                route_request_cmd.destination_address,
                self.core_now(),
                self.activity_params(),
            );
        }

        let rebroadcast_radius = nwk_frame.nwk_header.radius.saturating_sub(1);

        if rebroadcast_radius == 0 {
            tracing::debug!("Not relaying route request, re-broadcast radius is 0");
            return;
        }

        // Relayed route requests are not new frames: the originator's source address
        // and sequence number are preserved, only the path cost and radius change
        let relayed_route_request_cmd = self
            .nwk_command_frame(
                nwk_frame.nwk_header.destination,
                NwkCommand::RouteRequest(NwkRouteRequestCommand {
                    many_to_one: route_request_cmd.many_to_one,
                    route_request_identifier: route_request_cmd.route_request_identifier,
                    destination_address: route_request_cmd.destination_address,
                    path_cost: updated_path_cost, // We update only the path cost
                    destination_eui64: route_request_cmd.destination_eui64,
                }),
            )
            .with_source(nwk_frame.nwk_header.source)
            .with_source_ieee(nwk_frame.nwk_header.source_ieee)
            .with_radius(rebroadcast_radius)
            .with_sequence_number(nwk_frame.nwk_header.sequence_number);

        // Spec 3.6.4.5.1.4: relayed route requests are delayed and retried. The delay
        // grows with the cost of the link this copy came over, so along a path it adds
        // up to the path cost: the cheapest copy tends to arrive first, and fewer
        // routers relay again for a cheaper copy. The random part keeps neighbors that
        // heard the same copy from relaying at the same moment
        let jitter = self.tunables.rreq_delay_per_link_cost() * u32::from(sender_link.cost())
            + self
                .tunables
                .rreq_jitter()
                .mul_f32(crate::rng::random_f32::<R>());

        let attempts = self.tunables.rreq_retries().saturating_add(1);
        let mut core = self.core();

        // Equal-cost copies are duplicates only once one of them was relayed
        core.nib
            .routing
            .note_route_request_handled(originator, request_id);
        let relay = self.broadcast_route_request(
            &mut core,
            relayed_route_request_cmd,
            self.relay_phys(arrival),
            attempts,
            jitter,
        );
        core.sends
            .route_request_relayed(originator, request_id, relay);
        self.commit_sends(core);
    }

    /// Zigbee spec 3.6.4.5.1: advertise a many-to-one route to ourselves so that every
    /// router records a path toward the concentrator. Devices can then reach us without
    /// per-device route discoveries, and respond with route record commands that we
    /// store for future source routing.
    pub fn send_many_to_one_route_request(&self) -> SendHandle {
        let route_request_identifier = self.core().nib.routing.begin_many_to_one_advertisement(
            self.state.network_address,
            self.core_now(),
            self.tunables.route_discovery_time(),
        );

        tracing::debug!("Sending many-to-one route request {route_request_identifier}");

        let many_to_one_request_frame = self
            .nwk_command_frame(
                BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
                NwkCommand::RouteRequest(NwkRouteRequestCommand {
                    many_to_one: NwkRouteRequestManyToOne::ManyToOneSenderSupportsRouteRecordTable,
                    route_request_identifier,
                    destination_address: BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
                    path_cost: 0,
                    destination_eui64: None,
                }),
            )
            .with_radius(self.tunables.concentrator_radius());

        // Many-to-one route requests are not retried (spec 3.6.4.5.1)
        self.send_oneshot_broadcast(
            Broadcast {
                frame: many_to_one_request_frame,
                security: NwkSecurityMode::NetworkKey,
                policy: TxPolicy {
                    priority: TxPriority::Background,
                    class: TrafficClass::Critical,
                },
            },
            self.all_phys(),
        )
    }

    /// Advertise many-to-one routes while we are a concentrator, idling otherwise.
    pub async fn periodic_many_to_one_route_request_task(&self) {
        loop {
            while !self.is_concentrator() {
                self.concentrator_changed.notified().await;
            }

            // Receivers drop route requests from senders with a zero outgoing cost, so
            // the first advertisement waits until link status exchanges establish a
            // neighbor link, bounded by a fixed ceiling in case the network is silent
            let startup_deadline = self.core_now() + 2 * self.tunables.link_status_period();

            while !self.core().nib.neighbors.any_live_router_link()
                && self
                    .timeout_at_core(startup_deadline, self.link_status_received.notified())
                    .await
                    .is_ok()
            {}

            while self.is_concentrator() {
                let now = self.core_now();
                let max_interval = self.tunables.mtorr_max_interval();
                self.core().nib.mtorr_debouncer.fired(now, max_interval);

                let _ = self.send_many_to_one_route_request().delivered().await;

                self.core().nib.routing.reset_mtorr_triggers();

                // Advertise every max interval, or sooner when one was requested. Being
                // turned off ends the wait
                loop {
                    let due = core::pin::pin!(
                        self.wait_for_debouncer(|nib| &nib.mtorr_debouncer, &self.mtorr_wake)
                    );
                    let changed = core::pin::pin!(self.concentrator_changed.notified());

                    if matches!(
                        futures::future::select(due, changed).await,
                        futures::future::Either::Left(_)
                    ) || !self.is_concentrator()
                    {
                        break;
                    }
                }
            }
        }
    }

    /// Advertise the many-to-one route again soon, but never within the min interval
    /// of the last advertisement.
    fn request_many_to_one_route_request(&self) {
        let now = self.core_now();
        let min_interval = self.tunables.mtorr_min_interval();

        if self.core().nib.mtorr_debouncer.request(now, min_interval) {
            self.mtorr_wake.notify_one();
        }
    }

    /// Count a received route-failure network status toward an early many-to-one
    /// route request.
    pub(super) fn note_route_error(&self) {
        let kick = {
            let mut core = self.core();
            core.nib.is_concentrator
                && core
                    .nib
                    .routing
                    .note_route_error(self.tunables.mtorr_route_error_threshold())
        };

        if kick {
            self.request_many_to_one_route_request();
        }
    }

    /// Count a locally failed unicast delivery toward an early many-to-one route
    /// request.
    pub(super) fn note_delivery_failure(&self) {
        let kick = {
            let mut core = self.core();
            core.nib.is_concentrator
                && core
                    .nib
                    .routing
                    .note_delivery_failure(self.tunables.mtorr_delivery_failure_threshold())
        };

        if kick {
            self.request_many_to_one_route_request();
        }
    }

    /// Become a concentrator, or stop being one. It takes effect at once: the first
    /// advertisement goes out right away, and frames stop being source-routed when it
    /// is turned off. Route records keep being stored either way, since devices send
    /// them for as long as their many-to-one routes last.
    pub fn set_concentrator(&self, enabled: bool) {
        self.core().nib.is_concentrator = enabled;
        self.concentrator_changed.notify_one();
    }

    fn is_concentrator(&self) -> bool {
        self.core().nib.is_concentrator
    }

    /// Spec 3.6.4.5.5: transmit the route record due before `data`, to the same next hop.
    /// The route record tells the concentrator the path from us or our end device
    /// child. It goes out once here, so it always precedes the data. If it is not
    /// acked, the send table retries it like any other unicast.
    // The lint misses that `nib` borrows the guard until the frame is built
    #[allow(clippy::significant_drop_tightening)]
    pub(super) async fn transmit_route_record(
        &self,
        data: &NwkFrame,
        next_hop: Nwk,
        phy: PhyIndex,
    ) {
        let concentrator = data.nwk_header.destination;

        let mut frame = {
            let mut core = self.core();
            let nib = &mut core.nib;

            let Some(record) = next_hop::route_record_due(
                &nib.routing,
                &nib.neighbors,
                data,
                self.state.network_address,
            ) else {
                return;
            };

            let (source, source_eui64, relays) = match record {
                RouteRecord::Ours => (
                    self.state.network_address,
                    self.state.ieee_address,
                    Vec::new(),
                ),
                // The path from our child starts with us
                RouteRecord::Child { nwk, eui64 } => {
                    (nwk, eui64, Vec::from([self.state.network_address]))
                }
            };

            tracing::debug!("Sending a route record for {source:?} to {concentrator:?}");

            self.nwk_command_frame(
                concentrator,
                NwkCommand::RouteRecord(NwkRouteRecordCommand { relays }),
            )
            .with_source(source)
            .with_source_ieee(Some(source_eui64))
            .with_sequence_number(nib.next_sequence_number())
        };

        let result = self
            .transmit_unicast(
                &mut frame,
                next_hop,
                NwkSecurityMode::NetworkKey,
                false,
                phy,
            )
            .await;

        if result.is_err() {
            drop(self.enqueue_unicast(
                Frame::nwk(frame, NwkSecurityMode::NetworkKey),
                TxPolicy {
                    priority: TxPriority::UserNormal,
                    class: TrafficClass::Critical,
                },
                Confirm::OnHandoff,
                next_hop,
                None,
            ));
        }
    }

    pub(super) fn invalidate_routes_via(&self, next_hop: Nwk) {
        self.core().nib.routing.invalidate_via(next_hop);
    }

    /// Zigbee spec 3.6.4.8.1: another router could not deliver a frame we originated;
    /// drop the route so the next transmission performs a fresh discovery.
    pub(super) fn handle_network_status(
        &self,
        nwk_frame: &NwkFrame,
        network_status_cmd: NwkNetworkStatusCommand,
    ) {
        tracing::info!(
            "Network status from {:?}: {network_status_cmd:?}",
            nwk_frame.nwk_header.source
        );

        match network_status_cmd.status_code {
            NwkNetworkStatus::LegacyNoRouteAvailable
            | NwkNetworkStatus::LegacyLinkFailure
            | NwkNetworkStatus::LinkFailure
            | NwkNetworkStatus::SourceRouteFailure => {
                // The reported path is broken whatever it was: a source route, or a
                // next hop or direct route record gone stale when the device moved.
                // The next transmission discovers until a fresh route record arrives
                let removed_record = self
                    .core()
                    .nib
                    .routing
                    .forget_route_to(network_status_cmd.network_address);

                if removed_record {
                    tracing::info!(
                        "Removed failed route record to {:?}",
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
                self.handle_address_conflict(
                    network_status_cmd.network_address,
                    AddrConflictSource::Network,
                );
            }
            // A frame we sent to a sleepy child expired in its parent's queue. Nothing
            // to repair: the route is fine, the child did not poll in time.
            NwkNetworkStatus::IndirectTransactionExpiry => {}
            _ => {
                tracing::warn!("Unhandled network status: {network_status_cmd:?}");
            }
        }
    }

    /// Broadcast the route request of a discovery the routing table started or
    /// restarted toward a destination. Under a core lock the caller holds and commits.
    pub(super) fn broadcast_discovery_request(
        &self,
        core: &mut ZigbeeCore,
        destination: Nwk,
        route_request_identifier: u8,
    ) {
        tracing::debug!("Sending route discovery for NWK {destination:?}");

        // If we know the EUI64 corresponding to the NWK, use it
        let destination_eui64 = core.nib.address_map.eui64_for(destination);

        let route_request_frame = self
            .nwk_command_frame(
                BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
                NwkCommand::RouteRequest(NwkRouteRequestCommand {
                    many_to_one: NwkRouteRequestManyToOne::NotManyToOne,
                    route_request_identifier,
                    destination_address: destination,
                    path_cost: 0, // The path cost starts at 0, since we originate it
                    destination_eui64,
                }),
            )
            // Retried broadcasts of a route request share one sequence number,
            // assigned now: `transmit_*` does not touch it
            .with_sequence_number(core.nib.next_sequence_number());

        // Spec 3.6.4.5.1: the initial broadcast is repeated `nwkcInitialRREQRetries`
        // times, separated by the retry interval
        let request = self.broadcast_route_request(
            core,
            route_request_frame,
            self.all_phys(),
            self.tunables.initial_rreq_retries().saturating_add(1),
            Duration::ZERO,
        );
        core.sends.route_request_sent(destination, request);
    }
}
