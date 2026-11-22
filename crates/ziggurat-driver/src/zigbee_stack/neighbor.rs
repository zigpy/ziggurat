use crate::runtime::Runtime;
use alloc::vec::Vec;
use core::time::Duration;
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::RadioPhy;

use ziggurat_zigbee::nwk::NwkDeviceType;
use ziggurat_zigbee::nwk::commands::{NwkCommand, NwkLinkStatusCommand};
use ziggurat_zigbee::nwk::frame::{BROADCAST_ALL_ROUTERS_AND_COORDINATOR, NwkFrame};
use ziggurat_zigbee::nwk::next_hop;

use super::TrafficClass;

use super::{
    Broadcast, EnqueueError, NwkSecurityMode, SendHandle, TxPolicy, TxPriority, ZigbeeStack,
};

/// Maximum number of link status entries that can be carried in a single frame.
const MAX_LINK_STATUSES: usize = 7;

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    pub(super) fn maybe_recompute_lqa(&self, sender_nwk: Nwk, lqi: u8, _rssi: i8) {
        let link_status_due = self.core().nib.neighbors.record_lqa(sender_nwk, lqi);

        if link_status_due {
            self.request_link_status_for_new_router();
        }
    }

    /// Send the next link status soon: a router it will newly list waits for it to
    /// learn its cost.
    fn request_link_status_for_new_router(&self) {
        // Coordinator only. Routers must not run this as it is: every router that
        // hears a new neighbor would send within the same half second, each with its
        // whole list, and most of those frames would collide.
        if self.state.role == NwkDeviceType::Coordinator {
            self.request_early_link_status();
        }
    }

    /// Send the next link status after the delay of a gratuitous one (spec 3.6.4.4.2).
    fn request_early_link_status(&self) {
        let min_jitter = self.tunables.min_router_bootstrap_jitter();
        let max_jitter = self.tunables.max_router_bootstrap_jitter();
        let jitter = min_jitter
            + max_jitter
                .saturating_sub(min_jitter)
                .mul_f32(crate::rng::random_f32::<R>());

        let at = self.core_now() + jitter;

        if self
            .core()
            .nib
            .link_status_debouncer
            .request(at, Duration::ZERO)
        {
            self.link_status_wake.notify_one();
        }
    }

    pub(super) fn end_device_child_eui64(&self, nwk: Nwk) -> Option<Eui64> {
        self.core().nib.neighbors.end_device_child_eui64(nwk)
    }

    /// Whether a unicast goes straight to its destination, with no route: an end device
    /// child, a router child that has sent no link status yet, or a neighbor with a good
    /// link.
    #[allow(clippy::significant_drop_tightening)]
    pub(super) fn sends_directly_to(&self, destination: Nwk) -> bool {
        let now = self.core_now();
        let core = self.core();
        let neighbors = &core.nib.neighbors;
        let policy = self.next_hop_policy(&core.nib);

        neighbors.end_device_child_eui64(destination).is_some()
            || next_hop::is_direct_neighbor(neighbors, destination, policy.direct_max_link_cost)
            || neighbors.is_recently_attached_router_child(
                destination,
                now,
                policy.new_router_child_window,
            )
    }

    pub(super) fn sleepy_child_eui64(&self, nwk: Nwk) -> Option<Eui64> {
        self.core().nib.neighbors.sleepy_child_eui64(nwk)
    }

    /// Clean up after a child that attached to another parent: leftover state would
    /// keep hijacking its unicasts into our indirect queue. The address map entry and
    /// any negotiated link key are kept, exactly as for a leave.
    pub(super) fn cleanup_moved_child(&self, eui64: Eui64, nwk: Nwk, new_parent: Nwk) {
        tracing::info!("Child {eui64:?} ({nwk:?}) is now parented by {new_parent:?}");

        self.drop_indirect_transactions(Some(eui64), nwk);
        self.core().nib.routing.remove_route(nwk);
    }

    /// Drop our child entry for a device known to have attached to another parent.
    pub(super) fn forget_moved_child(&self, eui64: Eui64, new_parent: Nwk) {
        let removed = self.core().nib.neighbors.take_child(eui64);

        if let Some(nwk) = removed {
            self.cleanup_moved_child(eui64, nwk, new_parent);
        }
    }

    pub(super) fn maybe_age_neighbors(&self) {
        // Spec 3.6.4.4.4: link costs reset once `router_age_limit` link status frames
        // in a row are missed. Wait one extra period, so a frame that arrives a little
        // late is not counted as missed.
        let max_age =
            (u32::from(self.tunables.router_age_limit()) + 1) * self.tunables.link_status_period();

        // TODO: this function should be replaced by real timers
        let stale_neighbors = self.core().nib.neighbors.age(self.core_now(), max_age);

        for neighbor_nwk in stale_neighbors {
            self.invalidate_routes_via(neighbor_nwk);
        }
    }

    pub(super) fn handle_link_status(
        &self,
        nwk_frame: &NwkFrame,
        link_status_cmd: NwkLinkStatusCommand,
        lqi: u8,
    ) {
        tracing::debug!("Link status command frame: {link_status_cmd:?}");

        self.maybe_age_neighbors();

        let Some(source_ieee) = nwk_frame.nwk_header.source_ieee else {
            tracing::warn!("Link status command source EUI64 is missing");
            return;
        };

        let outcome = self.core().nib.neighbors.on_link_status(
            self.state.network_address,
            source_ieee,
            nwk_frame.nwk_header.source,
            lqi,
            &link_status_cmd,
            self.core_now(),
            self.activity_params(),
        );

        // The neighbor no longer answers at its old address, so routes through it
        // there would only fail on their next frame. Another neighbor at that address
        // (the one the router moved away from in a conflict) keeps its routes.
        if let Some(old_nwk) = outcome.replaced_address
            && !self.core().nib.neighbors.has_network_address(old_nwk)
        {
            self.invalidate_routes_via(old_nwk);
        }

        // Spec 3.6.4.4.2: when the outgoing cost collapses to zero the link is
        // considered broken, and routes through this neighbor with it
        if let Some(neighbor_nwk) = outcome.lost_link {
            self.invalidate_routes_via(neighbor_nwk);
        }

        if outcome.link_status_answer_due {
            self.request_early_link_status();
        } else if outcome.link_status_due
            && self.tunables.hack_early_link_status_for_unknown_routers()
        {
            self.request_link_status_for_new_router();
        }

        self.link_status_received.notify_one();
    }

    /// Broadcast the link status notification. The returned handle tracks the last
    /// frame of the batch.
    pub fn send_link_status_broadcast(&self, empty: bool) -> Result<SendHandle, EnqueueError> {
        tracing::debug!("Sending periodic link status broadcast");

        if self.state.network_address == Nwk(0xFFFF) {
            tracing::debug!("Skipping, stack has not been initialized yet");
            return Err(EnqueueError::NotStarted);
        }

        self.maybe_age_neighbors();

        let mut link_statuses = if empty {
            Vec::new()
        } else {
            self.core().nib.neighbors.link_status_entries()
        };

        // Link statuses are sorted in ascending order
        link_statuses.sort_by_key(|a| a.address.as_u16());

        let total = link_statuses.len();
        let mut start = 0;

        loop {
            // Each frame carries up to `MAX_LINK_STATUSES` entries; consecutive frames
            // repeat one boundary entry (the last of frame N is the first of frame N+1)
            // so a receiver can stitch the advertised address range together (spec
            // 3.6.4.4.2). An empty list still emits a single first+last frame.
            let end = core::cmp::min(start + MAX_LINK_STATUSES, total);

            let link_status_frame = self
                .nwk_command_frame(
                    BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
                    NwkCommand::LinkStatus(NwkLinkStatusCommand {
                        is_first_frame: start == 0,
                        is_last_frame: end == total,
                        link_statuses: link_statuses[start..end].to_vec(),
                    }),
                )
                .with_radius(1);

            // The last frame is the tracked one; earlier chunks are fire-and-forget.
            // They drain the single sender in admission order, so the last frame's
            // handoff implies the whole batch was transmitted.
            let is_last = end == total;

            // Spec 3.6.4.4.1: link statuses are one-hop broadcasts sent without
            // retries. Nobody relays a radius-1 frame, so the passive ack machinery
            // of the regular broadcast path could never complete for them anyway.
            let send = Broadcast {
                frame: link_status_frame,
                security: NwkSecurityMode::NetworkKey,
                // Housekeeping the mesh depends on: last to transmit, but never
                // refused by a host flood
                policy: TxPolicy {
                    priority: TxPriority::Background,
                    class: TrafficClass::Critical,
                },
            };

            let sent = self.send_oneshot_broadcast(send);
            if is_last {
                return Ok(sent);
            }

            // Repeat the boundary entry as the first of the next frame
            start = end - 1;
        }
    }

    fn restart_link_status_period(&self) {
        let now = self.core_now();
        let period = self.tunables.link_status_period();

        self.core().nib.link_status_debouncer.fired(now, period);
    }

    pub async fn periodic_link_status_broadcast_task(&self) {
        // The network start has just sent one
        self.restart_link_status_period();

        loop {
            self.wait_for_debouncer(|nib| &nib.link_status_debouncer, &self.link_status_wake)
                .await;

            self.restart_link_status_period();

            // The link status broadcast has a radius of 1 so delivery does not wait for
            // a relay quorum.
            if let Ok(link_status) = self.send_link_status_broadcast(false) {
                let _ = link_status.delivered().await;
            }
        }
    }
}
