use crate::runtime::Runtime;
use alloc::vec::Vec;
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::RadioPhy;

use ziggurat_zigbee::nwk::commands::{NwkCommand, NwkLinkStatusCommand};
use ziggurat_zigbee::nwk::frame::{BROADCAST_ALL_ROUTERS_AND_COORDINATOR, NwkFrame};

use super::{NwkSecurityMode, TxPriority, ZigbeeStack};

/// Maximum number of link status entries that can be carried in a single frame.
const MAX_LINK_STATUSES: usize = 7;

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    pub(super) fn maybe_recompute_lqa(&self, sender_nwk: Nwk, lqi: u8, _rssi: i8) {
        self.core().nib.neighbors.record_lqa(sender_nwk, lqi);
    }

    pub(super) fn end_device_child_eui64(&self, nwk: Nwk) -> Option<Eui64> {
        self.core().nib.neighbors.end_device_child_eui64(nwk)
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
        // TODO: this function should be replaced by real timers
        let stale_neighbors = self.core().nib.neighbors.age(self.core_now());

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

        let lost_link = self.core().nib.neighbors.on_link_status(
            source_ieee,
            nwk_frame.nwk_header.source,
            lqi,
            &link_status_cmd,
            self.core_now(),
        );

        // Spec 3.6.4.4.2: when the outgoing cost collapses to zero the link is
        // considered broken, and routes through this neighbor with it
        if let Some(neighbor_nwk) = lost_link {
            self.invalidate_routes_via(neighbor_nwk);
        }

        self.link_status_received.notify_one();
    }

    pub async fn send_link_status_broadcast(&self, empty: bool) {
        tracing::debug!("Sending periodic link status broadcast");

        if self.state.network_address == Nwk(0xFFFF) {
            tracing::debug!("Skipping, stack has not been initialized yet");
            return;
        }

        // Decrement the `recent_activity` field of every active routing table entry
        self.core().nib.routing.decay_activity();

        self.maybe_age_neighbors();

        // Decrement the inbound and outbound activity fields for neighbors
        let mut link_statuses = {
            let mut core = self.core();
            core.nib.neighbors.decay_activity();

            if empty {
                Vec::new()
            } else {
                core.nib.neighbors.link_status_entries()
            }
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
                .with_radius(1)
                // Sent via `transmit_*`, which does not assign sequence numbers
                .with_sequence_number(self.next_nwk_sequence_number());

            // Spec 3.6.4.4.1: link statuses are one-hop broadcasts sent without
            // retries. Nobody relays a radius-1 frame, so the passive ack machinery
            // of the regular broadcast path could never complete for them anyway.
            if let Err(err) = self
                .transmit_broadcast_nwk_frame(
                    link_status_frame,
                    NwkSecurityMode::NetworkKey,
                    TxPriority::BACKGROUND,
                )
                .await
            {
                tracing::warn!("Failed to broadcast link status: {err}");
            }

            if end == total {
                break;
            }

            // Repeat the boundary entry as the first of the next frame
            start = end - 1;
        }
    }

    pub async fn periodic_link_status_broadcast_task(&self) {
        loop {
            R::sleep(self.tunables.link_status_period).await;

            self.send_link_status_broadcast(false).await;
        }
    }
}
