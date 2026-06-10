use crate::zigbee_aps::{ApsDataFrame, ApsDeliveryMode};
use crate::zigbee_nwk::{BROADCAST_ALL_ROUTERS_AND_COORDINATOR, NwkFrame};
use ieee_802154::types::{Eui64, Nwk};

use tokio::time::Instant;
use zigbee_parts::zdp::{
    DeviceAnnce, ParentAnnce, ParentAnnceRsp, ZDP_PROFILE_ID, ZdpClusterId, ZdpCommand, ZdpStatus,
};

use super::{MAX_LOCK_DURATION, ZigbeeStack, ZigbeeStackError};

/// EUI64s per Parent_annce frame, keeping the ASDU within the NWK payload budget.
const PARENT_ANNCE_CHILDREN_PER_FRAME: usize = 8;

impl ZigbeeStack {
    /// Dispatch the ZDP commands the stack itself consumes: the neighbor table they
    /// maintain lives here. The client still observes the frames.
    pub(super) fn handle_zdp_frame(&self, nwk_frame: &NwkFrame, aps_frame: &ApsDataFrame) {
        if aps_frame.profile_id != ZDP_PROFILE_ID || aps_frame.destination_endpoint != Some(0) {
            return;
        }

        match ZdpClusterId::try_from(aps_frame.cluster_id) {
            Ok(ZdpClusterId::DeviceAnnce) => self.handle_device_annce(nwk_frame, aps_frame),
            Ok(ZdpClusterId::ParentAnnce) => self.handle_parent_annce(nwk_frame, aps_frame),
            Ok(ZdpClusterId::ParentAnnceRsp) => self.handle_parent_annce_rsp(nwk_frame, aps_frame),
            Err(_) => {}
        }
    }

    /// Spec 2.4.3.1.11.2: a (re)joined device announced its address pair. The address
    /// map is refreshed; any other device mapped to the announced network address is
    /// stale and forgotten. Full address conflict resolution (3.6.1.10.3) is not
    /// implemented yet.
    fn handle_device_annce(&self, nwk_frame: &NwkFrame, aps_frame: &ApsDataFrame) {
        let source = nwk_frame.nwk_header.source;

        let (_tsn, annce) = match DeviceAnnce::deserialize(&aps_frame.asdu) {
            Ok(parsed) => parsed,
            Err(err) => {
                log::warn!("Malformed device announcement from {source:?}: {err}");
                return;
            }
        };

        let mut address_map = self
            .state
            .address_map
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();

        // The announced network address under any other IEEE address no longer has "a
        // known valid 16-bit NWK address"
        address_map.retain(|&eui64, &mut nwk| {
            let stale = nwk == annce.nwk_addr && eui64 != annce.ieee_addr;
            if stale {
                log::info!(
                    "Forgetting stale address mapping {eui64:?} -> {nwk:?}, the address now belongs to {:?}",
                    annce.ieee_addr
                );
            }

            !stale
        });

        // The spec allows announcements with an unknown (all-ones) IEEE address
        if annce.ieee_addr != Eui64([0xFF; 8]) {
            address_map.insert(annce.ieee_addr, annce.nwk_addr);
        }
    }

    /// Spec 2.4.3.1.12: a router announces the end devices it believes are its
    /// children. Announced children we never heard a keepalive from are the other
    /// router's, and our stale entries are dropped; ones that did keep alive with us
    /// are claimed back with a Parent_annce_rsp.
    fn handle_parent_annce(&self, nwk_frame: &NwkFrame, aps_frame: &ApsDataFrame) {
        let source = nwk_frame.nwk_header.source;

        let (tsn, annce) = match ParentAnnce::deserialize(&aps_frame.asdu) {
            Ok(parsed) => parsed,
            Err(err) => {
                log::warn!("Malformed parent announcement from {source:?}: {err}");
                return;
            }
        };

        // Spec 2.4.3.1.12.2: another router's announcement restarts our own pending
        // announcement countdown to avoid a network-wide broadcast storm
        *self
            .parent_annce_received
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap() = Some(Instant::now());

        let (claimed, removed) = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .process_parent_annce(&annce.children);

        for &(eui64, nwk) in &removed {
            self.cleanup_moved_child(eui64, nwk, source);
        }

        if claimed.is_empty() {
            return;
        }

        log::info!(
            "Claiming {} children back from the parent announcement of {source:?}",
            claimed.len()
        );

        let response = ParentAnnceRsp {
            status: ZdpStatus::Success,
            children: claimed,
        };

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            if let Err(err) = arc_self
                .send_zdp_command(source, ApsDeliveryMode::Unicast, tsn, &response)
                .await
            {
                log::warn!("Failed to send a parent announcement response to {source:?}: {err}");
            }
        });
    }

    async fn send_zdp_command<T: ZdpCommand + Sync>(
        &self,
        destination: Nwk,
        delivery_mode: ApsDeliveryMode,
        tsn: u8,
        command: &T,
    ) -> Result<(), ZigbeeStackError> {
        self.send_aps_command(
            delivery_mode,
            destination,
            ZDP_PROFILE_ID,
            T::CLUSTER_ID as u16,
            0,
            0,
            false,
            2 * self.constants.max_depth,
            self.next_aps_counter(),
            command.serialize(tsn).unwrap(),
        )
        .await
    }

    /// Spec 2.4.4.2.22.2: a router answered our parent announcement, claiming
    /// children it has heard keepalives from. Our entries for them are stale.
    fn handle_parent_annce_rsp(&self, nwk_frame: &NwkFrame, aps_frame: &ApsDataFrame) {
        let source = nwk_frame.nwk_header.source;

        let (_tsn, response) = match ParentAnnceRsp::deserialize(&aps_frame.asdu) {
            Ok(parsed) => parsed,
            Err(err) => {
                log::warn!("Malformed parent announcement response from {source:?}: {err}");
                return;
            }
        };

        let removed = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .remove_claimed_children(&response.children);

        for (eui64, nwk) in removed {
            self.cleanup_moved_child(eui64, nwk, source);
        }
    }

    /// Spec 2.4.3.1.12.1: after a reboot, announce our end device children so other
    /// routers drop stale entries for them. Until neighbor table restoration exists
    /// the table is empty at startup and nothing is sent.
    pub(super) async fn parent_annce_task(&self) {
        let mut remaining: Option<Vec<Eui64>> = None;

        loop {
            let jitter = self
                .constants
                .parent_annce_jitter_max
                .mul_f32(rand::random::<f32>());
            let slept_at = Instant::now();
            tokio::time::sleep(self.constants.parent_annce_base_timer + jitter).await;

            // Spec 2.4.3.1.12.2: an announcement from another router restarts the
            // countdown
            if self
                .parent_annce_received
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .is_some_and(|received_at| received_at > slept_at)
            {
                continue;
            }

            {
                let neighbors = self
                    .state
                    .neighbors
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap();

                if let Some(remaining) = &mut remaining {
                    // Children that confirmed themselves with a keepalive since the
                    // previous chunk no longer need announcing
                    remaining.retain(|&eui64| neighbors.is_unconfirmed_end_device_child(eui64));
                } else {
                    // Keepalive state is intentionally not considered for the
                    // initial snapshot (spec 2.4.3.1.12.1 note 3)
                    remaining = Some(neighbors.end_device_children());
                }
            }

            let pending = remaining.as_mut().unwrap();
            let chunk_len = PARENT_ANNCE_CHILDREN_PER_FRAME.min(pending.len());
            let chunk: Vec<Eui64> = pending.drain(..chunk_len).collect();

            if chunk.is_empty() {
                return;
            }

            log::info!(
                "Announcing {} end device children to the network",
                chunk.len()
            );

            let announcement = ParentAnnce { children: chunk };
            let tsn = self.next_aps_counter();

            if let Err(err) = self
                .send_zdp_command(
                    BROADCAST_ALL_ROUTERS_AND_COORDINATOR,
                    ApsDeliveryMode::Broadcast,
                    tsn,
                    &announcement,
                )
                .await
            {
                log::warn!("Failed to broadcast a parent announcement: {err}");
            }

            if remaining.as_ref().is_some_and(Vec::is_empty) {
                return;
            }
        }
    }
}
