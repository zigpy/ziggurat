use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::{RadioPhy, TxPriority};
use ziggurat_zigbee::aps::frame::{ApsDataFrame, ApsDeliveryMode};
use ziggurat_zigbee::nwk::frame::{BROADCAST_ALL_ROUTERS_AND_COORDINATOR, NwkFrame};

use tokio::time::Instant;
use ziggurat_zigbee::zdp::{
    DeviceAnnce, MgmtLqiReq, MgmtLqiRsp, MgmtRtgReq, MgmtRtgRsp, NeighborDescriptor, ParentAnnce,
    ParentAnnceRsp, RoutingDescriptor, ZDP_PROFILE_ID, ZdpAffinity, ZdpClusterId, ZdpCommand,
    ZdpDeviceType, ZdpPermitJoining, ZdpRouteStatus, ZdpRxOnWhenIdle, ZdpStatus,
};

use super::{
    ApsAck, LOCK_ACQUIRE_TIMEOUT, MAX_DEPTH, NwkDeviceType, ZigbeeStack, ZigbeeStackError,
    neighbors, routing,
};

/// EUI64s per Parent_annce frame, keeping the ASDU within the NWK payload budget.
const PARENT_ANNCE_CHILDREN_PER_FRAME: usize = 8;

/// Neighbor records per Mgmt_Lqi_rsp; the spec caps the count field at 2
/// (Table 2-101) and clients paginate with the start index.
const MGMT_LQI_DESCRIPTORS_PER_FRAME: usize = 2;

/// Routing records per Mgmt_Rtg_rsp, keeping the ASDU within the NWK payload budget.
const MGMT_RTG_DESCRIPTORS_PER_FRAME: usize = 10;

impl<P: RadioPhy> ZigbeeStack<P> {
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
            Ok(ZdpClusterId::MgmtLqiReq) => self.handle_mgmt_lqi_req(nwk_frame, aps_frame),
            Ok(ZdpClusterId::MgmtRtgReq) => self.handle_mgmt_rtg_req(nwk_frame, aps_frame),
            // Management responses from other devices are the client's business
            Ok(ZdpClusterId::MgmtLqiRsp | ZdpClusterId::MgmtRtgRsp) | Err(_) => {}
        }
    }

    /// Spec 2.4.4.3.2: answer a neighbor table query, two records at a time. The
    /// tables live in the stack, so the client cannot answer these itself.
    #[allow(clippy::significant_drop_tightening)]
    fn handle_mgmt_lqi_req(&self, nwk_frame: &NwkFrame, aps_frame: &ApsDataFrame) {
        // Management queries are answered only when addressed to us directly
        if nwk_frame.nwk_header.destination != self.state.network_address {
            return;
        }

        let source = nwk_frame.nwk_header.source;

        let (tsn, request) = match MgmtLqiReq::deserialize(&aps_frame.asdu) {
            Ok(parsed) => parsed,
            Err(err) => {
                tracing::warn!("Malformed neighbor table request from {source:?}: {err}");
                return;
            }
        };

        let (total, descriptors) = {
            let core = self.core();

            let mut entries: Vec<&neighbors::TableEntry> = core.nib.neighbors.entries().collect();
            entries.sort_by_key(|entry| entry.network_address.as_u16());

            let descriptors: Vec<NeighborDescriptor> = entries
                .iter()
                .skip(usize::from(request.start_index))
                .take(MGMT_LQI_DESCRIPTORS_PER_FRAME)
                .map(|entry| NeighborDescriptor {
                    extended_pan_id: self.state.extended_pan_id,
                    extended_address: entry.extended_address,
                    network_address: entry.network_address,
                    device_type: match entry.device_type {
                        NwkDeviceType::Coordinator => ZdpDeviceType::Coordinator,
                        NwkDeviceType::Router => ZdpDeviceType::Router,
                        NwkDeviceType::EndDevice => ZdpDeviceType::EndDevice,
                    },
                    rx_on_when_idle: if entry.rx_on_when_idle {
                        ZdpRxOnWhenIdle::On
                    } else {
                        ZdpRxOnWhenIdle::Off
                    },
                    // Spec 2.4.4.3.2.1: relationships past Sibling are reported as
                    // NoneOfTheAbove
                    affinity: match entry.relationship {
                        neighbors::Relationship::Parent => ZdpAffinity::Parent,
                        neighbors::Relationship::Child => ZdpAffinity::Child,
                        neighbors::Relationship::Sibling => ZdpAffinity::Sibling,
                        _ => ZdpAffinity::NoneOfTheAbove,
                    },
                    permit_joining: ZdpPermitJoining::Unknown,
                    // We are the coordinator (tree depth 0), so every neighbor of
                    // ours sits at depth 1
                    depth: 1,
                    lqa: entry.lqa().unwrap_or(0),
                })
                .collect();

            (entries.len(), descriptors)
        };

        let response = MgmtLqiRsp {
            status: ZdpStatus::Success,
            neighbor_table_entries: total as u8,
            start_index: request.start_index,
            neighbor_table_list: descriptors,
        };

        self.spawn_tracked_self(|arc_self| async move {
            if let Err(err) = arc_self
                .send_zdp_command(source, ApsDeliveryMode::Unicast, tsn, &response)
                .await
            {
                tracing::warn!("Failed to send a neighbor table response to {source:?}: {err}");
            }
        });
    }

    /// Spec 2.4.4.3.3: answer a routing table query.
    #[allow(clippy::significant_drop_tightening)]
    fn handle_mgmt_rtg_req(&self, nwk_frame: &NwkFrame, aps_frame: &ApsDataFrame) {
        if nwk_frame.nwk_header.destination != self.state.network_address {
            return;
        }

        let source = nwk_frame.nwk_header.source;

        let (tsn, request) = match MgmtRtgReq::deserialize(&aps_frame.asdu) {
            Ok(parsed) => parsed,
            Err(err) => {
                tracing::warn!("Malformed routing table request from {source:?}: {err}");
                return;
            }
        };

        let (total, descriptors) = {
            let core = self.core();

            let mut entries: Vec<&routing::TableEntry> = core.nib.routing.entries().collect();
            entries.sort_by_key(|entry| entry.destination.as_u16());

            let descriptors: Vec<RoutingDescriptor> = entries
                .iter()
                .skip(usize::from(request.start_index))
                .take(MGMT_RTG_DESCRIPTORS_PER_FRAME)
                .map(|entry| RoutingDescriptor {
                    destination_address: entry.destination,
                    status: match entry.status {
                        routing::Status::Active => ZdpRouteStatus::Active,
                        routing::Status::DiscoveryUnderway => ZdpRouteStatus::DiscoveryUnderway,
                        routing::Status::DiscoveryFailed => ZdpRouteStatus::DiscoveryFailed,
                        routing::Status::Inactive => ZdpRouteStatus::Inactive,
                    },
                    memory_constrained: false,
                    many_to_one: entry.many_to_one,
                    route_record_required: entry.route_record_required,
                    next_hop_address: entry.next_hop_address,
                })
                .collect();

            (entries.len(), descriptors)
        };

        let response = MgmtRtgRsp {
            status: ZdpStatus::Success,
            routing_table_entries: total as u8,
            start_index: request.start_index,
            routing_table_list: descriptors,
        };

        self.spawn_tracked_self(|arc_self| async move {
            if let Err(err) = arc_self
                .send_zdp_command(source, ApsDeliveryMode::Unicast, tsn, &response)
                .await
            {
                tracing::warn!("Failed to send a routing table response to {source:?}: {err}");
            }
        });
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
                tracing::warn!("Malformed device announcement from {source:?}: {err}");
                return;
            }
        };

        // The spec allows announcements with an unknown (all-ones) IEEE address,
        // which evict stale owners of the announced address without claiming it
        if annce.ieee_addr == Eui64([0xFF; 8]) {
            self.core().nib.address_map.forget_address(annce.nwk_addr);
            return;
        }

        self.core()
            .nib
            .address_map
            .claim(annce.ieee_addr, annce.nwk_addr);

        // A child of ours confirming an address change (e.g. after conflict
        // resolution) must keep its neighbor entry in sync, or its new address
        // would bypass the indirect queue
        self.core()
            .nib
            .neighbors
            .update_network_address(annce.ieee_addr, annce.nwk_addr);
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
                tracing::warn!("Malformed parent announcement from {source:?}: {err}");
                return;
            }
        };

        // Spec 2.4.3.1.12.2: another router's announcement restarts our own pending
        // announcement countdown to avoid a network-wide broadcast storm
        *self
            .parent_annce_received
            .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
            .unwrap() = Some(Instant::now());

        let (claimed, removed) = self
            .core()
            .nib
            .neighbors
            .process_parent_annce(&annce.children);

        for &(eui64, nwk) in &removed {
            self.cleanup_moved_child(eui64, nwk, source);
        }

        if claimed.is_empty() {
            return;
        }

        tracing::info!(
            "Claiming {} children back from the parent announcement of {source:?}",
            claimed.len()
        );

        let response = ParentAnnceRsp {
            status: ZdpStatus::Success,
            children: claimed,
        };

        self.spawn_tracked_self(|arc_self| async move {
            if let Err(err) = arc_self
                .send_zdp_command(source, ApsDeliveryMode::Unicast, tsn, &response)
                .await
            {
                tracing::warn!(
                    "Failed to send a parent announcement response to {source:?}: {err}"
                );
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
            ApsAck::None,
            2 * MAX_DEPTH,
            self.next_aps_counter(),
            command.serialize(tsn).unwrap(),
            None,
            TxPriority::USER_NORMAL,
        )
        .await
        .map(|_| ())
    }

    /// Spec 2.4.4.2.22.2: a router answered our parent announcement, claiming
    /// children it has heard keepalives from. Our entries for them are stale.
    fn handle_parent_annce_rsp(&self, nwk_frame: &NwkFrame, aps_frame: &ApsDataFrame) {
        let source = nwk_frame.nwk_header.source;

        let (_tsn, response) = match ParentAnnceRsp::deserialize(&aps_frame.asdu) {
            Ok(parsed) => parsed,
            Err(err) => {
                tracing::warn!("Malformed parent announcement response from {source:?}: {err}");
                return;
            }
        };

        let removed = self
            .core()
            .nib
            .neighbors
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
                .tunables
                .parent_annce_jitter_max
                .mul_f32(rand::random::<f32>());
            let slept_at = Instant::now();
            tokio::time::sleep(self.tunables.parent_annce_base_timer + jitter).await;

            // Spec 2.4.3.1.12.2: an announcement from another router restarts the
            // countdown
            if self
                .parent_annce_received
                .try_lock_for(LOCK_ACQUIRE_TIMEOUT)
                .unwrap()
                .is_some_and(|received_at| received_at > slept_at)
            {
                continue;
            }

            {
                let core = self.core();

                if let Some(remaining) = &mut remaining {
                    // Children that confirmed themselves with a keepalive since the
                    // previous chunk no longer need announcing
                    remaining
                        .retain(|&eui64| core.nib.neighbors.is_unconfirmed_end_device_child(eui64));
                } else {
                    // Keepalive state is intentionally not considered for the
                    // initial snapshot (spec 2.4.3.1.12.1 note 3)
                    remaining = Some(core.nib.neighbors.end_device_children());
                }
            }

            let pending = remaining.as_mut().unwrap();
            let chunk_len = PARENT_ANNCE_CHILDREN_PER_FRAME.min(pending.len());
            let chunk: Vec<Eui64> = pending.drain(..chunk_len).collect();

            if chunk.is_empty() {
                return;
            }

            tracing::info!(
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
                tracing::warn!("Failed to broadcast a parent announcement: {err}");
            }

            if remaining.as_ref().is_some_and(Vec::is_empty) {
                return;
            }
        }
    }
}
