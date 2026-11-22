use crate::runtime::Runtime;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_ieee_802154::{TooLong, energy_detect_value, write_frame};
use ziggurat_phy::RadioPhy;
use ziggurat_zigbee::aps::frame::{ApsDataFrame, ApsDeliveryMode, Asdu};
use ziggurat_zigbee::nwk::frame::{BROADCAST_ALL_ROUTERS_AND_COORDINATOR, NwkFrame, is_broadcast};

use ziggurat_zigbee::zdp::nwk_update::{self, NwkUpdate};
use ziggurat_zigbee::zdp::{
    DeviceAnnce, MgmtBindReq, MgmtBindRsp, MgmtLqiReq, MgmtLqiRsp, MgmtNwkUpdateReq, MgmtRtgReq,
    MgmtRtgRsp, NeighborDescriptor, ParentAnnce, ParentAnnceRsp, RoutingDescriptor, ZDP_PROFILE_ID,
    ZdpAffinity, ZdpClusterId, ZdpCommand, ZdpDeviceType, ZdpPermitJoining, ZdpRouteStatus,
    ZdpRxOnWhenIdle, ZdpStatus, mgmt_table_page,
};

use super::{
    ApsAck, EnqueueError, MAX_DEPTH, NwkDeviceType, RouteDirective, SendHandle, TxPriority,
    ZigbeeCore, ZigbeeStack, neighbors, routing,
};

/// A ZDP response's cluster is its request's with the high bit set (spec 2.4.4.1).
const ZDP_RESPONSE_BIT: u16 = 0x8000;

/// EUI64s per Parent_annce frame, keeping the ASDU within the NWK payload budget.
const PARENT_ANNCE_CHILDREN_PER_FRAME: usize = 8;

/// Neighbor records per Mgmt_Lqi_rsp; the spec caps the count field at 2
/// (Table 2-101) and clients paginate with the start index.
const MGMT_LQI_DESCRIPTORS_PER_FRAME: usize = 2;

/// Routing records per Mgmt_Rtg_rsp, keeping the ASDU within the NWK payload budget.
const MGMT_RTG_DESCRIPTORS_PER_FRAME: usize = 10;

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    /// Dispatch the ZDP commands the stack itself consumes: the neighbor table they
    /// maintain and the descriptors they read live here. The client still observes the
    /// frames. `aps_security` is the requester's EUI64 if the request was APS-secured.
    pub(super) fn handle_zdp_frame(
        &self,
        nwk_frame: &NwkFrame,
        aps_frame: &ApsDataFrame,
        aps_security: Option<Eui64>,
    ) {
        if aps_frame.profile_id != ZDP_PROFILE_ID || aps_frame.destination_endpoint != Some(0) {
            return;
        }

        let source = nwk_frame.nwk_header.source;
        let broadcast = is_broadcast(nwk_frame.nwk_header.destination);

        match ZdpClusterId::try_from(aps_frame.cluster_id) {
            Ok(ZdpClusterId::DeviceAnnce) => self.handle_device_annce(nwk_frame, aps_frame),
            Ok(ZdpClusterId::ParentAnnce) => self.handle_parent_annce(nwk_frame, aps_frame),
            Ok(ZdpClusterId::ParentAnnceRsp) => self.handle_parent_annce_rsp(nwk_frame, aps_frame),
            Ok(ZdpClusterId::MgmtLqiReq) => self.handle_mgmt_lqi_req(nwk_frame, aps_frame),
            Ok(ZdpClusterId::MgmtRtgReq) => self.handle_mgmt_rtg_req(nwk_frame, aps_frame),
            Ok(ZdpClusterId::NwkAddrReq) => {
                self.answer_zdp_request(aps_frame, source, aps_security, |core, request| {
                    core.descriptors
                        .nwk_addr_rsp(request, &core.nib.neighbors, broadcast)
                });
            }
            Ok(ZdpClusterId::IeeeAddrReq) => {
                self.answer_zdp_request(aps_frame, source, aps_security, |core, request| {
                    core.descriptors
                        .ieee_addr_rsp(request, &core.nib.neighbors, broadcast)
                });
            }
            Ok(ZdpClusterId::NodeDescReq) => {
                self.answer_zdp_request(aps_frame, source, aps_security, |core, request| {
                    let requester = aps_security
                        .or(nwk_frame.nwk_header.source_ieee)
                        .or_else(|| core.nib.address_map.eui64_for(source));
                    core.descriptors.node_desc_rsp(
                        request,
                        &core.nib.neighbors,
                        broadcast,
                        requester,
                    )
                });
            }
            Ok(ZdpClusterId::PowerDescReq) => {
                self.answer_zdp_request(aps_frame, source, aps_security, |core, request| {
                    core.descriptors
                        .power_desc_rsp(request, &core.nib.neighbors, broadcast)
                });
            }
            Ok(ZdpClusterId::SimpleDescReq) => {
                self.answer_zdp_request(aps_frame, source, aps_security, |core, request| {
                    core.descriptors
                        .simple_desc_rsp(request, &core.nib.neighbors, broadcast)
                });
            }
            Ok(ZdpClusterId::ActiveEpReq) => {
                self.answer_zdp_request(aps_frame, source, aps_security, |core, request| {
                    core.descriptors.active_ep_rsp(request, broadcast)
                });
            }
            Ok(ZdpClusterId::MatchDescReq) => {
                self.answer_zdp_request(aps_frame, source, aps_security, |core, request| {
                    core.descriptors
                        .match_desc_rsp(request, &core.nib.neighbors, broadcast)
                });
            }
            // Spec 2.4.4.3.4: a router keeps no binding table, and reports it empty.
            // The coordinator's bindings are the client's business
            Ok(ZdpClusterId::MgmtBindReq) if self.state.role == NwkDeviceType::Router => {
                self.answer_zdp_request(aps_frame, source, aps_security, |_, _: &MgmtBindReq| {
                    (!broadcast).then_some(MgmtBindRsp {
                        status: ZdpStatus::Success,
                        binding_table_entries: 0,
                        start_index: 0,
                        binding_table_list_count: 0,
                    })
                });
            }
            Ok(ZdpClusterId::MgmtBindReq) => {}
            Ok(ZdpClusterId::MgmtNwkUpdateReq) if self.state.role == NwkDeviceType::Router => {
                self.handle_mgmt_nwk_update_req(nwk_frame, aps_frame, aps_security);
            }
            // The coordinator's channel is the client's to manage
            Ok(ZdpClusterId::MgmtNwkUpdateReq) => {}
            // Responses from other devices are the client's business
            Ok(
                ZdpClusterId::NwkAddrRsp
                | ZdpClusterId::IeeeAddrRsp
                | ZdpClusterId::NodeDescRsp
                | ZdpClusterId::PowerDescRsp
                | ZdpClusterId::SimpleDescRsp
                | ZdpClusterId::ActiveEpRsp
                | ZdpClusterId::MatchDescRsp
                | ZdpClusterId::MgmtLqiRsp
                | ZdpClusterId::MgmtRtgRsp
                | ZdpClusterId::MgmtBindRsp
                | ZdpClusterId::MgmtNwkUpdateNotify,
            ) => {}
            Err(_) if aps_frame.cluster_id & ZDP_RESPONSE_BIT == 0 => {
                self.reject_unsupported_zdp_request(nwk_frame, aps_frame, aps_security);
            }
            Err(_) => {}
        }
    }

    /// Spec 2.4.3.3.9.2: change channel, store a new manager, or scan for energy, as
    /// the network manager asks.
    fn handle_mgmt_nwk_update_req(
        &self,
        nwk_frame: &NwkFrame,
        aps_frame: &ApsDataFrame,
        aps_security: Option<Eui64>,
    ) {
        let source = nwk_frame.nwk_header.source;

        let (tsn, request) = match MgmtNwkUpdateReq::deserialize(&aps_frame.asdu) {
            Ok(parsed) => parsed,
            Err(err) => {
                tracing::warn!("Malformed network update request from {source:?}: {err}");
                return;
            }
        };

        let unicast = !is_broadcast(nwk_frame.nwk_header.destination)
            && aps_frame.frame_control.delivery_mode == ApsDeliveryMode::Unicast;

        let Some(update) = NwkUpdate::from_request(&request, unicast) else {
            return;
        };

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        match update {
            NwkUpdate::ChangeChannel { channel, update_id } => {
                self.tasklets.push(async move {
                    arc_self.change_channel_on_request(channel, update_id).await;
                });
            }
            NwkUpdate::UpdateManager {
                channel_mask,
                manager,
            } => {
                let mut core = self.core();
                core.aib.channel_mask = channel_mask;
                core.nib.manager_address = manager;
            }
            NwkUpdate::EnergyScan {
                channels,
                duration,
                count,
            } => {
                self.tasklets.push(async move {
                    arc_self
                        .report_energy_scans(source, tsn, channels, duration, count, aps_security)
                        .await;
                });
            }
            NwkUpdate::Reject(status) => {
                if let Err(err) =
                    self.send_zdp_unicast(source, tsn, &nwk_update::rejection(status), aps_security)
                {
                    tracing::warn!("Failed to refuse a network update from {source:?}: {err}");
                }
            }
        }
    }

    /// Frequency agility annex: switch channel once the request had time to reach
    /// every router, adopt its update id, and restart the transmission counts. The
    /// update id goes first so no beacon on the new channel advertises the old one.
    async fn change_channel_on_request(&self, channel: u8, update_id: u8) {
        R::sleep(self.tunables.broadcast_delivery_time()).await;

        tracing::info!("Changing to channel {channel} as the network manager asked");
        self.set_nwk_update_id(update_id);

        if let Err(err) = self.set_channel(channel).await {
            tracing::warn!("Failed to change to channel {channel}: {err}");
            return;
        }

        let mut core = self.core();
        core.nib.tx_total = 0;
        core.nib.neighbors.reset_transmit_failures();
    }

    /// Spec 2.4.3.3.9.2 step 5: scan the channels `count` times, reporting each pass
    /// to the requester.
    async fn report_energy_scans(
        &self,
        requester: Nwk,
        tsn: u8,
        channels: Vec<u8>,
        duration: Duration,
        count: u8,
        aps_security: Option<Eui64>,
    ) {
        for _ in 0..count {
            let mut energy_values = Vec::with_capacity(channels.len());

            for &channel in &channels {
                match self.energy_detect(channel, duration).await {
                    Ok(rssi) => energy_values.push(energy_detect_value(rssi)),
                    Err(err) => {
                        tracing::warn!("Energy scan of channel {channel} failed: {err}");
                        return;
                    }
                }
            }

            let total_transmissions = self.core().nib.tx_total;
            let report = nwk_update::scan_report(&channels, energy_values, total_transmissions);

            if let Err(err) = self.send_zdp_unicast(requester, tsn, &report, aps_security) {
                tracing::warn!("Failed to report an energy scan to {requester:?}: {err}");
            }
        }
    }

    /// Spec 2.4.4.1: a router answers a unicast request it does not support with only
    /// the response cluster and NOT_SUPPORTED, and drops a broadcast one. On the
    /// coordinator the client may support the request.
    fn reject_unsupported_zdp_request(
        &self,
        nwk_frame: &NwkFrame,
        aps_frame: &ApsDataFrame,
        aps_security: Option<Eui64>,
    ) {
        if self.state.role != NwkDeviceType::Router
            || is_broadcast(nwk_frame.nwk_header.destination)
            || aps_frame.frame_control.delivery_mode != ApsDeliveryMode::Unicast
        {
            return;
        }

        let Some(&tsn) = aps_frame.asdu.first() else {
            return;
        };

        let source = nwk_frame.nwk_header.source;

        if let Err(err) = self.send_aps_unicast(
            source,
            ZDP_PROFILE_ID,
            aps_frame.cluster_id | ZDP_RESPONSE_BIT,
            0,
            0,
            ApsAck::None,
            None,
            0,
            vec![tsn, ZdpStatus::NotSupported as u8],
            aps_security,
            false,
            TxPriority::UserNormal,
            RouteDirective::StackDecides,
        ) {
            tracing::warn!("Failed to reject a ZDP request from {source:?}: {err}");
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

            let (total, page) = mgmt_table_page(
                &entries,
                request.start_index,
                MGMT_LQI_DESCRIPTORS_PER_FRAME,
            );

            let descriptors: Vec<NeighborDescriptor> = page
                .iter()
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
                    // Spec Table 2-102: the neighbor's tree depth. We know only the
                    // coordinator's, the root's, and our children's, one below ours.
                    // Other neighbors are reported as if they were our children. A
                    // coordinator first heard in a link status is stored as a router,
                    // but its address is always 0x0000
                    depth: if entry.device_type == NwkDeviceType::Coordinator
                        || entry.network_address == Nwk(0x0000)
                    {
                        0
                    } else {
                        (self.state.depth + 1).min(MAX_DEPTH)
                    },
                    lqa: entry.lqas.median().unwrap_or(0),
                })
                .collect();

            (total, descriptors)
        };

        let response = MgmtLqiRsp {
            status: ZdpStatus::Success,
            neighbor_table_entries: total,
            start_index: request.start_index,
            neighbor_table_list: descriptors,
        };

        if let Err(err) = self.send_zdp_unicast(source, tsn, &response, None) {
            tracing::warn!("Failed to send a neighbor table response to {source:?}: {err}");
        }
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

            let (total, page) = mgmt_table_page(
                &entries,
                request.start_index,
                MGMT_RTG_DESCRIPTORS_PER_FRAME,
            );

            let descriptors: Vec<RoutingDescriptor> = page
                .iter()
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
                    route_record_required: entry.route_record_required(),
                    next_hop_address: entry.next_hop_address,
                })
                .collect();

            (total, descriptors)
        };

        let response = MgmtRtgRsp {
            status: ZdpStatus::Success,
            routing_table_entries: total,
            start_index: request.start_index,
            routing_table_list: descriptors,
        };

        if let Err(err) = self.send_zdp_unicast(source, tsn, &response, None) {
            tracing::warn!("Failed to send a routing table response to {source:?}: {err}");
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
        *self.parent_annce_received.lock() = Some(self.core_now());

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

        if let Err(err) = self.send_zdp_unicast(source, tsn, &response, None) {
            tracing::warn!("Failed to send a parent announcement response to {source:?}: {err}");
        }
    }

    /// Answer a device and service discovery request. The answer is unicast to the
    /// requester, with the APS security the request arrived with.
    fn answer_zdp_request<Req: ZdpCommand, Rsp: ZdpCommand>(
        &self,
        aps_frame: &ApsDataFrame,
        source: Nwk,
        aps_security: Option<Eui64>,
        answer: impl FnOnce(&ZigbeeCore, &Req) -> Option<Rsp>,
    ) {
        let (tsn, request) = match Req::deserialize(&aps_frame.asdu) {
            Ok(parsed) => parsed,
            Err(err) => {
                tracing::warn!("Malformed {:?} from {source:?}: {err}", Req::CLUSTER_ID);
                return;
            }
        };

        let Some(response) = answer(&self.core(), &request) else {
            return;
        };

        if let Err(err) = self.send_zdp_unicast(source, tsn, &response, aps_security) {
            tracing::warn!("Failed to send {:?} to {source:?}: {err}", Rsp::CLUSTER_ID);
        }
    }

    /// Unicast a ZDP command between endpoints 0. `aps_security` secures it with the
    /// link key shared with that device. Unacknowledged: a lost response is covered by
    /// the requester's own retries.
    fn send_zdp_unicast<T: ZdpCommand>(
        &self,
        destination: Nwk,
        tsn: u8,
        command: &T,
        aps_security: Option<Eui64>,
    ) -> Result<SendHandle, EnqueueError> {
        let asdu: Asdu = write_frame(|writer| command.serialize(tsn, writer))
            .map_err(|TooLong| EnqueueError::PayloadTooLong)?;

        self.send_aps_unicast(
            destination,
            ZDP_PROFILE_ID,
            T::CLUSTER_ID as u16,
            0,
            0,
            ApsAck::None,
            None,
            0,
            asdu.to_vec(),
            aps_security,
            false,
            TxPriority::UserNormal,
            RouteDirective::StackDecides,
        )
        .map(|(handle, _)| handle)
    }

    /// Broadcast a ZDP command between endpoints 0.
    fn send_zdp_broadcast<T: ZdpCommand>(
        &self,
        destination: Nwk,
        tsn: u8,
        command: &T,
    ) -> Result<SendHandle, EnqueueError> {
        let asdu: Asdu = write_frame(|writer| command.serialize(tsn, writer))
            .map_err(|TooLong| EnqueueError::PayloadTooLong)?;

        self.send_aps_broadcast(
            destination,
            ZDP_PROFILE_ID,
            T::CLUSTER_ID as u16,
            0,
            0,
            0,
            asdu.to_vec(),
            TxPriority::UserNormal,
        )
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
    /// the table is empty at startup and nothing is sent. A finite post-boot flow,
    /// run as a tasklet.
    pub(super) async fn run_parent_annce(&self) {
        let mut remaining: Option<Vec<Eui64>> = None;
        let mut send_time = Duration::ZERO;

        loop {
            let jitter = self
                .tunables
                .parent_annce_jitter_max()
                .mul_f32(crate::rng::random_f32::<R>());

            let slept_at = self.core_now();
            R::sleep((self.tunables.parent_annce_base_timer() + jitter).saturating_sub(send_time))
                .await;

            // Spec 2.4.3.1.12.2: an announcement from another router restarts the
            // countdown
            if self
                .parent_annce_received
                .lock()
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
            let started = self.core_now();

            match self.send_zdp_broadcast(BROADCAST_ALL_ROUTERS_AND_COORDINATOR, tsn, &announcement)
            {
                Ok(send) => {
                    let _ = send.handed_off().await;
                }
                Err(err) => {
                    tracing::warn!("Failed to broadcast a parent announcement: {err}");
                }
            }

            send_time = self.core_now().saturating_duration_since(started);

            if remaining.as_ref().is_some_and(Vec::is_empty) {
                return;
            }
        }
    }
}
