//! The runtime-agnostic bridge between the wire payloads and a live `ZigbeeStack`.
//!
//! Reads (network info, table scans), writes (load appliers), and the mappings for
//! `configure`, `send_aps`, beacons, and notifications. Shared verbatim by the
//! embedded firmware and the host server so the two cannot drift.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_driver::runtime::Runtime;
use ziggurat_driver::zigbee_stack::aps_security::TclkFlavor;
use ziggurat_driver::zigbee_stack::{
    ApsAck, DeliveryError, DeviceLeaveReason, EnqueueError, HostRoute, NetworkBeacon,
    NetworkConfig, NwkDeviceType, RequestId as StackRequestId, RouteDirective, TclkSeed,
    TxPriority, ZigbeeNotification, ZigbeeStack,
};
use ziggurat_ieee_802154::types::{Eui64, Key, Nwk};
use ziggurat_phy::RadioPhy;
use ziggurat_zigbee::nwk::frame::NwkSecurityHeaderKeyId;
use ziggurat_zigbee::nwk::neighbors::{ChildDescriptor, Relationship};
use ziggurat_zigbee::nwk::routing;

use crate::wire::*;

/// Child entries restored from a backup re-negotiate their real timeout at the
/// first keepalive; until then they age out after a conservative day.
const RESTORED_CHILD_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// Map a `configure` payload to the driver's `NetworkConfig`. The caller restores
/// the APS frame counter from `payload.state.aps_frame_counter` after construction.
pub fn network_config(payload: &ConfigurePayload) -> NetworkConfig {
    let state = &payload.state;
    NetworkConfig {
        role: match payload.role {
            NodeRole::Router => NwkDeviceType::Router,
            NodeRole::Coordinator => NwkDeviceType::Coordinator,
        },
        channel: state.channel,
        update_id: state.nwk_update_id,
        pan_id: state.pan_id,
        extended_pan_id: state.extended_pan_id,
        network_address: state.nwk_address,
        ieee_address: state.ieee_address,
        network_key: state.network_key.clone(),
        network_key_seq_number: state.network_key_seq,
        network_key_tx_counter: state.network_key_tx_counter,
        tc_link_key: state.tc_link_key.clone(),
        tclk_seed: state.has_tclk_seed.then(|| TclkSeed {
            seed: state.tclk_seed.clone(),
            flavor: match state.tclk_flavor {
                TclkFlavorId::Ezsp => TclkFlavor::Ezsp,
                TclkFlavorId::ZStack => TclkFlavor::ZStack,
            },
        }),
        tx_power: state.tx_power as i8,
        source_routing: payload.source_routing,
    }
}

pub fn network_info_payload<P: RadioPhy, R: Runtime>(
    stack: &ZigbeeStack<P, R>,
    started: bool,
) -> NetworkInfoPayload {
    let stack_state = &stack.state;
    let core = stack_state.core.lock();
    let nwk_security = &core.nib.nwk_security;
    let aps_security = &core.aib.aps_security;

    let (has_tclk_seed, tclk_seed, tclk_flavor) = stack.config.tclk_seed.as_ref().map_or(
        (false, Key([0; 16]), TclkFlavorId::ZStack),
        |tclk| {
            (
                true,
                tclk.seed.clone(),
                match tclk.flavor {
                    TclkFlavor::ZStack => TclkFlavorId::ZStack,
                    TclkFlavor::Ezsp => TclkFlavorId::Ezsp,
                },
            )
        },
    );

    NetworkInfoPayload {
        state: NetworkState {
            channel: core.mac.channel,
            nwk_update_id: core.nib.update_id,
            pan_id: core.mac.pan_id,
            extended_pan_id: stack_state.extended_pan_id,
            nwk_address: stack_state.network_address,
            ieee_address: stack_state.ieee_address,
            network_key: nwk_security.network_key(),
            network_key_seq: nwk_security.key_seq_number(),
            network_key_tx_counter: nwk_security.outgoing_frame_counter(),
            tc_link_key: stack.config.tc_link_key.clone(),
            has_tclk_seed,
            tclk_seed,
            tclk_flavor,
            tx_power: stack.config.tx_power as u8,
            aps_frame_counter: aps_security.outgoing_frame_counter(),
        },
        key_count: aps_security.device_key_count() as u16,
        started,
    }
}

#[allow(clippy::significant_drop_tightening)] // the snapshot is built under the lock
pub fn key_entries<P: RadioPhy, R: Runtime>(stack: &ZigbeeStack<P, R>) -> Vec<KeyEntry> {
    let core = stack.state.core.lock();
    let aps = &core.aib.aps_security;
    let outgoing = aps.outgoing_frame_counter();
    aps.device_keys()
        .map(|(partner, entry)| KeyEntry {
            key: entry.key.clone(),
            tx_counter: outgoing,
            rx_counter: aps.incoming_frame_counter(partner).unwrap_or(0),
            seq: 0,
            partner_ieee: partner,
        })
        .collect()
}

pub fn child_entries<P: RadioPhy, R: Runtime>(stack: &ZigbeeStack<P, R>) -> Vec<ChildEntry> {
    let core = stack.state.core.lock();
    core.nib
        .neighbors
        .entries()
        .filter(|entry| entry.is_child())
        .map(|entry| ChildEntry {
            ieee: entry.extended_address,
            nwk: entry.network_address,
            flags: ChildFlags {
                rx_on_when_idle: entry.rx_on_when_idle,
                device_type: match entry.device_type {
                    NwkDeviceType::Router => ChildDeviceType::Router,
                    _ => ChildDeviceType::EndDevice,
                },
            },
        })
        .collect()
}

pub fn address_entries<P: RadioPhy, R: Runtime>(stack: &ZigbeeStack<P, R>) -> Vec<AddressEntry> {
    let core = stack.state.core.lock();
    core.nib
        .address_map
        .entries()
        .map(|(ieee, nwk)| AddressEntry { ieee, nwk })
        .collect()
}

pub fn route_entries<P: RadioPhy, R: Runtime>(stack: &ZigbeeStack<P, R>) -> Vec<RouteEntry> {
    let core = stack.state.core.lock();
    core.nib
        .routing
        .entries()
        .filter(|entry| matches!(entry.status, routing::Status::Active))
        .map(|entry| RouteEntry {
            destination: entry.destination,
            next_hop: entry.next_hop_address,
            path_cost: entry.path_cost,
        })
        .collect()
}

pub fn apply_key_table<P: RadioPhy, R: Runtime>(
    stack: &ZigbeeStack<P, R>,
    payload: LoadKeyTablePayload,
) {
    let mut core = stack.state.core.lock();
    for entry in payload.entries {
        core.aib
            .aps_security
            .restore_device_key(entry.partner_ieee, entry.key);
        if entry.rx_counter != 0 {
            core.aib
                .aps_security
                .restore_incoming_frame_counter(entry.partner_ieee, entry.rx_counter);
        }
    }
}

pub fn apply_children<P: RadioPhy, R: Runtime>(
    stack: &ZigbeeStack<P, R>,
    payload: LoadChildrenPayload,
) {
    let now = stack.core_now();
    let mut core = stack.state.core.lock();
    for entry in payload.entries {
        let device_type = match entry.flags.device_type {
            ChildDeviceType::Router => NwkDeviceType::Router,
            // Unknown restores as an end device (the safe frame-pending default).
            ChildDeviceType::Unknown | ChildDeviceType::EndDevice => NwkDeviceType::EndDevice,
        };
        core.nib.neighbors.upsert_child(
            ChildDescriptor {
                eui64: entry.ieee,
                network_address: entry.nwk,
                device_type,
                rx_on_when_idle: entry.flags.rx_on_when_idle,
                device_timeout: RESTORED_CHILD_TIMEOUT,
                relationship: Relationship::Child,
            },
            now,
        );
        core.nib.address_map.update_mapping(entry.ieee, entry.nwk);
    }
}

pub fn apply_address_cache<P: RadioPhy, R: Runtime>(
    stack: &ZigbeeStack<P, R>,
    payload: LoadAddressCachePayload,
) {
    let mut core = stack.state.core.lock();
    for entry in payload.entries {
        core.nib.address_map.update_mapping(entry.ieee, entry.nwk);
    }
}

pub fn apply_route_table<P: RadioPhy, R: Runtime>(
    stack: &ZigbeeStack<P, R>,
    payload: LoadRouteTablePayload,
) {
    let mut core = stack.state.core.lock();
    for entry in payload.entries {
        core.nib
            .routing
            .restore_route(entry.destination, entry.next_hop, entry.path_cost);
    }
}

pub fn apply_source_routes<P: RadioPhy, R: Runtime>(
    stack: &ZigbeeStack<P, R>,
    payload: LoadSourceRoutesPayload,
) {
    let mut core = stack.state.core.lock();
    for entry in payload.entries {
        core.nib
            .routing
            .store_route_record(entry.destination, entry.relays);
    }
}

impl From<&NetworkBeacon> for BeaconPayload {
    fn from(beacon: &NetworkBeacon) -> Self {
        Self {
            channel: beacon.channel,
            source: beacon.source.unwrap_or(Nwk(0xFFFF)),
            pan_id: beacon.pan_id,
            extended_pan_id: beacon.extended_pan_id,
            permit_joining: beacon.permit_joining,
            router_capacity: beacon.router_capacity,
            end_device_capacity: beacon.end_device_capacity,
            stack_profile: beacon.stack_profile,
            protocol_version: beacon.protocol_version,
            device_depth: beacon.device_depth,
            update_id: beacon.update_id,
            lqi: beacon.lqi,
            rssi: beacon.rssi as u8,
        }
    }
}

/// Hand `send_aps` to the stack, translating the wire flags. The delivery outcome
/// arrives later as a `SendConfirm` / `ApsAckConfirm` notification keyed by
/// `request_id`.
pub fn send_aps<P: RadioPhy, R: Runtime>(
    stack: &ZigbeeStack<P, R>,
    payload: SendApsPayload,
    request_id: RequestId,
) -> Result<(), Error> {
    let aps_security = (payload.flags.aps_encryption && payload.flags.has_eui64)
        .then_some(payload.destination_eui64);

    let aps_ack = if payload.flags.aps_ack {
        ApsAck::Request
    } else {
        ApsAck::None
    };

    let route = route_directive(payload.route, payload.next_hop, payload.relays)?;

    stack
        .send_aps(
            payload.flags.delivery_mode,
            payload.destination,
            payload.profile_id,
            payload.cluster_id,
            payload.src_ep,
            payload.dst_ep,
            aps_ack,
            payload.radius,
            payload.aps_seq,
            payload.asdu,
            aps_security,
            payload.flags.sleepy_destination,
            TxPriority::from_host(payload.priority as i8),
            route,
            StackRequestId::from(request_id),
        )
        .map_err(|e| enqueue_error(&e))
}

/// Map a synchronous admission failure onto its wire `Error` frame.
fn enqueue_error(e: &EnqueueError) -> Error {
    match e {
        EnqueueError::RateLimited { retry_in } => Error::rate_limited(*retry_in),
        EnqueueError::BudgetExhausted => Error::new(Status::BudgetExhausted, &e.to_string()),
        EnqueueError::NotStarted => Error::new(Status::InvalidState, &e.to_string()),
        EnqueueError::PayloadTooLong
        | EnqueueError::SecurityUnavailable
        | EnqueueError::RouteDiscoverySuppressed => {
            Error::new(Status::InvalidRequest, &e.to_string())
        }
    }
}

/// Build the driver's [`RouteDirective`] from the wire route control.
fn route_directive(
    control: RouteControl,
    next_hop: Option<Nwk>,
    relays: Option<SourceRouteRelays>,
) -> Result<RouteDirective, Error> {
    let host_source_route = |relays: SourceRouteRelays| -> Result<HostRoute, Error> {
        if relays.relays.is_empty() {
            Err(Error::new(
                Status::InvalidRequest,
                "a source route must contain at least one relay",
            ))
        } else {
            Ok(HostRoute::SourceRoute(relays.relays))
        }
    };

    Ok(match control {
        RouteControl::StackDecides => RouteDirective::StackDecides,
        RouteControl::HintNextHop => RouteDirective::Hint(HostRoute::NextHop(next_hop.unwrap())),
        RouteControl::ForceNextHop => RouteDirective::Force(HostRoute::NextHop(next_hop.unwrap())),
        RouteControl::HintSourceRoute => RouteDirective::Hint(host_source_route(relays.unwrap())?),
        RouteControl::ForceSourceRoute => {
            RouteDirective::Force(host_source_route(relays.unwrap())?)
        }
    })
}

/// Cancel an in-flight send by the `request_id` it was issued under. Best-effort: the
/// reply reports whether a still-cancellable (pre-delivery) send was found and removed.
pub fn cancel_request<P: RadioPhy, R: Runtime>(
    stack: &ZigbeeStack<P, R>,
    payload: &CancelRequestPayload,
) -> CancelResultPayload {
    let cancelled = stack.cancel_send(StackRequestId::from(payload.request_id));
    CancelResultPayload { cancelled }
}

/// Apply a `set_tunable` to the stack: the name is matched against the Rust field
/// names of `Tunables`, the raw value decoded per the field's type.
pub fn set_tunable<P: RadioPhy, R: Runtime>(
    stack: &ZigbeeStack<P, R>,
    payload: &SetTunablePayload,
) -> Result<(), Error> {
    let name = core::str::from_utf8(&payload.name)
        .map_err(|_| Error::new(Status::InvalidRequest, "tunable name is not UTF-8"))?;

    stack
        .set_tunable(name, payload.value)
        .map_err(|e| Error::new(Status::InvalidRequest, &alloc::format!("{name}: {e}")))
}

/// Mirror a send's terminal result onto its wire status. Exhaustive on purpose: a new
/// `DeliveryError` variant must pick its `SendStatus` here to compile.
const fn send_status(result: &Result<(), DeliveryError>) -> SendStatus {
    match result {
        Ok(()) => SendStatus::Success,
        Err(err) => match err {
            DeliveryError::RouteDiscoveryTimeout(_) => SendStatus::RouteDiscoveryTimeout,
            DeliveryError::RouteDiscoveryNoEntry => SendStatus::RouteDiscoveryNoEntry,
            DeliveryError::RouteInactiveAfterDiscovery => SendStatus::RouteInactiveAfterDiscovery,
            DeliveryError::NwkNoAck { .. } => SendStatus::NwkNoAck,
            DeliveryError::CcaFailure => SendStatus::CcaFailure,
            DeliveryError::TransmitFailed(_) => SendStatus::TransmitFailed,
            DeliveryError::ApsAckTimeout => SendStatus::ApsAckTimeout,
            DeliveryError::QuorumNotReached => SendStatus::BroadcastQuorumNotReached,
            DeliveryError::IndirectExpired { .. } => SendStatus::IndirectExpired,
            DeliveryError::BudgetExhausted => SendStatus::FrameBudgetExhausted,
            DeliveryError::Cancelled => SendStatus::Cancelled,
            DeliveryError::Radio(_) => SendStatus::RadioError,
        },
    }
}

/// Encode one unsolicited notification. `send_confirm`/`aps_ack_confirm` carry
/// their originating request id in the envelope.
pub fn notification_frame(update: &ZigbeeNotification) -> Option<Vec<u8>> {
    let notification = match update {
        ZigbeeNotification::ReceivedApsCommand {
            source,
            destination,
            group,
            profile_id,
            cluster_id,
            src_ep,
            dst_ep,
            lqi,
            rssi,
            data,
        } => Notification::ReceivedAps(ReceivedApsPayload {
            source: *source,
            destination: *destination,
            has_group: group.is_some(),
            group: group.unwrap_or(0),
            profile_id: *profile_id,
            cluster_id: *cluster_id,
            src_ep: *src_ep,
            dst_ep: *dst_ep,
            lqi: *lqi,
            rssi: *rssi as u8,
            data: data.clone(),
        }),
        ZigbeeNotification::SendConfirm { request_id, result } => Notification::SendConfirm(
            *request_id as u16,
            SendConfirmPayload {
                status: send_status(result),
            },
        ),
        ZigbeeNotification::ApsAckConfirm { request_id, result } => Notification::ApsAckConfirm(
            *request_id as u16,
            ApsAckConfirmPayload {
                status: send_status(result),
            },
        ),
        ZigbeeNotification::DeviceJoined {
            nwk,
            ieee,
            parent,
            device_type,
            rx_on_when_idle,
        } => {
            let device_type = match device_type {
                Some(NwkDeviceType::Router) => ChildDeviceType::Router,
                Some(NwkDeviceType::EndDevice) => ChildDeviceType::EndDevice,
                // `None` (learned via a router's Update-Device) or the nonsensical
                // Coordinator both map to Unknown
                _ => ChildDeviceType::Unknown,
            };
            Notification::DeviceJoined(DeviceJoinedPayload {
                nwk: *nwk,
                ieee: *ieee,
                parent: *parent,
                flags: ChildFlags {
                    rx_on_when_idle: *rx_on_when_idle,
                    device_type,
                },
            })
        }
        ZigbeeNotification::DeviceLeft { nwk, ieee, reason } => {
            let (reason_code, rejoin, router, router_ieee) = match reason {
                DeviceLeaveReason::Announced { rejoin } => {
                    (LeaveReason::Announced, *rejoin, None, None)
                }
                DeviceLeaveReason::RouterReported {
                    router,
                    router_ieee,
                } => (
                    LeaveReason::RouterReported,
                    false,
                    Some(*router),
                    *router_ieee,
                ),
                DeviceLeaveReason::KeepaliveTimeout => {
                    (LeaveReason::KeepaliveTimeout, false, None, None)
                }
            };
            Notification::DeviceLeft(DeviceLeftPayload {
                nwk: *nwk,
                has_ieee: ieee.is_some(),
                rejoin,
                has_router_ieee: router_ieee.is_some(),
                ieee: ieee.unwrap_or(Eui64([0; 8])),
                reason: reason_code,
                router: router.unwrap_or(Nwk(0xFFFF)),
                router_ieee: router_ieee.unwrap_or(Eui64([0; 8])),
            })
        }
        ZigbeeNotification::FrameCounterUpdate { frame_counter } => {
            Notification::FrameCounter(FrameCounterPayload {
                frame_counter: *frame_counter,
            })
        }
        ZigbeeNotification::LinkKeyUpdate { ieee, key } => Notification::LinkKey(LinkKeyPayload {
            ieee: *ieee,
            key: key.clone(),
        }),
        ZigbeeNotification::RouteRecord {
            destination,
            relays,
        } => Notification::RouteRecord(RouteRecordPayload {
            destination: *destination,
            relays: relays.clone(),
        }),
        ZigbeeNotification::ApsFrameCounterUpdate { frame_counter } => {
            Notification::ApsFrameCounter(ApsFrameCounterPayload {
                frame_counter: *frame_counter,
            })
        }
        ZigbeeNotification::ApsDecryptionFailure {
            source,
            source_ieee,
            frame_counter,
            key_id,
        } => {
            let key_id = match key_id {
                NwkSecurityHeaderKeyId::DataKey => KeyId::Data,
                NwkSecurityHeaderKeyId::NetworkKey => KeyId::Network,
                NwkSecurityHeaderKeyId::KeyTransportKey => KeyId::KeyTransport,
                NwkSecurityHeaderKeyId::KeyLoadKey => KeyId::KeyLoad,
            };
            Notification::ApsDecryptFailure(ApsDecryptFailPayload {
                source: *source,
                source_ieee: *source_ieee,
                frame_counter: *frame_counter,
                key_id,
            })
        }
    };
    notification.frame()
}
