//! The line-delimited JSON-RPC surface, mirroring the host server's wire protocol. One
//! request per line; each is answered with an `accepted` event then a `response`.
//! Unsolicited `notification` lines carry network events.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use ziggurat_driver::zigbee_stack::aps_security::TclkFlavor;
use ziggurat_driver::zigbee_stack::{
    ApsAck, NetworkBeacon, NetworkConfig, NwkDeviceType, TclkSeed, Tunables, TxPriority,
    WELL_KNOWN_LINK_KEY, ZigbeeNotification, ZigbeeStack,
};
use ziggurat_driver::ziggurat_ieee_802154::types::{Eui64, Key, Nwk, PanId};
use ziggurat_zigbee::aps::frame::ApsDeliveryMode;

use crate::{App, OUTBOUND};

const PROTOCOL_VERSION: u32 = 1;
const DEFAULT_TX_POWER: i8 = 8;

/// Queue one JSON object for the serial writer task.
pub async fn emit(value: Value) {
    if let Ok(line) = serde_json::to_string(&value) {
        OUTBOUND.send(line).await;
    }
}

pub fn hello_message(configured: bool) -> Value {
    let state = if configured {
        "running"
    } else {
        "awaiting_configuration"
    };
    json!({"type": "hello", "version": PROTOCOL_VERSION, "state": state})
}

fn event(id: u64, name: &str) -> Value {
    json!({"type": "event", "id": id, "event": name})
}

fn event_data(id: u64, name: &str, data: Value) -> Value {
    json!({"type": "event", "id": id, "event": name, "data": data})
}

fn response(id: u64, result: Value) -> Value {
    json!({"type": "response", "id": id, "result": result})
}

fn error_response(id: u64, code: &str, message: impl ToString) -> Value {
    json!({
        "type": "response", "id": id,
        "error": {"code": code, "message": message.to_string()},
    })
}

fn notification(name: &str, data: Value) -> Value {
    json!({"type": "notification", "event": name, "data": data})
}

/// Big-endian colon-separated hex, matching the host server / zigpy format.
fn eui64_to_string(eui64: Eui64) -> String {
    let mut bytes = eui64.to_bytes();
    bytes.reverse();
    join_hex(&bytes)
}

fn key_to_string(key: &Key) -> String {
    join_hex(&key.to_bytes())
}

fn join_hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, byte) in bytes.iter().enumerate() {
        if i != 0 {
            out.push(':');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[derive(Deserialize)]
struct Request {
    id: u64,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum NodeRole {
    #[default]
    Coordinator,
    Router,
}

impl From<NodeRole> for NwkDeviceType {
    fn from(role: NodeRole) -> Self {
        match role {
            NodeRole::Coordinator => Self::Coordinator,
            NodeRole::Router => Self::Router,
        }
    }
}

#[derive(Deserialize)]
struct ConfigureRequest {
    #[serde(default)]
    role: NodeRole,
    channel: u8,
    nwk_update_id: u8,
    pan_id: PanId,
    extended_pan_id: Eui64,
    nwk_address: Nwk,
    ieee_address: Eui64,
    network_key: Key,
    network_key_seq: u8,
    network_key_tx_counter: u32,
    tc_link_key: Option<Key>,
    tclk_seed: Option<Key>,
    tclk_flavor: Option<TclkFlavor>,
    #[serde(default)]
    key_table: Vec<KeyTableEntry>,
    #[serde(default)]
    source_routing: bool,
    tx_power: Option<i8>,
}

#[derive(Deserialize)]
struct KeyTableEntry {
    partner_ieee: Eui64,
    key: Key,
}

#[derive(Deserialize)]
struct SendApsRequest {
    delivery_mode: ApsDeliveryMode,
    destination_eui64: Option<Eui64>,
    destination: Option<Nwk>,
    profile_id: u16,
    cluster_id: u16,
    src_ep: u8,
    dst_ep: u8,
    aps_ack: bool,
    aps_seq: u8,
    radius: u8,
    /// Hex-encoded ASDU
    data: String,
    #[serde(default)]
    aps_encryption: bool,
    #[serde(default)]
    priority: i8,
}

#[derive(Deserialize)]
struct PermitJoinsRequest {
    #[serde(default)]
    duration: u64,
    #[serde(default = "default_accept_direct_joins")]
    accept_direct_joins: bool,
}

const fn default_accept_direct_joins() -> bool {
    true
}

#[derive(Deserialize)]
struct EnergyScanRequest {
    channels: Vec<u8>,
    #[allow(dead_code)]
    duration_per_channel_ms: u16,
}

#[derive(Deserialize)]
struct NetworkScanRequest {
    channels: Vec<u8>,
    duration_per_channel_ms: u16,
}

#[derive(Deserialize)]
struct SetChannelRequest {
    channel: u8,
}

#[derive(Deserialize)]
struct SetNwkUpdateIdRequest {
    nwk_update_id: u8,
}

#[derive(Deserialize)]
struct SetProvisionalKeyRequest {
    ieee: Eui64,
    key: Key,
}

/// Parse and dispatch one inbound line, emitting the `accepted` event and the response.
pub async fn handle_line(app: &mut App, line: &[u8]) {
    let request: Request = match serde_json::from_slice(line) {
        Ok(request) => request,
        Err(e) => {
            emit(error_response(0, "invalid_request", e)).await;
            return;
        }
    };

    emit(event(request.id, "accepted")).await;

    let Request { id, method, params } = request;
    let message = match method.as_str() {
        "ping" => response(id, json!({"status": "pong"})),
        "configure" => handle_configure(app, id, params).await,
        "get_hw_address" => handle_get_hw_address(id),
        "get_network_info" => handle_get_network_info(app, id),
        "send_aps" => handle_send_aps(app, id, params).await,
        "energy_scan" => handle_energy_scan(id, params).await,
        "network_scan" => handle_network_scan(app, id, params).await,
        "permit_joins" => handle_permit_joins(app, id, params),
        "set_channel" => handle_set_channel(app, id, params).await,
        "set_nwk_update_id" => handle_set_nwk_update_id(app, id, params),
        "set_provisional_key" => handle_set_provisional_key(app, id, params),
        other => error_response(id, "unknown_method", other),
    };

    emit(message).await;
}

async fn handle_configure(app: &mut App, id: u64, params: Value) -> Value {
    let request: ConfigureRequest = match serde_json::from_value(params) {
        Ok(request) => request,
        Err(e) => return error_response(id, "invalid_request", e),
    };

    let tclk_seed = match (request.tclk_seed, request.tclk_flavor) {
        (Some(seed), Some(flavor)) => Some(TclkSeed { seed, flavor }),
        (None, None) => None,
        _ => {
            return error_response(
                id,
                "invalid_request",
                "tclk_seed and tclk_flavor must be provided together",
            );
        }
    };

    let stack = ZigbeeStack::new(
        app.phy.clone(),
        NetworkConfig {
            role: request.role.into(),
            channel: request.channel,
            update_id: request.nwk_update_id,
            pan_id: request.pan_id,
            extended_pan_id: request.extended_pan_id,
            network_address: request.nwk_address,
            ieee_address: request.ieee_address,
            network_key: request.network_key,
            network_key_seq_number: request.network_key_seq,
            network_key_tx_counter: request.network_key_tx_counter,
            tc_link_key: request.tc_link_key.unwrap_or(WELL_KNOWN_LINK_KEY),
            tclk_seed,
            tx_power: request.tx_power.unwrap_or(DEFAULT_TX_POWER),
            source_routing: request.source_routing,
        },
        Tunables::new(),
        app.spawner,
    );

    if !request.key_table.is_empty() {
        let mut core = stack.state.core.lock();
        for entry in request.key_table {
            core.aib
                .aps_security
                .restore_device_key(entry.partner_ieee, entry.key);
        }
    }

    if let Err(e) = stack.start_network().await {
        return error_response(id, "network_start_failed", e);
    }

    let run_stack = stack.clone();
    stack.spawn_tracked(async move {
        run_stack.run().await;
    });

    // Drain network events to the serial writer.
    let notify_stack = stack.clone();
    stack.spawn_tracked(async move {
        loop {
            for notification_event in notify_stack.next_notifications().await {
                emit(notification_to_json(notification_event)).await;
            }
        }
    });

    app.stack = Some(stack);
    response(id, json!({"status": "success"}))
}

/// The factory IEEE address, derived from the SoC's eFuse base MAC (EUI-48 → EUI-64).
fn handle_get_hw_address(id: u64) -> Value {
    let mac = esp_hal::efuse::base_mac_address();
    let mac = mac.as_bytes();
    // Big-endian EUI-64: first 3 MAC bytes, FF FE, last 3 MAC bytes.
    let big_endian = [
        mac[0], mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5],
    ];
    let mut le = big_endian;
    le.reverse();
    response(
        id,
        json!({"ieee_address": eui64_to_string(Eui64(le))}),
    )
}

fn handle_get_network_info(app: &App, id: u64) -> Value {
    let Some(stack) = app.stack.as_ref() else {
        return error_response(id, "not_configured", "no stack is running");
    };

    let state = &stack.state;
    let core = state.core.lock();
    let nwk_security = &core.nib.nwk_security;
    let aps_security = &core.aib.aps_security;
    let tclk_seed = &stack.config.tclk_seed;

    response(
        id,
        json!({
            "channel": core.mac.channel,
            "nwk_update_id": core.nib.update_id,
            "pan_id": format!("{:04x}", core.mac.pan_id.0),
            "extended_pan_id": eui64_to_string(state.extended_pan_id),
            "nwk_address": format!("{:04x}", state.network_address.as_u16()),
            "ieee_address": eui64_to_string(state.ieee_address),
            "network_key": key_to_string(&nwk_security.network_key()),
            "network_key_seq": nwk_security.key_seq_number(),
            "network_key_tx_counter": nwk_security.outgoing_frame_counter(),
            "tc_link_key": key_to_string(&stack.config.tc_link_key),
            "tclk_seed": tclk_seed.as_ref().map(|tclk| hex::encode(tclk.seed.to_bytes())),
            "tclk_flavor": tclk_seed.as_ref().map(|tclk| match tclk.flavor {
                TclkFlavor::ZStack => "zstack",
                TclkFlavor::Ezsp => "ezsp",
            }),
            "key_table": aps_security
                .device_keys()
                .map(|(partner_ieee, entry)| json!({
                    "partner_ieee": eui64_to_string(partner_ieee),
                    "key": key_to_string(&entry.key),
                }))
                .collect::<Vec<_>>(),
            "tx_power": stack.config.tx_power,
        }),
    )
}

async fn handle_send_aps(app: &App, id: u64, params: Value) -> Value {
    let request: SendApsRequest = match serde_json::from_value(params) {
        Ok(request) => request,
        Err(e) => return error_response(id, "invalid_request", e),
    };

    let Some(stack) = app.stack.as_ref() else {
        return error_response(id, "not_configured", "no stack is running");
    };

    let destination = match (request.destination_eui64, request.destination) {
        (_, Some(nwk)) => nwk,
        (Some(eui64), None) => match stack.state.core.lock().nib.address_map.nwk_for(eui64) {
            Some(nwk) => nwk,
            None => return error_response(id, "unknown_destination_eui64", format!("{eui64:?}")),
        },
        (None, None) => return error_response(id, "missing_destination", "no destination given"),
    };

    let asdu = match hex::decode(&request.data) {
        Ok(asdu) => asdu,
        Err(e) => return error_response(id, "invalid_data", e),
    };

    let aps_security = if request.aps_encryption {
        match (request.destination_eui64, request.delivery_mode) {
            (Some(eui64), ApsDeliveryMode::Unicast) => Some(eui64),
            _ => {
                return error_response(
                    id,
                    "invalid_request",
                    "aps_encryption requires a unicast destination_eui64",
                );
            }
        }
    } else {
        None
    };

    let ack_waiter = match stack
        .send_aps_command(
            request.delivery_mode,
            destination,
            request.profile_id,
            request.cluster_id,
            request.src_ep,
            request.dst_ep,
            if request.aps_ack {
                ApsAck::Request
            } else {
                ApsAck::None
            },
            request.radius,
            request.aps_seq,
            asdu,
            aps_security,
            TxPriority(request.priority),
        )
        .await
    {
        Ok(ack_waiter) => ack_waiter,
        Err(e) => return error_response(id, "transmit_failed", e),
    };

    emit(event(id, "transmitted")).await;

    match ack_waiter {
        None => response(id, json!({"status": "sent"})),
        Some(waiter) => match stack.wait_aps_ack(waiter).await {
            Ok(()) => response(id, json!({"status": "delivered"})),
            Err(e) => error_response(id, "aps_ack_timeout", e),
        },
    }
}

/// Placeholder energy scan: esp-radio exposes no energy-detect API, so this streams a
/// flat floor RSSI per channel. Channel selection is therefore not energy-informed, but
/// `form` and other callers that expect a per-channel stream still work.
async fn handle_energy_scan(id: u64, params: Value) -> Value {
    let request: EnergyScanRequest = match serde_json::from_value(params) {
        Ok(request) => request,
        Err(e) => return error_response(id, "invalid_request", e),
    };

    for channel in request.channels {
        emit(event_data(
            id,
            "energy_result",
            json!({"channel": channel, "rssi": -90}),
        ))
        .await;
    }

    response(id, json!({"status": "complete"}))
}

fn network_beacon_json(beacon: &NetworkBeacon) -> Value {
    json!({
        "channel": beacon.channel,
        "source": beacon.source.map(|nwk| format!("{:04x}", nwk.0)),
        "pan_id": format!("{:04x}", beacon.pan_id.0),
        "extended_pan_id": eui64_to_string(beacon.extended_pan_id),
        "permit_joining": beacon.permit_joining,
        "stack_profile": beacon.stack_profile,
        "protocol_version": beacon.protocol_version,
        "router_capacity": beacon.router_capacity,
        "end_device_capacity": beacon.end_device_capacity,
        "device_depth": beacon.device_depth,
        "update_id": beacon.update_id,
        "lqi": beacon.lqi,
        "rssi": beacon.rssi,
    })
}

/// Active scan: beacon-request each channel and stream the beacons heard. Runs inline —
/// the receive loop collects beacons concurrently during the per-channel dwell, so they
/// are all queued by the time the scan returns and we drain them.
async fn handle_network_scan(app: &App, id: u64, params: Value) -> Value {
    let request: NetworkScanRequest = match serde_json::from_value(params) {
        Ok(request) => request,
        Err(e) => return error_response(id, "invalid_request", e),
    };

    let Some(stack) = app.stack.as_ref() else {
        return error_response(id, "not_configured", "no stack is running");
    };

    stack.begin_network_scan();
    let duration = Duration::from_millis(u64::from(request.duration_per_channel_ms));
    let result = stack.run_network_scan(&request.channels, duration).await;

    loop {
        let batch = stack.next_scan_beacons().await;
        if batch.is_empty() {
            break;
        }
        for beacon in batch {
            emit(event_data(id, "network_found", network_beacon_json(&beacon))).await;
        }
    }

    match result {
        Ok(()) => response(id, json!({"status": "complete"})),
        Err(e) => error_response(id, "network_scan_failed", e),
    }
}

fn handle_permit_joins(app: &App, id: u64, params: Value) -> Value {
    let request: PermitJoinsRequest = match serde_json::from_value(params) {
        Ok(request) => request,
        Err(e) => return error_response(id, "invalid_request", e),
    };

    let Some(stack) = app.stack.as_ref() else {
        return error_response(id, "not_configured", "no stack is running");
    };

    stack.permit_joins(request.duration, request.accept_direct_joins);
    response(id, json!({"status": "success"}))
}

async fn handle_set_channel(app: &App, id: u64, params: Value) -> Value {
    let request: SetChannelRequest = match serde_json::from_value(params) {
        Ok(request) => request,
        Err(e) => return error_response(id, "invalid_request", e),
    };

    let Some(stack) = app.stack.as_ref() else {
        return error_response(id, "not_configured", "no stack is running");
    };

    match stack.set_channel(request.channel).await {
        Ok(()) => response(id, json!({"status": "success"})),
        Err(e) => error_response(id, "set_channel_failed", e),
    }
}

fn handle_set_nwk_update_id(app: &App, id: u64, params: Value) -> Value {
    let request: SetNwkUpdateIdRequest = match serde_json::from_value(params) {
        Ok(request) => request,
        Err(e) => return error_response(id, "invalid_request", e),
    };

    let Some(stack) = app.stack.as_ref() else {
        return error_response(id, "not_configured", "no stack is running");
    };

    stack.set_nwk_update_id(request.nwk_update_id);
    response(id, json!({"status": "success"}))
}

fn handle_set_provisional_key(app: &App, id: u64, params: Value) -> Value {
    let request: SetProvisionalKeyRequest = match serde_json::from_value(params) {
        Ok(request) => request,
        Err(e) => return error_response(id, "invalid_request", e),
    };

    let Some(stack) = app.stack.as_ref() else {
        return error_response(id, "not_configured", "no stack is running");
    };

    stack.set_provisional_key(request.ieee, request.key);
    response(id, json!({"status": "success"}))
}

fn notification_to_json(notification_event: ZigbeeNotification) -> Value {
    match notification_event {
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
        } => notification(
            "received_aps_command",
            json!({
                "source": hex::encode(source.to_bytes()),
                "destination": hex::encode(destination.to_bytes()),
                "group": group,
                "profile_id": profile_id,
                "cluster_id": cluster_id, "src_ep": src_ep, "dst_ep": dst_ep,
                "lqi": lqi, "rssi": rssi, "data": hex::encode(data),
            }),
        ),
        ZigbeeNotification::FrameCounterUpdate { frame_counter } => {
            notification("frame_counter_update", json!({"frame_counter": frame_counter}))
        }
        ZigbeeNotification::LinkKeyUpdate { ieee, key } => notification(
            "link_key_update",
            json!({"ieee": eui64_to_string(ieee), "key": key_to_string(&key)}),
        ),
        ZigbeeNotification::DeviceJoined { nwk, ieee, parent } => notification(
            "device_joined",
            json!({
                "nwk": hex::encode(nwk.to_bytes()),
                "ieee": eui64_to_string(ieee),
                "parent": hex::encode(parent.to_bytes()),
            }),
        ),
        ZigbeeNotification::DeviceLeft { nwk, ieee, .. } => notification(
            "device_left",
            json!({
                "nwk": hex::encode(nwk.to_bytes()),
                "ieee": ieee.map(eui64_to_string),
            }),
        ),
        ZigbeeNotification::ApsDecryptionFailure {
            source,
            source_ieee,
            frame_counter,
            key_id,
        } => notification(
            "aps_decryption_failure",
            json!({
                "source": hex::encode(source.to_bytes()),
                "source_ieee": eui64_to_string(source_ieee),
                "frame_counter": frame_counter,
                "key_id": key_id,
            }),
        ),
    }
}
