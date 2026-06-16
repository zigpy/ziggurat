//! Transport-agnostic JSON-RPC dispatch over the Ziggurat Zigbee stack.
//!
//! [`Api`] owns the stack lifecycle and notification hub and turns a parsed request
//! (`id`, `method`, `params`) into a single response value, emitting any intermediate
//! `event` messages through a caller-supplied sink. A transport (the WebSocket server,
//! the Python bindings) is a thin shell: it carries bytes, frames them, and calls
//! [`Api::dispatch`]. The serial port lives behind the [`SpinelClient`] handed in at
//! construction, so the same dispatch serves a port-owning server and an embedder that
//! shuttles bytes itself.

use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use spinel::client::{SpinelClient, TxPriority};
use zigbee::aps::frame::ApsDeliveryMode;
use ziggurat::ieee_802154::types::{Eui64, Key, Nwk, PanId};
use ziggurat::zigbee_stack::aps_security::TclkFlavor;
use ziggurat::zigbee_stack::{
    ApsAck, DeviceLeaveReason, NetworkBeacon, NetworkConfig, TclkSeed, Tunables,
    WELL_KNOWN_LINK_KEY, ZigbeeNotification, ZigbeeStack,
};

/// Bumped on any breaking change to the wire protocol; sent in the `hello` greeting.
pub const PROTOCOL_VERSION: u32 = 1;

/// The server-level notification hub buffers this many notifications for slow
/// connection forwarders before they start lagging.
const NOTIFICATION_HUB_DEPTH: usize = 1024;

/// The radio transmit power (in dBm) used when `configure` does not specify one.
const DEFAULT_TX_POWER: i8 = 8;

/// Constructs the [`SpinelClient`] on first use.
///
/// The server opens a serial port here (and can fail); an embedder that owns the byte
/// stream returns a client built over an in-memory pipe. The returned client must
/// already have its reader spawned.
pub type SpinelFactory = Box<dyn Fn() -> Result<Arc<SpinelClient>, String> + Send + Sync>;

/// Big-endian colon-separated hex, the format used by zigpy for EUI64 addresses
fn eui64_to_string(eui64: Eui64) -> String {
    let mut bytes = eui64.to_bytes();
    bytes.reverse();

    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn key_to_string(key: &Key) -> String {
    key.to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn network_beacon_json(beacon: &NetworkBeacon) -> serde_json::Value {
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

// The client wire protocol: requests carry a client-chosen correlation id; the
// server answers each request with exactly one `response`, preceded by zero or more
// `event` messages sharing the id. `notification` messages are unsolicited.

pub fn event(id: u64, event: &str) -> serde_json::Value {
    json!({"type": "event", "id": id, "event": event})
}

pub fn event_data(id: u64, event: &str, data: serde_json::Value) -> serde_json::Value {
    json!({"type": "event", "id": id, "event": event, "data": data})
}

pub fn response(id: u64, result: serde_json::Value) -> serde_json::Value {
    json!({"type": "response", "id": id, "result": result})
}

pub fn error_response(id: u64, code: &str, message: impl ToString) -> serde_json::Value {
    json!({
        "type": "response", "id": id,
        "error": {"code": code, "message": message.to_string()},
    })
}

fn notification(event: &str, data: serde_json::Value) -> serde_json::Value {
    json!({"type": "notification", "event": event, "data": data})
}

/// The greeting a transport sends as soon as a client connects, reporting the protocol
/// version and whether a stack is already running.
pub fn hello(is_configured: bool) -> serde_json::Value {
    let state = if is_configured {
        "running"
    } else {
        "awaiting_configuration"
    };

    json!({"type": "hello", "version": PROTOCOL_VERSION, "state": state})
}

// Each `params` payload deserializes into the struct matching its `method`.

#[derive(Deserialize, Debug)]
struct KeyTableEntry {
    partner_ieee: Eui64,
    key: Key,
}

#[derive(Deserialize, Debug)]
struct ConfigureRequest {
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
    /// A TCLK seed carried over from a microcontroller stack; unique link keys are
    /// derived from it instead of generated randomly. Requires `tclk_flavor`.
    tclk_seed: Option<Key>,
    tclk_flavor: Option<TclkFlavor>,
    #[serde(default)]
    key_table: Vec<KeyTableEntry>,
    #[serde(default)]
    source_routing: bool,
    /// Radio transmit power in dBm
    tx_power: Option<i8>,
}

#[derive(Deserialize, Debug)]
struct SendApsRequest {
    delivery_mode: ApsDeliveryMode,
    /// Resolved through the address map; takes precedence over `destination`
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
    /// APS-encrypt the ASDU with the destination's link key; requires a unicast
    /// `destination_eui64`
    #[serde(default)]
    aps_encryption: bool,
    #[serde(default)]
    priority: i8,
}

#[derive(Deserialize, Debug)]
struct EnergyScanRequest {
    channels: Vec<u8>,
    duration_per_channel_ms: u16,
}

#[derive(Deserialize, Debug)]
struct NetworkScanRequest {
    channels: Vec<u8>,
    duration_per_channel_ms: u16,
}

#[derive(Deserialize, Debug)]
struct PermitJoinsRequest {
    #[serde(default)]
    duration: u64,
    #[serde(default = "default_accept_direct_joins")]
    accept_direct_joins: bool,
}

const fn default_accept_direct_joins() -> bool {
    true
}

#[derive(Deserialize, Debug)]
struct SetProvisionalKeyRequest {
    ieee: Eui64,
    key: Key,
}

#[derive(Deserialize, Debug)]
struct SetChannelRequest {
    channel: u8,
}

#[derive(Deserialize, Debug)]
struct SetNwkUpdateIdRequest {
    nwk_update_id: u8,
}

/// Renders an unsolicited stack notification as its wire JSON message.
pub fn notification_to_message(notification_event: ZigbeeNotification) -> serde_json::Value {
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
        ZigbeeNotification::FrameCounterUpdate { frame_counter } => notification(
            "frame_counter_update",
            json!({"frame_counter": frame_counter}),
        ),
        ZigbeeNotification::LinkKeyUpdate { ieee, key } => notification(
            "link_key_update",
            json!({
                "ieee": eui64_to_string(ieee),
                "key": key_to_string(&key),
            }),
        ),
        ZigbeeNotification::DeviceJoined { nwk, ieee, parent } => notification(
            "device_joined",
            json!({
                "nwk": hex::encode(nwk.to_bytes()),
                "ieee": eui64_to_string(ieee),
                "parent": hex::encode(parent.to_bytes()),
            }),
        ),
        ZigbeeNotification::DeviceLeft { nwk, ieee, reason } => {
            let mut params = json!({
                "nwk": hex::encode(nwk.to_bytes()),
                "ieee": ieee.map(eui64_to_string),
            });
            match reason {
                DeviceLeaveReason::Announced { rejoin } => {
                    params["reason"] = json!("announced");
                    params["rejoin"] = json!(rejoin);
                }
                DeviceLeaveReason::RouterReported {
                    router,
                    router_ieee,
                } => {
                    params["reason"] = json!("router_reported");
                    params["router"] = json!(hex::encode(router.to_bytes()));
                    params["router_ieee"] = json!(router_ieee.map(eui64_to_string));
                }
                DeviceLeaveReason::KeepaliveTimeout => {
                    params["reason"] = json!("keepalive_timeout");
                }
            }
            notification("device_left", params)
        }
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

/// The protocol core shared by every transport. It holds the stack lifecycle and the
/// notification hub; a transport subscribes to [`Api::subscribe`] and feeds parsed
/// requests to [`Api::dispatch`].
pub struct Api {
    /// The Spinel client owns the serial transport for the lifetime of the process: it is
    /// built lazily by the first command that needs it and never rebuilt, so stack
    /// replacement cannot race a straggling handle.
    spinel: Mutex<Option<Arc<SpinelClient>>>,
    spinel_factory: SpinelFactory,
    stack: Mutex<Option<Arc<ZigbeeStack>>>,
    /// Connections subscribe to this hub, and it survives stack replacement (the
    /// forwarder task is swapped instead).
    notification_tx: broadcast::Sender<ZigbeeNotification>,
    notification_forwarder: Mutex<Option<JoinHandle<()>>>,
}

impl Api {
    /// The Spinel client is not built and the Zigbee stack is not created until a
    /// request needs them; `spinel_factory` is what builds the client on first use.
    pub fn new(spinel_factory: SpinelFactory) -> Arc<Self> {
        let (notification_tx, _) = broadcast::channel(NOTIFICATION_HUB_DEPTH);

        Arc::new(Self {
            spinel: Mutex::new(None),
            spinel_factory,
            stack: Mutex::new(None),
            notification_tx,
            notification_forwarder: Mutex::new(None),
        })
    }

    /// A receiver for the unsolicited notification stream, one per transport connection.
    pub fn subscribe(&self) -> broadcast::Receiver<ZigbeeNotification> {
        self.notification_tx.subscribe()
    }

    /// True once a stack is running, used by transports to report initial state.
    pub fn is_configured(&self) -> bool {
        self.current_stack().is_some()
    }

    fn current_stack(&self) -> Option<Arc<ZigbeeStack>> {
        self.stack.lock().unwrap().clone()
    }

    /// The process-lifetime Spinel client, built on first use via the factory.
    fn spinel_client(&self) -> Result<Arc<SpinelClient>, String> {
        let mut spinel = self.spinel.lock().unwrap();

        if let Some(spinel) = &*spinel {
            return Ok(spinel.clone());
        }

        let client = (self.spinel_factory)()?;
        *spinel = Some(client.clone());
        drop(spinel);

        Ok(client)
    }

    /// Runs a single request to its terminal response, emitting any intermediate `event`
    /// messages through `events`. The caller spawns this and is responsible for sending
    /// the returned response value back to the client.
    pub async fn dispatch(
        &self,
        id: u64,
        method: &str,
        params: serde_json::Value,
        events: &mpsc::Sender<serde_json::Value>,
    ) -> serde_json::Value {
        match method {
            "ping" => self.handle_ping(id).await,
            "configure" => self.handle_configure(id, params).await,
            "get_hw_address" => self.handle_get_hw_address(id).await,
            "get_network_info" => self.handle_get_network_info(id),
            "send_aps" => self.handle_send_aps(id, params, events).await,
            "energy_scan" => self.handle_energy_scan(id, params, events).await,
            "network_scan" => self.handle_network_scan(id, params, events).await,
            "permit_joins" => self.handle_permit_joins(id, params),
            "set_provisional_key" => self.handle_set_provisional_key(id, params),
            "set_nwk_update_id" => self.handle_set_nwk_update_id(id, params),
            "set_channel" => self.handle_set_channel(id, params).await,
            _ => error_response(id, "unknown_method", method),
        }
    }

    /// Liveness probe. Yielding makes the reply round-trip through the runtime like
    /// every real command, so a starved executor shows up in the latency.
    async fn handle_ping(&self, id: u64) -> serde_json::Value {
        tokio::task::yield_now().await;

        response(id, json!({"status": "pong"}))
    }

    /// (Re)initializes the Zigbee stack. The stack deliberately outlives client
    /// connections; reconfiguring replaces it wholesale.
    #[allow(clippy::significant_drop_tightening)]
    async fn handle_configure(&self, id: u64, params: serde_json::Value) -> serde_json::Value {
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

        // A replaced stack must be fully stopped before its successor registers its
        // own receivers with the shared Spinel client
        let old_stack = self.stack.lock().unwrap().take();
        if let Some(old_stack) = old_stack {
            tracing::info!("Replacing the running Zigbee stack");
            old_stack.shutdown().await;
        }

        let old_forwarder = self.notification_forwarder.lock().unwrap().take();
        if let Some(old_forwarder) = old_forwarder {
            old_forwarder.abort();
        }

        tracing::info!("Initializing Zigbee stack with new settings...");
        let spinel = match self.spinel_client() {
            Ok(s) => s,
            Err(e) => return error_response(id, "serial_port_error", e),
        };

        let (stack, mut stack_notification_rx) = ZigbeeStack::new(
            spinel,
            NetworkConfig {
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
        );

        // Restore unique trust center link keys negotiated in earlier sessions
        if !request.key_table.is_empty() {
            let mut core = stack.state.core.lock();

            for entry in request.key_table {
                core.aib
                    .aps_security
                    .restore_device_key(entry.partner_ieee, entry.key);
            }

            tracing::info!(
                "Restored {} trust center link keys",
                core.aib.aps_security.device_key_count()
            );
        }

        // The success response is the client's permission to send commands: the
        // network must be fully up (RCP reset handled, radio programmed) before
        // replying, or the client's first command would race with the boot-time reset.
        if let Err(e) = stack.start_network().await {
            stack.shutdown().await;
            return error_response(id, "network_start_failed", e);
        }

        let stack_clone = stack.clone();
        stack.spawn_tracked(async move {
            stack_clone.run().await;
        });

        // Pump the stack's notifications into the server-level hub
        let hub_tx = self.notification_tx.clone();
        let forwarder = tokio::spawn(async move {
            while let Ok(event) = stack_notification_rx.recv().await {
                // Send errors just mean no client is connected right now
                let _ = hub_tx.send(event);
            }
        });

        *self.stack.lock().unwrap() = Some(stack);
        *self.notification_forwarder.lock().unwrap() = Some(forwarder);

        tracing::info!("Zigbee stack initialized and running.");
        response(id, json!({"status": "success"}))
    }

    /// Updates the `nwkUpdateId` advertised in beacons, the companion to
    /// `set_channel` during a network-wide channel migration.
    fn handle_set_nwk_update_id(&self, id: u64, params: serde_json::Value) -> serde_json::Value {
        let request: SetNwkUpdateIdRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        let Some(stack) = self.current_stack() else {
            return error_response(id, "not_configured", "no stack is running");
        };

        stack.set_nwk_update_id(request.nwk_update_id);
        response(id, json!({"status": "success"}))
    }

    /// Retunes the radio to a new channel, the coordinator's half of a network-wide
    /// channel migration; broadcasting `Mgmt_NWK_Update_req` to the other devices is
    /// the client's job.
    async fn handle_set_channel(&self, id: u64, params: serde_json::Value) -> serde_json::Value {
        let request: SetChannelRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        let Some(stack) = self.current_stack() else {
            return error_response(id, "not_configured", "no stack is running");
        };

        match stack.set_channel(request.channel).await {
            Ok(()) => response(id, json!({"status": "success"})),
            Err(e) => error_response(id, "set_channel_failed", e),
        }
    }

    /// Reads back the running network's settings, the counterpart of `configure`.
    /// While the stack runs, the server is the authoritative holder of the live state
    /// (e.g. frame counters), not the client that configured it.
    #[allow(clippy::significant_drop_tightening)]
    fn handle_get_network_info(&self, id: u64) -> serde_json::Value {
        let Some(stack) = self.current_stack() else {
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
                "tx_power": stack.config.tx_power,
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
            }),
        )
    }

    /// Reads the radio's factory-programmed EUI64, which a client needs before it can
    /// form a network with `configure`.
    async fn handle_get_hw_address(&self, id: u64) -> serde_json::Value {
        let spinel = match self.spinel_client() {
            Ok(s) => s,
            Err(e) => return error_response(id, "serial_port_error", e),
        };

        match spinel.get_hw_address().await {
            Ok(ieee) => response(id, json!({"ieee_address": eui64_to_string(ieee)})),
            Err(e) => error_response(id, "hw_address_failed", e),
        }
    }

    async fn handle_send_aps(
        &self,
        id: u64,
        params: serde_json::Value,
        events: &mpsc::Sender<serde_json::Value>,
    ) -> serde_json::Value {
        let request: SendApsRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        let Some(stack) = self.current_stack() else {
            return error_response(id, "not_configured", "no stack is running");
        };

        // A network address is authoritative when given (`destination_eui64` then only
        // selects the link key); EUI64-only packets are resolved through the address map
        let destination = match (request.destination_eui64, request.destination) {
            (_, Some(nwk)) => nwk,
            (Some(eui64), None) => {
                let nwk = stack.state.core.lock().nib.address_map.nwk_for(eui64);

                match nwk {
                    Some(nwk) => nwk,
                    None => {
                        return error_response(
                            id,
                            "unknown_destination_eui64",
                            format!("{eui64:?}"),
                        );
                    }
                }
            }
            (None, None) => {
                return error_response(id, "missing_destination", "no destination given");
            }
        };

        let asdu = match hex::decode(&request.data) {
            Ok(asdu) => asdu,
            Err(e) => return error_response(id, "invalid_data", e),
        };

        // Link keys are pairwise: encryption needs a unicast EUI64-addressed target
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

        // The frame is on the air (or extracted from the indirect queue); the
        // terminal response then reports end-to-end delivery when an ack was requested
        let _ = events.send(event(id, "transmitted")).await;

        match ack_waiter {
            None => response(id, json!({"status": "sent"})),
            Some(waiter) => match stack.wait_aps_ack(waiter).await {
                Ok(()) => response(id, json!({"status": "delivered"})),
                Err(e) => error_response(id, "aps_ack_timeout", e),
            },
        }
    }

    async fn handle_energy_scan(
        &self,
        id: u64,
        params: serde_json::Value,
        events: &mpsc::Sender<serde_json::Value>,
    ) -> serde_json::Value {
        let request: EnergyScanRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        let Some(stack) = self.current_stack() else {
            return error_response(id, "not_configured", "no stack is running");
        };

        let (result_tx, mut result_rx) = mpsc::channel::<(u8, i8)>(32);

        // The scan runs on its own task so it always reaches its channel restore, even if
        // this request's task is dropped. Its only sender lives until the scan ends, so
        // the drain loop below terminates exactly when the scan is done.
        let duration = Duration::from_millis(u64::from(request.duration_per_channel_ms));
        let scan = tokio::spawn(async move {
            stack
                .energy_scan(&request.channels, duration, result_tx)
                .await
        });

        while let Some((channel, rssi)) = result_rx.recv().await {
            let _ = events
                .send(event_data(
                    id,
                    "energy_result",
                    json!({"channel": channel, "rssi": rssi}),
                ))
                .await;
        }

        match scan.await {
            Ok(Ok(())) => response(id, json!({"status": "complete"})),
            Ok(Err(e)) => error_response(id, "energy_scan_failed", e),
            Err(e) => error_response(id, "energy_scan_failed", e),
        }
    }

    async fn handle_network_scan(
        &self,
        id: u64,
        params: serde_json::Value,
        events: &mpsc::Sender<serde_json::Value>,
    ) -> serde_json::Value {
        let request: NetworkScanRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        let Some(stack) = self.current_stack() else {
            return error_response(id, "not_configured", "no stack is running");
        };

        let (found_tx, mut found_rx) = mpsc::channel::<NetworkBeacon>(32);

        // The scan runs on its own task so it always reaches its channel restore, even if
        // this request's task is dropped. Its only sender lives until the scan ends, so
        // the drain loop below terminates exactly when the scan is done.
        let duration = Duration::from_millis(u64::from(request.duration_per_channel_ms));
        let scan = tokio::spawn(async move {
            stack
                .network_scan(&request.channels, duration, found_tx)
                .await
        });

        while let Some(beacon) = found_rx.recv().await {
            let _ = events
                .send(event_data(
                    id,
                    "network_found",
                    network_beacon_json(&beacon),
                ))
                .await;
        }

        match scan.await {
            Ok(Ok(())) => response(id, json!({"status": "complete"})),
            Ok(Err(e)) => error_response(id, "network_scan_failed", e),
            Err(e) => error_response(id, "network_scan_failed", e),
        }
    }

    fn handle_permit_joins(&self, id: u64, params: serde_json::Value) -> serde_json::Value {
        let request: PermitJoinsRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        let Some(stack) = self.current_stack() else {
            return error_response(id, "not_configured", "no stack is running");
        };

        stack.permit_joins(request.duration, request.accept_direct_joins);

        response(id, json!({"status": "success"}))
    }

    fn handle_set_provisional_key(&self, id: u64, params: serde_json::Value) -> serde_json::Value {
        let request: SetProvisionalKeyRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        let Some(stack) = self.current_stack() else {
            return error_response(id, "not_configured", "no stack is running");
        };

        stack.set_provisional_key(request.ieee, request.key);

        response(id, json!({"status": "success"}))
    }
}
