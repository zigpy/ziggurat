use clap::{Parser, ValueEnum};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_serial::{FlowControl, SerialPortBuilderExt};
use tokio_tungstenite::tungstenite::Message;
use tracing::Instrument;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use spinel::client::{SpinelClient, TxPriority};
use zigbee::aps::frame::ApsDeliveryMode;
use ziggurat::ieee_802154::types::{Eui64, Key, Nwk, PanId};
use ziggurat::zigbee_stack::aps_security::TclkFlavor;
use ziggurat::zigbee_stack::{
    NetworkConfig, TclkSeed, Tunables, WELL_KNOWN_LINK_KEY, ZigbeeNotification, ZigbeeStack,
};

const PROTOCOL_VERSION: u32 = 1;

/// Outbound messages a connection can queue before it is considered too slow and
/// disconnected. Received frames dominate the traffic; a client that cannot keep up
/// with them is broken.
const OUTBOUND_QUEUE_DEPTH: usize = 1024;

/// The server-level notification hub buffers this many notifications for slow
/// connection forwarders before they start lagging.
const NOTIFICATION_HUB_DEPTH: usize = 1024;

/// The radio transmit power (in dBm) used when `configure` does not specify one.
const DEFAULT_TX_POWER: i8 = 8;

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

// The client wire protocol: requests carry a client-chosen correlation id; the
// server answers each request with exactly one `response`, preceded by zero or more
// `event` messages sharing the id. `notification` messages are unsolicited.

#[derive(Deserialize, Debug)]
struct Request {
    id: u64,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

fn event(id: u64, event: &str) -> serde_json::Value {
    json!({"type": "event", "id": id, "event": event})
}

fn response(id: u64, result: serde_json::Value) -> serde_json::Value {
    json!({"type": "response", "id": id, "result": result})
}

fn error_response(id: u64, code: &str, message: impl ToString) -> serde_json::Value {
    json!({
        "type": "response", "id": id,
        "error": {"code": code, "message": message.to_string()},
    })
}

fn notification(event: &str, data: serde_json::Value) -> serde_json::Value {
    json!({"type": "notification", "event": event, "data": data})
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
struct PermitJoinsRequest {
    #[serde(default)]
    duration: u64,
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

fn notification_to_message(notification_event: ZigbeeNotification) -> serde_json::Value {
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
        ZigbeeNotification::DeviceLeft { nwk, ieee } => notification(
            "device_left",
            json!({
                "nwk": hex::encode(nwk.to_bytes()),
                "ieee": ieee.map(eui64_to_string),
            }),
        ),
    }
}

pub struct ZigguratServer {
    serial: SerialConfig,
    /// The Spinel client owns the serial port for the lifetime of the process: it is
    /// opened lazily by the first command that needs it and never reopened, so stack
    /// replacement cannot race a straggling port handle (`EBUSY`)
    spinel: Mutex<Option<Arc<SpinelClient>>>,
    stack: Mutex<Option<Arc<ZigbeeStack>>>,
    /// The server-level notification hub: connections subscribe to it, and it
    /// survives stack replacement (the forwarder task is swapped instead)
    notification_tx: broadcast::Sender<ZigbeeNotification>,
    notification_forwarder: Mutex<Option<JoinHandle<()>>>,
}

impl ZigguratServer {
    /// The serial port is not opened and the Zigbee stack is not created until a
    /// client sends a command that needs them.
    pub fn new(serial: SerialConfig) -> Self {
        let (notification_tx, _) = broadcast::channel(NOTIFICATION_HUB_DEPTH);

        Self {
            serial,
            spinel: Mutex::new(None),
            stack: Mutex::new(None),
            notification_tx,
            notification_forwarder: Mutex::new(None),
        }
    }

    pub async fn run(self: Arc<Self>, listen_addr: &str) -> std::io::Result<()> {
        match listen_addr.strip_prefix("unix:") {
            Some(path) => self.run_unix(path).await,
            None => self.run_tcp(listen_addr).await,
        }
    }

    async fn run_tcp(self: Arc<Self>, listen_addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        tracing::info!("Listening for WebSocket clients on {listen_addr}");

        loop {
            let (socket, addr) = listener.accept().await?;
            self.spawn_connection(socket, addr.to_string());
        }
    }

    async fn run_unix(self: Arc<Self>, path: &str) -> std::io::Result<()> {
        // A previous run's socket file would make the bind fail with AddrInUse
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }

        let listener = UnixListener::bind(path)?;
        tracing::info!("Listening for WebSocket clients on unix:{path}");

        // Peer addresses of UNIX sockets are unnamed: number the clients instead
        for client in 0u64.. {
            let (socket, _) = listener.accept().await?;
            self.spawn_connection(socket, format!("unix#{client}"));
        }

        unreachable!()
    }

    fn spawn_connection<S>(self: &Arc<Self>, socket: S, addr: String)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let server = self.clone();

        tokio::spawn(async move {
            if let Err(e) = server.handle_connection(socket, &addr).await {
                tracing::warn!("Connection {addr} ended with error: {e}");
            }

            tracing::info!("Client {addr} disconnected");
        });
    }

    fn current_stack(&self) -> Option<Arc<ZigbeeStack>> {
        self.stack.lock().unwrap().clone()
    }

    /// The process-lifetime Spinel client, opening the serial port on first use.
    fn spinel_client(&self) -> Result<Arc<SpinelClient>, tokio_serial::Error> {
        let mut spinel = self.spinel.lock().unwrap();

        if let Some(spinel) = &*spinel {
            return Ok(spinel.clone());
        }

        // Without flow control the RCP's UART drops bytes under load, corrupting
        // host->RCP frames ("Framing error" + command timeout)
        let port = tokio_serial::new(&self.serial.device, self.serial.baudrate)
            .flow_control(self.serial.flow_control.into())
            .open_native_async()?;

        let client = Arc::new(SpinelClient::new(port));
        client.spawn_reader();
        *spinel = Some(client.clone());
        drop(spinel);

        Ok(client)
    }

    async fn handle_connection<S>(
        self: &Arc<Self>,
        socket: S,
        addr: &str,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let websocket = tokio_tungstenite::accept_async(socket).await?;
        let (mut sink, mut stream) = websocket.split();

        tracing::info!("Client {addr} connected");

        let (outbound_tx, mut outbound_rx) =
            mpsc::channel::<serde_json::Value>(OUTBOUND_QUEUE_DEPTH);

        // All outbound traffic (responses, events, notifications) converges on a
        // single writer task, so concurrent commands never contend on the socket
        let writer = tokio::spawn(async move {
            while let Some(message) = outbound_rx.recv().await {
                if sink.send(Message::text(message.to_string())).await.is_err() {
                    break;
                }
            }

            let _ = sink.close().await;
        });

        let state = if self.current_stack().is_some() {
            "running"
        } else {
            "awaiting_configuration"
        };
        outbound_tx
            .send(json!({"type": "hello", "version": PROTOCOL_VERSION, "state": state}))
            .await?;

        // Forward hub notifications to this connection
        let mut notification_rx = self.notification_tx.subscribe();
        let notification_outbound = outbound_tx.clone();
        let forwarder_addr = addr.to_owned();
        let notification_forwarder = tokio::spawn(async move {
            loop {
                match notification_rx.recv().await {
                    Ok(event) => {
                        let message = notification_to_message(event);

                        if notification_outbound.send(message).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        tracing::warn!("Client {forwarder_addr} lagged {count} notifications");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        while let Some(message) = stream.next().await {
            match message {
                Ok(Message::Text(text)) => {
                    let request = match serde_json::from_str::<Request>(&text) {
                        Ok(request) => request,
                        Err(e) => {
                            tracing::warn!("Invalid request from {addr}: {e}");
                            let _ = outbound_tx
                                .send(error_response(0, "invalid_request", e))
                                .await;
                            continue;
                        }
                    };

                    tracing::debug!("Request from {addr}: {request:?}");
                    outbound_tx.send(event(request.id, "accepted")).await?;
                    self.dispatch(request, outbound_tx.clone());
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {} // Pings and pongs are handled by tungstenite itself
                Err(e) => {
                    tracing::warn!("WebSocket error from {addr}: {e}");
                    break;
                }
            }
        }

        notification_forwarder.abort();
        drop(outbound_tx);
        let _ = writer.await;

        Ok(())
    }

    /// Dispatches a request, spawning everything that can block on network activity:
    /// a command waiting on a slow device must never delay other commands.
    fn dispatch(self: &Arc<Self>, request: Request, outbound: mpsc::Sender<serde_json::Value>) {
        let server = self.clone();

        // One span per request so the handler work nests under it and the close line
        // reports the full request-to-response latency.
        let span = tracing::info_span!("request", id = request.id, method = %request.method);

        tokio::spawn(
            async move {
                let Request { id, method, params } = request;

                let message = match method.as_str() {
                    "ping" => server.handle_ping(id).await,
                    "configure" => server.handle_configure(id, params).await,
                    "get_hw_address" => server.handle_get_hw_address(id).await,
                    "get_network_info" => server.handle_get_network_info(id),
                    "send_aps" => server.handle_send_aps(id, params, &outbound).await,
                    "energy_scan" => server.handle_energy_scan(id, params).await,
                    "permit_joins" => server.handle_permit_joins(id, params),
                    "set_provisional_key" => server.handle_set_provisional_key(id, params),
                    "set_nwk_update_id" => server.handle_set_nwk_update_id(id, params),
                    "set_channel" => server.handle_set_channel(id, params).await,
                    _ => error_response(id, "unknown_method", method),
                };

                let _ = outbound.send(message).await;
            }
            .instrument(span),
        );
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
            let mut aps_security = stack.state.aps_security.lock();

            for entry in request.key_table {
                aps_security.restore_device_key(entry.partner_ieee, entry.key);
            }

            tracing::info!(
                "Restored {} trust center link keys",
                aps_security.device_key_count()
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
        let nwk_security = state.nwk_security.lock();
        let aps_security = state.aps_security.lock();
        let tclk_seed = &stack.config.tclk_seed;

        response(
            id,
            json!({
                "channel": *state.channel.lock(),
                "nwk_update_id": *state.update_id.lock(),
                "pan_id": format!("{:04x}", state.pan_id.lock().0),
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
        outbound: &mpsc::Sender<serde_json::Value>,
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
                let nwk = stack.state.address_map.lock().nwk_for(eui64);

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
                request.aps_ack,
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
        let _ = outbound.send(event(id, "transmitted")).await;

        match ack_waiter {
            None => response(id, json!({"status": "sent"})),
            Some(waiter) => match stack.wait_aps_ack(waiter).await {
                Ok(()) => response(id, json!({"status": "delivered"})),
                Err(e) => error_response(id, "aps_ack_timeout", e),
            },
        }
    }

    async fn handle_energy_scan(&self, id: u64, params: serde_json::Value) -> serde_json::Value {
        let request: EnergyScanRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        let Some(stack) = self.current_stack() else {
            return error_response(id, "not_configured", "no stack is running");
        };

        let results = stack
            .energy_scan(
                &request.channels,
                Duration::from_millis(u64::from(request.duration_per_channel_ms)),
            )
            .await;

        match results {
            Ok(results) => response(
                id,
                json!({"results": results.into_iter().collect::<HashMap<u8, i8>>()}),
            ),
            Err(e) => error_response(id, "energy_scan_failed", e),
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

        stack.permit_joins(request.duration);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FlowControlMode {
    Hardware,
    Software,
    None,
}

impl From<FlowControlMode> for FlowControl {
    fn from(mode: FlowControlMode) -> Self {
        match mode {
            FlowControlMode::Hardware => Self::Hardware,
            FlowControlMode::Software => Self::Software,
            FlowControlMode::None => Self::None,
        }
    }
}

#[derive(Debug)]
pub struct SerialConfig {
    device: String,
    baudrate: u32,
    flow_control: FlowControlMode,
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Host-side Zigbee stack speaking Spinel to an 802.15.4 RCP"
)]
struct Args {
    /// Serial device of the 802.15.4 RCP
    #[arg(long)]
    device: String,

    /// Serial baudrate
    #[arg(long, default_value_t = 460_800)]
    baudrate: u32,

    /// Serial flow control; the RCP UART drops bytes under load without it
    #[arg(long, value_enum, default_value_t = FlowControlMode::Hardware)]
    flow_control: FlowControlMode,

    /// WebSocket listen address: `host:port` for TCP, `unix:/path/to.sock` for a
    /// UNIX socket
    #[arg(long, default_value = "0.0.0.0:9999")]
    listen: String,

    /// Log level (RUST_LOG still overrides, with per-module filters)
    #[arg(long, default_value_t = LevelFilter::DEBUG)]
    log_level: LevelFilter,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(args.log_level.to_string()));
        tracing_subscriber::registry()
            .with(fmt::layer().with_filter(filter))
            .init();

        let server = Arc::new(ZigguratServer::new(SerialConfig {
            device: args.device,
            baudrate: args.baudrate,
            flow_control: args.flow_control,
        }));

        server.run(&args.listen).await?;

        Ok(())
    })
}
