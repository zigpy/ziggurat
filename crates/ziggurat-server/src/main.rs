use clap::{Parser, ValueEnum};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_serial::{FlowControl, SerialPortBuilderExt};
use tokio_tungstenite::tungstenite::Message;
use tracing::Instrument;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use ziggurat_driver::runtime::TokioSpawner;
use ziggurat_driver::zigbee_stack::aps_security::TclkFlavor;
use ziggurat_driver::zigbee_stack::{
    ApsAck, ConfirmTrigger, DeviceLeaveReason, NetworkBeacon, NetworkConfig, NwkDeviceType,
    SendResult, RequestId, TclkSeed, Tunables, TxPriority, WELL_KNOWN_LINK_KEY,
    ZigbeeNotification, ZigbeeStack,
};
use ziggurat_driver::ziggurat_ieee_802154::types::{Eui64, Key, Nwk, PanId};
use ziggurat_phy::{RadioConfig, RadioPhy, Receiver};
use ziggurat_phy_spinel::SpinelPhy;
use ziggurat_spinel::client::SpinelClient;
use ziggurat_zigbee::aps::frame::ApsDeliveryMode;

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

/// Radio programming for promiscuous capture: receive every frame on `channel`, no PAN/
/// address filtering, no network required (dummy addresses).
const fn capture_config(channel: u8) -> RadioConfig {
    RadioConfig {
        channel,
        tx_power: DEFAULT_TX_POWER,
        short_address: Nwk(0xFFFF),
        extended_address: Eui64([0; 8]),
        pan_id: PanId(0xFFFF),
        promiscuous: true,
        rx_on_when_idle: true,
        frame_pending_short: Vec::new(),
        frame_pending_extended: Vec::new(),
    }
}

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

fn event_data(id: u64, event: &str, data: serde_json::Value) -> serde_json::Value {
    json!({"type": "event", "id": id, "event": event, "data": data})
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

#[derive(Deserialize, Debug, Default, Clone, Copy)]
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

#[derive(Deserialize, Debug)]
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

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum ResetType {
    /// Return to idle, leaving any configured network running.
    Soft,
    /// Reset the radio (RCP).
    Hard,
}

#[derive(Deserialize, Debug)]
struct ResetRequest {
    reset_type: ResetType,
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
        ZigbeeNotification::SendConfirm { request_id, result } => notification(
            "send_confirm",
            match result {
                SendResult::Confirmed { via } => json!({
                    "id": request_id,
                    "status": "confirmed",
                    "via": match via {
                        ConfirmTrigger::Quorum => "quorum",
                        ConfirmTrigger::NextHop => "next_hop",
                        ConfirmTrigger::ApsAck => "aps_ack",
                    },
                }),
                SendResult::Failed { reason } => json!({
                    "id": request_id,
                    "status": "failed",
                    "reason": reason,
                }),
            },
        ),
    }
}

pub struct ZigguratServer {
    serial: SerialConfig,
    /// The radio transport owns the serial port for the lifetime of the process: it is
    /// opened lazily by the first command that needs it and never reopened, so stack
    /// replacement cannot race a straggling port handle (`EBUSY`)
    phy: Mutex<Option<Arc<SpinelPhy>>>,
    stack: Mutex<Option<Arc<ZigbeeStack<SpinelPhy>>>>,
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
            phy: Mutex::new(None),
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

    fn current_stack(&self) -> Option<Arc<ZigbeeStack<SpinelPhy>>> {
        self.stack.lock().unwrap().clone()
    }

    /// The process-lifetime radio transport, opening the serial port on first use.
    fn phy(&self) -> Result<Arc<SpinelPhy>, tokio_serial::Error> {
        let mut phy = self.phy.lock().unwrap();

        if let Some(phy) = &*phy {
            return Ok(phy.clone());
        }

        // Without flow control the RCP's UART drops bytes under load, corrupting
        // host->RCP frames ("Framing error" + command timeout)
        let port = tokio_serial::new(&self.serial.device, self.serial.baudrate)
            .flow_control(self.serial.flow_control.into())
            .open_native_async()?;

        let new_phy = Arc::new(SpinelPhy::new(Arc::new(SpinelClient::new(port))));
        *phy = Some(new_phy.clone());
        drop(phy);

        Ok(new_phy)
    }

    /// The greeting sent to every client on connect, advertising the protocol version
    /// and whether the stack is already configured.
    fn hello_message(&self) -> serde_json::Value {
        let state = if self.current_stack().is_some() {
            "running"
        } else {
            "awaiting_configuration"
        };
        json!({"type": "hello", "version": PROTOCOL_VERSION, "state": state})
    }

    /// Fan hub notifications out to one connection's outbound queue until it closes.
    fn spawn_notification_forwarder(
        self: &Arc<Self>,
        outbound: mpsc::Sender<serde_json::Value>,
        addr: String,
    ) -> JoinHandle<()> {
        let mut notification_rx = self.notification_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match notification_rx.recv().await {
                    Ok(event) => {
                        if outbound.send(notification_to_message(event)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        tracing::warn!("Client {addr} lagged {count} notifications");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    }

    /// Parse one inbound JSON request (a WebSocket text frame or a serial line) and
    /// dispatch it. Returns `false` once the outbound queue is gone and the connection
    /// should be torn down.
    async fn handle_request_text(
        self: &Arc<Self>,
        text: &str,
        addr: &str,
        outbound: &mpsc::Sender<serde_json::Value>,
    ) -> bool {
        let request = match serde_json::from_str::<Request>(text) {
            Ok(request) => request,
            Err(e) => {
                tracing::warn!("Invalid request from {addr}: {e}");
                return outbound
                    .send(error_response(0, "invalid_request", e))
                    .await
                    .is_ok();
            }
        };

        tracing::debug!("Request from {addr}: {request:?}");
        if outbound.send(event(request.id, "accepted")).await.is_err() {
            return false;
        }
        self.dispatch(request, outbound.clone());
        true
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

        outbound_tx.send(self.hello_message()).await?;
        let notification_forwarder =
            self.spawn_notification_forwarder(outbound_tx.clone(), addr.to_owned());

        while let Some(message) = stream.next().await {
            match message {
                Ok(Message::Text(text)) => {
                    if !self.handle_request_text(&text, addr, &outbound_tx).await {
                        break;
                    }
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

    /// Serve the line-delimited JSON API over any byte stream (stdio, or a serial port
    /// on the eventual embedded target). One request per inbound line; one JSON object
    /// per outbound line. The dispatch and notification machinery is shared verbatim
    /// with the WebSocket transport.
    async fn handle_line_connection<R, W>(
        self: &Arc<Self>,
        reader: R,
        mut writer: W,
        addr: &str,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        tracing::info!("Client {addr} connected");

        let (outbound_tx, mut outbound_rx) =
            mpsc::channel::<serde_json::Value>(OUTBOUND_QUEUE_DEPTH);

        let writer_task = tokio::spawn(async move {
            while let Some(message) = outbound_rx.recv().await {
                let mut line = message.to_string();
                line.push('\n');
                if writer.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                let _ = writer.flush().await;
            }
        });

        let _ = outbound_tx.send(self.hello_message()).await;
        let notification_forwarder =
            self.spawn_notification_forwarder(outbound_tx.clone(), addr.to_owned());

        let mut lines = BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            if !self.handle_request_text(&line, addr, &outbound_tx).await {
                break;
            }
        }

        notification_forwarder.abort();
        drop(outbound_tx);
        let _ = writer_task.await;

        Ok(())
    }

    async fn run_stdio(self: Arc<Self>) -> std::io::Result<()> {
        tracing::info!("Serving line-delimited JSON API on stdin/stdout");
        self.handle_line_connection(tokio::io::stdin(), tokio::io::stdout(), "stdio")
            .await
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
                    "reset" => server.handle_reset(id, params).await,
                    "configure" => server.handle_configure(id, params).await,
                    "get_hw_address" => server.handle_get_hw_address(id).await,
                    "get_network_info" => server.handle_get_network_info(id),
                    "send_aps" => server.handle_send_aps(id, params),
                    "energy_scan" => server.handle_energy_scan(id, params, &outbound).await,
                    "network_scan" => server.handle_network_scan(id, params, &outbound).await,
                    "permit_joins" => server.handle_permit_joins(id, params),
                    "set_provisional_key" => server.handle_set_provisional_key(id, params),
                    "set_nwk_update_id" => server.handle_set_nwk_update_id(id, params),
                    "set_channel" => server.handle_set_channel(id, params).await,
                    "packet_capture" => server.handle_packet_capture(id, params, &outbound).await,
                    "packet_capture_change_channel" => {
                        server
                            .handle_packet_capture_change_channel(id, params)
                            .await
                    }
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

    /// Soft or hard reset. A soft reset is a no-op success on the host (no transient
    /// radio state outlives a connection here), kept for wire parity with the firmware. A
    /// hard reset resets the radio (RCP); the stack's recovery task reprograms it.
    async fn handle_reset(&self, id: u64, params: serde_json::Value) -> serde_json::Value {
        let request: ResetRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        if matches!(request.reset_type, ResetType::Hard) {
            let phy = match self.phy() {
                Ok(p) => p,
                Err(e) => return error_response(id, "serial_port_error", e),
            };
            if let Err(e) = phy.reset().await {
                return error_response(id, "reset_failed", e);
            }
        }

        response(id, json!({"status": "success"}))
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
        let phy = match self.phy() {
            Ok(p) => p,
            Err(e) => return error_response(id, "serial_port_error", e),
        };

        let stack = ZigbeeStack::new(
            phy,
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
            TokioSpawner::default(),
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

        // Drain the stack's notification outbox into the server-level hub. The task is
        // aborted when the stack is replaced (see `handle_configure`), so it doesn't
        // need to observe a closed channel to stop.
        let hub_tx = self.notification_tx.clone();
        let notification_stack = stack.clone();
        let forwarder = tokio::spawn(async move {
            loop {
                for event in notification_stack.next_notifications().await {
                    // Send errors just mean no client is connected right now
                    let _ = hub_tx.send(event);
                }
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

    /// Put the radio in promiscuous mode and stream every received frame as a
    /// `captured_packet` event until the client disconnects. No network is required (it
    /// reprograms the radio directly), so a running stack is disrupted for the session.
    async fn handle_packet_capture(
        &self,
        id: u64,
        params: serde_json::Value,
        outbound: &mpsc::Sender<serde_json::Value>,
    ) -> serde_json::Value {
        let request: SetChannelRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        let phy = match self.phy() {
            Ok(p) => p,
            Err(e) => return error_response(id, "serial_port_error", e),
        };

        if let Err(e) = phy.reconfigure(&capture_config(request.channel)).await {
            return error_response(id, "packet_capture_failed", e);
        }

        let mut rx = phy.subscribe_rx();
        while let Some(frame) = rx.recv().await {
            let event = event_data(
                id,
                "captured_packet",
                json!({
                    "channel": frame.channel,
                    "rssi": frame.rssi,
                    "lqi": frame.lqi,
                    "data": hex::encode(frame.psdu),
                }),
            );
            if outbound.send(event).await.is_err() {
                break; // client disconnected
            }
        }

        response(id, json!({"status": "complete"}))
    }

    async fn handle_packet_capture_change_channel(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> serde_json::Value {
        let request: SetChannelRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        let phy = match self.phy() {
            Ok(p) => p,
            Err(e) => return error_response(id, "serial_port_error", e),
        };

        match phy.reconfigure(&capture_config(request.channel)).await {
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
        let phy = match self.phy() {
            Ok(p) => p,
            Err(e) => return error_response(id, "serial_port_error", e),
        };

        match phy.hw_address().await {
            Ok(ieee) => response(id, json!({"ieee_address": eui64_to_string(ieee)})),
            Err(e) => error_response(id, "hw_address_failed", e),
        }
    }

    fn handle_send_aps(&self, id: u64, params: serde_json::Value) -> serde_json::Value {
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

        // The stack either accepts the frame for transmission or rejects it now. The
        // delivery outcome arrives later as a `send_confirm` notification keyed by
        // this request id (the send token).
        match stack.send_aps(
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
            id as RequestId,
        ) {
            Ok(()) => response(id, json!({"status": "accepted"})),
            Err(e) => error_response(id, "transmit_failed", e),
        }
    }

    async fn handle_energy_scan(
        &self,
        id: u64,
        params: serde_json::Value,
        outbound: &mpsc::Sender<serde_json::Value>,
    ) -> serde_json::Value {
        let request: EnergyScanRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        // An energy detect is a radio operation, not a network one: it drives the radio
        // directly and needs no configured stack.
        let phy = match self.phy() {
            Ok(p) => p,
            Err(e) => return error_response(id, "serial_port_error", e),
        };

        // An energy detect is self-contained per channel, so the manager owns the loop
        // and streams each result as the channel completes.
        let duration = Duration::from_millis(u64::from(request.duration_per_channel_ms));
        for channel in request.channels {
            match phy.energy_detect(channel, duration).await {
                Ok(rssi) => {
                    let _ = outbound
                        .send(event_data(
                            id,
                            "energy_result",
                            json!({"channel": channel, "rssi": rssi}),
                        ))
                        .await;
                }
                Err(e) => return error_response(id, "energy_scan_failed", e),
            }
        }

        response(id, json!({"status": "complete"}))
    }

    async fn handle_network_scan(
        &self,
        id: u64,
        params: serde_json::Value,
        outbound: &mpsc::Sender<serde_json::Value>,
    ) -> serde_json::Value {
        let request: NetworkScanRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        let Some(stack) = self.current_stack() else {
            return error_response(id, "not_configured", "no stack is running");
        };

        // Open the collection window before spawning, so the drain loop below cannot race
        // ahead of the scan starting. The scan runs on its own task so it always reaches
        // its channel restore even if this request's task is dropped.
        stack.begin_network_scan();
        let duration = Duration::from_millis(u64::from(request.duration_per_channel_ms));
        let scan_stack = stack.clone();
        let scan = tokio::spawn(async move {
            scan_stack
                .run_network_scan(&request.channels, duration)
                .await
        });

        // `next_scan_beacons` delivers beacons as they arrive and returns empty once the
        // window has closed and the queue is drained, which ends the loop.
        loop {
            let batch = stack.next_scan_beacons().await;
            if batch.is_empty() {
                break;
            }
            for beacon in batch {
                let _ = outbound
                    .send(event_data(
                        id,
                        "network_found",
                        network_beacon_json(&beacon),
                    ))
                    .await;
            }
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

/// How the Zigbee API is exposed to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ApiMode {
    /// JSON-RPC over WebSocket on `--listen`
    Ws,
    /// Line-delimited JSON over stdin/stdout (logs go to stderr)
    Stdio,
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Host-side Zigbee stack speaking Spinel to an 802.15.4 RCP"
)]
struct Args {
    /// How to expose the Zigbee API to clients
    #[arg(long, value_enum, default_value_t = ApiMode::Ws)]
    api: ApiMode,

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

        // In stdio mode stdout carries the JSON API, so logs must not touch it
        if args.api == ApiMode::Stdio {
            tracing_subscriber::registry()
                .with(
                    fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_filter(filter),
                )
                .init();
        } else {
            tracing_subscriber::registry()
                .with(fmt::layer().with_filter(filter))
                .init();
        }

        let server = Arc::new(ZigguratServer::new(SerialConfig {
            device: args.device,
            baudrate: args.baudrate,
            flow_control: args.flow_control,
        }));

        match args.api {
            ApiMode::Ws => server.run(&args.listen).await?,
            ApiMode::Stdio => server.run_stdio().await?,
        }

        Ok(())
    })
}
