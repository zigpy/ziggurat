use futures_util::{SinkExt, StreamExt};
use log::LevelFilter;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_serial::{FlowControl, SerialPortBuilderExt};
use tokio_tungstenite::tungstenite::Message;

use ziggurat::ieee_802154::types::{Eui64, Key, Nwk, PanId};
use ziggurat::spinel_client::SpinelClient;
use ziggurat::zigbee_aps::ApsDeliveryMode;
use ziggurat::zigbee_stack::aps_security::TclkFlavor;
use ziggurat::zigbee_stack::{Constants, TclkSeed, ZigbeeNotification, ZigbeeStack};

const PROTOCOL_VERSION: u32 = 1;

/// Outbound messages a connection can queue before it is considered too slow and
/// disconnected. Received frames dominate the traffic; a client that cannot keep up
/// with them is broken.
const OUTBOUND_QUEUE_DEPTH: usize = 1024;

/// The server-level notification hub buffers this many notifications for slow
/// connection forwarders before they start lagging.
const NOTIFICATION_HUB_DEPTH: usize = 1024;

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
    serial_path: String,
    stack: Mutex<Option<Arc<ZigbeeStack>>>,
    /// The server-level notification hub: connections subscribe to it, and it
    /// survives stack replacement (the forwarder task is swapped instead)
    notification_tx: broadcast::Sender<ZigbeeNotification>,
    notification_forwarder: Mutex<Option<JoinHandle<()>>>,
}

impl ZigguratServer {
    /// The serial port is not opened and the Zigbee stack is not created until a
    /// client sends the `configure` command.
    pub fn new(serial_path: &str) -> Self {
        let (notification_tx, _) = broadcast::channel(NOTIFICATION_HUB_DEPTH);

        Self {
            serial_path: serial_path.to_string(),
            stack: Mutex::new(None),
            notification_tx,
            notification_forwarder: Mutex::new(None),
        }
    }

    pub async fn run(self: Arc<Self>, listen_addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        log::info!("Listening for WebSocket clients on {listen_addr}");

        loop {
            let (socket, addr) = listener.accept().await?;
            let server = self.clone();

            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(socket, addr).await {
                    log::warn!("Connection {addr} ended with error: {e}");
                }

                log::info!("Client {addr} disconnected");
            });
        }
    }

    fn current_stack(&self) -> Option<Arc<ZigbeeStack>> {
        self.stack.lock().unwrap().clone()
    }

    async fn handle_connection(
        self: &Arc<Self>,
        socket: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let websocket = tokio_tungstenite::accept_async(socket).await?;
        let (mut sink, mut stream) = websocket.split();

        log::info!("Client {addr} connected");

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
                        log::warn!("Client {addr} lagged {count} notifications");
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
                            log::warn!("Invalid request from {addr}: {e}");
                            let _ = outbound_tx
                                .send(error_response(0, "invalid_request", e))
                                .await;
                            continue;
                        }
                    };

                    log::debug!("Request from {addr}: {request:?}");
                    outbound_tx.send(event(request.id, "accepted")).await?;
                    self.dispatch(request, outbound_tx.clone());
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {} // Pings and pongs are handled by tungstenite itself
                Err(e) => {
                    log::warn!("WebSocket error from {addr}: {e}");
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

        tokio::spawn(async move {
            let Request { id, method, params } = request;

            let message = match method.as_str() {
                "configure" => server.handle_configure(id, params).await,
                "send_aps" => server.handle_send_aps(id, params, &outbound).await,
                "energy_scan" => server.handle_energy_scan(id, params).await,
                "permit_joins" => server.handle_permit_joins(id, params),
                "set_provisional_key" => server.handle_set_provisional_key(id, params),
                _ => error_response(id, "unknown_method", method),
            };

            let _ = outbound.send(message).await;
        });
    }

    /// (Re)initializes the Zigbee stack. The stack deliberately outlives client
    /// connections; reconfiguring replaces it wholesale.
    #[allow(clippy::significant_drop_tightening)]
    async fn handle_configure(&self, id: u64, params: serde_json::Value) -> serde_json::Value {
        let request: ConfigureRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            Err(e) => return error_response(id, "invalid_request", e),
        };

        let mut constants = Constants::new();
        if let Some(tc_link_key) = request.tc_link_key {
            constants.global_link_key = tc_link_key;
        }

        match (request.tclk_seed, request.tclk_flavor) {
            (Some(seed), Some(flavor)) => constants.tclk_seed = Some(TclkSeed { seed, flavor }),
            (None, None) => {}
            _ => {
                return error_response(
                    id,
                    "invalid_request",
                    "tclk_seed and tclk_flavor must be provided together",
                );
            }
        }

        // A replaced stack must be fully stopped first: its spawned tasks hold strong
        // references and its serial reader would steal the successor's responses
        let old_stack = self.stack.lock().unwrap().take();
        if let Some(old_stack) = old_stack {
            log::info!("Replacing the running Zigbee stack");
            old_stack.shutdown();
        }

        let old_forwarder = self.notification_forwarder.lock().unwrap().take();
        if let Some(old_forwarder) = old_forwarder {
            old_forwarder.abort();
        }

        log::info!("Initializing Zigbee stack with new settings...");
        // Without flow control the RCP's UART drops bytes under load, corrupting
        // host->RCP frames ("Framing error" + command timeout)
        let port = match tokio_serial::new(&self.serial_path, 460_800)
            .flow_control(FlowControl::Hardware)
            .open_native_async()
        {
            Ok(p) => p,
            Err(e) => return error_response(id, "serial_port_error", e),
        };

        let spinel = SpinelClient::new(port);
        spinel.spawn_reader();

        let (stack, mut stack_notification_rx) = ZigbeeStack::new(
            spinel,
            constants,
            request.channel,
            request.nwk_update_id,
            request.pan_id,
            request.extended_pan_id,
            request.nwk_address,
            request.ieee_address,
            request.network_key,
            request.network_key_seq,
            request.network_key_tx_counter,
            request.source_routing,
        );

        // Restore unique trust center link keys negotiated in earlier sessions
        if !request.key_table.is_empty() {
            let mut aps_security = stack.state.aps_security.lock();

            for entry in request.key_table {
                aps_security.restore_device_key(entry.partner_ieee, entry.key);
            }

            log::info!(
                "Restored {} trust center link keys",
                aps_security.device_key_count()
            );
        }

        // The success response is the client's permission to send commands: the
        // network must be fully up (RCP reset handled, radio programmed) before
        // replying, or the client's first command would race with the boot-time reset.
        if let Err(e) = stack.start_network().await {
            stack.shutdown();
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

        log::info!("Zigbee stack initialized and running.");
        response(id, json!({"status": "success"}))
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
                let nwk = stack.state.address_map.lock().get(&eui64).copied();

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        // Debug by default, overridable through RUST_LOG
        env_logger::builder()
            .format_timestamp_micros()
            .filter(None, LevelFilter::Debug)
            .parse_default_env()
            .init();

        let args: Vec<String> = env::args().collect();
        if args.len() < 2 {
            eprintln!("Usage: {} <serial_path> [ws_listen_addr]", args[0]);
            return Ok(());
        }
        let serial_path = &args[1];
        let listen_addr = args
            .get(2)
            .cloned()
            .unwrap_or_else(|| "0.0.0.0:9999".to_string());

        let server = Arc::new(ZigguratServer::new(serial_path));

        server.run(&listen_addr).await?;

        Ok(())
    })
}
