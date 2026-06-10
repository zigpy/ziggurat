use log::LevelFilter;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_serial::{FlowControl, SerialPortBuilderExt};

use ziggurat::ieee_802154::types::{Eui64, Key, Nwk, PanId};
use ziggurat::spinel_client::SpinelClient;
use ziggurat::zigbee_aps::ApsDeliveryMode;
use ziggurat::zigbee_stack::{Constants, ZigbeeNotification, ZigbeeStack};

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

#[derive(Deserialize, Debug)]
struct CommandRequest {
    tid: u64,
    cmd: String,
    #[serde(default)]
    data: serde_json::Value,
}

#[derive(Serialize, Debug)]
struct CommandResponse {
    tid: u64,
    cmd: String,
    data: serde_json::Value,
}

// The structs below define the client wire protocol: each `data` payload deserializes
// into the struct matching its `cmd`.

#[derive(Deserialize, Debug)]
struct KeyTableEntry {
    partner_ieee: Eui64,
    key: Key,
}

#[derive(Deserialize, Debug)]
struct SetNetworkSettingsRequest {
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
    #[serde(default)]
    key_table: Vec<KeyTableEntry>,
}

#[derive(Deserialize, Debug)]
struct SendApsCommandRequest {
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

/// Holds the state that exists only after the Zigbee stack is initialized.
struct ServerState {
    zigbee_stack: Arc<ZigbeeStack>,
    notification_rx: broadcast::Receiver<ZigbeeNotification>,
}

pub struct ZigguratServer {
    serial_path: String,
    server_state: Mutex<Option<ServerState>>,
    is_client_connected: Mutex<bool>,
}

impl ZigguratServer {
    /// The serial port is not opened and the Zigbee stack is not created until a client
    /// connects and sends the `set_network_settings` command.
    pub fn new(serial_path: &str) -> Self {
        Self {
            serial_path: serial_path.to_string(),
            server_state: Mutex::new(None),
            is_client_connected: Mutex::new(false),
        }
    }

    /// Listens for and handles incoming TCP connections.
    pub async fn run_tcp_server(self: Arc<Self>, listen_addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        log::info!("Listening for a single TCP client on {listen_addr}");

        loop {
            let (socket, addr) = listener.accept().await?;

            // Enforce the single-client rule using the async mutex
            let mut is_connected_guard = self.is_client_connected.lock().unwrap();
            if *is_connected_guard {
                log::warn!(
                    "Rejecting connection from {addr}: another client is already connected."
                );
                drop(socket);
                continue; // The lock guard is dropped here
            }

            log::info!("Accepted new TCP client from {addr}");
            *is_connected_guard = true;
            drop(is_connected_guard); // Release the lock before spawning the task

            let server_clone = self.clone();
            tokio::spawn(async move {
                server_clone.handle_client(socket, addr).await;
            });
        }
    }

    /// Manages the entire lifecycle of a single client connection.
    async fn handle_client(self: Arc<Self>, stream: TcpStream, addr: SocketAddr) {
        if let Err(e) = self.handle_client_loop(stream, addr).await {
            log::warn!("Error handling client {addr}: {e:?}");
        }

        log::info!("Client {addr} disconnected.");
        *self.is_client_connected.lock().unwrap() = false;

        // The stack's spawned tasks hold strong references to it: without an explicit
        // shutdown the old stack would keep running alongside its successor, sharing
        // the serial port and stealing its responses
        let maybe_state = self.server_state.lock().unwrap().take();

        if let Some(state) = maybe_state {
            state.zigbee_stack.shutdown();
        }
        log::info!("Zigbee stack has been reset.");
    }

    /// The core logic loop for handling client messages.
    async fn handle_client_loop(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        log::info!("Client {addr} connected. Waiting for 'set_network_settings'...");
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => return Ok(()), // Client disconnected
                Ok(_) => {
                    let cmd = match serde_json::from_str::<CommandRequest>(line.trim()) {
                        Ok(cmd) => cmd,
                        Err(e) => {
                            log::warn!("JSON parse error from {addr}: {e}");
                            let resp = json!({"tid": 0, "cmd": "error", "data": {"reason": "invalid_json", "details": e.to_string()}});
                            writer.write_all(resp.to_string().as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                            continue;
                        }
                    };

                    log::debug!("Received command from {addr}: {cmd:?}");
                    let resp = self.process_command(cmd).await;
                    let resp_str = serde_json::to_string(&resp)?;
                    writer.write_all(resp_str.as_bytes()).await?;
                    writer.write_all(b"\n").await?;

                    if resp.cmd == "set_network_settings"
                        && resp.data.get("status").and_then(|v| v.as_str()) == Some("success")
                    {
                        break;
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }

        let notification_rx = {
            let state_guard = self.server_state.lock().unwrap();
            state_guard.as_ref().unwrap().notification_rx.resubscribe()
        };

        log::info!("Stack initialized. Now listening for commands and notifications.");

        self.run_initialized_loop(reader, writer, notification_rx, addr)
            .await
    }

    /// Runs the main operational loop after the Zigbee stack has been initialized.
    async fn run_initialized_loop(
        &self,
        reader: BufReader<OwnedReadHalf>,
        mut writer: OwnedWriteHalf,
        mut notification_rx: broadcast::Receiver<ZigbeeNotification>,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut reader = reader;
        let mut line = String::new();

        loop {
            line.clear();
            tokio::select! {
                read_result = reader.read_line(&mut line) => {
                    let n = read_result?;
                    if n == 0 { break; }

                    match serde_json::from_str::<CommandRequest>(line.trim()) {
                        Ok(cmd) => {
                            log::debug!("Received command from {addr}: {cmd:?}");
                            let resp = self.process_command(cmd).await;
                            let resp_str = serde_json::to_string(&resp)?;
                            log::debug!("Sending response: {resp_str}");
                            writer.write_all(resp_str.as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                        },
                        Err(e) => {
                            log::warn!("JSON parse error from {addr}: {e}");
                            let resp = json!({"tid": 0, "cmd": "error", "data": {"reason": "invalid_json", "details": e.to_string()}});
                            writer.write_all(resp.to_string().as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                        }
                    }
                },
                notify_event = notification_rx.recv() => {
                     match notify_event {
                        Ok(notification) => {
                            let event = match notification {
                                ZigbeeNotification::ReceivedApsCommand {
                                    source, destination, group, profile_id, cluster_id,
                                    src_ep, dst_ep, lqi, rssi, data,
                                } => json!({
                                    "tid": 0, "cmd": "received_aps_command",
                                    "data": {
                                        "source": hex::encode(source.to_bytes()),
                                        "destination": hex::encode(destination.to_bytes()),
                                        "group": group,
                                        "profile_id": profile_id,
                                        "cluster_id": cluster_id, "src_ep": src_ep, "dst_ep": dst_ep,
                                        "lqi": lqi, "rssi": rssi, "data": hex::encode(data),
                                    }
                                }),
                                ZigbeeNotification::FrameCounterUpdate { frame_counter } => json!({
                                    "tid": 0, "cmd": "frame_counter_update",
                                    "data": { "frame_counter": frame_counter }
                                }),
                                ZigbeeNotification::LinkKeyUpdate { ieee, key } => json!({
                                    "tid": 0, "cmd": "link_key_update",
                                    "data": {
                                        "ieee": eui64_to_string(ieee),
                                        "key": key_to_string(&key),
                                    }
                                }),
                                ZigbeeNotification::DeviceJoined { nwk, ieee, parent } => json!({
                                    "tid": 0, "cmd": "device_joined",
                                    "data": {
                                        "nwk": hex::encode(nwk.to_bytes()),
                                        "ieee": eui64_to_string(ieee),
                                        "parent": hex::encode(parent.to_bytes()),
                                    }
                                }),
                                ZigbeeNotification::DeviceLeft { nwk, ieee } => json!({
                                    "tid": 0, "cmd": "device_left",
                                    "data": {
                                        "nwk": hex::encode(nwk.to_bytes()),
                                        "ieee": ieee.map(eui64_to_string),
                                    }
                                }),
                            };

                            log::debug!("Sending notification: {event:?}");
                            writer.write_all(event.to_string().as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            log::warn!("Client {addr} lagged {count} messages, skipping...");
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            log::warn!("Broadcast channel closed, ending client connection for {addr}");
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn initialized_stack(&self) -> Option<Arc<ZigbeeStack>> {
        self.server_state
            .lock()
            .unwrap()
            .as_ref()
            .map(|server_state| server_state.zigbee_stack.clone())
    }

    /// Processes a single command from the client, mutating the server state if necessary.
    #[allow(clippy::significant_drop_tightening)]
    async fn process_command(&self, cmd: CommandRequest) -> CommandResponse {
        let CommandRequest {
            tid,
            cmd: name,
            data,
        } = cmd;

        let error = |reason: serde_json::Value, name: String| CommandResponse {
            tid,
            cmd: name,
            data: json!({"status": "error", "reason": reason}),
        };

        match name.as_str() {
            "set_network_settings" => {
                let request: SetNetworkSettingsRequest = match serde_json::from_value(data) {
                    Ok(request) => request,
                    Err(e) => {
                        return error(json!(format!("invalid_request: {e}")), name);
                    }
                };

                let mut state_guard = self.server_state.lock().unwrap();
                if state_guard.is_some() {
                    return error(json!("stack_already_initialized"), name);
                }

                let mut constants = Constants::new();
                if let Some(tc_link_key) = request.tc_link_key {
                    constants.global_link_key = tc_link_key;
                }

                log::info!("Initializing Zigbee stack with new settings...");
                // Without flow control the RCP's UART drops bytes under load,
                // corrupting host->RCP frames ("Framing error" + command timeout)
                let port = match tokio_serial::new(&self.serial_path, 460_800)
                    .flow_control(FlowControl::Hardware)
                    .open_native_async()
                {
                    Ok(p) => p,
                    Err(e) => {
                        return error(json!(format!("serial_port_error: {e}")), name);
                    }
                };

                let spinel = SpinelClient::new(port);
                spinel.spawn_reader();

                let (zigbee_stack, notification_rx) = ZigbeeStack::new(
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
                );

                // Restore unique trust center link keys negotiated in earlier sessions
                if !request.key_table.is_empty() {
                    let mut aps_security = zigbee_stack.state.aps_security.lock();

                    for entry in request.key_table {
                        aps_security.restore_device_key(entry.partner_ieee, entry.key);
                    }

                    log::info!(
                        "Restored {} trust center link keys",
                        aps_security.device_key_count()
                    );
                }

                let stack_clone = zigbee_stack.clone();
                zigbee_stack.spawn_tracked(async move {
                    stack_clone.run().await;
                });

                *state_guard = Some(ServerState {
                    zigbee_stack,
                    notification_rx,
                });

                log::info!("Zigbee stack initialized and running.");
                CommandResponse {
                    tid,
                    cmd: name,
                    data: json!({"status": "success"}),
                }
            }
            "send_aps_command" => {
                let request: SendApsCommandRequest = match serde_json::from_value(data) {
                    Ok(request) => request,
                    Err(e) => {
                        return error(json!(format!("invalid_request: {e}")), name);
                    }
                };

                let Some(zigbee_stack) = self.initialized_stack() else {
                    return error(json!("not_initialized"), name);
                };

                // EUI64-addressed packets are resolved through the address map
                let destination = match (request.destination_eui64, request.destination) {
                    (Some(eui64), _) => {
                        let nwk = zigbee_stack.state.address_map.lock().get(&eui64).copied();

                        match nwk {
                            Some(nwk) => nwk,
                            None => {
                                return error(json!("unknown_destination_eui64"), name);
                            }
                        }
                    }
                    (None, Some(nwk)) => nwk,
                    (None, None) => {
                        return error(json!("missing_destination"), name);
                    }
                };

                let asdu = match hex::decode(&request.data) {
                    Ok(asdu) => asdu,
                    Err(e) => {
                        return error(json!(format!("invalid_data: {e}")), name);
                    }
                };

                let status = zigbee_stack
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
                    )
                    .await;

                CommandResponse {
                    tid,
                    cmd: name,
                    data: json!({"status": if status.is_ok() { "success" } else { "error" }, "reason": status.err().map(|e| e.to_string())}),
                }
            }
            "energy_scan" => {
                let request: EnergyScanRequest = match serde_json::from_value(data) {
                    Ok(request) => request,
                    Err(e) => {
                        return error(json!(format!("invalid_request: {e}")), name);
                    }
                };

                let Some(zigbee_stack) = self.initialized_stack() else {
                    return error(json!("not_initialized"), name);
                };

                let results = zigbee_stack
                    .energy_scan(
                        &request.channels,
                        Duration::from_millis(u64::from(request.duration_per_channel_ms)),
                    )
                    .await;

                match results {
                    Ok(results) => CommandResponse {
                        tid,
                        cmd: name,
                        data: json!({
                            "status": "success",
                            "results": results.into_iter().collect::<HashMap<u8, i8>>(),
                        }),
                    },
                    Err(e) => error(json!(format!("energy_scan_failed: {e}")), name),
                }
            }
            "permit_joins" => {
                let request: PermitJoinsRequest = match serde_json::from_value(data) {
                    Ok(request) => request,
                    Err(e) => {
                        return error(json!(format!("invalid_request: {e}")), name);
                    }
                };

                let Some(zigbee_stack) = self.initialized_stack() else {
                    return error(json!("not_initialized"), name);
                };

                zigbee_stack.permit_joins(request.duration);

                CommandResponse {
                    tid,
                    cmd: name,
                    data: json!({"status": "success", "reason": "none"}),
                }
            }
            _ => error(json!("unknown_command"), name),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        env_logger::builder()
            .format_timestamp_micros()
            .filter(None, LevelFilter::Debug)
            //.filter_module("ziggurat::spinel", LevelFilter::Info
            .init();

        let args: Vec<String> = env::args().collect();
        if args.len() < 2 {
            eprintln!("Usage: {} <serial_path> [tcp_listen_addr]", args[0]);
            return Ok(());
        }
        let serial_path = &args[1];
        let tcp_listen_addr = args
            .get(2)
            .cloned()
            .unwrap_or_else(|| "0.0.0.0:9999".to_string());

        let server = Arc::new(ZigguratServer::new(serial_path));

        server.run_tcp_server(&tcp_listen_addr).await?;

        Ok(())
    })
}
