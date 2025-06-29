use log::LevelFilter;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serial2::Settings;
use serial2_tokio::SerialPort;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::LocalRuntime;
use tokio::sync::broadcast;
use tokio::task::spawn_local;

use ziggurat::ieee_802154::types::{Eui64, Key, Nwk, PanId};
use ziggurat::spinel_client::SpinelClient;
use ziggurat::zigbee_aps::ApsDeliveryMode;
use ziggurat::zigbee_stack::{ZigbeeNotification, ZigbeeStack};

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

/// Holds the state that exists only after the Zigbee stack is initialized.
struct ServerState {
    zigbee_stack: Arc<ZigbeeStack>,
    notification_rx: broadcast::Receiver<ZigbeeNotification>,
}

pub struct ZigguratServer {
    serial_path: String,
    // Use tokio::sync::Mutex for async-aware locking
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
        log::info!("Listening for a single TCP client on {}", listen_addr);

        loop {
            let (socket, addr) = listener.accept().await?;

            // Enforce the single-client rule using the async mutex
            let mut is_connected_guard = self.is_client_connected.lock().unwrap();
            if *is_connected_guard {
                log::warn!(
                    "Rejecting connection from {}: another client is already connected.",
                    addr
                );
                drop(socket);
                continue; // The lock guard is dropped here
            }

            log::info!("Accepted new TCP client from {}", addr);
            *is_connected_guard = true;
            drop(is_connected_guard); // Release the lock before spawning the task

            let server_clone = self.clone();
            spawn_local(async move {
                server_clone.handle_client(socket, addr).await;
            });
        }
    }

    /// Manages the entire lifecycle of a single client connection.
    async fn handle_client(self: Arc<Self>, stream: TcpStream, addr: SocketAddr) {
        if let Err(e) = self.handle_client_loop(stream, addr).await {
            log::warn!("Error handling client {}: {:?}", addr, e);
        }

        log::info!("Client {} disconnected.", addr);
        *self.is_client_connected.lock().unwrap() = false;
        *self.server_state.lock().unwrap() = None;
        log::info!("Zigbee stack has been reset.");
    }

    /// The core logic loop for handling client messages. This function now correctly
    /// separates the uninitialized and initialized states.
    async fn handle_client_loop(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        log::info!(
            "Client {} connected. Waiting for 'set_network_settings'...",
            addr
        );
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => return Ok(()), // Client disconnected
                Ok(_) => {
                    let cmd = match serde_json::from_str::<CommandRequest>(line.trim()) {
                        Ok(cmd) => cmd,
                        Err(e) => {
                            log::warn!("JSON parse error from {}: {}", addr, e);
                            let resp = json!({"tid": 0, "cmd": "error", "data": {"reason": "invalid_json", "details": e.to_string()}});
                            writer.write_all(resp.to_string().as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                            continue;
                        }
                    };

                    log::debug!("Received command from {}: {:?}", addr, cmd);
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

        let state_guard = self.server_state.lock().unwrap();
        let notification_rx = state_guard.as_ref().unwrap().notification_rx.resubscribe();
        drop(state_guard);

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
                            log::debug!("Received command from {}: {:?}", addr, cmd);
                            let resp = self.process_command(cmd).await;
                            let resp_str = serde_json::to_string(&resp)?;
                            log::debug!("Sending response: {}", resp_str);
                            writer.write_all(resp_str.as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                        },
                        Err(e) => {
                            log::warn!("JSON parse error from {}: {}", addr, e);
                            let resp = json!({"tid": 0, "cmd": "error", "data": {"reason": "invalid_json", "details": e.to_string()}});
                            writer.write_all(resp.to_string().as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                        }
                    }
                },
                notify_event = notification_rx.recv() => {
                     match notify_event {
                        Ok(ZigbeeNotification::ReceivedApsCommand {
                            source, profile_id, cluster_id, src_ep, dst_ep, lqi, rssi, data,
                        }) => {
                            let event = json!({
                                "tid": 0, "cmd": "received_aps_command",
                                "data": {
                                    "source": hex::encode(source.to_bytes()), "profile_id": profile_id,
                                    "cluster_id": cluster_id, "src_ep": src_ep, "dst_ep": dst_ep,
                                    "lqi": lqi, "rssi": rssi, "data": hex::encode(data),
                                }
                            });
                            log::debug!("Sending APS frame notification: {:?}", event);
                            writer.write_all(event.to_string().as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            log::warn!("Client {} lagged {} messages, skipping...", addr, count);
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            log::warn!("Broadcast channel closed, ending client connection for {}", addr);
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Processes a single command from the client, mutating the server state if necessary.
    async fn process_command(&self, cmd: CommandRequest) -> CommandResponse {
        match cmd.cmd.as_str() {
            "set_network_settings" => {
                let mut state_guard = self.server_state.lock().unwrap();
                if state_guard.is_some() {
                    return CommandResponse {
                        tid: cmd.tid,
                        cmd: cmd.cmd,
                        data: json!({"status": "error", "reason": "stack_already_initialized"}),
                    };
                }

                let channel = cmd.data.get("channel").unwrap().as_u64().unwrap() as u8;
                let nwk_update_id = cmd.data.get("nwk_update_id").unwrap().as_u64().unwrap() as u8;
                let pan_id = PanId::from_hex(cmd.data.get("pan_id").unwrap().as_str().unwrap());
                let extended_pan_id =
                    Eui64::from_hex(cmd.data.get("extended_pan_id").unwrap().as_str().unwrap());
                let nwk_address =
                    Nwk::from_hex(cmd.data.get("nwk_address").unwrap().as_str().unwrap());
                let ieee_address =
                    Eui64::from_hex(cmd.data.get("ieee_address").unwrap().as_str().unwrap());
                let network_key =
                    Key::from_hex(cmd.data.get("network_key").unwrap().as_str().unwrap());
                let network_key_seq =
                    cmd.data.get("network_key_seq").unwrap().as_u64().unwrap() as u8;
                let network_key_tx_counter = cmd
                    .data
                    .get("network_key_tx_counter")
                    .unwrap()
                    .as_u64()
                    .unwrap() as u32;

                log::info!("Initializing Zigbee stack with new settings...");
                let port = match SerialPort::open(&self.serial_path, |mut settings: Settings| {
                    settings.set_raw();
                    settings.set_baud_rate(460_800)?;
                    Ok(settings)
                }) {
                    Ok(p) => p,
                    Err(e) => {
                        return CommandResponse {
                            tid: cmd.tid,
                            cmd: cmd.cmd,
                            data: json!({"status": "error", "reason": format!("serial_port_error: {}", e)}),
                        };
                    }
                };

                let spinel = SpinelClient::new(port);
                spinel.spawn_reader();

                let (zigbee_stack, notification_rx) = ZigbeeStack::new(
                    spinel,
                    channel,
                    nwk_update_id,
                    pan_id,
                    extended_pan_id,
                    nwk_address,
                    ieee_address,
                    network_key,
                    network_key_seq,
                    network_key_tx_counter,
                );

                let stack_clone = zigbee_stack.clone();
                spawn_local(async move {
                    stack_clone.run().await;
                });

                *state_guard = Some(ServerState {
                    zigbee_stack,
                    notification_rx,
                });

                log::info!("Zigbee stack initialized and running.");
                CommandResponse {
                    tid: cmd.tid,
                    cmd: cmd.cmd,
                    data: json!({"status": "success"}),
                }
            }
            "send_aps_command" => {
                let state_guard = self.server_state.lock().unwrap();
                if let Some(server_state) = &*state_guard {
                    // ... (parsing logic remains the same)
                    let delivery_mode = match cmd
                        .data
                        .get("delivery_mode")
                        .unwrap()
                        .as_str()
                        .unwrap()
                    {
                        "unicast" => ApsDeliveryMode::Unicast,
                        "broadcast" => ApsDeliveryMode::Broadcast,
                        "multicast" => ApsDeliveryMode::Multicast,
                        _ => {
                            return CommandResponse {
                                tid: cmd.tid,
                                cmd: cmd.cmd,
                                data: json!({"status": "error", "reason": "invalid_delivery_mode"}),
                            };
                        }
                    };
                    let destination =
                        Nwk::from_hex(cmd.data.get("destination").unwrap().as_str().unwrap());
                    let profile_id = cmd.data.get("profile_id").unwrap().as_u64().unwrap() as u16;
                    let cluster_id = cmd.data.get("cluster_id").unwrap().as_u64().unwrap() as u16;
                    let src_ep = cmd.data.get("src_ep").unwrap().as_u64().unwrap() as u8;
                    let dst_ep = cmd.data.get("dst_ep").unwrap().as_u64().unwrap() as u8;
                    let aps_ack = cmd.data.get("aps_ack").unwrap().as_bool().unwrap();
                    let aps_seq = cmd.data.get("aps_seq").unwrap().as_u64().unwrap() as u8;
                    let radius = cmd.data.get("radius").unwrap().as_u64().unwrap() as u8;
                    let data =
                        hex::decode(cmd.data.get("data").unwrap().as_str().unwrap()).unwrap();

                    // The lock is held across this await, which is now safe.
                    let status = server_state
                        .zigbee_stack
                        .send_aps_command(
                            delivery_mode,
                            destination,
                            profile_id,
                            cluster_id,
                            src_ep,
                            dst_ep,
                            aps_ack,
                            radius,
                            aps_seq,
                            data,
                        )
                        .await;

                    CommandResponse {
                        tid: cmd.tid,
                        cmd: cmd.cmd,
                        data: json!({"status": if status.is_ok() { "success" } else { "error" }, "reason": status.err().map(|e| e.to_string())}),
                    }
                } else {
                    CommandResponse {
                        tid: cmd.tid,
                        cmd: cmd.cmd,
                        data: json!({"status": "error", "reason": "stack_not_initialized"}),
                    }
                }
            }
            _ => CommandResponse {
                tid: cmd.tid,
                cmd: cmd.cmd,
                data: json!({ "status": "error", "reason": "unknown_command" }),
            },
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = LocalRuntime::new()?;
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
