use log::LevelFilter;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serial2::Settings;
use serial2_tokio::SerialPort;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, broadcast, mpsc};

use ziggurat::ieee_802154::Ieee802154Frame;
use ziggurat::spinel::SpinelPropertyId;
use ziggurat::spinel_client::{SpinelClient, SpinelRxFrame};
use ziggurat::types::{Eui64, Key, Nwk, PanId};
use ziggurat::zigbee_stack::ZigbeeStack;

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

pub struct ZigguratServer {
    zigbee_stack: Arc<Mutex<ZigbeeStack>>,
    notify_tx: broadcast::Sender<serde_json::Value>,
}

impl ZigguratServer {
    pub async fn new(serial_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Open a serial port
        let port = SerialPort::open(serial_path, |mut settings: Settings| {
            settings.set_raw();
            settings.set_baud_rate(460_800)?;
            Ok(settings)
        })?;

        // Connect the Spinel client to the port
        let spinel = SpinelClient::new(port);
        spinel.spawn_reader();

        // Start the radio via the stack
        let zigbee_stack = Arc::new(Mutex::new(ZigbeeStack::new(spinel)));

        {
            let mut stack = zigbee_stack.lock().await;
            stack.start_radio().await;
        }

        // Spawn the receiver loop in the background
        {
            let stack = Arc::clone(&zigbee_stack);
            tokio::spawn(async move {
                ZigbeeStack::run_802154_receiver(stack).await;
            });
        }

        // Create a channel for notification events
        let (notify_tx, _notify_rx) = broadcast::channel::<serde_json::Value>(100);

        let server = ZigguratServer {
            zigbee_stack: zigbee_stack,
            notify_tx: notify_tx,
        };

        Ok(server)
    }

    pub async fn run_tcp_server(&self, listen_addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        log::debug!("Listening for TCP connections on {}", listen_addr);

        loop {
            let (socket, addr) = listener.accept().await?;
            log::debug!("New TCP client from {}", addr);

            let notify_rx = self.notify_tx.subscribe();

            let server = self.clone();

            tokio::spawn(async move {
                if let Err(e) = server.handle_client(socket, addr, notify_rx).await {
                    log::warn!("Error handling client {}: {:?}", addr, e);
                } else {
                    log::debug!("Client {} disconnected", addr);
                }
            });
        }
    }

    async fn handle_client(
        self,
        mut stream: TcpStream,
        addr: SocketAddr,
        mut notify_rx: broadcast::Receiver<serde_json::Value>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (reader, mut writer) = stream.split();
        let mut reader = BufReader::new(reader);

        let mut line = String::new();

        loop {
            line.clear();
            tokio::select! {
                read_result = reader.read_line(&mut line) => {
                    let n = read_result?;
                    if n == 0 {
                        // EOF
                        break;
                    }
                    match serde_json::from_str::<CommandRequest>(line.trim()) {
                        Ok(cmd) => {
                            log::debug!("Received command from {}: {:?}", addr, cmd);
                            let resp = self.process_command(cmd).await;
                            let resp_str = serde_json::to_string(&resp)?;
                            log::debug!("Sending response: {:?}", resp_str);
                            writer.write_all(resp_str.as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                        },
                        Err(e) => {
                            log::warn!("JSON parse error from {}: {:?}", addr, e);
                            let err_response = json!({
                                "tid": 0,
                                "cmd": "error",
                                "data": {
                                    "reason": "invalid_json",
                                    "details": e.to_string()
                                }
                            });
                            writer.write_all(err_response.to_string().as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                        }
                    }
                }

                broadcast_event = notify_rx.recv() => {
                    match broadcast_event {
                        Ok(event) => {
                            let event_str = event.to_string();
                            writer.write_all(event_str.as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            log::warn!("Client {} lagged {} messages, skipping...", addr, count);
                            continue;
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

    async fn process_command(&self, cmd: CommandRequest) -> CommandResponse {
        match cmd.cmd.as_str() {
            "set_network_settings" => {
                let channel = cmd.data.get("channel").map(|v| v.as_u64().unwrap() as u8);
                let nwk_update_id = cmd
                    .data
                    .get("nwk_update_id")
                    .map(|v| v.as_u64().unwrap() as u8);
                let pan_id = cmd
                    .data
                    .get("pan_id")
                    .map(|v| PanId::from_hex(v.as_str().unwrap()));
                let extended_pan_id = cmd
                    .data
                    .get("extended_pan_id")
                    .map(|v| Eui64::from_hex(v.as_str().unwrap()));
                let nwk_address = cmd
                    .data
                    .get("nwk_address")
                    .map(|v| Nwk::from_hex(v.as_str().unwrap()));
                let ieee_address = cmd
                    .data
                    .get("ieee_address")
                    .map(|v| Eui64::from_hex(v.as_str().unwrap()));
                let network_key = cmd
                    .data
                    .get("network_key")
                    .map(|v| Key::from_hex(v.as_str().unwrap()));
                let network_key_seq = cmd
                    .data
                    .get("network_key_seq")
                    .map(|v| v.as_u64().unwrap() as u8);
                let network_key_tx_counter = cmd
                    .data
                    .get("network_key_tx_counter")
                    .map(|v| v.as_u64().unwrap() as u32);

                {
                    log::info!("Acquiring Zigbee stack lock...");
                    let stack = Arc::clone(&self.zigbee_stack);
                    let mut zigbee = stack.lock().await;
                    log::info!("Setting network settings...");
                    zigbee
                        .set_network_settings(
                            channel.unwrap(),
                            nwk_update_id.unwrap(),
                            pan_id.unwrap(),
                            extended_pan_id.unwrap(),
                            nwk_address.unwrap(),
                            ieee_address.unwrap(),
                            network_key.unwrap(),
                            network_key_seq.unwrap(),
                            network_key_tx_counter.unwrap(),
                        )
                        .await;
                    log::info!("Done!");
                }

                CommandResponse {
                    tid: cmd.tid,
                    cmd: cmd.cmd,
                    data: json!({"status": "success"}),
                }
            }

            "send_aps_command" => {
                let destination_nwk = cmd
                    .data
                    .get("destination_nwk")
                    .map(|v| Nwk::from_hex(v.as_str().unwrap()));
                let profile_id = cmd
                    .data
                    .get("profile_id")
                    .map(|v| v.as_u64().unwrap() as u16);
                let cluster_id = cmd
                    .data
                    .get("cluster_id")
                    .map(|v| v.as_u64().unwrap() as u16);
                let src_ep = cmd.data.get("src_ep").map(|v| v.as_u64().unwrap() as u8);
                let dst_ep = cmd.data.get("dst_ep").map(|v| v.as_u64().unwrap() as u8);
                let data = cmd
                    .data
                    .get("data")
                    .map(|v| hex::decode(v.as_str().unwrap()).unwrap());

                {
                    log::info!("Acquiring Zigbee stack lock...");
                    let stack = Arc::clone(&self.zigbee_stack);
                    let mut zigbee = stack.lock().await;
                    log::info!("Sending APS command...");
                    zigbee
                        .send_aps_command(
                            destination_nwk.unwrap(),
                            profile_id.unwrap(),
                            cluster_id.unwrap(),
                            src_ep.unwrap(),
                            dst_ep.unwrap(),
                            data.unwrap(),
                        )
                        .await;
                    log::info!("Done!");
                }

                CommandResponse {
                    tid: cmd.tid,
                    cmd: cmd.cmd,
                    data: json!({"status": "success"}),
                }
            }

            _ => CommandResponse {
                tid: cmd.tid,
                cmd: cmd.cmd,
                data: json!({
                    "status": "error",
                    "reason": "unknown_command",
                }),
            },
        }
    }
}

impl Clone for ZigguratServer {
    fn clone(&self) -> Self {
        ZigguratServer {
            zigbee_stack: Arc::clone(&self.zigbee_stack),
            notify_tx: self.notify_tx.clone(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .format_timestamp_micros()
        .filter(None, LevelFilter::Debug)
        //.filter_module("ziggurat::spinel", LevelFilter::Info)
        .init();

    // Grab arguments
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

    // Create and configure our Zigbee server
    let server = ZigguratServer::new(serial_path).await?;

    // Now run our async TCP server
    server.run_tcp_server(&tcp_listen_addr).await?;

    Ok(())
}
