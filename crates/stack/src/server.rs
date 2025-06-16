use log::LevelFilter;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serial2::Settings;
use serial2_tokio::SerialPort;
use std::env;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::LocalRuntime;
use tokio::sync::broadcast;
use tokio::task::spawn_local;

use std::sync::Arc;

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

pub struct ZigguratServer {
    zigbee_stack: Arc<ZigbeeStack>,
    notification_rx: broadcast::Receiver<ZigbeeNotification>,
}

impl ZigguratServer {
    pub fn new(serial_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Open a serial port
        let port = SerialPort::open(serial_path, |mut settings: Settings| {
            settings.set_raw();
            settings.set_baud_rate(460_800)?;
            Ok(settings)
        })?;

        let spinel = SpinelClient::new(port);
        spinel.spawn_reader();

        let (zigbee_stack, notification_rx) = ZigbeeStack::new(spinel);
        let server = ZigguratServer {
            zigbee_stack: zigbee_stack,
            notification_rx: notification_rx,
        };

        Ok(server)
    }

    pub async fn start(&self) {
        self.zigbee_stack.run().await;
    }

    pub async fn run_tcp_server(&self, listen_addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        log::debug!("Listening for TCP connections on {}", listen_addr);

        loop {
            let (socket, addr) = listener.accept().await?;
            log::debug!("New TCP client from {}", addr);

            if let Err(e) = self.handle_client(socket, addr).await {
                log::warn!("Error handling client {}: {:?}", addr, e);
            } else {
                log::debug!("Client {} disconnected", addr);
            }
        }
    }

    // TODO replace with tokio-serde
    async fn handle_client(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut notification_rx = self.notification_rx.resubscribe();
        let mut line = String::new();

        loop {
            line.clear();

            tokio::select! {
                read_result = reader.read_line(&mut line) => {
                    let n = read_result?;
                    if n == 0 {
                        break; // EOF reached
                    }
                    match serde_json::from_str::<CommandRequest>(line.trim()) {
                        Ok(cmd) => {
                            log::debug!("Received command from {}: {:?}", addr, cmd);

                            let resp = self.process_command(cmd).await;
                            let resp_str = serde_json::to_string(&resp).unwrap();

                            log::debug!("Sending response: {:?}", resp_str);
                            writer.write_all(resp_str.as_bytes()).await.unwrap();
                            writer.write_all(b"\n").await.unwrap();
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
                notify_event = notification_rx.recv() => {
                    match notify_event {
                        Ok(ZigbeeNotification::ReceivedApsCommand {
                            source,
                            profile_id,
                            cluster_id,
                            src_ep,
                            dst_ep,
                            lqi,
                            rssi,
                            data,
                        }) => {
                            let event = json!({
                                "tid": 0,
                                "cmd": "received_aps_command",
                                "data": {
                                    "source": hex::encode(source.to_bytes()),
                                    "profile_id": profile_id,
                                    "cluster_id": cluster_id,
                                    "src_ep": src_ep,
                                    "dst_ep": dst_ep,
                                    "lqi": lqi,
                                    "rssi": rssi,
                                    "data": hex::encode(data),
                                }
                            });
                            log::debug!("Sending APS frame notification: {:?}", event);
                            writer.write_all(event.to_string().as_bytes()).await?;
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
                // Extract parameters from the data
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

                let status = self
                    .zigbee_stack
                    .set_network_settings(
                        channel,
                        nwk_update_id,
                        pan_id,
                        extended_pan_id,
                        nwk_address,
                        ieee_address,
                        network_key,
                        network_key_seq,
                        network_key_tx_counter,
                    )
                    .await;

                if status.is_ok() {
                    CommandResponse {
                        tid: cmd.tid,
                        cmd: cmd.cmd,
                        data: json!({"status": "success"}),
                    }
                } else {
                    CommandResponse {
                        tid: cmd.tid,
                        cmd: cmd.cmd,
                        data: json!({"status": "error", "reason": status.err().map(|e| e.to_string())}),
                    }
                }
            }
            "send_aps_command" => {
                let delivery_mode = match cmd.data.get("delivery_mode").unwrap().as_str().unwrap() {
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
                let data = hex::decode(cmd.data.get("data").unwrap().as_str().unwrap()).unwrap();

                let status = self
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
                    data: json!({"status": if status.is_ok() { "success" } else { "error" } }),
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

        let server = Arc::new(ZigguratServer::new(serial_path)?);

        let server_clone = server.clone();
        spawn_local(async move { server_clone.start().await });

        server.run_tcp_server(&tcp_listen_addr).await?;

        Ok(())
    })
}
