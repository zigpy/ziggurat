use log::LevelFilter;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serial2::Settings;
use serial2_tokio::SerialPort;
use std::env;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::{broadcast, oneshot};

use ziggurat::ieee_802154::Ieee802154Frame;
use ziggurat::spinel::SpinelPropertyId;
use ziggurat::spinel_client::{SpinelClient, SpinelRxFrame};
use ziggurat::types::{Eui64, Key, Nwk, PanId};
use ziggurat::zigbee_stack::{ZigbeeCommand, ZigbeeNotification, ZigbeeStack, ZigbeeStackActor};

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
    // Outgoing Zigbee stack commands
    zigbee_tx: mpsc::Sender<ZigbeeCommand>,

    // Incoming Zigbee stack notification
    notification_rx: broadcast::Receiver<ZigbeeNotification>,
}

impl ZigguratServer {
    pub async fn new(serial_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Open a serial port
        let port = SerialPort::open(serial_path, |mut settings: Settings| {
            settings.set_raw();
            settings.set_baud_rate(460_800)?;
            Ok(settings)
        })?;

        let spinel = SpinelClient::new(port);
        spinel.spawn_reader();

        let stack = ZigbeeStack::new(spinel);
        let (actor, zigbee_tx, notification_rx) = ZigbeeStackActor::new(stack).await;
        tokio::spawn(actor.run());

        Ok(ZigguratServer {
            zigbee_tx: zigbee_tx,
            notification_rx: notification_rx,
        })
    }

    pub async fn run_tcp_server(&self, listen_addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        log::debug!("Listening for TCP connections on {}", listen_addr);

        loop {
            let (socket, addr) = listener.accept().await?;
            log::debug!("New TCP client from {}", addr);

            let server = self.clone();

            tokio::spawn(async move {
                if let Err(e) = server.handle_client(socket, addr).await {
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (reader, mut writer) = stream.split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        let mut notification_rx = self.notification_rx.resubscribe();

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
                // Build the oneshot channel
                let (resp_tx, resp_rx) = oneshot::channel();
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

                // Send the command to the Zigbee actor
                let command = ZigbeeCommand::SetNetworkSettings {
                    nwk_channel: channel,
                    nwk_update_id,
                    nwk_pan_id: pan_id,
                    nwk_extended_pan_id: extended_pan_id,
                    nwk_network_address: nwk_address,
                    nwk_ieee_address: ieee_address,
                    key: network_key,
                    key_seq_number: network_key_seq,
                    outgoing_frame_counter: network_key_tx_counter,
                    resp: resp_tx,
                };
                let _ = self.zigbee_tx.send(command).await;
                let status = resp_rx.await.unwrap_or(Err("Unknown error".to_string()));

                CommandResponse {
                    tid: cmd.tid,
                    cmd: cmd.cmd,
                    data: json!({"status": if status.is_ok() { "success" } else { "error" } }),
                }
            }
            "send_aps_command" => {
                let (resp_tx, resp_rx) = oneshot::channel();
                let destination_nwk =
                    Nwk::from_hex(cmd.data.get("destination_nwk").unwrap().as_str().unwrap());
                let profile_id = cmd.data.get("profile_id").unwrap().as_u64().unwrap() as u16;
                let cluster_id = cmd.data.get("cluster_id").unwrap().as_u64().unwrap() as u16;
                let src_ep = cmd.data.get("src_ep").unwrap().as_u64().unwrap() as u8;
                let dst_ep = cmd.data.get("dst_ep").unwrap().as_u64().unwrap() as u8;
                let data = hex::decode(cmd.data.get("data").unwrap().as_str().unwrap()).unwrap();

                let command = ZigbeeCommand::SendApsCommand {
                    destination: destination_nwk,
                    profile_id,
                    cluster_id,
                    src_ep,
                    dst_ep,
                    data,
                    resp: resp_tx,
                };
                let _ = self.zigbee_tx.send(command).await;
                let status = resp_rx.await.unwrap_or(Err("Unknown error".to_string()));

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

impl Clone for ZigguratServer {
    fn clone(&self) -> Self {
        ZigguratServer {
            zigbee_tx: self.zigbee_tx.clone(),
            notification_rx: self.notification_rx.resubscribe(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let server = ZigguratServer::new(serial_path).await?;
    server.run_tcp_server(&tcp_listen_addr).await?;
    Ok(())
}
