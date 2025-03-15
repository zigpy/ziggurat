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
    spinel: Arc<SpinelClient>,
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
        let spinel = Arc::new(SpinelClient::new(port));
        spinel.spawn_reader();

        // Enable the PHY and set up the radio, save for the channel
        spinel
            .prop_value_set(SpinelPropertyId::PhyEnabled as u32, vec![true as u8])
            .await
            .expect("Failed to enable the PHY");
        spinel
            .prop_value_set(SpinelPropertyId::MacPromiscuousMode as u32, vec![2])
            .await
            .expect("Failed to set the MAC promiscuous mode");
        spinel
            .prop_value_set(
                SpinelPropertyId::MacRawStreamEnabled as u32,
                vec![true as u8],
            )
            .await
            .expect("Failed to enable the RAW stream");

        let zigbee_stack = ZigbeeStack::new();

        // Create a channel for notification events
        let (notify_tx, _notify_rx) = broadcast::channel::<serde_json::Value>(100);

        let server = ZigguratServer {
            spinel: spinel,
            zigbee_stack: Arc::new(Mutex::new(zigbee_stack)),
            notify_tx: notify_tx,
        };

        Ok(server)
    }

    pub async fn spawn_zigbee_receiver(&self) {
        let (stream_raw_tx, mut stream_raw_rx) = mpsc::channel(32);

        {
            // Lock the protocol and set the property update receiver for StreamRaw
            let mut guard = self.spinel.protocol.lock().await;
            guard.set_property_update_receiver(
                SpinelPropertyId::StreamRaw as u32,
                stream_raw_tx.clone(),
            );
        }

        let zigbee_stack = Arc::clone(&self.zigbee_stack);
        let notify_tx = self.notify_tx.clone();

        // Spawn a new task
        tokio::spawn(async move {
            log::debug!("Spawning Zigbee/Spinel receive loop...");
            while let Some(raw_frame) = stream_raw_rx.recv().await {
                let packet = match SpinelRxFrame::from_bytes(&raw_frame.value) {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!("Error parsing spinel frame: {:?}", e);
                        continue;
                    }
                };

                if packet.psdu.len() < 2 {
                    log::warn!("Packet too short to contain FCS");
                    continue;
                }
                let frame_data = &packet.psdu[..packet.psdu.len() - 2];

                let ieee802154_frame = match Ieee802154Frame::from_bytes_without_fcs(frame_data) {
                    Ok(f) => f,
                    Err(e) => {
                        log::warn!("Error parsing IEEE 802.15.4 frame: {:?}", e);
                        continue;
                    }
                };

                log::debug!("Received 802.15.4 frame: {:?}", ieee802154_frame);

                // Pass the 802.15.4 frame to the Zigbee stack for decryption
                let maybe_zigbee_frame = {
                    let mut zs = zigbee_stack.lock().await;
                    zs.receive_802154_frame(&ieee802154_frame)
                };

                if maybe_zigbee_frame.is_none() {
                    continue;
                }

                let zigbee_frame = maybe_zigbee_frame.unwrap();

                // Broadcast the received packet to listening clients
                let async_event = json!({
                    "tid": 0,
                    "cmd": "packet_received",
                    "data": {
                        "destination": zigbee_frame.nwk_header.destination.as_u16(),
                        "source": zigbee_frame.nwk_header.source.as_u16(),
                        "radius": zigbee_frame.nwk_header.radius,
                        "sequence_number": zigbee_frame.nwk_header.sequence_number,
                        //"destination_ieee": zigbee_frame.nwk_header.destination_ieee.map(|v| hex::encode(v.serialize())),
                        //"source_ieee": zigbee_frame.nwk_header.source_ieee.map(|v| hex::encode(v.serialize())),
                        //"source_route": zigbee_frame.nwk_header.source_route,
                        "payload": hex::encode(zigbee_frame.payload),
                    }
                });

                // If no subscribers, ignore error
                let _ = notify_tx.send(async_event);
            }
        });
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
                // 1) Inbound commands
                read_result = reader.read_line(&mut line) => {
                    let n = read_result?;
                    if n == 0 {
                        // EOF
                        break;
                    }
                    match serde_json::from_str::<CommandRequest>(line.trim()) {
                        Ok(cmd) => {
                            let resp = self.process_command(cmd).await;
                            let resp_str = serde_json::to_string(&resp)?;
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
                // 2) Outbound async notifications (like packet_received)
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

                // Add the parameters to the stack
                {
                    let mut zigbee = self.zigbee_stack.lock().await;

                    if let Some(v) = nwk_update_id {
                        zigbee.nib.nwk_update_id = v;
                    }
                    if let Some(v) = pan_id {
                        zigbee.nib.nwk_pan_id = v;
                    }
                    if let Some(v) = extended_pan_id {
                        zigbee.nib.nwk_extended_pan_id = v;
                    }
                    if let Some(v) = nwk_address {
                        zigbee.nib.nwk_network_address = v;
                    }
                    if let Some(v) = ieee_address {
                        zigbee.nib.nwk_ieee_address = v;
                    }
                    if let Some(v) = network_key {
                        zigbee.nib.nwk_security_material_primary.key = v;
                    }
                    if let Some(v) = network_key_seq {
                        zigbee.nib.nwk_security_material_primary.key_seq_number = v;
                    }
                    if let Some(v) = network_key_tx_counter {
                        zigbee
                            .nib
                            .nwk_security_material_primary
                            .outgoing_frame_counter = v;
                    }

                    // Update the MAC layer with the new network settings to enable auto-ACK
                    self.spinel
                        .prop_value_set(
                            SpinelPropertyId::Mac154Laddr as u32,
                            zigbee.nib.nwk_ieee_address.to_bytes().to_vec(),
                        )
                        .await
                        .expect("Failed to set the MAC IEEE address");

                    self.spinel
                        .prop_value_set(
                            SpinelPropertyId::Mac154Saddr as u32,
                            zigbee.nib.nwk_network_address.to_bytes().to_vec(),
                        )
                        .await
                        .expect("Failed to set the MAC NWK address");

                    self.spinel
                        .prop_value_set(
                            SpinelPropertyId::Mac154Panid as u32,
                            zigbee.nib.nwk_pan_id.to_bytes().to_vec(),
                        )
                        .await
                        .expect("Failed to set the MAC PAN ID");
                }

                CommandResponse {
                    tid: cmd.tid,
                    cmd: cmd.cmd,
                    data: json!({"status": "success"}),
                }
            }

            "set_channel" => {
                let channel = cmd
                    .data
                    .get("channel")
                    .unwrap()
                    .as_number()
                    .unwrap()
                    .as_u64()
                    .unwrap() as u8;

                if channel < 11 || channel > 26 {
                    return CommandResponse {
                        tid: cmd.tid,
                        cmd: cmd.cmd,
                        data: json!({
                            "status": "error",
                            "reason": "invalid_channel",
                        }),
                    };
                }

                {
                    self.spinel
                        .prop_value_set(SpinelPropertyId::PhyChan as u32, vec![channel])
                        .await
                        .expect("Failed to set the PHY channel");
                }

                CommandResponse {
                    tid: cmd.tid,
                    cmd: cmd.cmd,
                    data: json!({"status": "success"}),
                }
            }

            // Insert more commands here
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
            spinel: Arc::clone(&self.spinel),
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

    // Spawn the Zigbee receiver loop, which processes frames from the radio
    // and broadcasts async events (tid=0).
    server.spawn_zigbee_receiver().await;

    // Now run our async TCP server
    server.run_tcp_server(&tcp_listen_addr).await?;

    Ok(())
}
