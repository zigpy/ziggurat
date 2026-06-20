//! The simulation medium server: a virtual shared radio channel.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use ziggurat_ieee_802154::{Ieee802154Address, Ieee802154Frame};
use ziggurat_radio_sim::proto::{HubMsg, NodeMsg, Position, read_frame, write_frame};

const TX_POWER_DBM: f32 = 8.0;
const REFERENCE_LOSS_DBM: f32 = 40.0;
const PATH_LOSS_EXPONENT: f32 = 3.0;
const RX_SENSITIVITY_DBM: f32 = -95.0;
/// dB above sensitivity at which the noise-driven reception probability crosses 50%.
const NOISE_TRANSITION_DB: f32 = 5.0;

/// Log-distance path loss: `Some((rssi, lqi))` if `rx` is in range of `tx`, else `None`.
fn link_quality(tx: Position, rx: Position) -> Option<(i8, u8)> {
    let distance = (tx.x - rx.x).hypot(tx.y - rx.y).max(1.0);
    let rssi =
        (-10.0 * PATH_LOSS_EXPONENT).mul_add(distance.log10(), TX_POWER_DBM - REFERENCE_LOSS_DBM);
    if rssi < RX_SENSITIVITY_DBM {
        return None;
    }
    let lqi = ((rssi - RX_SENSITIVITY_DBM) / -RX_SENSITIVITY_DBM).clamp(0.0, 1.0) * 255.0;
    Some((rssi.clamp(-128.0, 0.0) as i8, lqi as u8))
}

/// Logistic packet reception rate: marginal links drop frames, strong links don't.
fn reception_probability(rssi: i8) -> f32 {
    let margin = f32::from(rssi) - RX_SENSITIVITY_DBM - NOISE_TRANSITION_DB;
    1.0 / (1.0 + (-margin).exp())
}

struct Node {
    channel: Option<u8>,
    position: Option<Position>,
    short: Option<u16>,
    extended: Option<[u8; 8]>,
    outbound: mpsc::Sender<HubMsg>,
}

impl Node {
    fn is_addressed_by(&self, dest: Option<Ieee802154Address>) -> bool {
        match dest {
            Some(Ieee802154Address::Nwk(nwk)) => self.short == Some(nwk.0),
            Some(Ieee802154Address::Eui64(eui64)) => self.extended == Some(eui64.0),
            None => false,
        }
    }
}

type Medium = Arc<Mutex<HashMap<u64, Node>>>;

/// A candidate receiver gathered for one transmit: its channel, position, and whether
/// the frame's MAC destination addresses it.
type Recipient = (mpsc::Sender<HubMsg>, Position, bool);

/// Whether a frame survives the link: in range and not lost to noise this attempt.
fn delivered(source: Position, destination: Position) -> Option<(i8, u8)> {
    let (rssi, lqi) = link_quality(source, destination)?;
    (rand::random::<f32>() < reception_probability(rssi)).then_some((rssi, lqi))
}

/// Serve the medium until the listener errors. Each accepted node runs independently.
pub async fn serve(listener: TcpListener) -> std::io::Result<()> {
    let medium: Medium = Arc::new(Mutex::new(HashMap::new()));

    let mut next_id = 0u64;
    loop {
        let (stream, _) = listener.accept().await?;
        let id = next_id;
        next_id += 1;
        tokio::spawn(handle_node(id, stream, Arc::clone(&medium)));
    }
}

#[allow(clippy::significant_drop_tightening)]
async fn handle_node(id: u64, stream: TcpStream, medium: Medium) {
    let (mut read_half, mut write_half) = stream.into_split();

    let (outbound, mut outbound_rx) = mpsc::channel::<HubMsg>(64);
    let writer = tokio::spawn(async move {
        while let Some(msg) = outbound_rx.recv().await {
            if write_frame(&mut write_half, &msg.encode()).await.is_err() {
                break;
            }
        }
    });

    let reply_to = outbound.clone();
    medium.lock().insert(
        id,
        Node {
            channel: None,
            position: None,
            short: None,
            extended: None,
            outbound,
        },
    );

    while let Ok(bytes) = read_frame(&mut read_half).await {
        let Some(msg) = NodeMsg::decode(&bytes) else {
            continue;
        };
        match msg {
            NodeMsg::SetPosition(position) => {
                if let Some(node) = medium.lock().get_mut(&id) {
                    node.position = Some(position);
                }
            }
            NodeMsg::SetAddresses { short, extended } => {
                if let Some(node) = medium.lock().get_mut(&id) {
                    node.short = Some(short);
                    node.extended = Some(extended);
                }
            }
            NodeMsg::Listen { channel } => {
                if let Some(node) = medium.lock().get_mut(&id) {
                    node.channel = Some(channel);
                }
            }
            NodeMsg::Transmit {
                id: tx_id,
                channel,
                psdu,
            } => {
                let Ok(frame) = Ieee802154Frame::from_bytes_without_fcs(&psdu) else {
                    let _ = reply_to
                        .send(HubMsg::TxResult {
                            id: tx_id,
                            acked: false,
                        })
                        .await;
                    continue;
                };
                let ack_request = frame.header().frame_control.ack_request;
                let dest = frame.header().dest_address;

                let (source, recipients) = {
                    let medium = medium.lock();
                    let source = medium.get(&id).and_then(|node| node.position);
                    let recipients: Vec<Recipient> = medium
                        .iter()
                        .filter(|(other, node)| **other != id && node.channel == Some(channel))
                        .filter_map(|(_, node)| {
                            Some((
                                node.outbound.clone(),
                                node.position?,
                                node.is_addressed_by(dest),
                            ))
                        })
                        .collect();
                    (source, recipients)
                };
                let Some(source) = source else {
                    let _ = reply_to
                        .send(HubMsg::TxResult {
                            id: tx_id,
                            acked: false,
                        })
                        .await;
                    continue;
                };

                // A unicast is acked only if its addressed next hop receives it; a
                // broadcast reaches every in-range listener and is never acked.
                let acked = if ack_request {
                    match recipients.into_iter().find(|(_, _, addressed)| *addressed) {
                        Some((outbound, position, _)) => match delivered(source, position) {
                            Some((rssi, lqi)) => {
                                let _ = outbound
                                    .send(HubMsg::Frame {
                                        channel,
                                        rssi,
                                        lqi,
                                        psdu,
                                    })
                                    .await;
                                true
                            }
                            None => false,
                        },
                        None => false,
                    }
                } else {
                    for (outbound, position, _) in recipients {
                        if let Some((rssi, lqi)) = delivered(source, position) {
                            let _ = outbound
                                .send(HubMsg::Frame {
                                    channel,
                                    rssi,
                                    lqi,
                                    psdu: psdu.clone(),
                                })
                                .await;
                        }
                    }
                    true
                };

                let _ = reply_to.send(HubMsg::TxResult { id: tx_id, acked }).await;
            }
        }
    }

    medium.lock().remove(&id);
    writer.abort();
}
