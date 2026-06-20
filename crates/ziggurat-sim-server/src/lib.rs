//! The simulation medium server: a virtual shared radio channel.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use ziggurat_radio_sim::proto::{HubMsg, NodeMsg, Position, read_frame, write_frame};

const TX_POWER_DBM: f32 = 8.0;
const REFERENCE_LOSS_DBM: f32 = 40.0;
const PATH_LOSS_EXPONENT: f32 = 3.0;
const RX_SENSITIVITY_DBM: f32 = -95.0;

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

struct Node {
    channel: Option<u8>,
    position: Option<Position>,
    outbound: mpsc::Sender<HubMsg>,
}

type Medium = Arc<Mutex<HashMap<u64, Node>>>;

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

    medium.lock().insert(
        id,
        Node {
            channel: None,
            position: None,
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
            NodeMsg::Listen { channel } => {
                if let Some(node) = medium.lock().get_mut(&id) {
                    node.channel = Some(channel);
                }
            }
            NodeMsg::Transmit { channel, psdu } => {
                let recipients: Vec<(mpsc::Sender<HubMsg>, (i8, u8))> = {
                    let medium = medium.lock();
                    let Some(source) = medium.get(&id).and_then(|node| node.position) else {
                        continue;
                    };
                    medium
                        .iter()
                        .filter(|(other, node)| **other != id && node.channel == Some(channel))
                        .filter_map(|(_, node)| Some((node.outbound.clone(), node.position?)))
                        .filter_map(|(tx, position)| {
                            link_quality(source, position).map(|link| (tx, link))
                        })
                        .collect()
                };

                for (outbound, (rssi, lqi)) in recipients {
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
        }
    }

    medium.lock().remove(&id);
    writer.abort();
}
