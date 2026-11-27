//! The simulated air. Simulated radios connect over TCP, and every frame one of them
//! transmits is relayed to all the others. Radios filter by their own channel and
//! receive state; the medium keeps no radio state.

mod zep;

use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};
use ziggurat_ieee_802154::types::Eui64;
use ziggurat_sim_proto::{Frame, MediumMessage, NodeMessage, read_message, write_message};

use crate::zep::Zep;

/// Frames queued for a node that is not reading are dropped past this, like a radio
/// whose receive buffer overflows. It also keeps one stalled node from stalling the air.
const RX_QUEUE_SIZE: usize = 256;

#[derive(Parser, Debug)]
#[command(about = "Simulated 802.15.4 medium")]
struct Args {
    /// TCP listen address for simulated radios
    #[arg(long, default_value = "0.0.0.0:9997")]
    listen: SocketAddr,

    /// Also send every frame as ZEP to this UDP address, for Wireshark: a multicast
    /// group such as 239.255.0.1:17754, or 127.0.0.1:17754
    #[arg(long)]
    zep: Option<SocketAddr>,

    /// Log level (RUST_LOG still overrides, with per-module filters)
    #[arg(long, default_value_t = LevelFilter::INFO)]
    log_level: LevelFilter,
}

struct Node {
    eui64: Eui64,
    name: String,
    rx_queue: mpsc::Sender<Frame>,
}

struct Medium {
    nodes: Mutex<HashMap<u64, Node>>,
    zep: Option<Zep>,
}

impl Medium {
    /// Registers a node, unless another connected node already has its EUI64.
    fn join(&self, id: u64, node: Node) -> bool {
        let mut nodes = self.nodes.lock().unwrap();

        if nodes.values().any(|other| other.eui64 == node.eui64) {
            return false;
        }

        nodes.insert(id, node);
        true
    }

    fn leave(&self, id: u64) {
        self.nodes.lock().unwrap().remove(&id);
    }

    /// Queues the frame for every node except the sender. The lock makes every node
    /// see transmissions in the same order.
    fn transmit(&self, sender: u64, frame: &Frame) {
        let nodes = self.nodes.lock().unwrap();

        if let Some(zep) = &self.zep {
            zep.send(sender as u16, frame);
        }

        for (_, node) in nodes.iter().filter(|(id, _)| **id != sender) {
            if node.rx_queue.try_send(frame.clone()).is_err() {
                warn!("{}: receive queue full, dropping a frame", node.name);
            }
        }
    }
}

async fn serve_node(medium: Arc<Medium>, id: u64, stream: TcpStream, peer: SocketAddr) {
    // An ACK makes a round trip through the medium, so do not let Nagle delay it
    stream.set_nodelay(true).unwrap();
    let (mut reader, writer) = stream.into_split();

    let (eui64, name) = match read_message::<NodeMessage>(&mut reader).await {
        Ok(Some(NodeMessage::Hello { eui64, name })) => (eui64, name),
        Ok(Some(message)) => {
            warn!("{peer}: expected Hello, got {message:?}");
            return;
        }
        Ok(None) => return,
        Err(err) => {
            warn!("{peer}: {err}");
            return;
        }
    };

    let (rx_queue, rx_receiver) = mpsc::channel(RX_QUEUE_SIZE);

    if !medium.join(
        id,
        Node {
            eui64,
            name: name.clone(),
            rx_queue,
        },
    ) {
        warn!("{name} ({eui64:?}, {peer}): rejected, another node has this EUI64");
        return;
    }

    info!("{name} ({eui64:?}, {peer}): joined as ZEP device {id}");

    let forward = tokio::spawn(forward_frames(writer, rx_receiver));
    let result = relay_frames(&medium, id, &name, &mut reader).await;

    medium.leave(id);
    forward.abort();

    match result {
        Ok(()) => info!("{name}: left"),
        Err(err) => warn!("{name}: dropped: {err}"),
    }
}

async fn relay_frames(
    medium: &Medium,
    id: u64,
    name: &str,
    reader: &mut OwnedReadHalf,
) -> Result<(), String> {
    loop {
        match read_message::<NodeMessage>(reader).await {
            Ok(Some(NodeMessage::Tx(frame))) => {
                debug!("{name}: TX ch {}: {:02x?}", frame.channel, &frame.psdu[..]);
                medium.transmit(id, &frame);
            }
            Ok(Some(message)) => return Err(format!("unexpected {message:?}")),
            Ok(None) => return Ok(()),
            Err(err) => return Err(err.to_string()),
        }
    }
}

async fn forward_frames(mut writer: OwnedWriteHalf, mut rx_receiver: mpsc::Receiver<Frame>) {
    while let Some(frame) = rx_receiver.recv().await {
        if write_message(&mut writer, &MediumMessage::Rx(frame))
            .await
            .is_err()
        {
            // The reader side sees the same broken connection and cleans up
            return;
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(args.log_level.to_string()));
    let timer = ChronoLocal::new("%Y-%m-%dT%H:%M:%S%.6f%:z".to_string());
    tracing_subscriber::registry()
        .with(fmt::layer().with_timer(timer).with_filter(filter))
        .init();

    let listener = TcpListener::bind(args.listen).await.unwrap();
    info!("Listening on {}", args.listen);

    if let Some(zep) = args.zep {
        info!("Sending frames as ZEP to {zep}");
    }

    let medium = Arc::new(Medium {
        nodes: Mutex::new(HashMap::new()),
        zep: args.zep.map(Zep::new),
    });

    let mut next_id = 0;

    loop {
        let (stream, peer) = listener.accept().await.unwrap();
        tokio::spawn(serve_node(medium.clone(), next_id, stream, peer));
        next_id += 1;
    }
}
