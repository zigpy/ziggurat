//! A simulated RCP. A host (zigbeed, Ziggurat) talks Spinel to it over a pty or TCP as if
//! it were a real radio, and its frames go through the simulation medium.

mod pty;
mod rcp;

use clap::{ArgGroup, Parser};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};
use tracing::{info, warn};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};
use ziggurat_ieee_802154::types::Eui64;
use ziggurat_sim_proto::{MediumMessage, NodeMessage, read_message, write_message};
use ziggurat_spinel::{HdlcDecoder, HdlcLiteFrame};

use crate::pty::Pty;
use crate::rcp::{Output, Rcp};

#[derive(Parser, Debug)]
#[command(about = "Simulated OpenThread RCP on the simulation medium")]
#[command(group(ArgGroup::new("host").required(true).args(["pty", "listen"])))]
struct Args {
    /// The radio's EUI64, as hex in display order
    #[arg(long)]
    eui64: String,

    /// Name in the medium's logs; defaults to the EUI64
    #[arg(long)]
    name: Option<String>,

    /// The simulation medium
    #[arg(long, default_value = "127.0.0.1:9997")]
    medium: String,

    /// Serve the host on a pty, symlinked at this path
    #[arg(long)]
    pty: Option<PathBuf>,

    /// Serve the host over TCP, for `tcp://` RCP URLs
    #[arg(long)]
    listen: Option<SocketAddr>,

    /// How long to wait for an ACK before retrying. Every ACK makes a round trip
    /// through the medium, so this is far longer than on air.
    #[arg(long, default_value_t = 20)]
    ack_timeout_ms: u64,

    /// Log level (RUST_LOG still overrides, with per-module filters)
    #[arg(long, default_value_t = LevelFilter::INFO)]
    log_level: LevelFilter,
}

enum Host {
    Pty(Pty),
    Tcp {
        listener: TcpListener,
        stream: Option<TcpStream>,
    },
}

impl Host {
    /// Waits for bytes from the host. Returns 0 when a TCP host connects or leaves.
    async fn read(&mut self, buffer: &mut [u8]) -> usize {
        match self {
            Self::Pty(pty) => pty.read(buffer).await,
            Self::Tcp { listener, stream } => match stream {
                None => {
                    let (connection, peer) = listener.accept().await.unwrap();
                    connection.set_nodelay(true).unwrap();
                    info!("Host connected from {peer}");
                    *stream = Some(connection);
                    0
                }
                Some(connection) => match connection.read(buffer).await {
                    Ok(0) | Err(_) => {
                        info!("Host disconnected");
                        *stream = None;
                        0
                    }
                    Ok(read) => read,
                },
            },
        }
    }

    /// Writes without waiting; see [`Pty::write`].
    fn write(&mut self, bytes: &[u8]) {
        match self {
            Self::Pty(pty) => pty.write(bytes),
            Self::Tcp { stream, .. } => {
                let Some(connection) = stream else {
                    return;
                };

                match connection.try_write(bytes) {
                    Ok(written) if written == bytes.len() => {}
                    Ok(written) => {
                        warn!(
                            "Host is not reading, dropped {} bytes",
                            bytes.len() - written
                        );
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        warn!("Host is not reading, dropped {} bytes", bytes.len());
                    }
                    Err(err) => {
                        info!("Host disconnected: {err}");
                        *stream = None;
                    }
                }
            }
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

    let eui64 = Eui64::from_hex(&args.eui64);
    let name = args.name.unwrap_or(args.eui64);

    let medium = TcpStream::connect(&args.medium).await.unwrap();
    medium.set_nodelay(true).unwrap();
    let (mut medium_reader, mut medium_writer) = medium.into_split();
    write_message(&mut medium_writer, &NodeMessage::Hello { eui64, name })
        .await
        .unwrap();
    info!("Connected to the medium at {}", args.medium);

    // A read from the medium is not cancel-safe, so it gets a task of its own
    let (air_sender, mut air_receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            match read_message::<MediumMessage>(&mut medium_reader)
                .await
                .unwrap()
            {
                Some(MediumMessage::Rx(frame)) => air_sender.send(frame).unwrap(),
                None => panic!("the medium closed the connection"),
            }
        }
    });

    let mut host = match (args.pty, args.listen) {
        (Some(path), None) => {
            info!("Serving the host on {}", path.display());
            Host::Pty(Pty::open(&path))
        }
        (None, Some(address)) => {
            info!("Serving the host on tcp://{address}");
            Host::Tcp {
                listener: TcpListener::bind(address).await.unwrap(),
                stream: None,
            }
        }
        _ => unreachable!("clap requires exactly one host transport"),
    };

    let start = Instant::now();
    let mut rcp = Rcp::new(eui64, Duration::from_millis(args.ack_timeout_ms));
    let mut decoder = HdlcDecoder::new();
    let mut buffer = vec![0; 4096];
    let mut frame = Vec::new();

    loop {
        let deadline = rcp.next_deadline().map(|deadline| start + deadline);

        tokio::select! {
            read = host.read(&mut buffer) => {
                if read == 0 {
                    decoder = HdlcDecoder::new();
                } else {
                    decoder.push(&buffer[..read]);

                    while decoder.next_frame_into(&mut frame) {
                        rcp.handle_host_frame(&frame, start.elapsed());
                    }
                }
            }
            air = air_receiver.recv() => rcp.handle_air_frame(air.unwrap(), start.elapsed()),
            () = sleep_until(deadline.unwrap_or(start)), if deadline.is_some() => {
                rcp.handle_timeout(start.elapsed());
            }
        }

        while let Some(output) = rcp.poll_output() {
            match output {
                Output::Host(data) => host.write(&HdlcLiteFrame { data }.to_bytes_with_flags()),
                Output::Air(frame) => write_message(&mut medium_writer, &NodeMessage::Tx(frame))
                    .await
                    .unwrap(),
            }
        }
    }
}
