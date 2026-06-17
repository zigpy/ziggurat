use clap::{Parser, ValueEnum};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{broadcast, mpsc};
use tokio_serial::{FlowControl, SerialPortBuilderExt};
use tokio_tungstenite::tungstenite::Message;
use tracing::Instrument;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use spinel::client::SpinelClient;
use ziggurat_api::{Api, error_response, event, hello, notification_to_message};

/// Outbound messages a connection can queue before it is considered too slow and
/// disconnected. Received frames dominate the traffic; a client that cannot keep up
/// with them is broken.
const OUTBOUND_QUEUE_DEPTH: usize = 1024;

// The client wire protocol: requests carry a client-chosen correlation id; the
// server answers each request with exactly one `response`, preceded by zero or more
// `event` messages sharing the id. `notification` messages are unsolicited.

#[derive(Deserialize, Debug)]
struct Request {
    id: u64,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

pub struct ZigguratServer {
    api: Arc<Api>,
}

impl ZigguratServer {
    /// The serial port is not opened and the Zigbee stack is not created until a
    /// client sends a command that needs them.
    pub fn new(serial: SerialConfig) -> Self {
        // The factory opens the serial port on first use, building the process-lifetime
        // Spinel client. Without flow control the RCP's UART drops bytes under load,
        // corrupting host->RCP frames ("Framing error" + command timeout).
        let api = Api::new(Box::new(move || {
            let port = tokio_serial::new(&serial.device, serial.baudrate)
                .flow_control(serial.flow_control.into())
                .open_native_async()
                .map_err(|e| e.to_string())?;

            let client = Arc::new(SpinelClient::new(port));
            client.spawn_reader();
            Ok(client)
        }));

        Self { api }
    }

    pub async fn run(self: Arc<Self>, listen_addr: &str) -> std::io::Result<()> {
        match listen_addr.strip_prefix("unix:") {
            Some(path) => self.run_unix(path).await,
            None => self.run_tcp(listen_addr).await,
        }
    }

    async fn run_tcp(self: Arc<Self>, listen_addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        tracing::info!("Listening for WebSocket clients on {listen_addr}");

        loop {
            let (socket, addr) = listener.accept().await?;
            self.spawn_connection(socket, addr.to_string());
        }
    }

    async fn run_unix(self: Arc<Self>, path: &str) -> std::io::Result<()> {
        // A previous run's socket file would make the bind fail with AddrInUse
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }

        let listener = UnixListener::bind(path)?;
        tracing::info!("Listening for WebSocket clients on unix:{path}");

        // Peer addresses of UNIX sockets are unnamed: number the clients instead
        for client in 0u64.. {
            let (socket, _) = listener.accept().await?;
            self.spawn_connection(socket, format!("unix#{client}"));
        }

        unreachable!()
    }

    fn spawn_connection<S>(self: &Arc<Self>, socket: S, addr: String)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let server = self.clone();

        tokio::spawn(async move {
            if let Err(e) = server.handle_connection(socket, &addr).await {
                tracing::warn!("Connection {addr} ended with error: {e}");
            }

            tracing::info!("Client {addr} disconnected");
        });
    }

    async fn handle_connection<S>(
        self: &Arc<Self>,
        socket: S,
        addr: &str,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let websocket = tokio_tungstenite::accept_async(socket).await?;
        let (mut sink, mut stream) = websocket.split();

        tracing::info!("Client {addr} connected");

        let (outbound_tx, mut outbound_rx) =
            mpsc::channel::<serde_json::Value>(OUTBOUND_QUEUE_DEPTH);

        // All outbound traffic (responses, events, notifications) converges on a
        // single writer task, so concurrent commands never contend on the socket
        let writer = tokio::spawn(async move {
            while let Some(message) = outbound_rx.recv().await {
                if sink.send(Message::text(message.to_string())).await.is_err() {
                    break;
                }
            }

            let _ = sink.close().await;
        });

        outbound_tx.send(hello(self.api.is_configured())).await?;

        // Forward hub notifications to this connection
        let mut notification_rx = self.api.subscribe();
        let notification_outbound = outbound_tx.clone();
        let forwarder_addr = addr.to_owned();
        let notification_forwarder = tokio::spawn(async move {
            loop {
                match notification_rx.recv().await {
                    Ok(event) => {
                        let message = notification_to_message(event);

                        if notification_outbound.send(message).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        tracing::warn!("Client {forwarder_addr} lagged {count} notifications");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        while let Some(message) = stream.next().await {
            match message {
                Ok(Message::Text(text)) => {
                    let request = match serde_json::from_str::<Request>(&text) {
                        Ok(request) => request,
                        Err(e) => {
                            tracing::warn!("Invalid request from {addr}: {e}");
                            let _ = outbound_tx
                                .send(error_response(0, "invalid_request", e))
                                .await;
                            continue;
                        }
                    };

                    tracing::debug!("Request from {addr}: {request:?}");
                    outbound_tx.send(event(request.id, "accepted")).await?;
                    self.dispatch(request, outbound_tx.clone());
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {} // Pings and pongs are handled by tungstenite itself
                Err(e) => {
                    tracing::warn!("WebSocket error from {addr}: {e}");
                    break;
                }
            }
        }

        notification_forwarder.abort();
        drop(outbound_tx);
        let _ = writer.await;

        Ok(())
    }

    /// Dispatches a request, spawning everything that can block on network activity:
    /// a command waiting on a slow device must never delay other commands.
    fn dispatch(self: &Arc<Self>, request: Request, outbound: mpsc::Sender<serde_json::Value>) {
        let api = self.api.clone();

        // One span per request so the handler work nests under it and the close line
        // reports the full request-to-response latency.
        let span = tracing::info_span!("request", id = request.id, method = %request.method);

        tokio::spawn(
            async move {
                let Request { id, method, params } = request;

                let message = api.dispatch(id, &method, params, &outbound).await;

                let _ = outbound.send(message).await;
            }
            .instrument(span),
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FlowControlMode {
    Hardware,
    Software,
    None,
}

impl From<FlowControlMode> for FlowControl {
    fn from(mode: FlowControlMode) -> Self {
        match mode {
            FlowControlMode::Hardware => Self::Hardware,
            FlowControlMode::Software => Self::Software,
            FlowControlMode::None => Self::None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SerialConfig {
    device: String,
    baudrate: u32,
    flow_control: FlowControlMode,
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Host-side Zigbee stack speaking Spinel to an 802.15.4 RCP"
)]
struct Args {
    /// Serial device of the 802.15.4 RCP
    #[arg(long)]
    device: String,

    /// Serial baudrate
    #[arg(long, default_value_t = 460_800)]
    baudrate: u32,

    /// Serial flow control; the RCP UART drops bytes under load without it
    #[arg(long, value_enum, default_value_t = FlowControlMode::Hardware)]
    flow_control: FlowControlMode,

    /// WebSocket listen address: `host:port` for TCP, `unix:/path/to.sock` for a
    /// UNIX socket
    #[arg(long, default_value = "0.0.0.0:9999")]
    listen: String,

    /// Log level (RUST_LOG still overrides, with per-module filters)
    #[arg(long, default_value_t = LevelFilter::DEBUG)]
    log_level: LevelFilter,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(args.log_level.to_string()));
        tracing_subscriber::registry()
            .with(fmt::layer().with_filter(filter))
            .init();

        let server = Arc::new(ZigguratServer::new(SerialConfig {
            device: args.device,
            baudrate: args.baudrate,
            flow_control: args.flow_control,
        }));

        server.run(&args.listen).await?;

        Ok(())
    })
}
