use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, ValueEnum};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::{Mutex as AsyncMutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_serial::{FlowControl, SerialPortBuilderExt};
use tokio_tungstenite::tungstenite::Message;
use tracing::Instrument;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use ziggurat_driver::runtime::TokioSpawner;
use ziggurat_driver::zigbee_stack::{Tunables, ZigbeeNotification, ZigbeeStack};
use ziggurat_driver::ziggurat_ieee_802154::types::{Eui64, Nwk, PanId};
use ziggurat_phy::{RadioConfig, RadioPhy, Receiver};
use ziggurat_phy_spinel::SpinelPhy;
use ziggurat_protocol::{self as proto};
use ziggurat_spinel::client::{RcpTransport, SpinelClient};

/// Outbound frames a connection can queue before it is considered too slow and
/// disconnected. Received frames dominate the traffic; a client that cannot keep up
/// with them is broken.
const OUTBOUND_QUEUE_DEPTH: usize = 1024;

/// The server-level notification hub buffers this many notifications for slow
/// connection forwarders before they start lagging.
const NOTIFICATION_HUB_DEPTH: usize = 1024;

/// The radio transmit power (in dBm) when not overridden by the application.
const DEFAULT_TX_POWER: i8 = 8;

/// Radio programming for promiscuous capture: receive every frame on `channel`, no PAN/
/// address filtering, no network required (dummy addresses).
const fn capture_config(channel: u8) -> RadioConfig {
    RadioConfig {
        channel,
        tx_power: DEFAULT_TX_POWER,
        short_address: Nwk(0xFFFF),
        extended_address: Eui64([0; 8]),
        pan_id: PanId(0xFFFF),
        promiscuous: true,
        rx_on_when_idle: true,
        frame_pending_short: Vec::new(),
        frame_pending_extended: Vec::new(),
    }
}

/// Map a serial-port open failure to a protocol error.
fn radio_error(e: impl ToString) -> proto::Error {
    proto::Error::new(proto::Status::RadioError, &e.to_string())
}

pub struct ZigguratServer {
    serial: SerialConfig,
    /// The radio transport owns the serial port for the lifetime of the process: it is
    /// opened lazily by the first command that needs it and never reopened, so stack
    /// replacement cannot race a straggling port handle (`EBUSY`)
    phy: AsyncMutex<Option<Arc<SpinelPhy>>>,
    stack: Mutex<Option<Arc<ZigbeeStack<SpinelPhy>>>>,
    started: AtomicBool,
    notification_tx: broadcast::Sender<ZigbeeNotification>,
    notification_forwarder: Mutex<Option<JoinHandle<()>>>,
}

impl ZigguratServer {
    /// The serial port is not opened and the Zigbee stack is not created until a
    /// client sends a command that needs them.
    pub fn new(serial: SerialConfig) -> Self {
        let (notification_tx, _) = broadcast::channel(NOTIFICATION_HUB_DEPTH);

        Self {
            serial,
            phy: AsyncMutex::new(None),
            stack: Mutex::new(None),
            started: AtomicBool::new(false),
            notification_tx,
            notification_forwarder: Mutex::new(None),
        }
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

    fn current_stack(&self) -> Option<Arc<ZigbeeStack<SpinelPhy>>> {
        self.stack.lock().unwrap().clone()
    }

    /// The process-lifetime radio transport, opening the serial port on first use.
    async fn phy(&self) -> std::io::Result<Arc<SpinelPhy>> {
        let mut phy = self.phy.lock().await;

        if let Some(phy) = &*phy {
            return Ok(phy.clone());
        }

        let transport = open_transport(&self.serial).await?;
        let new_phy = Arc::new(SpinelPhy::new(Arc::new(SpinelClient::new(transport))));
        *phy = Some(new_phy.clone());
        drop(phy);

        Ok(new_phy)
    }

    /// The `hello` notification sent to every client on connect, advertising whether
    /// the stack is already configured.
    fn hello_frame(&self) -> Vec<u8> {
        proto::Notification::Hello(proto::HelloPayload {
            protocol_version: proto::PROTOCOL_VERSION,
            configured: self.current_stack().is_some(),
        })
        .frame()
        .unwrap_or_default()
    }

    /// Fan hub notifications out to one connection's outbound queue until it closes.
    fn spawn_notification_forwarder(
        self: &Arc<Self>,
        outbound: mpsc::Sender<Vec<u8>>,
        addr: String,
    ) -> JoinHandle<()> {
        let mut notification_rx = self.notification_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match notification_rx.recv().await {
                    Ok(event) => {
                        if let Some(frame) = proto::notification_frame(&event)
                            && outbound.send(frame).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        tracing::warn!("Client {addr} lagged {count} notifications");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        })
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

        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_QUEUE_DEPTH);

        // All outbound traffic (responses, events, notifications) converges on a
        // single writer task, so concurrent commands never contend on the socket. One
        // protocol frame per WebSocket binary message.
        let writer = tokio::spawn(async move {
            while let Some(frame) = outbound_rx.recv().await {
                if sink.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }

            let _ = sink.close().await;
        });

        outbound_tx.send(self.hello_frame()).await?;
        let notification_forwarder =
            self.spawn_notification_forwarder(outbound_tx.clone(), addr.to_owned());

        while let Some(message) = stream.next().await {
            match message {
                Ok(Message::Binary(data)) => {
                    if !self.handle_frame(&data, addr, &outbound_tx).await {
                        break;
                    }
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {} // Text, pings and pongs are ignored / handled by tungstenite
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

    /// Serve the binary API over any byte stream (stdio, or a serial port on an
    /// eventual embedded host). Frames are COBS-encoded and zero-delimited; the
    /// dispatch and notification machinery is shared verbatim with the WebSocket
    /// transport.
    async fn handle_stream_connection<R, W>(
        self: &Arc<Self>,
        reader: R,
        mut writer: W,
        addr: &str,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        tracing::info!("Client {addr} connected");

        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_QUEUE_DEPTH);

        let writer_task = tokio::spawn(async move {
            while let Some(frame) = outbound_rx.recv().await {
                let mut encoded = cobs::encode_vec(&frame);
                encoded.push(0); // frame delimiter
                if writer.write_all(&encoded).await.is_err() {
                    break;
                }
                let _ = writer.flush().await;
            }
        });

        let _ = outbound_tx.send(self.hello_frame()).await;
        let notification_forwarder =
            self.spawn_notification_forwarder(outbound_tx.clone(), addr.to_owned());

        let mut reader = reader;
        let mut buffer = [0u8; 1024];
        let mut accumulator: Vec<u8> = Vec::new();
        'read: loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            for &byte in &buffer[..read] {
                if byte != 0 {
                    accumulator.push(byte);
                    continue;
                }
                if accumulator.is_empty() {
                    continue;
                }
                let decoded = cobs::decode_vec(&accumulator);
                accumulator.clear();
                match decoded {
                    Ok(frame) => {
                        if !self.handle_frame(&frame, addr, &outbound_tx).await {
                            break 'read;
                        }
                    }
                    Err(()) => {
                        let _ = outbound_tx
                            .send(proto::Error::parse("cobs").frame(0, 0))
                            .await;
                    }
                }
            }
        }

        notification_forwarder.abort();
        drop(outbound_tx);
        let _ = writer_task.await;

        Ok(())
    }

    async fn run_stdio(self: Arc<Self>) -> std::io::Result<()> {
        tracing::info!("Serving COBS-framed binary API on stdin/stdout");
        self.handle_stream_connection(tokio::io::stdin(), tokio::io::stdout(), "stdio")
            .await
    }

    /// Parse one inbound frame and dispatch it. Returns `false` once the outbound
    /// queue is gone and the connection should be torn down.
    async fn handle_frame(
        self: &Arc<Self>,
        bytes: &[u8],
        addr: &str,
        outbound: &mpsc::Sender<Vec<u8>>,
    ) -> bool {
        let Some((header, consumed)) = proto::RequestHeader::parse(bytes) else {
            return outbound
                .send(proto::Error::parse("truncated header").frame(0, 0))
                .await
                .is_ok();
        };
        let payload = &bytes[consumed..];

        let request = proto::CommandId::try_from(header.command)
            .map_err(|_| proto::Error::new(proto::Status::UnknownCommand, ""))
            .and_then(|command| proto::Request::parse(command, payload));

        tracing::debug!("Request from {addr}: command={:#04x}", header.command);

        match request {
            Ok(request) => {
                self.dispatch(header, request, outbound.clone());
                true
            }
            Err(e) => outbound
                .send(e.frame(header.command, header.request_id))
                .await
                .is_ok(),
        }
    }

    /// Dispatches a request, spawning everything that can block on network activity:
    /// a command waiting on a slow device must never delay other commands. Every path
    /// emits exactly one response or error, preceded by any streamed events.
    fn dispatch(
        self: &Arc<Self>,
        header: proto::RequestHeader,
        request: proto::Request,
        outbound: mpsc::Sender<Vec<u8>>,
    ) {
        let server = self.clone();

        // One span per request so the handler work nests under it and the close line
        // reports the full request-to-response latency.
        let span = tracing::info_span!("request", id = header.request_id, command = header.command);

        tokio::spawn(
            async move {
                let request_id = header.request_id;
                let reply = server.handle(request_id, request, &outbound).await;
                let frame = match reply {
                    Ok(response) => response.frame(header.command, request_id),
                    Err(e) => e.frame(header.command, request_id),
                };
                let _ = outbound.send(frame).await;
            }
            .instrument(span),
        );
    }

    // -- guards --------------------------------------------------------------------

    /// The stack, in any state after `configure`.
    fn configured(&self) -> Result<Arc<ZigbeeStack<SpinelPhy>>, proto::Error> {
        self.current_stack()
            .ok_or_else(proto::Error::not_configured)
    }

    /// The stack, if it is in the load window (configured but not started).
    fn loadable(&self) -> Result<Arc<ZigbeeStack<SpinelPhy>>, proto::Error> {
        match self.current_stack() {
            Some(_) if self.started.load(Ordering::SeqCst) => Err(proto::Error::new(
                proto::Status::InvalidState,
                "network already started",
            )),
            Some(stack) => Ok(stack),
            None => Err(proto::Error::not_configured()),
        }
    }

    /// The stack, if it is running.
    fn running(&self) -> Result<Arc<ZigbeeStack<SpinelPhy>>, proto::Error> {
        match self.current_stack() {
            Some(stack) if self.started.load(Ordering::SeqCst) => Ok(stack),
            _ => Err(proto::Error::not_configured()),
        }
    }

    // -- dispatch table ------------------------------------------------------------

    async fn handle(
        self: &Arc<Self>,
        request_id: proto::RequestId,
        request: proto::Request,
        outbound: &mpsc::Sender<Vec<u8>>,
    ) -> Result<proto::Response, proto::Error> {
        use proto::Request as R;
        match request {
            R::Ping => Ok(proto::Response::Empty),
            R::Reset(payload) => self.handle_reset(payload).await,
            R::GetFirmwareInfo => Ok(proto::Response::FirmwareInfo(proto::FirmwareInfoPayload {
                protocol_version: proto::PROTOCOL_VERSION,
                version: concat!("ziggurat/", env!("CARGO_PKG_VERSION"))
                    .as_bytes()
                    .to_vec(),
            })),
            R::GetHwAddress => self.handle_get_hw_address().await,
            R::Shutdown => self.handle_shutdown().await,
            R::Configure(payload) => self.handle_configure(payload).await,
            R::LoadKeyTable(payload) => {
                proto::apply_key_table(&*self.loadable()?, payload);
                Ok(proto::Response::Empty)
            }
            R::LoadChildren(payload) => {
                proto::apply_children(&*self.loadable()?, payload);
                Ok(proto::Response::Empty)
            }
            R::LoadAddressCache(payload) => {
                proto::apply_address_cache(&*self.loadable()?, payload);
                Ok(proto::Response::Empty)
            }
            R::LoadRouteTable(payload) => {
                proto::apply_route_table(&*self.loadable()?, payload);
                Ok(proto::Response::Empty)
            }
            R::LoadSourceRoutes(payload) => {
                proto::apply_source_routes(&*self.loadable()?, payload);
                Ok(proto::Response::Empty)
            }
            R::StartNetwork => self.handle_start_network().await,
            R::GetNetworkInfo => Ok(proto::Response::NetworkInfo(proto::network_info_payload(
                &*self.configured()?,
                self.started.load(Ordering::SeqCst),
            ))),
            R::ScanKeyTable => {
                let events = proto::key_entries(&*self.configured()?)
                    .into_iter()
                    .map(proto::Event::KeyEntry)
                    .collect();
                self.stream_scan(request_id, outbound, events).await
            }
            R::ScanChildren => {
                let events = proto::child_entries(&*self.configured()?)
                    .into_iter()
                    .map(proto::Event::Child)
                    .collect();
                self.stream_scan(request_id, outbound, events).await
            }
            R::ScanAddressCache => {
                let events = proto::address_entries(&*self.configured()?)
                    .into_iter()
                    .map(proto::Event::Address)
                    .collect();
                self.stream_scan(request_id, outbound, events).await
            }
            R::ScanRouteTable => {
                let events = proto::route_entries(&*self.configured()?)
                    .into_iter()
                    .map(proto::Event::Route)
                    .collect();
                self.stream_scan(request_id, outbound, events).await
            }
            R::SendAps(payload) => {
                proto::send_aps(&*self.running()?, payload, request_id)?;
                Ok(proto::Response::Empty)
            }
            R::PermitJoins(payload) => {
                self.running()?
                    .permit_joins(u64::from(payload.duration), payload.accept_direct_joins);
                Ok(proto::Response::Empty)
            }
            R::SetChannel(payload) => {
                self.running()?
                    .set_channel(payload.channel)
                    .await
                    .map_err(radio_error)?;
                Ok(proto::Response::Empty)
            }
            R::SetNwkUpdateId(payload) => {
                self.running()?.set_nwk_update_id(payload.nwk_update_id);
                Ok(proto::Response::Empty)
            }
            R::SetProvisionalKey(payload) => {
                self.running()?
                    .set_provisional_key(payload.ieee, payload.key);
                Ok(proto::Response::Empty)
            }
            R::EnergyScan(payload) => self.handle_energy_scan(request_id, payload, outbound).await,
            R::NetworkScan(payload) => {
                self.handle_network_scan(request_id, payload, outbound)
                    .await
            }
            R::PacketCapture(payload) => {
                self.handle_packet_capture(request_id, payload, outbound)
                    .await
            }
            R::PacketCaptureChannel(payload) => self.handle_packet_capture_channel(payload).await,
            R::SetTunable(payload) => {
                proto::set_tunable(&*self.configured()?, &payload)?;
                Ok(proto::Response::Empty)
            }
            R::CancelRequest(payload) => Ok(proto::Response::CancelResult(proto::cancel_request(
                &*self.running()?,
                &payload,
            ))),
        }
    }

    // -- handlers ------------------------------------------------------------------

    /// Soft reset is a host no-op (no transient radio state outlives a connection
    /// here); hard reset resets the radio (RCP), whose recovery task reprograms it.
    async fn handle_reset(
        &self,
        payload: proto::ResetPayload,
    ) -> Result<proto::Response, proto::Error> {
        if payload.hard {
            let phy = self.phy().await.map_err(radio_error)?;
            phy.reset()
                .await
                .map_err(|e| proto::Error::new(proto::Status::RadioError, &e.to_string()))?;
        }

        Ok(proto::Response::Empty)
    }

    async fn handle_get_hw_address(&self) -> Result<proto::Response, proto::Error> {
        let phy = self.phy().await.map_err(radio_error)?;
        let ieee = phy
            .hw_address()
            .await
            .map_err(|e| proto::Error::new(proto::Status::RadioError, &e.to_string()))?;
        Ok(proto::Response::HwAddress(proto::HwAddressPayload { ieee }))
    }

    /// Tear the stack fully down and clear the source-match table.
    async fn handle_shutdown(&self) -> Result<proto::Response, proto::Error> {
        self.teardown_stack().await;

        let phy = self.phy().await.map_err(radio_error)?;
        phy.set_frame_pending_table(&[], &[])
            .await
            .map_err(|e| proto::Error::new(proto::Status::RadioError, &e.to_string()))?;

        Ok(proto::Response::Empty)
    }

    /// (Re)initializes the Zigbee stack, but does not start it: `load_*` then
    /// `start_network` follow. The stack deliberately outlives client connections;
    /// reconfiguring replaces it wholesale.
    async fn handle_configure(
        &self,
        payload: proto::ConfigurePayload,
    ) -> Result<proto::Response, proto::Error> {
        // A replaced stack must be fully stopped before its successor registers its
        // own receivers with the shared radio transport.
        self.teardown_stack().await;

        tracing::info!("Initializing Zigbee stack with new settings...");
        let phy = self.phy().await.map_err(radio_error)?;

        let aps_frame_counter = payload.state.aps_frame_counter;
        let stack = ZigbeeStack::new(
            phy,
            proto::network_config(&payload),
            Tunables::default(),
            TokioSpawner::default(),
        );
        stack
            .state
            .core
            .lock()
            .aib
            .aps_security
            .restore_outgoing_frame_counter(aps_frame_counter);

        *self.stack.lock().unwrap() = Some(stack);
        self.started.store(false, Ordering::SeqCst);

        Ok(proto::Response::Empty)
    }

    /// Bring up the network on the loaded stack. The success response is the client's
    /// permission to send commands: the network must be fully up (RCP reset handled,
    /// radio programmed) before replying, or the client's first command would race
    /// with the boot-time reset.
    async fn handle_start_network(&self) -> Result<proto::Response, proto::Error> {
        let stack = self.loadable()?;

        if let Err(e) = stack.start_network().await {
            return Err(proto::Error::new(
                proto::Status::NetworkStartFailed,
                &e.to_string(),
            ));
        }

        let run_stack = stack.clone();
        stack.spawn_tracked(async move {
            run_stack.run().await;
        });

        // Drain the stack's notification outbox into the server-level hub. The task is
        // aborted when the stack is replaced, so it doesn't need to observe a closed
        // channel to stop.
        let hub_tx = self.notification_tx.clone();
        let notification_stack = stack.clone();
        let forwarder = tokio::spawn(async move {
            loop {
                for event in notification_stack.next_notifications().await {
                    // Send errors just mean no client is connected right now
                    let _ = hub_tx.send(event);
                }
            }
        });
        *self.notification_forwarder.lock().unwrap() = Some(forwarder);

        self.started.store(true, Ordering::SeqCst);
        tracing::info!("Zigbee stack initialized and running.");

        Ok(proto::Response::Empty)
    }

    /// Stop and drop the running stack and its notification forwarder, if any.
    async fn teardown_stack(&self) {
        let old_stack = self.stack.lock().unwrap().take();
        if let Some(old_stack) = old_stack {
            tracing::info!("Stopping the running Zigbee stack");
            old_stack.shutdown().await;
        }

        let old_forwarder = self.notification_forwarder.lock().unwrap().take();
        if let Some(old_forwarder) = old_forwarder {
            old_forwarder.abort();
        }

        self.started.store(false, Ordering::SeqCst);
    }

    /// Stream a table scan's events, then respond with the count.
    async fn stream_scan(
        &self,
        request_id: proto::RequestId,
        outbound: &mpsc::Sender<Vec<u8>>,
        events: Vec<proto::Event>,
    ) -> Result<proto::Response, proto::Error> {
        let count = events.len() as u16;
        for event in events {
            if let Some(frame) = event.frame(request_id)
                && outbound.send(frame).await.is_err()
            {
                break;
            }
        }
        Ok(proto::Response::ScanCount(proto::ScanCountPayload {
            count,
        }))
    }

    async fn handle_energy_scan(
        &self,
        request_id: proto::RequestId,
        payload: proto::ScanRequestPayload,
        outbound: &mpsc::Sender<Vec<u8>>,
    ) -> Result<proto::Response, proto::Error> {
        // An energy detect is a radio operation, not a network one: it drives the
        // radio directly and needs no configured stack.
        let phy = self.phy().await.map_err(radio_error)?;

        let duration = Duration::from_millis(u64::from(payload.duration_per_channel_ms));
        for channel in payload.channels {
            match phy.energy_detect(channel, duration).await {
                Ok(rssi) => {
                    let event = proto::Event::EnergyResult(proto::EnergyResultPayload {
                        channel,
                        rssi: rssi as u8,
                    });
                    if let Some(frame) = event.frame(request_id) {
                        let _ = outbound.send(frame).await;
                    }
                }
                Err(e) => {
                    return Err(proto::Error::new(proto::Status::ScanFailed, &e.to_string()));
                }
            }
        }

        Ok(proto::Response::Empty)
    }

    async fn handle_network_scan(
        &self,
        request_id: proto::RequestId,
        payload: proto::ScanRequestPayload,
        outbound: &mpsc::Sender<Vec<u8>>,
    ) -> Result<proto::Response, proto::Error> {
        let stack = self.running()?;

        // Open the collection window before spawning, so the drain loop below cannot
        // race ahead of the scan starting. The scan runs on its own task so it always
        // reaches its channel restore even if this request's task is dropped.
        stack.begin_network_scan();
        let duration = Duration::from_millis(u64::from(payload.duration_per_channel_ms));
        let scan_stack = stack.clone();
        let channels = payload.channels;
        let scan =
            tokio::spawn(async move { scan_stack.run_network_scan(&channels, duration).await });

        // `next_scan_beacons` delivers beacons as they arrive and returns empty once
        // the window has closed and the queue is drained, which ends the loop.
        loop {
            let batch = stack.next_scan_beacons().await;
            if batch.is_empty() {
                break;
            }
            for beacon in batch {
                let event = proto::Event::Beacon((&beacon).into());
                if let Some(frame) = event.frame(request_id) {
                    let _ = outbound.send(frame).await;
                }
            }
        }

        match scan.await {
            Ok(Ok(())) => Ok(proto::Response::Empty),
            Ok(Err(e)) => Err(proto::Error::new(proto::Status::ScanFailed, &e.to_string())),
            Err(e) => Err(proto::Error::new(proto::Status::ScanFailed, &e.to_string())),
        }
    }

    /// Put the radio in promiscuous mode and stream every received frame as a
    /// `PacketCapture` event to this connection until it disconnects. No network is
    /// required (it reprograms the radio directly), so a running stack is disrupted.
    /// The terminal `Ok` reply is sent immediately; captured frames follow as events.
    async fn handle_packet_capture(
        &self,
        request_id: proto::RequestId,
        payload: proto::ChannelPayload,
        outbound: &mpsc::Sender<Vec<u8>>,
    ) -> Result<proto::Response, proto::Error> {
        let phy = self.phy().await.map_err(radio_error)?;

        phy.reconfigure(&capture_config(payload.channel))
            .await
            .map_err(|e| proto::Error::new(proto::Status::RadioError, &e.to_string()))?;

        // The stream outlives this request, ending when the connection's outbound
        // queue closes (the client disconnected).
        let outbound = outbound.clone();
        tokio::spawn(async move {
            let mut rx = phy.subscribe_rx();
            while let Some(frame) = rx.recv().await {
                let event = proto::Event::CapturedPacket(proto::CapturedPacketPayload {
                    channel: frame.channel,
                    rssi: frame.rssi as u8,
                    lqi: frame.lqi,
                    psdu: frame.psdu,
                });
                // A frame too large to encode is dropped; a closed queue ends the stream.
                if let Some(bytes) = event.frame(request_id)
                    && outbound.send(bytes).await.is_err()
                {
                    break;
                }
            }
        });

        Ok(proto::Response::Empty)
    }

    async fn handle_packet_capture_channel(
        &self,
        payload: proto::ChannelPayload,
    ) -> Result<proto::Response, proto::Error> {
        let phy = self.phy().await.map_err(radio_error)?;

        phy.reconfigure(&capture_config(payload.channel))
            .await
            .map_err(|e| proto::Error::new(proto::Status::RadioError, &e.to_string()))?;

        Ok(proto::Response::Empty)
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

#[derive(Debug)]
pub struct SerialConfig {
    device: String,
    baudrate: u32,
    flow_control: FlowControlMode,
}

/// A local network hop should establish in well under this; past it, something (a
/// blackholed host, a firewall silently dropping packets) is wrong. Without a bound,
/// `TcpStream::connect` rides out the kernel's full SYN-retry window (minutes, by
/// default) while `phy()`'s lock is held, wedging every other command behind it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connects to the RCP per `serial.device`: a `tcp://host:port` (or `socket://host:port`,
/// accepted for parity with pyserial-style tools) address for a raw TCP socket — e.g. a
/// network-attached RCP or a `ser2net`-style serial-to-TCP bridge — or a path for a
/// local serial device.
async fn open_transport(serial: &SerialConfig) -> std::io::Result<Box<dyn RcpTransport>> {
    let tcp_addr = serial
        .device
        .strip_prefix("tcp://")
        .or_else(|| serial.device.strip_prefix("socket://"));

    if let Some(addr) = tcp_addr {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "RCP connect timed out")
            })??;
        // The Spinel control plane is latency-sensitive request/response traffic in
        // small frames; Nagle's algorithm would needlessly delay them.
        stream.set_nodelay(true)?;
        return Ok(Box::new(stream));
    }

    // Without flow control the RCP's UART drops bytes under load, corrupting
    // host->RCP frames ("Framing error" + command timeout)
    let port = tokio_serial::new(&serial.device, serial.baudrate)
        .flow_control(serial.flow_control.into())
        .open_native_async()
        .map_err(std::io::Error::other)?;
    Ok(Box::new(port))
}

/// How the Zigbee API is exposed to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ApiMode {
    /// Binary protocol over WebSocket on `--listen`
    Ws,
    /// COBS-framed binary protocol over stdin/stdout (logs go to stderr)
    Stdio,
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Host-side Zigbee stack speaking Spinel to an 802.15.4 RCP"
)]
struct Args {
    /// How to expose the Zigbee API to clients
    #[arg(long, value_enum, default_value_t = ApiMode::Ws)]
    api: ApiMode,

    /// RCP transport: a serial device path, or `tcp://host:port` for a raw TCP socket
    #[arg(long)]
    device: String,

    /// Serial baudrate; ignored for a `tcp://` device
    #[arg(long, default_value_t = 460_800)]
    baudrate: u32,

    /// Serial flow control; the RCP UART drops bytes under load without it. Ignored
    /// for a `tcp://` device
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

        let timer = ChronoLocal::new("%Y-%m-%dT%H:%M:%S%.6f%:z".to_string());

        // In stdio mode stdout carries the binary API, so logs must not touch it
        if args.api == ApiMode::Stdio {
            tracing_subscriber::registry()
                .with(
                    fmt::layer()
                        .with_timer(timer)
                        .with_writer(std::io::stderr)
                        .with_filter(filter),
                )
                .init();
        } else {
            tracing_subscriber::registry()
                .with(fmt::layer().with_timer(timer).with_filter(filter))
                .init();
        }

        let server = Arc::new(ZigguratServer::new(SerialConfig {
            device: args.device,
            baudrate: args.baudrate,
            flow_control: args.flow_control,
        }));

        match args.api {
            ApiMode::Ws => server.run(&args.listen).await?,
            ApiMode::Stdio => server.run_stdio().await?,
        }

        Ok(())
    })
}
