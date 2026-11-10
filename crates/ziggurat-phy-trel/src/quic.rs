//! SPIKE: secure ZLOE peer links over QUIC (see BROADCAST.md, "Secure ZLOE over QUIC").
//!
//! One QUIC connection per peer pair (the lower EUI64 dials), mutual TLS against the
//! network CA derived from the network key, ZLOE datagrams carried as QUIC DATAGRAM
//! frames. The same endpoint serves enrollment (`zloe-enroll/1`) on the coordinator.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use quinn::{AckFrequencyConfig, IdleTimeout, TransportConfig, VarInt};
use rustls::pki_types::CertificateDer;
use ziggurat_ieee_802154::types::Eui64;

use crate::security::{
    self, ALPN_ENROLL, ALPN_ZLOE, NetworkSecrets, Role, cert_names, enrollment_proof, exporter,
    proof_matches,
};

/// Handles one incoming ZLOE datagram; returns the reply to send back, if any.
pub type Handler = Arc<dyn Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync>;
/// The encoded network settings handed to an enrolling satellite.
pub type NetInfo = Arc<dyn Fn() -> Option<Vec<u8>> + Send + Sync>;
/// Whether the network is in pairing mode (permit-join open): enrollment without a
/// code is accepted then, like Zigbee joining with the well-known link key.
pub type PairingOpen = Arc<dyn Fn() -> bool + Send + Sync>;

/// The code an auto-enrolling satellite proves: none.
pub const AUTO_CODE: &str = "";

const ENROLL_CODE_LIFETIME: Duration = Duration::from_secs(600);

pub struct QuicLink {
    endpoint: quinn::Endpoint,
    pub port: u16,
    state: Mutex<State>,
    handler: Handler,
    netinfo: NetInfo,
    code_file: Option<PathBuf>,
    pairing_open: Mutex<Option<PairingOpen>>,
}

#[derive(Default)]
struct State {
    client: Option<quinn::ClientConfig>,
    me: Option<Eui64>,
    conns: HashMap<Eui64, quinn::Connection>,
    dialing: HashSet<Eui64>,
    /// Coordinator: the current enrollment code and when it was issued
    code: Option<(String, Instant)>,
    accepting: bool,
}

/// spinel2quic's tuning: fixed congestion window (no backoff stalls), immediate acks.
fn transport() -> Arc<TransportConfig> {
    #[derive(Clone)]
    struct FixedWindow(u64);
    impl quinn::congestion::Controller for FixedWindow {
        fn on_congestion_event(&mut self, _: Instant, _: Instant, _: bool, _: u64) {}
        fn on_mtu_update(&mut self, _: u16) {}
        fn window(&self) -> u64 {
            self.0
        }
        fn clone_box(&self) -> Box<dyn quinn::congestion::Controller> {
            Box::new(self.clone())
        }
        fn initial_window(&self) -> u64 {
            self.0
        }
        fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
            self
        }
    }
    struct Factory;
    impl quinn::congestion::ControllerFactory for Factory {
        fn build(self: Arc<Self>, _: Instant, _: u16) -> Box<dyn quinn::congestion::Controller> {
            Box::new(FixedWindow(256 * 1024))
        }
    }

    let mut t = TransportConfig::default();
    t.max_idle_timeout(Some(
        IdleTimeout::try_from(Duration::from_secs(10)).expect("10 s"),
    ));
    t.keep_alive_interval(Some(Duration::from_secs(1)));
    let mut ack = AckFrequencyConfig::default();
    ack.ack_eliciting_threshold(VarInt::from_u32(0))
        .max_ack_delay(Some(Duration::from_millis(1)));
    t.ack_frequency_config(Some(ack));
    t.initial_rtt(Duration::from_millis(10));
    t.datagram_receive_buffer_size(Some(64 * 1024));
    t.congestion_controller_factory(Arc::new(Factory));
    Arc::new(t)
}

fn io_err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn client_config(tls: rustls::ClientConfig) -> std::io::Result<quinn::ClientConfig> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(io_err)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport());
    Ok(config)
}

impl QuicLink {
    pub fn new(
        port: u16,
        handler: Handler,
        netinfo: NetInfo,
        code_file: Option<PathBuf>,
    ) -> std::io::Result<Arc<Self>> {
        use socket2::{Domain, Protocol, Socket, Type};
        // Dual-stack, like the UDP socket
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(false)?;
        socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket.into(),
            Arc::new(quinn::TokioRuntime),
        )?;
        tracing::info!("ZLOE/QUIC endpoint on UDP {port}");
        Ok(Arc::new(Self {
            endpoint,
            port,
            state: Mutex::new(State::default()),
            handler,
            netinfo,
            code_file,
            pairing_open: Mutex::new(None),
        }))
    }

    /// The network key is known (configured, or after enrollment): derive the network
    /// CA, issue our certificate, start accepting peers. Existing connections belong
    /// to the previous key and are closed.
    pub fn set_network(
        self: &Arc<Self>,
        nwk_key: &[u8; 16],
        epan: Eui64,
        me: Eui64,
        role: Role,
    ) -> std::io::Result<()> {
        let secrets = NetworkSecrets::derive(nwk_key, epan).map_err(io_err)?;
        let identity = secrets.issue(me, role).map_err(io_err)?;
        let client = client_config(secrets.client_config(&identity).map_err(io_err)?)?;
        let server_tls = secrets.server_config(&identity).map_err(io_err)?;
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).map_err(io_err)?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server.transport_config(transport());
        self.endpoint.set_server_config(Some(server));

        let start_accepting = {
            let mut state = self.state.lock();
            for (_, conn) in state.conns.drain() {
                conn.close(VarInt::from_u32(1), b"network key changed");
            }
            state.client = Some(client);
            state.me = Some(me);
            !std::mem::replace(&mut state.accepting, true)
        };
        tracing::info!(
            "ZLOE/QUIC: identity {} under network CA for {epan:?}",
            security::node_name(me)
        );
        if role == Role::Coordinator {
            self.new_code();
        }
        if start_accepting {
            let link = Arc::clone(self);
            tokio::spawn(async move { link.accept_loop().await });
        }
        Ok(())
    }

    fn new_code(&self) {
        let code = security::new_enrollment_code();
        tracing::info!("ZLOE/QUIC: enrollment code {code} (one use, 10 minutes)");
        if let Some(file) = &self.code_file {
            let _ = std::fs::write(file, format!("{code}\n"));
        }
        self.state.lock().code = Some((code, Instant::now()));
    }

    pub fn set_pairing_open(&self, pairing_open: PairingOpen) {
        *self.pairing_open.lock() = Some(pairing_open);
    }

    pub fn is_connected(&self, peer: Eui64) -> bool {
        self.state.lock().conns.contains_key(&peer)
    }

    pub fn connected(&self) -> Vec<Eui64> {
        self.state.lock().conns.keys().copied().collect()
    }

    /// Send one ZLOE datagram to a connected peer.
    pub fn send(&self, peer: Eui64, datagram: &[u8]) -> bool {
        let conn = self.state.lock().conns.get(&peer).cloned();
        conn.is_some_and(|c| c.send_datagram(datagram.to_vec().into()).is_ok())
    }

    /// Dial a peer if we are the lower EUI64 and have no connection or dial underway.
    pub fn ensure_connected(self: &Arc<Self>, peer: Eui64, addr: SocketAddr) {
        let client = {
            let mut state = self.state.lock();
            let Some(me) = state.me else { return };
            if me.to_be_bytes() >= peer.to_be_bytes()
                || state.conns.contains_key(&peer)
                || state.dialing.contains(&peer)
            {
                return;
            }
            let Some(client) = state.client.clone() else {
                return;
            };
            state.dialing.insert(peer);
            client
        };
        let link = Arc::clone(self);
        tokio::spawn(async move {
            let result = link.dial(peer, addr, client).await;
            link.state.lock().dialing.remove(&peer);
            if let Err(e) = result {
                tracing::debug!("ZLOE/QUIC: dial {peer:?} at {addr} failed: {e}");
            }
        });
    }

    async fn dial(
        self: &Arc<Self>,
        peer: Eui64,
        addr: SocketAddr,
        client: quinn::ClientConfig,
    ) -> std::io::Result<()> {
        let conn = self
            .endpoint
            .connect_with(client, addr, &security::node_name(peer))
            .map_err(io_err)?
            .await
            .map_err(io_err)?;
        // Tell the acceptor who we claim to be; it checks our certificate names it
        let me = self.state.lock().me.ok_or_else(|| io_err("no identity"))?;
        let mut hello = conn.open_uni().await.map_err(io_err)?;
        hello.write_all(&me.0).await.map_err(io_err)?;
        hello.finish().map_err(io_err)?;
        tracing::info!("ZLOE/QUIC: connected to {peer:?} at {addr}");
        self.adopt(peer, conn);
        Ok(())
    }

    async fn accept_loop(self: Arc<Self>) {
        while let Some(incoming) = self.endpoint.accept().await {
            let link = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = link.accept(incoming).await {
                    tracing::warn!("ZLOE/QUIC: rejected connection: {e}");
                }
            });
        }
    }

    async fn accept(self: &Arc<Self>, incoming: quinn::Incoming) -> std::io::Result<()> {
        let conn = incoming.await.map_err(io_err)?;
        let alpn = conn
            .handshake_data()
            .and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|h| h.protocol);
        match alpn.as_deref() {
            Some(ALPN_ZLOE) => {
                let leaf = conn
                    .peer_identity()
                    .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
                    .and_then(|chain| chain.first().cloned());
                let Some(leaf) = leaf else {
                    conn.close(VarInt::from_u32(2), b"certificate required");
                    return Err(io_err("peer sent no certificate"));
                };
                let mut hello = conn.accept_uni().await.map_err(io_err)?;
                let claimed = hello.read_to_end(8).await.map_err(io_err)?;
                let claimed = Eui64(claimed.try_into().map_err(|_| io_err("bad hello"))?);
                if !cert_names(&leaf, claimed) {
                    conn.close(VarInt::from_u32(3), b"certificate does not name you");
                    return Err(io_err(format!("certificate does not name {claimed:?}")));
                }
                tracing::info!(
                    "ZLOE/QUIC: accepted {claimed:?} from {}",
                    conn.remote_address()
                );
                self.adopt(claimed, conn);
                Ok(())
            }
            Some(ALPN_ENROLL) => self.serve_enrollment(conn).await,
            _ => {
                conn.close(VarInt::from_u32(4), b"unknown protocol");
                Err(io_err("unknown ALPN"))
            }
        }
    }

    /// Keep the connection and read its datagrams until it closes.
    fn adopt(self: &Arc<Self>, peer: Eui64, conn: quinn::Connection) {
        if let Some(old) = self.state.lock().conns.insert(peer, conn.clone()) {
            old.close(VarInt::from_u32(5), b"replaced");
        }
        let link = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match conn.read_datagram().await {
                    Ok(datagram) => {
                        if let Some(reply) = (link.handler)(&datagram, conn.remote_address()) {
                            let _ = conn.send_datagram(reply.into());
                        }
                    }
                    Err(e) => {
                        tracing::info!("ZLOE/QUIC: link to {peer:?} closed: {e}");
                        let mut state = link.state.lock();
                        if state
                            .conns
                            .get(&peer)
                            .is_some_and(|c| c.stable_id() == conn.stable_id())
                        {
                            state.conns.remove(&peer);
                        }
                        return;
                    }
                }
            }
        });
    }

    // -- enrollment ------------------------------------------------------------------

    async fn serve_enrollment(&self, conn: quinn::Connection) -> std::io::Result<()> {
        let peer = conn.remote_address();
        let (mut send, mut recv) = conn.accept_bi().await.map_err(io_err)?;
        let proof = recv.read_to_end(64).await.map_err(io_err)?;
        let exporter = exporter(&conn).ok_or_else(|| io_err("no exporter"))?;

        let code = {
            let state = self.state.lock();
            state
                .code
                .as_ref()
                .filter(|(_, issued)| issued.elapsed() < ENROLL_CODE_LIFETIME)
                .map(|(code, _)| code.clone())
        };
        // The current code, or no code at all while the network is in pairing mode
        let pairing = self.pairing_open.lock().clone().is_some_and(|open| open());
        let code = if let Some(code) = code.filter(|c| proof_matches(c, &exporter, b'C', &proof)) {
            code
        } else if pairing && proof_matches(AUTO_CODE, &exporter, b'C', &proof) {
            tracing::info!("ZLOE/QUIC: auto-enrolling {peer} (pairing mode is open)");
            AUTO_CODE.to_string()
        } else {
            tracing::warn!(
                "ZLOE/QUIC: enrollment from {peer} rejected (wrong or expired code, or \
                 pairing mode closed)"
            );
            conn.close(VarInt::from_u32(6), b"enrollment rejected");
            return Ok(());
        };
        let Some(info) = (self.netinfo)() else {
            conn.close(VarInt::from_u32(7), b"no network");
            return Ok(());
        };
        // One use: the next satellite needs the next code
        if !code.is_empty() {
            self.new_code();
        }

        let mut reply = enrollment_proof(&code, &exporter, b'S').to_vec();
        reply.extend_from_slice(&info);
        send.write_all(&reply).await.map_err(io_err)?;
        send.finish().map_err(io_err)?;
        let _ = send.stopped().await;
        tracing::info!("ZLOE/QUIC: enrolled {peer}");
        Ok(())
    }

    /// Satellite: prove the code to the coordinator at `addr`, check its proof, and
    /// return the network settings it sends.
    pub async fn enroll(&self, addr: SocketAddr, code: &str) -> std::io::Result<Vec<u8>> {
        let client = client_config(security::enroll_client_config().map_err(io_err)?)?;
        let conn = self
            .endpoint
            .connect_with(client, addr, "zloe-enroll")
            .map_err(io_err)?
            .await
            .map_err(io_err)?;
        let exporter = exporter(&conn).ok_or_else(|| io_err("no exporter"))?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(io_err)?;
        send.write_all(&enrollment_proof(code, &exporter, b'C'))
            .await
            .map_err(io_err)?;
        send.finish().map_err(io_err)?;
        let reply = recv.read_to_end(4096).await.map_err(io_err)?;
        conn.close(VarInt::from_u32(0), b"done");
        if reply.len() < 32 || !proof_matches(code, &exporter, b'S', &reply[..32]) {
            return Err(io_err("coordinator did not prove the code"));
        }
        Ok(reply[32..].to_vec())
    }
}
