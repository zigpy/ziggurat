//! SPIKE (throwaway): ZLOE (Zigbee Link Over Ethernet), a TREL-like IP backbone,
//! wrapped around any [`RadioPhy`].
//!
//! The backbone behaves as a second 802.15.4 "radio" that only reaches other Ziggurat
//! nodes. Raw 802.15.4 frames (FCS stripped) are carried in UDP datagrams:
//!
//! * unicasts whose MAC destination is a known backbone peer go over UDP only, with a
//!   tiny ack/retransmit standing in for the MAC ACK, falling back to the air on
//!   failure;
//! * broadcasts go over the air *and* to every backbone peer (NWK broadcast dedup
//!   absorbs the duplicates);
//! * frames received over the backbone carry an LQI derived from the backbone link's
//!   health (ack success), 255 when clean, so NWK link costs to backbone peers are low
//!   and routing prefers the backbone without NWK changes; over-the-air copies of a
//!   live backbone peer's frames are dropped (they also come over the backbone), so the
//!   peer's link quality is not mixed with the radio's.
//!
//! Peers are discovered with mDNS/DNS-SD (`_zloe._udp`, TXT `xa`/`xp` as in TREL),
//! configured statically, or learned from the first datagram they send us. Transport
//! is one dual-stack UDP socket: IPv6 link-local is preferred, IPv4 works too.
//!
//! A test-only deny list fakes "out of radio range": over-the-air frames whose MAC
//! source is denied are dropped, and over-the-air unicasts to a denied MAC destination
//! report `NoAck` without being transmitted. The RCP still auto-ACKs frames from denied
//! devices at the hardware level; see the spike notes.

pub mod quic;
pub mod security;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::{RadioConfig, RadioError, RadioPhy, Receiver, RxFrame, TxFrame, TxResult};

pub const SERVICE_TYPE: &str = "_zloe._udp.local.";
const MAGIC: [u8; 2] = *b"ZL";
const VERSION: u8 = 2;
const HEADER_LEN: usize = 27;
const KIND_DATA: u8 = 0;
const KIND_ACK: u8 = 1;
/// Trusted-backbone bootstrap: ask a coordinator for the network settings, and its
/// answer (an encoded `NetworkInfoPayload`, opaque to this crate).
const KIND_NETINFO_REQ: u8 = 2;
const KIND_NETINFO_RSP: u8 = 3;

/// Produces the encoded network settings a coordinator hands to satellites.
pub type NetInfoProvider = Arc<dyn Fn() -> Option<Vec<u8>> + Send + Sync>;
const FLAG_ACK_REQUEST: u8 = 0x01;
/// Multicast liveness probe: no payload, answered with a unicast ack.
const KIND_PROBE: u8 = 4;
const PROBE_INTERVAL: Duration = Duration::from_secs(5);
/// A peer that has not acked a probe for this long (two missed probes) gets unicast
/// copies of broadcasts again.
const MCAST_CONFIRM_WINDOW: Duration = Duration::from_secs(12);
/// 802.15.4 frame type "data": the only broadcasts that belong on the backbone.
const MAC_FRAME_DATA: u8 = 1;

const ACK_TIMEOUT: Duration = Duration::from_millis(50);
const ATTEMPTS: usize = 3;
const DEDUP_WINDOW: usize = 64;
/// RSSI reported for frames received over the backbone.
const BACKBONE_RSSI: i8 = -20;
/// A peer whose datagrams arrived this recently has a live backbone link: its
/// over-the-air frames are duplicates (two Link Status periods).
const BACKBONE_LIVE: Duration = Duration::from_secs(35);
/// Weight of the newest sample in the backbone ack-success average.
const HEALTH_ALPHA: f32 = 0.125;

#[derive(Debug, Clone, Default)]
pub struct DenyList {
    pub eui64: HashSet<Eui64>,
    pub nwk: HashSet<Nwk>,
}

impl DenyList {
    fn denies(&self, address: &MacAddress) -> bool {
        match address {
            MacAddress::Short(nwk) => self.nwk.contains(nwk),
            MacAddress::Extended(eui64) => self.eui64.contains(eui64),
            MacAddress::None => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrelConfig {
    /// UDP port to listen on (0 disables the backbone entirely)
    pub port: u16,
    /// Peers reachable without discovery; their identity is learned from traffic
    pub static_peers: Vec<SocketAddr>,
    pub mdns: bool,
    /// Network interface (e.g. `eth0`) the backbone is confined to: mDNS only runs
    /// there and peers are reached through its addresses. `None`: all interfaces.
    pub interface: Option<String>,
    /// Reach peers over IPv4 when they advertise both (default: IPv6 link-local)
    pub prefer_ipv4: bool,
    /// UDP port of the network's multicast group (0: do not listen or advertise).
    /// Needs `interface`: link-local multicast is per interface.
    pub mcast_port: u16,
    /// Test hook: while this file exists, datagrams arriving on the multicast group
    /// are dropped, as if the network had stopped delivering multicast to us.
    pub mcast_block_file: Option<std::path::PathBuf>,
    /// Test hook: behave like a host without IPv6 (IPv4 socket, no IPv6 peers or group)
    pub ipv4_only: bool,
    /// Secure mode: peer links over authenticated QUIC; plain UDP data, multicast and
    /// the unauthenticated settings hand-out are off
    pub quic: Option<QuicConfig>,
    pub deny: DenyList,
}

#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// UDP port of the QUIC endpoint
    pub port: u16,
    /// Coordinator: where to write the current enrollment code
    pub code_file: Option<std::path::PathBuf>,
}

/// The addresses of the interface the backbone is confined to.
#[derive(Debug, Clone, Copy)]
struct LocalNet {
    index: u32,
    v4: Option<(Ipv4Addr, Ipv4Addr)>,
}

fn local_net(name: &str) -> std::io::Result<LocalNet> {
    let addrs: Vec<_> = if_addrs::get_if_addrs()?
        .into_iter()
        .filter(|iface| iface.name == name)
        .collect();
    let index = addrs.iter().find_map(|i| i.index).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("ZLOE interface {name:?} not found"),
        )
    })?;
    let v4 = addrs.iter().find_map(|i| match &i.addr {
        if_addrs::IfAddr::V4(v4) => Some((v4.ip, v4.netmask)),
        if_addrs::IfAddr::V6(_) => None,
    });
    Ok(LocalNet { index, v4 })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerSource {
    Mdns,
    Learned,
}

#[derive(Debug, Clone)]
struct Peer {
    addr: SocketAddr,
    nwk: Option<Nwk>,
    source: PeerSource,
    last_rx: Option<Instant>,
    /// Backbone ack success, exponentially averaged (1.0 = clean)
    health: f32,
    /// Every usable address mDNS gave, best first: tried in turn when sends fail
    alternates: Vec<SocketAddr>,
    /// The multicast group and port the peer listens on (mDNS TXT `mc`), scoped to
    /// our backbone interface. `None`: the peer cannot be reached by multicast.
    mcast: [Group; 2],
    /// QUIC port the peer announced (TXT `qp`), secure mode only
    quic_port: Option<u16>,
    /// The confirmation state last logged, to log each change once
    mcast_logged_ok: bool,
}

impl Peer {
    fn new(addr: SocketAddr, nwk: Option<Nwk>, source: PeerSource) -> Self {
        Self {
            addr,
            nwk,
            source,
            last_rx: None,
            health: 1.0,
            alternates: Vec::new(),
            mcast: [Group::default(), Group::default()],
            quic_port: None,
            mcast_logged_ok: false,
        }
    }

    /// The group our multicast reaches this peer through, by preference: a group the
    /// peer announced and has acked a recent probe on.
    fn multicast_group(&self, prefer_ipv4: bool) -> Option<SocketAddr> {
        let order = if prefer_ipv4 { [V4, V6] } else { [V6, V4] };
        order
            .into_iter()
            .find(|&f| self.mcast[f].confirmed())
            .and_then(|f| self.mcast[f].addr)
    }

    /// The current address went unanswered: move to the next advertised one.
    fn rotate(&mut self) {
        if self.alternates.len() < 2 {
            return;
        }
        let next = self
            .alternates
            .iter()
            .position(|a| *a == self.addr)
            .map_or(0, |i| (i + 1) % self.alternates.len());
        tracing::info!(
            "ZLOE: {} unanswered, trying {}",
            self.addr,
            self.alternates[next]
        );
        self.addr = self.alternates[next];
    }

    fn live(&self) -> bool {
        self.last_rx.is_some_and(|t| t.elapsed() < BACKBONE_LIVE)
    }

    fn lqi(&self) -> u8 {
        (self.health * 255.0).round().clamp(1.0, 255.0) as u8
    }

    fn record(&mut self, acked: bool) {
        let sample = if acked { 1.0 } else { 0.0 };
        self.health += HEALTH_ALPHA * (sample - self.health);
    }
}

/// Our identity on the backbone: complete once both the radio configuration (address,
/// channel) and the network's extended PAN ID are known.
/// Index into per-family multicast state.
const V6: usize = 0;
const V4: usize = 1;

/// One multicast group a peer announced, and whether our probes reach it there.
#[derive(Debug, Clone, Copy, Default)]
struct Group {
    /// Scoped to our backbone interface (IPv6) or plain (IPv4)
    addr: Option<SocketAddr>,
    /// When the peer last acked one of our probes on this group
    acked: Option<Instant>,
}

impl Group {
    fn confirmed(&self) -> bool {
        self.addr.is_some()
            && self
                .acked
                .is_some_and(|t| t.elapsed() < MCAST_CONFIRM_WINDOW)
    }
}

#[derive(Debug, Clone, Copy)]
struct Identity {
    eui64: Eui64,
    nwk: Nwk,
    epan: Eui64,
    channel: u8,
}

#[derive(Default)]
struct Shared {
    identity: Option<Identity>,
    /// Radio half of the identity, from `reconfigure`
    radio: Option<(Eui64, Nwk, u8)>,
    /// Network half, from `set_extended_pan_id`
    epan: Option<Eui64>,
    peers: HashMap<Eui64, Peer>,
    /// Recently delivered (sender, backbone seq), to drop retransmits of a frame whose
    /// ack was lost.
    seen: HashMap<Eui64, VecDeque<u32>>,
    rx_tx: Option<mpsc::Sender<RxFrame>>,
    mdns_fullname: Option<String>,
    /// Coordinators seen on the backbone (mDNS `role=coordinator`), kept even before
    /// we have an identity of our own: satellites bootstrap from them
    coordinators: HashMap<Eui64, (SocketAddr, Option<Eui64>)>,
    /// Everything mDNS resolved, by extended address
    resolved: HashMap<Eui64, Resolved>,
    /// Secure (QUIC) mode
    secure: bool,
    /// QUIC ports of coordinators seen on the backbone (enrollment targets)
    coordinator_quic: HashMap<Eui64, u16>,
    netinfo_provider: Option<NetInfoProvider>,
    netinfo_waiter: Option<oneshot::Sender<Vec<u8>>>,
    /// Packet numbers of our latest multicast probes, with their family
    probes: VecDeque<(u32, usize)>,
}

/// Datagram counters, for the bench.
#[derive(Default)]
struct Stats {
    /// 802.15.4 broadcasts handed to the backbone
    broadcasts: AtomicU64,
    /// Multicast datagrams they were sent as
    multicast: AtomicU64,
    /// Unicast copies sent to peers multicast does not reach
    unicast_copies: AtomicU64,
    probes: AtomicU64,
}

struct Backbone {
    socket: Arc<UdpSocket>,
    shared: Arc<Mutex<Shared>>,
    pending: Arc<Mutex<HashMap<u32, oneshot::Sender<()>>>>,
    seq: Arc<AtomicU32>,
    stats: Arc<Stats>,
    mcast_block_file: Option<std::path::PathBuf>,
    static_peers: Vec<SocketAddr>,
    mdns: Option<mdns_sd::ServiceDaemon>,
    port: u16,
    /// Set when confined to one interface
    local_net: Option<LocalNet>,
    prefer_ipv4: bool,
    /// The socket is IPv6 dual-stack: IPv4 targets go out as v4-mapped addresses
    dual_stack: bool,
    mcast_port: u16,
    /// The task reading our multicast socket; replaced when the network changes
    mcast_reader: Mutex<Option<tokio::task::JoinHandle<()>>>,
    mcast4_reader: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Secure mode: the QUIC link to peers
    quic: Option<Arc<quic::QuicLink>>,
}

pub struct TrelPhy<P: RadioPhy> {
    inner: P,
    backbone: Option<Backbone>,
    deny: DenyList,
    shared: Arc<Mutex<Shared>>,
}

/// The merged received-frame stream.
pub struct TrelRx(mpsc::Receiver<RxFrame>);

impl Receiver<RxFrame> for TrelRx {
    async fn recv(&mut self) -> Option<RxFrame> {
        self.0.recv().await
    }
}

impl<P: RadioPhy> TrelPhy<P> {
    /// Must be called from within a Tokio runtime.
    pub async fn new(inner: P, config: TrelConfig) -> std::io::Result<Self> {
        let shared = Arc::new(Mutex::new(Shared::default()));

        let backbone = if config.port == 0 {
            None
        } else {
            let local_net = config.interface.as_deref().map(local_net).transpose()?;
            let (socket, dual_stack) = bind_socket(config.port, config.ipv4_only)?;
            let socket = Arc::new(socket);
            tracing::info!(
                "ZLOE backbone listening on UDP {} ({}, {}, prefer {})",
                config.port,
                if dual_stack {
                    "IPv6 dual-stack"
                } else {
                    "IPv4 only"
                },
                config.interface.as_deref().unwrap_or("all interfaces"),
                if config.prefer_ipv4 {
                    "IPv4"
                } else {
                    "IPv6 link-local"
                },
            );

            let mdns = if config.mdns {
                match mdns_sd::ServiceDaemon::new() {
                    Ok(daemon) => {
                        if let Some(name) = &config.interface {
                            let _ = daemon.disable_interface(mdns_sd::IfKind::All);
                            let _ = daemon.disable_interface(mdns_sd::IfKind::LoopbackV4);
                            let _ = daemon.disable_interface(mdns_sd::IfKind::LoopbackV6);
                            if let Err(e) =
                                daemon.enable_interface(mdns_sd::IfKind::Name(name.clone()))
                            {
                                tracing::warn!("ZLOE: mDNS on {name} failed: {e}");
                            }
                        }
                        Some(daemon)
                    }
                    Err(e) => {
                        tracing::warn!("ZLOE: mDNS unavailable, static peers only: {e}");
                        None
                    }
                }
            } else {
                None
            };

            // Secure mode: QUIC peer links; its datagrams go through the same handler
            let quic = match &config.quic {
                Some(qc) => {
                    let (h_shared, h_pending) =
                        (Arc::clone(&shared), Arc::new(Mutex::new(HashMap::new())));
                    let handler: quic::Handler = {
                        let h_pending: Arc<Mutex<HashMap<u32, oneshot::Sender<()>>>> =
                            Arc::clone(&h_pending);
                        let h_shared = Arc::clone(&h_shared);
                        Arc::new(move |buf: &[u8], from: SocketAddr| {
                            process_datagram(&h_shared, &h_pending, buf, from, false)
                        })
                    };
                    let n_shared = Arc::clone(&shared);
                    let netinfo: quic::NetInfo = Arc::new(move || {
                        let provider = n_shared.lock().netinfo_provider.clone();
                        provider.and_then(|provide| provide())
                    });
                    shared.lock().secure = true;
                    Some((
                        quic::QuicLink::new(qc.port, handler, netinfo, qc.code_file.clone())?,
                        h_pending,
                    ))
                }
                None => None,
            };
            let (quic, pending) = match quic {
                Some((link, pending)) => (Some(link), pending),
                None => (None, Arc::new(Mutex::new(HashMap::new()))),
            };

            let backbone = Backbone {
                quic,
                socket,
                shared: Arc::clone(&shared),
                pending,
                seq: Arc::new(AtomicU32::new(rand_u32())),
                stats: Arc::new(Stats::default()),
                mcast_block_file: config.mcast_block_file,
                static_peers: config.static_peers,
                mdns,
                port: config.port,
                local_net,
                prefer_ipv4: config.prefer_ipv4,
                dual_stack,
                mcast_port: if config.quic.is_some() {
                    0
                } else {
                    config.mcast_port
                },
                mcast_reader: Mutex::new(None),
                mcast4_reader: Mutex::new(None),
            };
            backbone.spawn_udp_reader(Arc::clone(&backbone.socket), None);
            backbone.spawn_mdns_browser();
            backbone.spawn_prober();
            Some(backbone)
        };

        Ok(Self {
            inner,
            backbone,
            deny: config.deny,
            shared,
        })
    }

    pub const fn inner(&self) -> &P {
        &self.inner
    }

    /// The network's extended PAN ID (TREL's `xp` in mDNS): peers on other networks are
    /// ignored. Set by the stack's owner when the network is configured.
    pub fn set_extended_pan_id(&self, epan: Eui64) {
        let identity = {
            let mut shared = self.shared.lock();
            shared.epan = Some(epan);
            update_identity(&mut shared)
        };
        if let (Some(identity), Some(backbone)) = (identity, &self.backbone) {
            backbone.advertise(identity);
        }
    }

    /// Secure mode: the network key is known (configured, or after enrollment). Derives
    /// the network CA and our certificate and starts the QUIC links.
    pub fn set_network_key(
        &self,
        nwk_key: &[u8; 16],
        epan: Eui64,
        me: Eui64,
        coordinator: bool,
    ) -> std::io::Result<()> {
        let Some(link) = self.backbone.as_ref().and_then(|b| b.quic.as_ref()) else {
            return Ok(());
        };
        let role = if coordinator {
            security::Role::Coordinator
        } else {
            security::Role::Satellite
        };
        link.set_network(nwk_key, epan, me, role)
    }

    /// Secure mode, coordinator side: whether the network is in pairing mode, when
    /// satellites may enroll without a code.
    pub fn set_pairing_open(&self, pairing_open: quic::PairingOpen) {
        if let Some(link) = self.backbone.as_ref().and_then(|b| b.quic.as_ref()) {
            link.set_pairing_open(pairing_open);
        }
    }

    /// Secure mode, satellite side: find a coordinator on the backbone (on `epan`, when
    /// given) and enroll with `code`: returns the network settings it sends.
    pub async fn enroll(
        &self,
        epan: Option<Eui64>,
        code: &str,
        timeout: Duration,
    ) -> std::io::Result<Vec<u8>> {
        let Some(backbone) = &self.backbone else {
            return Err(std::io::Error::other("ZLOE backbone is disabled"));
        };
        let Some(link) = &backbone.quic else {
            return Err(std::io::Error::other(
                "enrollment needs --zloe-security quic",
            ));
        };
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let target = {
                let shared = self.shared.lock();
                shared
                    .coordinators
                    .iter()
                    .filter(|(_, (_, e))| epan.is_none() || *e == epan)
                    .find_map(|(eui64, (addr, _))| {
                        shared
                            .coordinator_quic
                            .get(eui64)
                            .map(|qp| (*eui64, SocketAddr::new(addr.ip(), *qp)))
                    })
            };
            if let Some((eui64, addr)) = target {
                tracing::info!("ZLOE/QUIC: enrolling with coordinator {eui64:?} at {addr}");
                return link.enroll(addr, code).await;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no secure coordinator on the ZLOE backbone",
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Coordinator side: hand these settings to satellites that ask over the backbone.
    pub fn set_netinfo_provider(&self, provider: NetInfoProvider) {
        self.shared.lock().netinfo_provider = Some(provider);
    }

    /// Satellite side: find a coordinator on the backbone (on extended PAN `epan`, when
    /// given) and fetch its network settings. Retries until `timeout`.
    pub async fn fetch_network(
        &self,
        epan: Option<Eui64>,
        timeout: Duration,
    ) -> std::io::Result<Vec<u8>> {
        let backbone = self
            .backbone
            .as_ref()
            .ok_or_else(|| std::io::Error::other("ZLOE backbone is disabled (--zloe-port 0)"))?;
        let deadline = tokio::time::Instant::now() + timeout;

        while tokio::time::Instant::now() < deadline {
            let candidates: Vec<(Eui64, SocketAddr, Option<Eui64>)> = {
                let shared = self.shared.lock();
                shared
                    .coordinators
                    .iter()
                    .filter(|(_, (_, x))| epan.is_none() || *x == epan)
                    .map(|(eui64, (addr, x))| (*eui64, *addr, *x))
                    .collect()
            };
            let Some(&(eui64, addr, coordinator_epan)) = candidates.first() else {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            };
            if candidates.len() > 1 {
                tracing::warn!(
                    "ZLOE: {} coordinators match, using {eui64:?} (epan {coordinator_epan:?}); \
                     pick one with --zloe-satellite-epan",
                    candidates.len()
                );
            }

            let (tx, rx) = oneshot::channel();
            self.shared.lock().netinfo_waiter = Some(tx);
            let seq = backbone.seq.fetch_add(1, Ordering::Relaxed);
            let request = netinfo_header(KIND_NETINFO_REQ, seq, None);
            tracing::info!("ZLOE: asking coordinator {eui64:?} at {addr} for network settings");
            backbone
                .socket
                .send_to(&request, backbone.target(addr))
                .await?;
            if let Ok(Ok(info)) = tokio::time::timeout(Duration::from_secs(1), rx).await {
                return Ok(info);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "no coordinator answered on the ZLOE backbone",
        ))
    }
}

/// Handle one ZLOE datagram (from UDP or a QUIC link); returns the reply to send back
/// to `from` (an ack or the network settings), if any.
fn process_datagram(
    shared: &Mutex<Shared>,
    pending: &Mutex<HashMap<u32, oneshot::Sender<()>>>,
    buf: &[u8],
    from: SocketAddr,
    allow_netinfo: bool,
) -> Option<Vec<u8>> {
    let Some(header) = WireHeader::parse(buf) else {
        tracing::debug!("ZLOE: dropping malformed datagram from {from}");
        return None;
    };

    if header.kind == KIND_ACK {
        let waiter = pending.lock().remove(&header.seq);
        if let Some(waiter) = waiter {
            let _ = waiter.send(());
        } else {
            // Not a unicast we are waiting on: an answer to a probe?
            let mut shared = shared.lock();
            let family = shared
                .probes
                .iter()
                .find(|(seq, _)| *seq == header.seq)
                .map(|(_, f)| *f);
            if let Some(family) = family
                && let Some(peer) = shared.peers.get_mut(&header.eui64)
            {
                peer.mcast[family].acked = Some(Instant::now());
            }
        }
        return None;
    }

    // Bootstrap exchange: the backbone is trusted, so the settings (network
    // key included) go to whoever asks
    if header.kind == KIND_NETINFO_REQ && allow_netinfo {
        let (provider, identity) = {
            let shared = shared.lock();
            (shared.netinfo_provider.clone(), shared.identity)
        };
        let info = provider.and_then(|provide| provide())?;
        tracing::info!(
            "ZLOE: sending network settings to {from} ({:?})",
            header.eui64
        );
        let mut rsp = netinfo_header(KIND_NETINFO_RSP, header.seq, identity);
        rsp.extend_from_slice(&info);
        return Some(rsp);
    }
    if header.kind == KIND_NETINFO_RSP {
        if let Some(waiter) = shared.lock().netinfo_waiter.take() {
            let _ = waiter.send(buf[HEADER_LEN..].to_vec());
        }
        return None;
    }

    if header.kind != KIND_DATA && header.kind != KIND_PROBE {
        return None;
    }
    let psdu = buf[HEADER_LEN..].to_vec();
    let (deliver, ack_to) = {
        let mut shared = shared.lock();
        let identity = shared.identity?;
        if header.epan != identity.epan || header.eui64 == identity.eui64 {
            return None;
        }

        // Learn (or refresh) the peer from its own traffic
        let peer = shared.peers.entry(header.eui64).or_insert_with(|| {
            tracing::info!(
                "ZLOE: learned peer {:?} / {:?} at {from}",
                header.eui64,
                header.nwk
            );
            Peer::new(from, None, PeerSource::Learned)
        });
        peer.addr = from;
        peer.nwk = Some(header.nwk);
        peer.last_rx = Some(Instant::now());
        let lqi = peer.lqi();

        // A probe only refreshes the peer and gets its ack
        let seen = shared.seen.entry(header.eui64).or_default();
        let duplicate = header.kind == KIND_PROBE || seen.contains(&header.seq);
        if !duplicate {
            seen.push_back(header.seq);
            if seen.len() > DEDUP_WINDOW {
                seen.pop_front();
            }
        }

        let ack_to = (header.flags & FLAG_ACK_REQUEST != 0).then_some(from);
        let deliver = (!duplicate).then(|| {
            (
                shared.rx_tx.clone(),
                RxFrame {
                    psdu,
                    channel: identity.channel,
                    rssi: BACKBONE_RSSI,
                    lqi,
                    timestamp_us: 0,
                },
            )
        });
        (deliver, ack_to.map(|to| (to, identity)))
    };

    if let Some((Some(tx), frame)) = deliver {
        tracing::trace!(
            "ZLOE: rx {} bytes from {:?}",
            frame.psdu.len(),
            header.eui64
        );
        let _ = tx.try_send(frame);
    }
    if let Some((_, identity)) = ack_to {
        let ack = WireHeader {
            kind: KIND_ACK,
            flags: 0,
            seq: header.seq,
            eui64: identity.eui64,
            nwk: identity.nwk,
            epan: identity.epan,
        }
        .to_bytes();
        return Some(ack);
    }
    None
}

/// Header for the bootstrap messages, sent before we may have an identity.
fn netinfo_header(kind: u8, seq: u32, identity: Option<Identity>) -> Vec<u8> {
    WireHeader {
        kind,
        flags: 0,
        seq,
        eui64: identity.map_or(Eui64([0; 8]), |i| i.eui64),
        nwk: identity.map_or(Nwk(0xFFFF), |i| i.nwk),
        epan: identity.map_or(Eui64([0; 8]), |i| i.epan),
    }
    .to_bytes()
}

/// What mDNS last told us about a node.
#[derive(Debug, Clone)]
struct Resolved {
    epan: Option<Eui64>,
    nwk: Option<Nwk>,
    /// Usable addresses, best first, with their rank
    candidates: Vec<((u8, u8), SocketAddr)>,
    /// Announced groups: [IPv6 (`mc`), IPv4 (`mc4`)]
    mcast: [Option<SocketAddr>; 2],
    /// Security mode (`sec`) and QUIC port (`qp`)
    quic_port: Option<u16>,
}

/// Create or update the peer for a resolved node on our network.
fn apply_resolved(shared: &mut Shared, eui64: Eui64) {
    let Some(identity) = shared.identity else {
        return;
    };
    let Some(resolved) = shared.resolved.get(&eui64).cloned() else {
        return;
    };
    if eui64 == identity.eui64 || resolved.epan != Some(identity.epan) {
        return;
    }
    // A secure node only peers with secure nodes, and the other way around
    if shared.secure != resolved.quic_port.is_some() {
        return;
    }
    let Some(&(best_key, addr)) = resolved.candidates.first() else {
        return;
    };
    let nwk = resolved.nwk;

    let peer = shared.peers.entry(eui64).or_insert_with(|| {
        tracing::info!("ZLOE: mDNS peer {eui64:?} / {nwk:?} at {addr}");
        Peer::new(addr, nwk, PeerSource::Mdns)
    });
    // Once the peer has talked to us, its datagrams' source address is authoritative.
    // Until then follow mDNS, but only to a strictly better address: answers trickle
    // in per interface and would make it flap
    let current_key = resolved
        .candidates
        .iter()
        .find(|(_, a)| *a == peer.addr)
        .map(|(k, _)| *k);
    peer.alternates = resolved.candidates.iter().map(|(_, a)| *a).collect();
    peer.quic_port = resolved.quic_port;
    for family in [V6, V4] {
        if peer.mcast[family].addr != resolved.mcast[family] {
            tracing::info!(
                "ZLOE: peer {eui64:?} multicast: {:?}",
                resolved.mcast[family]
            );
            peer.mcast[family] = Group {
                addr: resolved.mcast[family],
                acked: None,
            };
        }
    }
    if peer.last_rx.is_none() && current_key.is_none_or(|k| best_key < k) {
        tracing::info!("ZLOE: mDNS peer {eui64:?} moved to {addr}");
        peer.addr = addr;
    }
    if nwk.is_some() {
        peer.nwk = nwk;
    }
}

/// Combine the radio and network halves into the identity, once both are known.
fn update_identity(shared: &mut Shared) -> Option<Identity> {
    let (eui64, nwk, channel) = shared.radio?;
    let epan = shared.epan?;
    let identity = Identity {
        eui64,
        nwk,
        epan,
        channel,
    };
    let changed = shared.identity.is_none_or(|old| {
        old.eui64 != identity.eui64 || old.nwk != identity.nwk || old.epan != identity.epan
    });
    shared.identity = Some(identity);
    if changed {
        // Nodes resolved before we knew our network become peers now
        let known: Vec<Eui64> = shared.resolved.keys().copied().collect();
        for eui64 in known {
            apply_resolved(shared, eui64);
        }
    }
    changed.then_some(identity)
}

/// One dual-stack IPv6 socket (IPv4 arrives v4-mapped); IPv4-only when the host has no
/// IPv6.
fn bind_socket(port: u16, ipv4_only: bool) -> std::io::Result<(UdpSocket, bool)> {
    use socket2::{Domain, Protocol, Socket, Type};
    let v6 = if ipv4_only {
        Err(std::io::Error::other("IPv4 only requested"))
    } else {
        Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).and_then(|s| {
            s.set_only_v6(false)?;
            s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
            Ok(s)
        })
    };
    let (socket, dual_stack) = match v6 {
        Ok(s) => (s, true),
        Err(e) => {
            tracing::warn!("ZLOE: no IPv6 socket ({e}), using IPv4 only");
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
            (s, false)
        }
    };
    socket.set_nonblocking(true)?;
    Ok((UdpSocket::from_std(socket.into())?, dual_stack))
}

/// v4-mapped IPv6 back to plain IPv4, so a peer has one spelling of its address.
fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map_or(addr, |v4| SocketAddr::new(IpAddr::V4(v4), v6.port())),
        SocketAddr::V4(_) => addr,
    }
}

impl Backbone {
    /// Read datagrams from `rx` (the unicast socket, or the multicast one). Acks and
    /// replies always leave from the unicast socket, so peers see our unicast port.
    fn spawn_udp_reader(
        &self,
        rx: Arc<UdpSocket>,
        block: Option<(std::path::PathBuf, &'static str)>,
    ) -> tokio::task::JoinHandle<()> {
        let socket = Arc::clone(&self.socket);
        let shared = Arc::clone(&self.shared);
        let pending = Arc::clone(&self.pending);
        let dual_stack = self.dual_stack;
        let secure = self.quic.is_some();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (len, from) = match rx.recv_from(&mut buf).await {
                    Ok((len, from)) => (len, canonical(from)),
                    Err(e) => {
                        tracing::warn!("ZLOE: UDP receive failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                // Test hook: an empty file blocks every group, "v4"/"v6" just one
                if let Some((file, family)) = &block
                    && let Ok(content) = std::fs::read_to_string(file)
                    && (content.trim().is_empty() || content.contains(family))
                {
                    continue;
                }
                // Secure mode: plain UDP carries nothing we trust
                if secure {
                    continue;
                }
                if let Some(reply) = process_datagram(&shared, &pending, &buf[..len], from, true) {
                    let _ = socket.send_to(&reply, to_family(from, dual_stack)).await;
                }
            }
        })
    }

    fn spawn_mdns_browser(&self) {
        let Some(daemon) = &self.mdns else { return };
        let events = match daemon.browse(SERVICE_TYPE) {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!("ZLOE: mDNS browse failed: {e}");
                return;
            }
        };
        let shared = Arc::clone(&self.shared);
        let local_net = self.local_net;
        let dual_stack = self.dual_stack;
        let prefer_ipv4 = self.prefer_ipv4;

        tokio::spawn(async move {
            while let Ok(event) = events.recv_async().await {
                match event {
                    mdns_sd::ServiceEvent::ServiceResolved(info) => {
                        let Some(eui64) = info
                            .get_property_val_str("xa")
                            .and_then(|s| Eui64::try_from_hex(s).ok())
                        else {
                            continue;
                        };
                        let epan = info
                            .get_property_val_str("xp")
                            .and_then(|s| Eui64::try_from_hex(s).ok());
                        let nwk = info
                            .get_property_val_str("nwk")
                            .and_then(|s| Nwk::try_from_hex(s).ok());
                        // Usable only on a known interface: the group is link-local
                        // Usable only on a known interface: groups are link-local
                        // (IPv6) or bound to the interface's subnet (IPv4)
                        let mc6 = info
                            .get_property_val_str("mc")
                            .and_then(|s| s.parse::<SocketAddrV6>().ok())
                            .filter(|mc| mc.ip().is_multicast() && dual_stack)
                            .zip(local_net)
                            .map(|(mut mc, net)| {
                                mc.set_scope_id(net.index);
                                SocketAddr::V6(mc)
                            });
                        let mc4 = info
                            .get_property_val_str("mc4")
                            .and_then(|s| s.parse::<SocketAddrV4>().ok())
                            .filter(|mc| mc.ip().is_multicast())
                            .filter(|_| local_net.is_some_and(|n| n.v4.is_some()))
                            .map(SocketAddr::V4);
                        let mcast = [mc6, mc4];
                        let quic_port = (info.get_property_val_str("sec") == Some("quic"))
                            .then(|| info.get_property_val_str("qp"))
                            .flatten()
                            .and_then(|p| p.parse::<u16>().ok());
                        // mDNS lists every address of every interface (Docker bridges,
                        // loopback, ...): pick deterministically
                        let candidates = candidate_addresses(
                            info.get_addresses(),
                            info.get_port(),
                            local_net,
                            prefer_ipv4,
                            dual_stack,
                        );
                        let Some(&(_, addr)) = candidates.first() else {
                            continue;
                        };

                        let mut shared = shared.lock();
                        if info.get_property_val_str("role") == Some("coordinator")
                            && let Some(qp) = quic_port
                        {
                            shared.coordinator_quic.insert(eui64, qp);
                        }
                        if info.get_property_val_str("role") == Some("coordinator") {
                            let known = shared.coordinators.insert(eui64, (addr, epan));
                            if known.is_none() {
                                tracing::info!(
                                    "ZLOE: coordinator {eui64:?} (epan {epan:?}) at {addr}"
                                );
                            }
                        }
                        // Kept even while we have no identity (a satellite browses
                        // before it knows its network) and applied once we do
                        shared.resolved.insert(
                            eui64,
                            Resolved {
                                epan,
                                nwk,
                                candidates,
                                mcast,
                                quic_port,
                            },
                        );
                        apply_resolved(&mut shared, eui64);
                    }
                    mdns_sd::ServiceEvent::ServiceRemoved(_, fullname) => {
                        let Some(eui64) = fullname
                            .split('.')
                            .next()
                            .and_then(|s| Eui64::try_from_hex(s).ok())
                        else {
                            continue;
                        };
                        let mut shared = shared.lock();
                        shared.resolved.remove(&eui64);
                        if let Some(peer) = shared.peers.get_mut(&eui64) {
                            // A peer kept alive by its own traffic loses what only
                            // mDNS told us
                            peer.mcast = [Group::default(), Group::default()];
                        }
                        if shared
                            .peers
                            .get(&eui64)
                            .is_some_and(|p| p.source == PeerSource::Mdns)
                        {
                            tracing::info!("ZLOE: mDNS peer {eui64:?} went away");
                            shared.peers.remove(&eui64);
                        }
                    }
                    _ => {}
                }
            }
        });
    }

    fn block_hook(&self, family: &'static str) -> Option<(std::path::PathBuf, &'static str)> {
        self.mcast_block_file.clone().map(|f| (f, family))
    }

    /// Join the network's multicast groups and read from them: `[IPv6, IPv4]`, each
    /// `None` when multicast is off, the backbone interface (or its address of that
    /// family) is unknown, or joining fails.
    fn listen_multicast(&self, epan: Eui64) -> [Option<SocketAddr>; 2] {
        use socket2::{Domain, Protocol, SockRef, Socket, Type};

        for reader in [&self.mcast_reader, &self.mcast4_reader] {
            if let Some(old) = reader.lock().take() {
                old.abort(); // closes the socket, leaving the previous group
            }
        }
        if self.mcast_port == 0 {
            return [None, None];
        }
        let Some(net) = self.local_net else {
            tracing::info!("ZLOE: no multicast without --zloe-interface");
            return [None, None];
        };

        // Several nodes on one host (the bench) share the port
        let open = |domain: Domain, bind: SocketAddr| -> std::io::Result<Socket> {
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            if domain == Domain::IPV6 {
                socket.set_only_v6(true)?;
            }
            socket.set_reuse_address(true)?;
            socket.set_reuse_port(true)?;
            socket.bind(&bind.into())?;
            Ok(socket)
        };
        let start = |socket: Socket| -> std::io::Result<Arc<UdpSocket>> {
            socket.set_nonblocking(true)?;
            Ok(Arc::new(UdpSocket::from_std(socket.into())?))
        };

        let mc6 = self.dual_stack.then(|| {
            let group = multicast_group(epan);
            let joined = open(
                Domain::IPV6,
                (Ipv6Addr::UNSPECIFIED, self.mcast_port).into(),
            )
            .and_then(|s| s.join_multicast_v6(&group, net.index).map(|()| s))
            .and_then(start);
            match joined {
                Ok(socket) => {
                    let mc = SocketAddrV6::new(group, self.mcast_port, 0, net.index);
                    tracing::info!("ZLOE: listening on multicast group {mc}");
                    *self.mcast_reader.lock() =
                        Some(self.spawn_udp_reader(socket, self.block_hook("v6")));
                    Some(SocketAddr::V6(mc))
                }
                Err(e) => {
                    tracing::warn!("ZLOE: cannot join multicast group {group}: {e}");
                    None
                }
            }
        });

        let mc4 = net.v4.map(|(iface_ip, _)| {
            let group = multicast_group_v4(epan);
            let joined = open(
                Domain::IPV4,
                (Ipv4Addr::UNSPECIFIED, self.mcast_port).into(),
            )
            .and_then(|s| s.join_multicast_v4(&group, &iface_ip).map(|()| s))
            .and_then(start);
            // Our IPv4 multicast leaves through the unicast socket (so peers see our
            // unicast port), out of the backbone interface
            let sending = SockRef::from(&*self.socket).set_multicast_if_v4(&iface_ip);
            match (joined, sending) {
                (Ok(socket), Ok(())) => {
                    let mc = SocketAddrV4::new(group, self.mcast_port);
                    tracing::info!("ZLOE: listening on multicast group {mc}");
                    *self.mcast4_reader.lock() =
                        Some(self.spawn_udp_reader(socket, self.block_hook("v4")));
                    Some(SocketAddr::V4(mc))
                }
                (Err(e), _) | (_, Err(e)) => {
                    tracing::warn!("ZLOE: cannot use IPv4 multicast group {group}: {e}");
                    None
                }
            }
        });

        [mc6.flatten(), mc4.flatten()]
    }

    fn advertise(&self, identity: Identity) {
        let mcast = self.listen_multicast(identity.epan);
        let Some(daemon) = &self.mdns else { return };
        let mut shared = self.shared.lock();
        if let Some(old) = shared.mdns_fullname.take() {
            let _ = daemon.unregister(&old);
        }

        let instance = hex_be(&identity.eui64.to_be_bytes());
        let mut properties: HashMap<String, String> = [
            ("v".to_string(), VERSION.to_string()),
            ("xa".to_string(), instance.clone()),
            ("xp".to_string(), hex_be(&identity.epan.to_be_bytes())),
            ("nwk".to_string(), format!("{:04x}", identity.nwk.as_u16())),
            (
                "role".to_string(),
                if identity.nwk == Nwk(0x0000) {
                    "coordinator"
                } else {
                    "router"
                }
                .to_string(),
            ),
        ]
        .into_iter()
        .collect();

        // `mc`: where we listen for multicast. Absent when we cannot, so peers know
        // to reach us by unicast only
        if let [Some(SocketAddr::V6(mc)), _] = mcast {
            properties.insert("mc".to_string(), format!("[{}]:{}", mc.ip(), mc.port()));
        }
        if let [_, Some(mc4)] = mcast {
            properties.insert("mc4".to_string(), mc4.to_string());
        }
        // Security mode; a secure node also announces its QUIC port
        match &self.quic {
            Some(link) => {
                properties.insert("sec".to_string(), "quic".to_string());
                properties.insert("qp".to_string(), link.port.to_string());
            }
            None => {
                properties.insert("sec".to_string(), "none".to_string());
            }
        }

        // Addresses (IPv6 link-local and IPv4) come from the interfaces mDNS runs on,
        // which --zloe-interface already narrows to one
        let host = format!("ziggurat-{instance}.local.");
        match mdns_sd::ServiceInfo::new(SERVICE_TYPE, &instance, &host, "", self.port, properties) {
            Ok(info) => {
                let info = info.enable_addr_auto();
                let fullname = info.get_fullname().to_string();
                match daemon.register(info) {
                    Ok(()) => {
                        tracing::info!("ZLOE: advertising {fullname}");
                        shared.mdns_fullname = Some(fullname);
                    }
                    Err(e) => tracing::warn!("ZLOE: mDNS register failed: {e}"),
                }
            }
            Err(e) => tracing::warn!("ZLOE: bad mDNS service info: {e}"),
        }
    }

    /// Every probe interval: multicast an empty datagram that each peer answers by
    /// unicast, so we know which peers our multicast reaches.
    fn spawn_prober(&self) {
        let socket = Arc::clone(&self.socket);
        let shared = Arc::clone(&self.shared);
        let seq = Arc::clone(&self.seq);
        let stats = Arc::clone(&self.stats);
        let prefer_ipv4 = self.prefer_ipv4;
        let dual_stack = self.dual_stack;
        let quic = self.quic.clone();

        tokio::spawn(async move {
            let mut tick = tokio::time::interval(PROBE_INTERVAL);
            loop {
                tick.tick().await;
                // Secure mode: keep a QUIC link to every secure peer (the lower EUI64
                // dials); no multicast to probe
                if let Some(link) = &quic {
                    let targets: Vec<(Eui64, SocketAddr)> = shared
                        .lock()
                        .peers
                        .iter()
                        .filter_map(|(eui64, p)| {
                            p.quic_port
                                .map(|qp| (*eui64, SocketAddr::new(p.addr.ip(), qp)))
                        })
                        .collect();
                    for (peer, addr) in targets {
                        link.ensure_connected(peer, addr);
                    }
                    continue;
                }
                let probes = {
                    let mut shared = shared.lock();
                    let Some(identity) = shared.identity else {
                        continue;
                    };

                    let mut groups: Vec<(usize, SocketAddr)> = Vec::new();
                    for (eui64, peer) in &mut shared.peers {
                        // Probe the preferred group only; the other one only while
                        // the preferred one is absent or unconfirmed, so a peer can
                        // fail over without doubling the probe traffic
                        let order = if prefer_ipv4 { [V4, V6] } else { [V6, V4] };
                        for family in order {
                            let Some(group) = peer.mcast[family].addr else {
                                continue;
                            };
                            if !groups.contains(&(family, group)) {
                                groups.push((family, group));
                            }
                            if peer.mcast[family].confirmed() {
                                break;
                            }
                        }
                        let ok = peer.multicast_group(prefer_ipv4);
                        if ok.is_some() != peer.mcast_logged_ok {
                            peer.mcast_logged_ok = ok.is_some();
                            match ok {
                                Some(group) => {
                                    tracing::info!("ZLOE: multicast reaches {eui64:?} via {group}");
                                }
                                None => tracing::warn!(
                                    "ZLOE: multicast does not reach {eui64:?}, \
                                     sending it unicast copies"
                                ),
                            }
                        }
                    }
                    if groups.is_empty() {
                        continue;
                    }

                    // One probe per group, so an ack tells which family works
                    let probes: Vec<(SocketAddr, Vec<u8>)> = groups
                        .into_iter()
                        .map(|(family, group)| {
                            let seq = seq.fetch_add(1, Ordering::Relaxed);
                            shared.probes.push_back((seq, family));
                            let probe = WireHeader {
                                kind: KIND_PROBE,
                                flags: FLAG_ACK_REQUEST,
                                seq,
                                eui64: identity.eui64,
                                nwk: identity.nwk,
                                epan: identity.epan,
                            }
                            .to_bytes();
                            (group, probe)
                        })
                        .collect();
                    while shared.probes.len() > 8 {
                        shared.probes.pop_front();
                    }
                    probes
                };
                for (group, probe) in probes {
                    let _ = socket.send_to(&probe, to_family(group, dual_stack)).await;
                    stats.probes.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    fn peer_for(&self, dest: &MacAddress) -> Option<SocketAddr> {
        let shared = self.shared.lock();
        match dest {
            MacAddress::Extended(eui64) => shared.peers.get(eui64).map(|p| p.addr),
            MacAddress::Short(nwk) => shared
                .peers
                .values()
                .find(|p| p.nwk == Some(*nwk))
                .map(|p| p.addr),
            MacAddress::None => None,
        }
    }

    fn header(&self, kind: u8, flags: u8, seq: u32) -> Option<Vec<u8>> {
        let identity = self.shared.lock().identity?;
        Some(
            WireHeader {
                kind,
                flags,
                seq,
                eui64: identity.eui64,
                nwk: identity.nwk,
                epan: identity.epan,
            }
            .to_bytes(),
        )
    }

    /// The address as this socket's family wants it.
    fn target(&self, addr: SocketAddr) -> SocketAddr {
        to_family(addr, self.dual_stack)
    }

    fn record_link(&self, to: SocketAddr, acked: bool) {
        let mut shared = self.shared.lock();
        if let Some(peer) = shared.peers.values_mut().find(|p| p.addr == to) {
            peer.record(acked);
        }
    }

    async fn send_broadcast(&self, psdu: &[u8]) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let Some(mut datagram) = self.header(KIND_DATA, 0, seq) else {
            return;
        };
        datagram.extend_from_slice(psdu);

        // Secure mode: one QUIC datagram per connected peer
        if let Some(link) = &self.quic {
            self.stats.broadcasts.fetch_add(1, Ordering::Relaxed);
            for peer in link.connected() {
                if link.send(peer, &datagram) {
                    self.stats.unicast_copies.fetch_add(1, Ordering::Relaxed);
                }
            }
            return;
        }

        // One multicast datagram covers every peer it is known to reach; the others
        // (no announced address, or probes unanswered) get a unicast copy with the
        // same packet number, so a peer that receives both keeps one
        let (groups, copies) = {
            let shared = self.shared.lock();
            let mut groups: Vec<SocketAddr> = Vec::new();
            let mut copies: Vec<SocketAddr> = Vec::new();
            for peer in shared.peers.values() {
                match peer.multicast_group(self.prefer_ipv4) {
                    Some(group) => {
                        if !groups.contains(&group) {
                            groups.push(group);
                        }
                    }
                    None => copies.push(peer.addr),
                }
            }
            // Static peers that have not identified themselves yet
            for addr in &self.static_peers {
                if !shared.peers.values().any(|p| p.addr == *addr) {
                    copies.push(*addr);
                }
            }
            (groups, copies)
        };

        self.stats.broadcasts.fetch_add(1, Ordering::Relaxed);
        for group in groups {
            let _ = self.socket.send_to(&datagram, self.target(group)).await;
            self.stats.multicast.fetch_add(1, Ordering::Relaxed);
        }
        for target in copies {
            let _ = self.socket.send_to(&datagram, self.target(target)).await;
            self.stats.unicast_copies.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Secure mode: unicast over the peer's QUIC link, acked like the UDP path.
    async fn send_unicast_quic(&self, peer: Eui64, psdu: &[u8], ack_request: bool) -> bool {
        let Some(link) = &self.quic else { return false };
        if !link.is_connected(peer) {
            return false;
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let flags = if ack_request { FLAG_ACK_REQUEST } else { 0 };
        let Some(mut datagram) = self.header(KIND_DATA, flags, seq) else {
            return false;
        };
        datagram.extend_from_slice(psdu);
        if !ack_request {
            return link.send(peer, &datagram);
        }
        for _ in 0..ATTEMPTS {
            let (tx, rx) = oneshot::channel();
            self.pending.lock().insert(seq, tx);
            if !link.send(peer, &datagram) {
                break;
            }
            if tokio::time::timeout(ACK_TIMEOUT, rx).await.is_ok() {
                return true;
            }
        }
        self.pending.lock().remove(&seq);
        false
    }

    fn peer_eui_for(&self, dest: &MacAddress) -> Option<Eui64> {
        let shared = self.shared.lock();
        match dest {
            MacAddress::Extended(eui64) => shared.peers.contains_key(eui64).then_some(*eui64),
            MacAddress::Short(nwk) => shared
                .peers
                .iter()
                .find(|(_, p)| p.nwk == Some(*nwk))
                .map(|(e, _)| *e),
            MacAddress::None => None,
        }
    }

    /// Reliable-ish unicast to one peer. `true` once acked.
    async fn send_unicast(&self, to: SocketAddr, psdu: &[u8], ack_request: bool) -> bool {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let flags = if ack_request { FLAG_ACK_REQUEST } else { 0 };
        let Some(mut datagram) = self.header(KIND_DATA, flags, seq) else {
            return false;
        };
        datagram.extend_from_slice(psdu);

        let dest = self.target(to);
        if !ack_request {
            return self.socket.send_to(&datagram, dest).await.is_ok();
        }

        for attempt in 0..ATTEMPTS {
            let (tx, rx) = oneshot::channel();
            self.pending.lock().insert(seq, tx);
            if self.socket.send_to(&datagram, dest).await.is_err() {
                self.record_link(to, false);
                break;
            }
            let acked = tokio::time::timeout(ACK_TIMEOUT, rx).await.is_ok();
            self.record_link(to, acked);
            if acked {
                if attempt > 0 {
                    tracing::debug!("ZLOE: unicast to {to} acked after {} retries", attempt);
                }
                return true;
            }
        }
        self.pending.lock().remove(&seq);
        tracing::debug!("ZLOE: unicast to {to} not acked");
        if let Some(peer) = self.shared.lock().peers.values_mut().find(|p| p.addr == to) {
            peer.rotate();
        }
        false
    }
}

impl<P: RadioPhy> RadioPhy for TrelPhy<P> {
    type Exclusive<'a> = P::Exclusive<'a>;
    type RxStream = TrelRx;
    type ResetStream = P::ResetStream;

    async fn reset(&self) -> Result<(), RadioError> {
        self.inner.reset().await
    }

    async fn reconfigure(&self, config: &RadioConfig) -> Result<(), RadioError> {
        self.inner.reconfigure(config).await?;

        // The capture config uses a broadcast address; there is no identity to announce
        if config.short_address == Nwk(0xFFFF) || config.promiscuous {
            return Ok(());
        }
        let identity = {
            let mut shared = self.shared.lock();
            shared.radio = Some((
                config.extended_address,
                config.short_address,
                config.channel,
            ));
            update_identity(&mut shared)
        };
        if let (Some(identity), Some(backbone)) = (identity, &self.backbone) {
            backbone.advertise(identity);
        }
        Ok(())
    }

    async fn set_frame_pending_table(
        &self,
        short: &[Nwk],
        extended: &[Eui64],
    ) -> Result<(), RadioError> {
        self.inner.set_frame_pending_table(short, extended).await
    }

    async fn transmit(&self, frame: TxFrame) -> Result<TxResult, RadioError> {
        let Some(mac) = MacHeader::parse(&frame.psdu) else {
            return self.inner.transmit(frame).await;
        };

        if let Some(backbone) = &self.backbone {
            if mac.dest.is_broadcast() {
                // Beacon requests and other MAC commands mean nothing to backbone peers
                if mac.frame_type == MAC_FRAME_DATA {
                    backbone.send_broadcast(&frame.psdu).await;
                }
            } else if backbone.quic.is_some() {
                if let Some(peer) = backbone.peer_eui_for(&mac.dest) {
                    if backbone
                        .send_unicast_quic(peer, &frame.psdu, mac.ack_request)
                        .await
                    {
                        tracing::trace!("ZLOE: tx to {:?} via QUIC", mac.dest);
                        return Ok(TxResult::Acked);
                    }
                    tracing::info!("ZLOE: QUIC to {:?} failed, falling back to air", mac.dest);
                }
            } else if let Some(peer) = backbone.peer_for(&mac.dest) {
                if backbone
                    .send_unicast(peer, &frame.psdu, mac.ack_request)
                    .await
                {
                    tracing::trace!("ZLOE: tx to {:?} via backbone", mac.dest);
                    return Ok(TxResult::Acked);
                }
                tracing::info!(
                    "ZLOE: backbone to {:?} failed, falling back to air",
                    mac.dest
                );
            }
        }

        if self.deny.denies(&mac.dest) {
            tracing::trace!("ZLOE deny: not transmitting to {:?}", mac.dest);
            return Ok(if mac.ack_request {
                TxResult::NoAck
            } else {
                TxResult::Acked
            });
        }

        self.inner.transmit(frame).await
    }

    async fn energy_detect(&self, channel: u8, duration: Duration) -> Result<i8, RadioError> {
        self.inner.energy_detect(channel, duration).await
    }

    async fn lock(&self) -> Self::Exclusive<'_> {
        self.inner.lock().await
    }

    fn subscribe_rx(&self) -> TrelRx {
        let (tx, rx) = mpsc::channel(64);
        self.shared.lock().rx_tx = Some(tx.clone());

        let mut inner_rx = self.inner.subscribe_rx();
        let deny = self.deny.clone();
        let shared = Arc::clone(&self.shared);
        let has_backbone = self.backbone.is_some();

        // Over-the-air frames: apply the deny list, and drop copies of what a live
        // backbone peer also sends over the backbone
        tokio::spawn(async move {
            while let Some(frame) = inner_rx.recv().await {
                if let Some(mac) = MacHeader::parse(&frame.psdu) {
                    if deny.denies(&mac.source) {
                        tracing::trace!("ZLOE deny: dropping air frame from {:?}", mac.source);
                        continue;
                    }
                    if has_backbone {
                        let live_peer = {
                            let shared = shared.lock();
                            match &mac.source {
                                MacAddress::Extended(eui64) => {
                                    shared.peers.get(eui64).is_some_and(Peer::live)
                                }
                                MacAddress::Short(nwk) => shared
                                    .peers
                                    .values()
                                    .any(|p| p.nwk == Some(*nwk) && p.live()),
                                MacAddress::None => false,
                            }
                        };
                        if live_peer {
                            tracing::trace!("ZLOE: dropping air copy from {:?}", mac.source);
                            continue;
                        }
                    }
                }
                if tx.send(frame).await.is_err() {
                    break;
                }
            }
        });

        TrelRx(rx)
    }

    fn subscribe_reset(&self) -> Self::ResetStream {
        self.inner.subscribe_reset()
    }
}

impl<P: RadioPhy> TrelPhy<P> {
    /// Datagram counters since start, for diagnostics.
    pub fn stats(&self) -> Option<String> {
        let stats = &self.backbone.as_ref()?.stats;
        Some(format!(
            "broadcasts={} multicast={} unicast_copies={} probes={}",
            stats.broadcasts.load(Ordering::Relaxed),
            stats.multicast.load(Ordering::Relaxed),
            stats.unicast_copies.load(Ordering::Relaxed),
            stats.probes.load(Ordering::Relaxed),
        ))
    }

    /// Peers currently known, for diagnostics.
    pub fn peers(&self) -> Vec<String> {
        self.shared
            .lock()
            .peers
            .iter()
            .map(|(eui64, p)| {
                format!(
                    "{eui64:?} nwk={:?} addr={} via={:?} lqi={} mc={} last_rx={:?}",
                    p.nwk,
                    p.addr,
                    p.source,
                    p.lqi(),
                    [V6, V4]
                        .into_iter()
                        .filter_map(|f| p.mcast[f].addr.map(|a| (a, p.mcast[f].confirmed())))
                        .map(|(a, ok)| format!("{a} {}", if ok { "ok" } else { "unconfirmed" }))
                        .collect::<Vec<_>>()
                        .join(", "),
                    p.last_rx.map(|t| t.elapsed())
                )
            })
            .collect()
    }
}

// -- wire format ---------------------------------------------------------------------

/// `"ZL" | ver=2 | kind | flags | seq:u32le | xa: EUI64 | nwk:u16le | epan: extended PAN ID`
/// (EUI64s in 802.15.4 wire order, i.e. little-endian)
struct WireHeader {
    kind: u8,
    flags: u8,
    seq: u32,
    eui64: Eui64,
    nwk: Nwk,
    epan: Eui64,
}

impl WireHeader {
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN || bytes[..2] != MAGIC || bytes[2] != VERSION {
            return None;
        }
        Some(Self {
            kind: bytes[3],
            flags: bytes[4],
            seq: u32::from_le_bytes(bytes[5..9].try_into().ok()?),
            eui64: Eui64(bytes[9..17].try_into().ok()?),
            nwk: Nwk(u16::from_le_bytes([bytes[17], bytes[18]])),
            epan: Eui64(bytes[19..27].try_into().ok()?),
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 128);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.kind);
        out.push(self.flags);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.eui64.0);
        out.extend_from_slice(&self.nwk.0.to_le_bytes());
        out.extend_from_slice(&self.epan.0);
        out
    }
}

// -- minimal 802.15.4 MAC header parsing --------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacAddress {
    None,
    Short(Nwk),
    Extended(Eui64),
}

impl MacAddress {
    const fn is_broadcast(&self) -> bool {
        matches!(self, Self::Short(Nwk(0xFFFF)))
    }
}

struct MacHeader {
    frame_type: u8,
    ack_request: bool,
    dest: MacAddress,
    source: MacAddress,
}

impl MacHeader {
    fn parse(psdu: &[u8]) -> Option<Self> {
        let fcf = u16::from_le_bytes([*psdu.first()?, *psdu.get(1)?]);
        let ack_request = fcf & (1 << 5) != 0;
        let pan_compression = fcf & (1 << 6) != 0;
        let dest_mode = (fcf >> 10) & 0b11;
        let src_mode = (fcf >> 14) & 0b11;

        let mut i = 3; // FCF + sequence number
        let mut read_addr = |mode: u16, with_pan: bool| -> Option<MacAddress> {
            if mode == 0 {
                return Some(MacAddress::None);
            }
            if with_pan {
                i += 2;
            }
            match mode {
                2 => {
                    let nwk = u16::from_le_bytes([*psdu.get(i)?, *psdu.get(i + 1)?]);
                    i += 2;
                    Some(MacAddress::Short(Nwk(nwk)))
                }
                3 => {
                    let eui64 = Eui64(psdu.get(i..i + 8)?.try_into().ok()?);
                    i += 8;
                    Some(MacAddress::Extended(eui64))
                }
                _ => None,
            }
        };
        let dest = read_addr(dest_mode, true)?;
        let source = read_addr(src_mode, !pan_compression)?;
        Some(Self {
            frame_type: (fcf & 0b111) as u8,
            ack_request,
            dest,
            source,
        })
    }
}

/// Every address mDNS resolved for a peer that we could use, best first.
///
/// Confined to one interface (`--zloe-interface`): IPv6 link-local on that interface
/// first (IPv4 first with `prefer_ipv4`), then IPv4 on its subnet, then routable IPv6.
/// Not confined: a link-local address's scope is ambiguous (mDNS reports it once per
/// interface the answer arrived on, Docker bridges and veths included), so IPv4 and
/// routable IPv6 come first and link-local is a last resort.
fn candidate_addresses(
    addrs: &HashSet<mdns_sd::ScopedIp>,
    port: u16,
    local_net: Option<LocalNet>,
    prefer_ipv4: bool,
    dual_stack: bool,
) -> Vec<((u8, u8), SocketAddr)> {
    let mut ranked: Vec<((u8, u8), SocketAddr)> = addrs
        .iter()
        .filter_map(|scoped| match scoped {
            mdns_sd::ScopedIp::V6(v6) => {
                let ip = *v6.addr();
                let index = v6.scope_id().index;
                if ip.is_loopback() || !dual_stack {
                    return None;
                }
                let link_local = (ip.segments()[0] & 0xffc0) == 0xfe80;
                let class = match (local_net, link_local) {
                    (Some(net), true) if net.index != index => return None,
                    (Some(_), true) => u8::from(prefer_ipv4),
                    (Some(_), false) | (None, false) => 2,
                    (None, true) => 3,
                };
                let scope = if link_local { index } else { 0 };
                Some((
                    (class, 0),
                    SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)),
                ))
            }
            mdns_sd::ScopedIp::V4(v4) => {
                let ip = *v4.addr();
                if let Some(net) = local_net {
                    let (ours, mask) = net.v4?;
                    if u32::from(ip) & u32::from(mask) != u32::from(ours) & u32::from(mask) {
                        return None;
                    }
                }
                let class = if local_net.is_some() {
                    u8::from(!prefer_ipv4)
                } else {
                    0
                };
                Some((
                    (class, address_rank(ip)),
                    SocketAddr::new(IpAddr::V4(ip), port),
                ))
            }
            _ => None,
        })
        .collect();
    ranked.sort();
    ranked
}

/// The network's multicast group: transient (`ff1x`), link-local scope (`ffx2`), with
/// the low 32 bits of the extended PAN ID: `ff12::5a4c:hhhh:hhhh`.
fn multicast_group(epan: Eui64) -> Ipv6Addr {
    let e = epan.to_be_bytes();
    Ipv6Addr::new(
        0xff12,
        0,
        0,
        0,
        0,
        0x5a4c,
        u16::from_be_bytes([e[4], e[5]]),
        u16::from_be_bytes([e[6], e[7]]),
    )
}

/// The network's IPv4 multicast group, organization-local scope (RFC 2365), with the
/// last two bytes of the extended PAN ID: `239.255.h.h`.
fn multicast_group_v4(epan: Eui64) -> Ipv4Addr {
    let e = epan.to_be_bytes();
    Ipv4Addr::new(239, 255, e[6], e[7])
}

/// IPv4 targets on a dual-stack IPv6 socket must be v4-mapped.
fn to_family(addr: SocketAddr, dual_stack: bool) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) if dual_stack => {
            SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
        }
        _ => addr,
    }
}

/// Lower is better: 192.168/16, 10/8, other non-loopback, 172.16/12 (usually
/// container bridges), link-local, loopback.
const fn address_rank(ip: std::net::Ipv4Addr) -> u8 {
    let o = ip.octets();
    match o {
        [192, 168, ..] => 0,
        [10, ..] => 1,
        [172, 16..=31, ..] => 3,
        [169, 254, ..] => 4,
        [127, ..] => 5,
        _ => 2,
    }
}

fn hex_be(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn rand_u32() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    (nanos ^ (nanos >> 32)) as u32
}
