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
//! * frames from backbone peers are reported with LQI 255 (whichever link they came in
//!   on), so NWK link costs to backbone peers are 1 and routing prefers the backbone
//!   without any NWK changes.
//!
//! Peers are discovered with mDNS/DNS-SD (`_zloe._udp`), configured statically, or
//! learned from the first datagram they send us.
//!
//! A test-only deny list fakes "out of radio range": over-the-air frames whose MAC
//! source is denied are dropped, and over-the-air unicasts to a denied MAC destination
//! report `NoAck` without being transmitted. The RCP still auto-ACKs frames from denied
//! devices at the hardware level; see the spike notes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use ziggurat_ieee_802154::types::{Eui64, Nwk, PanId};
use ziggurat_phy::{RadioConfig, RadioError, RadioPhy, Receiver, RxFrame, TxFrame, TxResult};

pub const SERVICE_TYPE: &str = "_zloe._udp.local.";
const MAGIC: [u8; 2] = *b"ZT";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 19;
const KIND_DATA: u8 = 0;
const KIND_ACK: u8 = 1;
const FLAG_ACK_REQUEST: u8 = 0x01;

const ACK_TIMEOUT: Duration = Duration::from_millis(50);
const ATTEMPTS: usize = 3;
const DEDUP_WINDOW: usize = 64;
/// LQI and RSSI reported for frames from backbone peers.
const BACKBONE_LQI: u8 = 255;
const BACKBONE_RSSI: i8 = -20;

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
    /// Network interface (e.g. `eth0`) the backbone is confined to: the UDP socket
    /// binds its IPv4 address and mDNS only runs there. `None`: all interfaces.
    pub interface: Option<String>,
    pub deny: DenyList,
}

/// The IPv4 address and netmask of a named interface.
fn interface_v4(name: &str) -> std::io::Result<(Ipv4Addr, Ipv4Addr)> {
    if_addrs::get_if_addrs()?
        .into_iter()
        .find_map(|iface| match iface.addr {
            if_addrs::IfAddr::V4(v4) if iface.name == name => Some((v4.ip, v4.netmask)),
            _ => None,
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("ZLOE interface {name:?} has no IPv4 address"),
            )
        })
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
}

#[derive(Debug, Clone, Copy)]
struct Identity {
    eui64: Eui64,
    nwk: Nwk,
    pan_id: PanId,
    channel: u8,
}

#[derive(Default)]
struct Shared {
    identity: Option<Identity>,
    peers: HashMap<Eui64, Peer>,
    /// Recently delivered (sender, backbone seq), to drop retransmits of a frame whose
    /// ack was lost.
    seen: HashMap<Eui64, VecDeque<u16>>,
    rx_tx: Option<mpsc::Sender<RxFrame>>,
    mdns_fullname: Option<String>,
}

struct Backbone {
    socket: Arc<UdpSocket>,
    shared: Arc<Mutex<Shared>>,
    pending: Arc<Mutex<HashMap<u16, oneshot::Sender<()>>>>,
    seq: AtomicU16,
    static_peers: Vec<SocketAddr>,
    mdns: Option<mdns_sd::ServiceDaemon>,
    port: u16,
    /// Set when confined to one interface: its address and netmask
    local_net: Option<(Ipv4Addr, Ipv4Addr)>,
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
            let local_net = config.interface.as_deref().map(interface_v4).transpose()?;
            let bind_ip = local_net.map_or(Ipv4Addr::UNSPECIFIED, |(ip, _)| ip);
            let socket = Arc::new(UdpSocket::bind((bind_ip, config.port)).await?);
            tracing::info!(
                "ZLOE backbone listening on {bind_ip}:{} ({})",
                config.port,
                config.interface.as_deref().unwrap_or("all interfaces")
            );

            let mdns = if config.mdns {
                match mdns_sd::ServiceDaemon::new() {
                    Ok(daemon) => {
                        if let Some(name) = &config.interface {
                            let _ = daemon.disable_interface(mdns_sd::IfKind::All);
                            let _ = daemon.disable_interface(mdns_sd::IfKind::LoopbackV4);
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

            let backbone = Backbone {
                socket,
                shared: Arc::clone(&shared),
                pending: Arc::new(Mutex::new(HashMap::new())),
                seq: AtomicU16::new(rand_u16()),
                static_peers: config.static_peers,
                mdns,
                port: config.port,
                local_net,
            };
            backbone.spawn_udp_reader();
            backbone.spawn_mdns_browser();
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
}

impl Backbone {
    fn spawn_udp_reader(&self) {
        let socket = Arc::clone(&self.socket);
        let shared = Arc::clone(&self.shared);
        let pending = Arc::clone(&self.pending);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (len, from) = match socket.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("ZLOE: UDP receive failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Some(header) = WireHeader::parse(&buf[..len]) else {
                    tracing::debug!("ZLOE: dropping malformed datagram from {from}");
                    continue;
                };

                if header.kind == KIND_ACK {
                    if let Some(waiter) = pending.lock().remove(&header.seq) {
                        let _ = waiter.send(());
                    }
                    continue;
                }

                let psdu = buf[HEADER_LEN..len].to_vec();
                let (deliver, ack_to) = {
                    let mut shared = shared.lock();
                    let Some(identity) = shared.identity else {
                        continue;
                    };
                    if header.pan_id != identity.pan_id || header.eui64 == identity.eui64 {
                        continue;
                    }

                    // Learn (or refresh) the peer from its own traffic
                    let peer = shared.peers.entry(header.eui64).or_insert_with(|| {
                        tracing::info!(
                            "ZLOE: learned peer {:?} / {:?} at {from}",
                            header.eui64,
                            header.nwk
                        );
                        Peer {
                            addr: from,
                            nwk: None,
                            source: PeerSource::Learned,
                            last_rx: None,
                        }
                    });
                    peer.addr = from;
                    peer.nwk = Some(header.nwk);
                    peer.last_rx = Some(Instant::now());

                    let seen = shared.seen.entry(header.eui64).or_default();
                    let duplicate = seen.contains(&header.seq);
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
                                lqi: BACKBONE_LQI,
                                timestamp_us: 0,
                            },
                        )
                    });
                    (deliver, ack_to.map(|to| (to, identity)))
                };

                if let Some((to, identity)) = ack_to {
                    let ack = WireHeader {
                        kind: KIND_ACK,
                        flags: 0,
                        seq: header.seq,
                        eui64: identity.eui64,
                        nwk: identity.nwk,
                        pan_id: identity.pan_id,
                    }
                    .to_bytes();
                    let _ = socket.send_to(&ack, to).await;
                }

                if let Some((Some(tx), frame)) = deliver {
                    tracing::trace!(
                        "ZLOE: rx {} bytes from {:?}",
                        frame.psdu.len(),
                        header.eui64
                    );
                    let _ = tx.try_send(frame);
                }
            }
        });
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

        tokio::spawn(async move {
            while let Ok(event) = events.recv_async().await {
                match event {
                    mdns_sd::ServiceEvent::ServiceResolved(info) => {
                        let Some(eui64) = info
                            .get_property_val_str("eui64")
                            .and_then(|s| Eui64::try_from_hex(s).ok())
                        else {
                            continue;
                        };
                        let pan_id = info
                            .get_property_val_str("pan")
                            .and_then(|s| PanId::try_from_hex(s).ok());
                        let nwk = info
                            .get_property_val_str("nwk")
                            .and_then(|s| Nwk::try_from_hex(s).ok());
                        // mDNS lists every interface (Docker bridges, loopback, ...):
                        // pick deterministically, LAN first
                        let Some(ip) = info.get_addresses_v4().into_iter().min_by_key(|ip| {
                            let on_our_net = local_net.is_some_and(|(ours, mask)| {
                                u32::from(*ip) & u32::from(mask)
                                    == u32::from(ours) & u32::from(mask)
                            });
                            (!on_our_net, address_rank(*ip), *ip)
                        }) else {
                            continue;
                        };
                        let addr = SocketAddr::new(IpAddr::V4(ip), info.get_port());

                        let mut shared = shared.lock();
                        let Some(identity) = shared.identity else {
                            continue;
                        };
                        if eui64 == identity.eui64 || pan_id != Some(identity.pan_id) {
                            continue;
                        }
                        let peer = shared.peers.entry(eui64).or_insert_with(|| {
                            tracing::info!("ZLOE: mDNS peer {eui64:?} / {nwk:?} at {addr}");
                            Peer {
                                addr,
                                nwk,
                                source: PeerSource::Mdns,
                                last_rx: None,
                            }
                        });
                        // Once the peer has talked to us, its datagrams' source address
                        // is authoritative
                        if peer.last_rx.is_none() && peer.addr != addr {
                            tracing::info!("ZLOE: mDNS peer {eui64:?} moved to {addr}");
                            peer.addr = addr;
                        }
                        if nwk.is_some() {
                            peer.nwk = nwk;
                        }
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

    fn advertise(&self, identity: Identity) {
        let Some(daemon) = &self.mdns else { return };
        let mut shared = self.shared.lock();
        if let Some(old) = shared.mdns_fullname.take() {
            let _ = daemon.unregister(&old);
        }

        let instance = hex_be(&identity.eui64.to_be_bytes());
        let properties: HashMap<String, String> = [
            ("v".to_string(), VERSION.to_string()),
            ("eui64".to_string(), instance.clone()),
            ("nwk".to_string(), format!("{:04x}", identity.nwk.as_u16())),
            ("pan".to_string(), format!("{:04x}", identity.pan_id.0)),
        ]
        .into_iter()
        .collect();

        let host = format!("ziggurat-{instance}.local.");
        let ip = self
            .local_net
            .map(|(ip, _)| ip.to_string())
            .unwrap_or_default();
        match mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &host,
            ip.as_str(),
            self.port,
            properties,
        ) {
            Ok(info) => {
                let info = if self.local_net.is_some() {
                    info
                } else {
                    info.enable_addr_auto()
                };
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

    /// Every address a broadcast goes to: known peers plus unidentified static peers.
    fn broadcast_targets(&self) -> Vec<SocketAddr> {
        let shared = self.shared.lock();
        let mut targets: Vec<SocketAddr> = shared.peers.values().map(|p| p.addr).collect();
        for addr in &self.static_peers {
            if !targets.contains(addr) {
                targets.push(*addr);
            }
        }
        targets
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

    fn header(&self, kind: u8, flags: u8, seq: u16) -> Option<Vec<u8>> {
        let identity = self.shared.lock().identity?;
        Some(
            WireHeader {
                kind,
                flags,
                seq,
                eui64: identity.eui64,
                nwk: identity.nwk,
                pan_id: identity.pan_id,
            }
            .to_bytes(),
        )
    }

    async fn send_broadcast(&self, psdu: &[u8]) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let Some(mut datagram) = self.header(KIND_DATA, 0, seq) else {
            return;
        };
        datagram.extend_from_slice(psdu);
        for target in self.broadcast_targets() {
            let _ = self.socket.send_to(&datagram, target).await;
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

        if !ack_request {
            return self.socket.send_to(&datagram, to).await.is_ok();
        }

        for attempt in 0..ATTEMPTS {
            let (tx, rx) = oneshot::channel();
            self.pending.lock().insert(seq, tx);
            if self.socket.send_to(&datagram, to).await.is_err() {
                break;
            }
            if tokio::time::timeout(ACK_TIMEOUT, rx).await.is_ok() {
                if attempt > 0 {
                    tracing::debug!("ZLOE: unicast to {to} acked after {} retries", attempt);
                }
                return true;
            }
        }
        self.pending.lock().remove(&seq);
        tracing::debug!("ZLOE: unicast to {to} not acked");
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
        let identity = Identity {
            eui64: config.extended_address,
            nwk: config.short_address,
            pan_id: config.pan_id,
            channel: config.channel,
        };
        let changed = {
            let mut shared = self.shared.lock();
            let changed = shared.identity.is_none_or(|old| {
                old.eui64 != identity.eui64
                    || old.nwk != identity.nwk
                    || old.pan_id != identity.pan_id
            });
            shared.identity = Some(identity);
            changed
        };
        if changed && let Some(backbone) = &self.backbone {
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
                backbone.send_broadcast(&frame.psdu).await;
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

        // Over-the-air frames: apply the deny list and pin peers' LQI
        tokio::spawn(async move {
            while let Some(mut frame) = inner_rx.recv().await {
                if let Some(mac) = MacHeader::parse(&frame.psdu) {
                    if deny.denies(&mac.source) {
                        tracing::trace!("ZLOE deny: dropping air frame from {:?}", mac.source);
                        continue;
                    }
                    if has_backbone {
                        let is_peer = {
                            let shared = shared.lock();
                            match &mac.source {
                                MacAddress::Extended(eui64) => shared.peers.contains_key(eui64),
                                MacAddress::Short(nwk) => {
                                    shared.peers.values().any(|p| p.nwk == Some(*nwk))
                                }
                                MacAddress::None => false,
                            }
                        };
                        if is_peer {
                            frame.lqi = BACKBONE_LQI;
                            frame.rssi = BACKBONE_RSSI;
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
    /// Peers currently known, for diagnostics.
    pub fn peers(&self) -> Vec<String> {
        self.shared
            .lock()
            .peers
            .iter()
            .map(|(eui64, p)| {
                format!(
                    "{eui64:?} nwk={:?} addr={} via={:?} last_rx={:?}",
                    p.nwk,
                    p.addr,
                    p.source,
                    p.last_rx.map(|t| t.elapsed())
                )
            })
            .collect()
    }
}

// -- wire format ---------------------------------------------------------------------

/// `"ZT" | ver | kind | flags | seq:u16le | eui64 (wire order) | nwk:u16le | pan:u16le`
struct WireHeader {
    kind: u8,
    flags: u8,
    seq: u16,
    eui64: Eui64,
    nwk: Nwk,
    pan_id: PanId,
}

impl WireHeader {
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN || bytes[..2] != MAGIC || bytes[2] != VERSION {
            return None;
        }
        Some(Self {
            kind: bytes[3],
            flags: bytes[4],
            seq: u16::from_le_bytes([bytes[5], bytes[6]]),
            eui64: Eui64(bytes[7..15].try_into().ok()?),
            nwk: Nwk(u16::from_le_bytes([bytes[15], bytes[16]])),
            pan_id: PanId(u16::from_le_bytes([bytes[17], bytes[18]])),
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
        out.extend_from_slice(&self.pan_id.0.to_le_bytes());
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
            ack_request,
            dest,
            source,
        })
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

fn rand_u16() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos ^ (nanos >> 16)) as u16
}
