//! SPIKE (throwaway): Zigbee Border Router, coordinator placement.
//!
//! Every device on the network is reachable at `<prefix>::<modified EUI-64>`, the /64
//! prefix being a ULA derived from the Extended PAN ID. IP clients send raw ZCL in UDP
//! to one fixed port with an 8-byte header; replies come back by unicast, everything
//! else the coordinator receives is copied to a per-network multicast group.
//!
//! Header (all frames, both directions), little-endian like APS:
//!
//! | byte | field                                                                |
//! |------|----------------------------------------------------------------------|
//! | 0    | flags: 0x80 ack requested, 0x40 ack, 0x20 nack, 0x08 unsolicited    |
//! | 1    | client sequence number, echoed in acks/nacks and in matched replies  |
//! | 2    | endpoint: destination on requests, source on frames from the device  |
//! | 3-4  | cluster                                                              |
//! | 5-6  | profile (0 on requests = endpoint 0 -> ZDO, else Home Automation)    |
//! | 7    | status (nack reason; 0 otherwise)                                    |
//!
//! The host must route the prefix locally (Linux "AnyIP"):
//! `ip -6 route add local <prefix>::/64 dev lo`.

use std::collections::{HashMap, HashSet};
use std::io::{IoSlice, IoSliceMut};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::ValueEnum;
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, SockaddrIn6, recvmsg, sendmsg, setsockopt,
    sockopt,
};
use sha2::{Digest, Sha256};
use tokio::io::unix::AsyncFd;
use tokio::sync::broadcast;

use ziggurat_driver::zigbee_stack::ZigbeeNotification;
use ziggurat_driver::ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_protocol as proto;

use crate::Stack;

const HEADER_LEN: usize = 8;
const FLAG_ACK_REQUESTED: u8 = 0x80;
const FLAG_ACK: u8 = 0x40;
const FLAG_NACK: u8 = 0x20;
const FLAG_UNSOLICITED: u8 = 0x08;

const PROFILE_ZDO: u16 = 0x0000;
const PROFILE_HA: u16 = 0x0104;
/// The coordinator endpoint IP-originated frames come from (zigpy's own HA endpoint).
const GATEWAY_SRC_EP: u8 = 1;
/// ZDP TSN of the gateway's own NWK_addr_req (outside the rewrite range 0x80..)
const DISCOVERY_TSN: u8 = 0x7f;
/// A reply that has not arrived by then is no longer matched to its client.
const PENDING_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Status {
    Malformed = 1,
    UnknownDevice = 2,
    PolicyDenied = 3,
    NotOurPrefix = 4,
    SendRejected = 5,
    DeliveryFailed = 6,
    ApsAckTimeout = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Policy {
    /// Read Attributes and the discovery commands only
    ReadOnly,
    /// Also cluster-specific commands and attribute writes
    Commands,
    /// Everything, ZDO and reporting configuration included
    Full,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub policy: Policy,
    /// Interface the multicast copies leave by (index resolved at start)
    pub multicast_interface: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct Header {
    flags: u8,
    seq: u8,
    endpoint: u8,
    cluster: u16,
    profile: u16,
    status: u8,
}

impl Header {
    fn parse(datagram: &[u8]) -> Option<(Self, &[u8])> {
        if datagram.len() < HEADER_LEN {
            return None;
        }
        let header = Self {
            flags: datagram[0],
            seq: datagram[1],
            endpoint: datagram[2],
            cluster: u16::from_le_bytes([datagram[3], datagram[4]]),
            profile: u16::from_le_bytes([datagram[5], datagram[6]]),
            status: datagram[7],
        };
        Some((header, &datagram[HEADER_LEN..]))
    }

    fn encode(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(&[self.flags, self.seq, self.endpoint]);
        out.extend_from_slice(&self.cluster.to_le_bytes());
        out.extend_from_slice(&self.profile.to_le_bytes());
        out.push(self.status);
        out.extend_from_slice(payload);
        out
    }
}

/// `fd` + the first 40 bits of SHA-256("zigbee-br" ‖ EPID), subnet 0.
pub fn ula_prefix(epid: Eui64) -> [u8; 8] {
    let digest = Sha256::new()
        .chain_update(b"zigbee-br")
        .chain_update(epid.to_be_bytes())
        .finalize();
    let mut prefix = [0u8; 8];
    prefix[0] = 0xfd;
    prefix[1..6].copy_from_slice(&digest[..5]);
    prefix
}

/// The device's address: the prefix and its modified EUI-64 (U/L bit flipped).
fn device_address(prefix: &[u8; 8], eui64: Eui64) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[..8].copy_from_slice(prefix);
    octets[8..].copy_from_slice(&eui64.to_be_bytes());
    octets[8] ^= 0x02;
    Ipv6Addr::from(octets)
}

fn device_eui64(prefix: &[u8; 8], address: Ipv6Addr) -> Option<Eui64> {
    let octets = address.octets();
    if octets[..8] != prefix[..] {
        return None;
    }
    let mut iid = [0u8; 8];
    iid.copy_from_slice(&octets[8..]);
    iid[0] ^= 0x02;
    Some(Eui64::from_be_bytes(iid))
}

/// RFC 3306 unicast-prefix-based group `ff35:40:<prefix>::1`.
fn multicast_group(prefix: &[u8; 8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[0] = 0xff;
    octets[1] = 0x35;
    octets[3] = 0x40;
    octets[4..12].copy_from_slice(prefix);
    octets[15] = 1;
    Ipv6Addr::from(octets)
}

/// Offset of the transaction sequence number in a ZCL or ZDP frame.
fn tsn_offset(profile: u16, frame: &[u8]) -> Option<usize> {
    if profile == PROFILE_ZDO {
        return (!frame.is_empty()).then_some(0);
    }
    let manufacturer_specific = frame.first()? & 0x04 != 0;
    let offset = if manufacturer_specific { 3 } else { 1 };
    (frame.len() > offset).then_some(offset)
}

fn allowed(policy: Policy, profile: u16, frame: &[u8]) -> bool {
    if policy == Policy::Full {
        return true;
    }
    if profile == PROFILE_ZDO {
        return false;
    }
    let Some(&control) = frame.first() else {
        return false;
    };
    let Some(command_offset) = tsn_offset(profile, frame).map(|tsn| tsn + 1) else {
        return false;
    };
    let Some(&command) = frame.get(command_offset) else {
        return false;
    };
    let cluster_specific = control & 0x03 == 0x01;
    // Read Attributes, Read Reporting Configuration, the discovery commands
    let read = matches!(command, 0x00 | 0x08 | 0x0c | 0x11 | 0x13 | 0x15);
    // Write Attributes (normal, undivided, no response)
    let write = matches!(command, 0x02 | 0x03 | 0x05);
    match policy {
        Policy::ReadOnly => !cluster_specific && read,
        Policy::Commands => cluster_specific || read || write,
        Policy::Full => true,
    }
}

struct Pending {
    client: SocketAddrV6,
    client_tsn: u8,
    client_seq: u8,
    expires: Instant,
}

/// (device, cluster without the ZDP response bit, gateway TSN)
type PendingKey = (Nwk, u16, u8);

struct Gateway {
    stack: Arc<Stack>,
    socket: AsyncFd<std::net::UdpSocket>,
    prefix: [u8; 8],
    group: Ipv6Addr,
    multicast_ifindex: u32,
    config: Config,
    pending: Mutex<HashMap<PendingKey, Pending>>,
    next_tsn: Mutex<u8>,
    /// SPIKE: devices whose Device_annce said receiver off when idle
    sleepy: Mutex<HashSet<Eui64>>,
}

pub async fn run(
    stack: Arc<Stack>,
    notifications: broadcast::Receiver<ZigbeeNotification>,
    config: Config,
) {
    if let Err(e) = run_inner(stack, notifications, config).await {
        tracing::error!("ZBR: stopped: {e}");
    }
}

async fn run_inner(
    stack: Arc<Stack>,
    mut notifications: broadcast::Receiver<ZigbeeNotification>,
    config: Config,
) -> std::io::Result<()> {
    let epid = stack.state.extended_pan_id;
    let prefix = ula_prefix(epid);
    let group = multicast_group(&prefix);

    let multicast_ifindex = match &config.multicast_interface {
        Some(name) => nix::net::if_::if_nametoindex(name.as_str()).map_err(std::io::Error::from)?,
        None => 0,
    };

    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_only_v6(true)?;
    // Local listeners of the multicast group bind the same port
    socket.set_reuse_address(true)?;
    // Device addresses are routed locally (AnyIP), never assigned: sourcing from them
    // through IPV6_PKTINFO needs freebind
    socket.set_freebind_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.set_multicast_if_v6(multicast_ifindex)?;
    socket.set_multicast_loop_v6(true)?;
    socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, config.port, 0, 0).into())?;
    let socket: std::net::UdpSocket = socket.into();
    setsockopt(&socket, sockopt::Ipv6RecvPacketInfo, &true).map_err(std::io::Error::from)?;

    let mut prefix_octets = [0u8; 16];
    prefix_octets[..8].copy_from_slice(&prefix);
    let prefix_addr = Ipv6Addr::from(prefix_octets);
    tracing::info!(
        "ZBR: EPID {epid:?} -> prefix {prefix_addr}/64, multicast {group}, UDP port {}, policy {:?}",
        config.port,
        config.policy
    );
    tracing::info!("ZBR: route the prefix locally: ip -6 route add local {prefix_addr}/64 dev lo");

    let gateway = Arc::new(Gateway {
        stack,
        socket: AsyncFd::new(socket)?,
        prefix,
        group,
        multicast_ifindex,
        config,
        pending: Mutex::new(HashMap::new()),
        next_tsn: Mutex::new(0x80),
        sleepy: Mutex::new(HashSet::new()),
    });

    let mut buf = vec![0u8; 2048];
    loop {
        tokio::select! {
            ready = gateway.socket.readable() => {
                let mut guard = ready?;
                match guard.try_io(|inner| recv_with_destination(inner.get_ref(), &mut buf)) {
                    Ok(Ok((len, client, local))) => {
                        let datagram = buf[..len].to_vec();
                        gateway.handle_request(&datagram, client, local);
                    }
                    Ok(Err(e)) => tracing::warn!("ZBR: receive failed: {e}"),
                    Err(_would_block) => {}
                }
            }
            event = notifications.recv() => match event {
                Ok(event) => gateway.handle_notification(event),
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    tracing::warn!("ZBR: lagged {count} notifications");
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
        }
    }
}

impl Gateway {
    fn handle_request(self: &Arc<Self>, datagram: &[u8], client: SocketAddrV6, local: Ipv6Addr) {
        let Some((header, frame)) = Header::parse(datagram) else {
            tracing::debug!("ZBR: short datagram from {client}");
            return;
        };
        let nack = |status: Status| {
            self.reply_status(local, client, header, Some(status));
        };

        let Some(eui64) = device_eui64(&self.prefix, local) else {
            return nack(Status::NotOurPrefix);
        };
        let profile = match header.profile {
            0 if header.endpoint == 0 => PROFILE_ZDO,
            0 => PROFILE_HA,
            profile => profile,
        };
        if frame.is_empty() || tsn_offset(profile, frame).is_none() {
            return nack(Status::Malformed);
        }
        if !allowed(self.config.policy, profile, frame) {
            tracing::info!(
                "ZBR: {client} -> {eui64:?} cluster {:#06x}: denied by policy",
                header.cluster
            );
            return nack(Status::PolicyDenied);
        }
        let nwk = self.stack.state.core.lock().nib.address_map.nwk_for(eui64);
        let frame = frame.to_vec();
        match nwk {
            Some(nwk) => self.forward(header, profile, frame, eui64, nwk, client, local),
            // SPIKE: a router knows few addresses: ask the network, then forward
            None => {
                let gateway = self.clone();
                tokio::spawn(async move {
                    match gateway.discover(eui64).await {
                        Some(nwk) => {
                            gateway.forward(header, profile, frame, eui64, nwk, client, local);
                        }
                        None => gateway.reply_status(
                            local,
                            client,
                            header,
                            Some(Status::UnknownDevice),
                        ),
                    }
                });
            }
        }
    }

    /// Broadcast a ZDP NWK_addr_req for `eui64` and wait for the mapping to appear.
    async fn discover(&self, eui64: Eui64) -> Option<Nwk> {
        let mut request = vec![DISCOVERY_TSN];
        request.extend_from_slice(&eui64.0);
        request.extend_from_slice(&[0x00, 0x00]);
        let sent = self.stack.send_aps_broadcast(
            Nwk(0xFFFD),
            PROFILE_ZDO,
            0x0000,
            0,
            0,
            30,
            request,
            ziggurat_driver::zigbee_stack::TxPriority::UserNormal,
        );
        tracing::info!("ZBR: NWK_addr_req for {eui64:?}: {:?}", sent.map(|_| ()));
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if let Some(nwk) = self.stack.state.core.lock().nib.address_map.nwk_for(eui64) {
                return Some(nwk);
            }
        }
        tracing::info!("ZBR: {eui64:?} not found");
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn forward(
        self: &Arc<Self>,
        header: Header,
        profile: u16,
        frame: Vec<u8>,
        eui64: Eui64,
        nwk: Nwk,
        client: SocketAddrV6,
        local: Ipv6Addr,
    ) {
        let nack = |status: Status| {
            self.reply_status(local, client, header, Some(status));
        };

        // Own the TSN space for IP-originated frames: rewrite, remember the client's
        let mut asdu = frame;
        let offset = tsn_offset(profile, &asdu).unwrap();
        let client_tsn = asdu[offset];
        let gateway_tsn = {
            let mut next = self.next_tsn.lock().unwrap();
            let tsn = *next;
            *next = next.wrapping_add(1).max(0x80);
            tsn
        };
        asdu[offset] = gateway_tsn;
        {
            let mut pending = self.pending.lock().unwrap();
            let now = Instant::now();
            pending.retain(|_, entry| entry.expires > now);
            pending.insert(
                (nwk, header.cluster & 0x7fff, gateway_tsn),
                Pending {
                    client,
                    client_tsn,
                    client_seq: header.seq,
                    expires: now + PENDING_TTL,
                },
            );
        }

        let ack_requested = header.flags & FLAG_ACK_REQUESTED != 0;
        let payload = proto::SendUnicastPayload {
            flags: proto::SendUnicastFlags {
                has_eui64: true,
                aps_ack: ack_requested,
                aps_encryption: false,
                sleepy_destination: self.sleepy.lock().unwrap().contains(&eui64),
                force_aps_seq: false,
            },
            destination: nwk,
            destination_eui64: eui64,
            profile_id: profile,
            cluster_id: header.cluster,
            src_ep: if profile == PROFILE_ZDO {
                0
            } else {
                GATEWAY_SRC_EP
            },
            dst_ep: header.endpoint,
            aps_seq: 0,
            radius: 0,
            priority: 0,
            route: proto::RouteControl::StackDecides,
            next_hop: None,
            relays: None,
            asdu,
        };
        tracing::info!(
            "ZBR: {client} -> {eui64:?} ({nwk:?}) ep {} cluster {:#06x} profile {profile:#06x} tsn {client_tsn}->{gateway_tsn}",
            header.endpoint,
            header.cluster
        );
        // SPIKE: a sleepy device's parent holds the frame for 7.68 s only; with a longer
        // poll interval the frame can expire before the device polls, so try once more
        let retry = payload.flags.sleepy_destination.then(|| payload.clone());
        let ((handle, _), _) = match proto::send_unicast(&self.stack, payload) {
            Ok(sent) => sent,
            Err(e) => {
                let _ = e;
                tracing::warn!("ZBR: send rejected by the stack");
                return nack(Status::SendRejected);
            }
        };
        if !ack_requested {
            return;
        }
        let gateway = self.clone();
        tokio::spawn(async move {
            use ziggurat_driver::zigbee_stack::DeliveryError;
            let mut result = handle.delivered().await;
            if let (Err(DeliveryError::ApsAckTimeout), Some(payload)) = (&result, retry) {
                tracing::info!("ZBR: sleepy {eui64:?} missed it, sending again");
                if let Ok(((handle, _), _)) = proto::send_unicast(&gateway.stack, payload) {
                    result = handle.delivered().await;
                }
            }
            let status = match result {
                Ok(()) => None,
                Err(DeliveryError::ApsAckTimeout) => Some(Status::ApsAckTimeout),
                Err(e) => {
                    tracing::info!("ZBR: delivery to {eui64:?} failed: {e}");
                    Some(Status::DeliveryFailed)
                }
            };
            gateway.reply_status(local, client, header, status);
        });
    }

    fn reply_status(
        &self,
        local: Ipv6Addr,
        client: SocketAddrV6,
        request: Header,
        status: Option<Status>,
    ) {
        let header = Header {
            flags: if status.is_some() {
                FLAG_NACK
            } else {
                FLAG_ACK
            },
            status: status.map_or(0, |status| status as u8),
            ..request
        };
        self.send_from(local, client, &header.encode(&[]));
    }

    fn handle_notification(&self, event: ZigbeeNotification) {
        let ZigbeeNotification::ReceivedApsCommand {
            source,
            group,
            profile_id,
            cluster_id,
            src_ep,
            data,
            ..
        } = event
        else {
            return;
        };
        if group.is_some() {
            return;
        }
        // SPIKE: learn addresses from ZDP address responses and announcements
        if profile_id == PROFILE_ZDO {
            let learned = match (cluster_id, &data[..]) {
                (0x8000, [tsn, 0x00, rest @ ..]) if rest.len() >= 10 => {
                    Some((*tsn, &rest[..8], [rest[8], rest[9]]))
                }
                (0x0013, [tsn, lo, hi, rest @ ..]) if rest.len() >= 8 => {
                    Some((*tsn, &rest[..8], [*lo, *hi]))
                }
                _ => None,
            };
            if let Some((tsn, ieee, nwk)) = learned {
                let eui64 = Eui64(ieee.try_into().unwrap());
                // Device_annce capability: bit 3 = receiver on when idle
                if let (0x0013, Some(&capability)) = (cluster_id, data.get(11)) {
                    let mut sleepy = self.sleepy.lock().unwrap();
                    if capability & 0x08 == 0 {
                        tracing::info!("ZBR: {eui64:?} is sleepy (capability {capability:#04x})");
                        sleepy.insert(eui64);
                    } else {
                        sleepy.remove(&eui64);
                    }
                }
                let nwk = Nwk(u16::from_le_bytes(nwk));
                tracing::info!("ZBR: learned {eui64:?} = {nwk:?}");
                self.stack
                    .state
                    .core
                    .lock()
                    .nib
                    .address_map
                    .update_mapping(eui64, nwk);
                if cluster_id == 0x8000 && tsn == DISCOVERY_TSN {
                    return;
                }
            }
        }
        let eui64 = self
            .stack
            .state
            .core
            .lock()
            .nib
            .address_map
            .eui64_for(source);
        let Some(eui64) = eui64 else {
            tracing::debug!("ZBR: frame from {source:?} with no known EUI-64, not forwarded");
            return;
        };
        let device = device_address(&self.prefix, eui64);

        let mut frame = data;
        let matched = tsn_offset(profile_id, &frame).and_then(|offset| {
            let key = (source, cluster_id & 0x7fff, frame[offset]);
            let entry = self.pending.lock().unwrap().remove(&key)?;
            frame[offset] = entry.client_tsn;
            Some(entry)
        });

        let mut header = Header {
            flags: 0,
            seq: 0,
            endpoint: src_ep,
            cluster: cluster_id,
            profile: profile_id,
            status: 0,
        };
        match matched {
            Some(entry) => {
                header.seq = entry.client_seq;
                tracing::info!(
                    "ZBR: reply {device} cluster {cluster_id:#06x} -> {}",
                    entry.client
                );
                self.send_from(device, entry.client, &header.encode(&frame));
            }
            None => {
                header.flags = FLAG_UNSOLICITED;
                let target =
                    SocketAddrV6::new(self.group, self.config.port, 0, self.multicast_ifindex);
                tracing::debug!(
                    "ZBR: unsolicited {device} cluster {cluster_id:#06x} -> {}",
                    self.group
                );
                self.send_from(device, target, &header.encode(&frame));
            }
        }
    }

    fn send_from(&self, source: Ipv6Addr, destination: SocketAddrV6, datagram: &[u8]) {
        let info = nix::libc::in6_pktinfo {
            ipi6_addr: nix::libc::in6_addr {
                s6_addr: source.octets(),
            },
            ipi6_ifindex: if destination.ip().is_multicast() {
                self.multicast_ifindex
            } else {
                0
            },
        };
        let control = [ControlMessage::Ipv6PacketInfo(&info)];
        let address = SockaddrIn6::from(destination);
        let result = sendmsg(
            self.socket.get_ref().as_raw_fd(),
            &[IoSlice::new(datagram)],
            &control,
            MsgFlags::empty(),
            Some(&address),
        );
        if let Err(e) = result {
            tracing::warn!("ZBR: send from {source} to {destination} failed: {e}");
        }
    }
}

/// One datagram, its sender and the local address it was sent to.
fn recv_with_destination(
    socket: &std::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddrV6, Ipv6Addr)> {
    let mut iov = [IoSliceMut::new(buf)];
    let mut control = nix::cmsg_space!(nix::libc::in6_pktinfo);
    let message = recvmsg::<SockaddrIn6>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::MSG_DONTWAIT,
    )
    .map_err(std::io::Error::from)?;

    let mut local = None;
    for cmsg in message.cmsgs().map_err(std::io::Error::from)? {
        if let ControlMessageOwned::Ipv6PacketInfo(info) = cmsg {
            local = Some(Ipv6Addr::from(info.ipi6_addr.s6_addr));
        }
    }
    let client = message
        .address
        .map(SocketAddrV6::from)
        .ok_or_else(|| std::io::Error::other("datagram without a sender"))?;
    let local = local.ok_or_else(|| std::io::Error::other("datagram without IPV6_PKTINFO"))?;
    Ok((message.bytes, client, local))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_round_trip() {
        let prefix = ula_prefix(Eui64::from_hex("b23e7f02f5d97c12"));
        assert_eq!(prefix[0], 0xfd);
        assert_eq!(prefix[6..], [0, 0]);
        let eui64 = Eui64::from_hex("206ef1fffe0ae0a0");
        let address = device_address(&prefix, eui64);
        assert_eq!(address.octets()[8], 0x22);
        assert_eq!(device_eui64(&prefix, address), Some(eui64));
    }

    #[test]
    fn policy_presets() {
        let read = [0x00, 0x01, 0x00, 0x00, 0x00];
        let on = [0x01, 0x01, 0x01];
        let configure_reporting = [0x00, 0x01, 0x06];
        assert!(allowed(Policy::ReadOnly, PROFILE_HA, &read));
        assert!(!allowed(Policy::ReadOnly, PROFILE_HA, &on));
        assert!(allowed(Policy::Commands, PROFILE_HA, &on));
        assert!(!allowed(Policy::Commands, PROFILE_HA, &configure_reporting));
        assert!(!allowed(Policy::Commands, PROFILE_ZDO, &[0x01]));
        assert!(allowed(Policy::Full, PROFILE_ZDO, &[0x01]));
    }
}
