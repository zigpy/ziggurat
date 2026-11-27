//! ZigBee Encapsulation Protocol (ZEP) v2 output. Wireshark dissects it natively on UDP
//! port 17754, so it can follow the air live.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;
use ziggurat_sim_proto::Frame;

const PREAMBLE: &[u8; 2] = b"EX";
const VERSION: u8 = 2;
const TYPE_DATA: u8 = 1;
/// The frame ends in its FCS, rather than in LQI and RSSI bytes
const CRC_MODE: u8 = 1;
const LQI: u8 = 255;

/// Seconds from the NTP epoch (1900) to the Unix epoch (1970)
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

pub struct Zep {
    socket: UdpSocket,
    destination: SocketAddr,
    sequence: AtomicU32,
}

fn ntp_timestamp() -> [u8; 8] {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let seconds = (now.as_secs() + NTP_UNIX_OFFSET) as u32;
    let fraction = ((u64::from(now.subsec_nanos()) << 32) / 1_000_000_000) as u32;

    let mut timestamp = [0; 8];
    timestamp[..4].copy_from_slice(&seconds.to_be_bytes());
    timestamp[4..].copy_from_slice(&fraction.to_be_bytes());
    timestamp
}

impl Zep {
    pub fn new(destination: SocketAddr) -> Self {
        let bind: SocketAddr = if destination.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(bind).unwrap();
        socket.set_nonblocking(true).unwrap();

        // Viewers on this machine see multicast only if it loops back
        if let IpAddr::V4(ip) = destination.ip()
            && ip.is_multicast()
        {
            socket.set_multicast_loop_v4(true).unwrap();
        }

        Self {
            socket,
            destination,
            sequence: AtomicU32::new(0),
        }
    }

    /// Sends one frame. A datagram that cannot go out right away is dropped, so a
    /// viewer never stalls the air.
    pub fn send(&self, device_id: u16, frame: &Frame) {
        let mut datagram = Vec::with_capacity(32 + frame.psdu.len());
        datagram.extend_from_slice(PREAMBLE);
        datagram.push(VERSION);
        datagram.push(TYPE_DATA);
        datagram.push(frame.channel);
        datagram.extend_from_slice(&device_id.to_be_bytes());
        datagram.push(CRC_MODE);
        datagram.push(LQI);
        datagram.extend_from_slice(&ntp_timestamp());
        datagram.extend_from_slice(&self.sequence.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        datagram.extend_from_slice(&[0; 10]);
        datagram.push(frame.psdu.len() as u8);
        datagram.extend_from_slice(&frame.psdu);

        if let Err(err) = self.socket.send_to(&datagram, self.destination) {
            warn!("ZEP: dropped a frame: {err}");
        }
    }
}
