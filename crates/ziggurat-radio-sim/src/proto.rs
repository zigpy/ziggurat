//! The node<->medium-server wire protocol: length-delimited, tag-prefixed messages.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A node's position in the simulated plane; the medium derives RSSI/LQI from distance.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Position {
    pub x: f32,
    pub y: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NodeMsg {
    SetPosition(Position),
    SetAddresses { short: u16, extended: [u8; 8] },
    Listen { channel: u8 },
    Transmit { id: u32, channel: u8, psdu: Vec<u8> },
}

/// A message from the medium server to a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubMsg {
    /// A frame heard on the node's channel, with simulated link quality.
    Frame {
        channel: u8,
        rssi: i8,
        lqi: u8,
        psdu: Vec<u8>,
    },
    /// The MAC-level outcome of the transmit with this id: `acked` for a unicast whose
    /// addressed next hop received it, always true for a broadcast.
    TxResult { id: u32, acked: bool },
}

impl NodeMsg {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::SetPosition(position) => {
                let mut out = vec![0];
                out.extend_from_slice(&position.x.to_le_bytes());
                out.extend_from_slice(&position.y.to_le_bytes());
                out
            }
            Self::SetAddresses { short, extended } => {
                let mut out = vec![1];
                out.extend_from_slice(&short.to_le_bytes());
                out.extend_from_slice(extended);
                out
            }
            Self::Listen { channel } => vec![2, *channel],
            Self::Transmit { id, channel, psdu } => {
                let mut out = vec![3];
                out.extend_from_slice(&id.to_le_bytes());
                out.push(*channel);
                out.extend_from_slice(psdu);
                out
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        match bytes.split_first()? {
            (0, rest) if rest.len() == 8 => Some(Self::SetPosition(Position {
                x: f32::from_le_bytes(rest[0..4].try_into().ok()?),
                y: f32::from_le_bytes(rest[4..8].try_into().ok()?),
            })),
            (1, rest) if rest.len() == 10 => Some(Self::SetAddresses {
                short: u16::from_le_bytes(rest[0..2].try_into().ok()?),
                extended: rest[2..10].try_into().ok()?,
            }),
            (2, [channel]) => Some(Self::Listen { channel: *channel }),
            (3, [a, b, c, d, channel, psdu @ ..]) => Some(Self::Transmit {
                id: u32::from_le_bytes([*a, *b, *c, *d]),
                channel: *channel,
                psdu: psdu.to_vec(),
            }),
            _ => None,
        }
    }
}

impl HubMsg {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Frame {
                channel,
                rssi,
                lqi,
                psdu,
            } => {
                let mut out = vec![0, *channel, *rssi as u8, *lqi];
                out.extend_from_slice(psdu);
                out
            }
            Self::TxResult { id, acked } => {
                let mut out = vec![1];
                out.extend_from_slice(&id.to_le_bytes());
                out.push(u8::from(*acked));
                out
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        match bytes.split_first()? {
            (0, [channel, rssi, lqi, psdu @ ..]) => Some(Self::Frame {
                channel: *channel,
                rssi: *rssi as i8,
                lqi: *lqi,
                psdu: psdu.to_vec(),
            }),
            (1, [a, b, c, d, acked]) => Some(Self::TxResult {
                id: u32::from_le_bytes([*a, *b, *c, *d]),
                acked: *acked != 0,
            }),
            _ => None,
        }
    }
}

/// Write one length-delimited frame: a little-endian `u32` length followed by `payload`.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> std::io::Result<()> {
    writer
        .write_all(&(payload.len() as u32).to_le_bytes())
        .await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

/// Read one length-delimited frame written by [`write_frame`].
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut length = [0u8; 4];
    reader.read_exact(&mut length).await?;
    let mut payload = vec![0u8; u32::from_le_bytes(length) as usize];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}
