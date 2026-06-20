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
    Listen { channel: u8 },
    Transmit { channel: u8, psdu: Vec<u8> },
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
}

impl NodeMsg {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::SetPosition(position) => {
                let mut out = Vec::with_capacity(9);
                out.push(0);
                out.extend_from_slice(&position.x.to_le_bytes());
                out.extend_from_slice(&position.y.to_le_bytes());
                out
            }
            Self::Listen { channel } => vec![1, *channel],
            Self::Transmit { channel, psdu } => {
                let mut out = Vec::with_capacity(2 + psdu.len());
                out.push(2);
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
            (1, [channel]) => Some(Self::Listen { channel: *channel }),
            (2, [channel, psdu @ ..]) => Some(Self::Transmit {
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
                let mut out = Vec::with_capacity(3 + psdu.len());
                out.push(*channel);
                out.push(*rssi as u8);
                out.push(*lqi);
                out.extend_from_slice(psdu);
                out
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [channel, rssi, lqi, psdu @ ..] => Some(Self::Frame {
                channel: *channel,
                rssi: *rssi as i8,
                lqi: *lqi,
                psdu: psdu.to_vec(),
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
