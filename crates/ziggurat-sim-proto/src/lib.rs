//! Messages between a simulated radio (a node) and the simulation medium.
//!
//! Each message is a big-endian `u16` body length, then the body: a one-byte tag and
//! the tag's fields. Nodes send [`NodeMessage`]s; the medium sends [`MediumMessage`]s.

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use ziggurat_ieee_802154::Psdu;
use ziggurat_ieee_802154::types::Eui64;

const TAG_HELLO: u8 = 0x01;
const TAG_TX: u8 = 0x02;
const TAG_RX: u8 = 0x03;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("empty message")]
    Empty,
    #[error("unknown message tag 0x{0:02x}")]
    UnknownTag(u8),
    #[error("message too short")]
    Truncated,
    #[error("PSDU longer than {} bytes", ziggurat_ieee_802154::MAX_PHY_PACKET_SIZE)]
    PsduTooLong,
    #[error("node name is not UTF-8")]
    InvalidName,
}

/// One 802.15.4 frame on a channel, as it goes on air: the PSDU includes the FCS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub channel: u8,
    pub psdu: Psdu,
}

impl Frame {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.channel);
        out.extend_from_slice(&self.psdu);
    }

    fn decode(fields: &[u8]) -> Result<Self, ProtoError> {
        let (&channel, psdu) = fields.split_first().ok_or(ProtoError::Truncated)?;
        let psdu = Psdu::from_slice(psdu).map_err(|_| ProtoError::PsduTooLong)?;

        Ok(Self { channel, psdu })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeMessage {
    /// The first message on every connection.
    Hello { eui64: Eui64, name: String },
    /// A frame the node puts on air.
    Tx(Frame),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediumMessage {
    /// A frame another node put on air. The node filters it by its own radio state.
    Rx(Frame),
}

pub trait Message: Sized + Send + Sync {
    fn encode(&self, out: &mut Vec<u8>);
    fn decode(body: &[u8]) -> Result<Self, ProtoError>;
}

impl Message for NodeMessage {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Hello { eui64, name } => {
                out.push(TAG_HELLO);
                out.extend_from_slice(&eui64.to_bytes());
                out.extend_from_slice(name.as_bytes());
            }
            Self::Tx(frame) => {
                out.push(TAG_TX);
                frame.encode(out);
            }
        }
    }

    fn decode(body: &[u8]) -> Result<Self, ProtoError> {
        let (&tag, fields) = body.split_first().ok_or(ProtoError::Empty)?;

        match tag {
            TAG_HELLO => {
                let (eui64, name) = fields
                    .split_first_chunk::<8>()
                    .ok_or(ProtoError::Truncated)?;
                let name = std::str::from_utf8(name).map_err(|_| ProtoError::InvalidName)?;

                Ok(Self::Hello {
                    eui64: Eui64(*eui64),
                    name: name.to_string(),
                })
            }
            TAG_TX => Ok(Self::Tx(Frame::decode(fields)?)),
            tag => Err(ProtoError::UnknownTag(tag)),
        }
    }
}

impl Message for MediumMessage {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Rx(frame) => {
                out.push(TAG_RX);
                frame.encode(out);
            }
        }
    }

    fn decode(body: &[u8]) -> Result<Self, ProtoError> {
        let (&tag, fields) = body.split_first().ok_or(ProtoError::Empty)?;

        match tag {
            TAG_RX => Ok(Self::Rx(Frame::decode(fields)?)),
            tag => Err(ProtoError::UnknownTag(tag)),
        }
    }
}

/// Reads one message. Returns `None` if the peer closed the connection between messages.
pub async fn read_message<M: Message>(
    reader: &mut (impl AsyncRead + Unpin + Send),
) -> Result<Option<M>, ProtoError> {
    let length = match reader.read_u16().await {
        Ok(length) => length,
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    let mut body = vec![0; usize::from(length)];
    reader.read_exact(&mut body).await?;

    M::decode(&body).map(Some)
}

pub async fn write_message<M: Message>(
    writer: &mut (impl AsyncWrite + Unpin + Send),
    message: &M,
) -> Result<(), ProtoError> {
    let mut buffer = vec![0; 2];
    message.encode(&mut buffer);

    let length = u16::try_from(buffer.len() - 2).expect("messages are far below 64 KiB");
    buffer[..2].copy_from_slice(&length.to_be_bytes());

    writer.write_all(&buffer).await?;

    Ok(())
}
