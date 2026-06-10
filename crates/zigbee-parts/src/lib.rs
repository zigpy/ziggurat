use abstract_bits::{AbstractBits, BitReader};
use commands::NwkCommandId;

pub mod commands;
pub mod zdp;

/// 802.15.4 mac layer has a maximum payload length of 104 bytes
/// see the introduction of this paper for a good overview:
/// https://www.researchgate.net/publication/305365904_Dissecting_Customized_Protocols_Automatic_Analysis_for_Customized_Protocols_based_on_IEEE_802154
const MAC_PAYLOAD_MAX_LEN: usize = 104;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("Could not serialize {ty}")]
pub struct SerializeError {
    ty: &'static str,
    #[source]
    cause: abstract_bits::ToBytesError,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeserializeError {
    #[error("Could not deserialize payload to {ty}")]
    Payload {
        ty: &'static str,
        #[source]
        cause: abstract_bits::FromBytesError,
    },
    #[error(
        "Could not deserialize incorrect Id. \
        Expected {expected_discriminant} (which represents {expected_variant:?}), \
        found: {found_discriminant:?} instead"
    )]
    IncorrectId {
        expected_variant: NwkCommandId,
        expected_discriminant: u8,
        found_discriminant: u8,
    },
    #[error("Got zero bytes, no valid command/request/response is zero bytes")]
    ZeroBytes,
}

fn serialize<T: AbstractBits>(thing: &T, id: NwkCommandId) -> Result<Vec<u8>, SerializeError> {
    let mut bytes = vec![0u8; MAC_PAYLOAD_MAX_LEN];
    bytes[0] = id as u8;
    let mut writer = abstract_bits::BitWriter::from(&mut bytes[1..]);
    thing
        .write_abstract_bits(&mut writer)
        .map_err(|cause| SerializeError {
            ty: core::any::type_name::<T>(),
            cause,
        })?;
    let len = writer.bytes_written();
    bytes.truncate(len + 1); // +1 for id
    Ok(bytes)
}

fn deserialize<T: AbstractBits>(
    bytes: &[u8],
    correct_id: NwkCommandId,
) -> Result<T, DeserializeError> {
    let [command_id, payload @ ..] = bytes else {
        return Err(DeserializeError::ZeroBytes);
    };

    if *command_id != correct_id as u8 {
        return Err(DeserializeError::IncorrectId {
            expected_variant: correct_id,
            expected_discriminant: correct_id as u8,
            found_discriminant: *command_id,
        });
    }

    let mut reader = BitReader::from(payload);
    T::read_abstract_bits(&mut reader).map_err(|cause| DeserializeError::Payload {
        ty: core::any::type_name::<T>(),
        cause,
    })
}

pub trait Request: Command {
    type REPLY: Response;
}

pub trait Response: Command {
    type REQUEST: Request;
}

pub trait Command: AbstractBits + Sized {
    const COMMAND_ID: NwkCommandId;

    fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        serialize(self, Self::COMMAND_ID)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        deserialize(bytes, Self::COMMAND_ID)
    }
}
