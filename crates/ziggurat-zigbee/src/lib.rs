pub mod aps;
pub mod beacon;
pub mod constants;
pub mod crypto;
pub mod indirect;
pub mod nwk;
pub mod zdp;

/// Failure to parse an NWK or APS frame (or one of its fields) off the wire.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("not enough data to parse {ty}")]
    UnexpectedEnd { ty: &'static str },
    #[error("{ty} is too long for its frame bound")]
    TooLong { ty: &'static str },
    #[error("invalid discriminant {got} for {ty}")]
    InvalidDiscriminant { ty: &'static str, got: u8 },
    #[error("{0} is not supported")]
    Unsupported(&'static str),
    #[error(transparent)]
    Bits(#[from] abstract_bits::FromBytesError),
    #[error(transparent)]
    Address(#[from] ziggurat_ieee_802154::ParseError),
    #[error(transparent)]
    Decrypt(#[from] crypto::DecryptionError),
}
