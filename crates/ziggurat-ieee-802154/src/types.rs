use core::fmt;

use alloc::string::String;
use hex;

use crate::ParseError;

#[derive(Debug, thiserror::Error)]
pub enum FromHexError {
    #[error("invalid length, expected {expected} hex characters, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("invalid hex")]
    InvalidHex(hex::FromHexError),
}

impl From<hex::FromHexError> for FromHexError {
    fn from(err: hex::FromHexError) -> Self {
        Self::InvalidHex(err)
    }
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], FromHexError> {
    // Strip off colons and a 0x prefix, if present
    let text = text.replace(":", "").replace("0x", "");

    if text.len() != 2 * N {
        return Err(FromHexError::InvalidLength {
            expected: 2 * N,
            got: text.len(),
        });
    }

    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes)?;

    Ok(bytes)
}

/// Hex-string forms (as used in the client wire protocol) deserialize through
/// `try_from_hex` so malformed client input is an error, never a panic.
macro_rules! deserialize_via_try_from_hex {
    ($ty:ty) => {
        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Self::try_from_hex(&text).map_err(serde::de::Error::custom)
            }
        }
    };
}

deserialize_via_try_from_hex!(Nwk);
deserialize_via_try_from_hex!(Eui64);
deserialize_via_try_from_hex!(PanId);
deserialize_via_try_from_hex!(Key);

#[abstract_bits::abstract_bits]
#[derive(Eq, Hash, Copy, Clone, PartialEq)]
pub struct Nwk(pub u16);

impl Nwk {
    pub fn try_from_hex(text: &str) -> Result<Self, FromHexError> {
        Ok(Self(u16::from_be_bytes(decode_hex(text)?)))
    }

    pub fn from_hex(text: &str) -> Self {
        Self::try_from_hex(text).unwrap()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        if bytes.len() < 2 {
            return Err(ParseError::UnexpectedEnd { ty: "Nwk" });
        }

        Ok((Self(u16::from_le_bytes([bytes[0], bytes[1]])), &bytes[2..]))
    }

    pub const fn to_bytes(&self) -> [u8; 2] {
        self.0.to_le_bytes()
    }

    pub const fn as_u16(&self) -> u16 {
        self.0
    }
}

impl fmt::Debug for Nwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Nwk")
            .field(&format_args!("0x{:04x}", self.0))
            .finish()
    }
}

#[abstract_bits::abstract_bits]
#[derive(Eq, PartialEq, Hash, Copy, Clone)]
pub struct Eui64(pub [u8; 8]);

impl Eui64 {
    pub fn try_from_hex(text: &str) -> Result<Self, FromHexError> {
        let mut eui64: [u8; 8] = decode_hex(text)?;
        eui64.reverse();

        Ok(Self(eui64))
    }

    pub fn from_hex(text: &str) -> Self {
        Self::try_from_hex(text).unwrap()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        if bytes.len() < 8 {
            return Err(ParseError::UnexpectedEnd { ty: "Eui64" });
        }

        let mut eui = [0; 8];
        eui.copy_from_slice(&bytes[..8]);

        Ok((Self(eui), &bytes[8..]))
    }

    pub const fn to_bytes(&self) -> [u8; 8] {
        self.0
    }
}

impl fmt::Debug for Eui64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Eui64")
            .field(&format_args!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.0[7],
                self.0[6],
                self.0[5],
                self.0[4],
                self.0[3],
                self.0[2],
                self.0[1],
                self.0[0],
            ))
            .finish()
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Address {
    Nwk(Nwk),
    Eui64(Eui64),
}

#[abstract_bits::abstract_bits]
#[derive(Eq, Hash, Copy, Clone, PartialEq)]
pub struct PanId(pub u16);

impl PanId {
    pub fn try_from_hex(text: &str) -> Result<Self, FromHexError> {
        Ok(Self(u16::from_be_bytes(decode_hex(text)?)))
    }

    pub fn from_hex(text: &str) -> Self {
        Self::try_from_hex(text).unwrap()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        if bytes.len() < 2 {
            return Err(ParseError::UnexpectedEnd { ty: "PanId" });
        }

        Ok((Self(u16::from_le_bytes([bytes[0], bytes[1]])), &bytes[2..]))
    }

    pub const fn to_bytes(&self) -> [u8; 2] {
        self.0.to_le_bytes()
    }
}

impl fmt::Debug for PanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PanId")
            .field(&format_args!("0x{:04x}", self.0))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
#[abstract_bits::abstract_bits]
pub struct Key(pub [u8; 16]);

impl Key {
    pub fn try_from_hex(text: &str) -> Result<Self, FromHexError> {
        Ok(Self(decode_hex(text)?))
    }

    pub fn from_hex(text: &str) -> Self {
        Self::try_from_hex(text).unwrap()
    }

    pub const fn from_string(text: &[u8; 16]) -> Self {
        let mut key = [0; 16];
        key.copy_from_slice(text);

        Self(key)
    }

    pub const fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() != 16 {
            return Err(ParseError::InvalidLength { ty: "Key" });
        }

        let mut key = [0; 16];
        key.copy_from_slice(bytes);

        Ok(Self(key))
    }

    pub const fn to_bytes(&self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Key")
            .field(&format_args!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
                self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13], self.0[14], self.0[15]
            ))
            .finish()
    }
}

pub fn format_hex<T: AsRef<[u8]>>(data: T, f: &mut fmt::Formatter) -> fmt::Result {
    for (index, b) in data.as_ref().iter().enumerate() {
        if index == 0 {
            write!(f, "{b:02X}")?;
        } else {
            write!(f, ":{b:02X}")?;
        }
    }
    Ok(())
}
