use hex;
use std::fmt;

#[abstract_bits::abstract_bits]
#[derive(Eq, Hash, Copy, Clone, PartialEq)]
pub struct Nwk(pub u16);

impl Nwk {
    pub fn from_hex(text: &str) -> Self {
        // Strip off colons and a 0x prefix, if present
        let text = text.replace(":", "").replace("0x", "");

        if text.len() != 4 {
            panic!("Invalid Nwk length");
        }

        let mut nwk_bytes = [0; 2];
        hex::decode_to_slice(text, &mut nwk_bytes).expect("Decoding failed");

        Self(u16::from_be_bytes(nwk_bytes))
    }

    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 2 {
            return Err("Not enough data to parse Nwk");
        }

        Ok((Self(u16::from_le_bytes([bytes[0], bytes[1]])), &bytes[2..]))
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        self.0.to_le_bytes()
    }

    pub fn as_u16(&self) -> u16 {
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
    pub fn from_hex(text: &str) -> Self {
        // Strip off colons and a 0x prefix, if present
        let text = text.replace(":", "").replace("0x", "");

        if text.len() != 16 {
            panic!("Invalid Eui64 length");
        }

        let mut eui64 = [0; 8];
        hex::decode_to_slice(text, &mut eui64).expect("Decoding failed");

        eui64.reverse();

        Self(eui64)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 8 {
            return Err("Not enough data to parse Eui64");
        }

        let mut eui = [0; 8];
        eui.copy_from_slice(&bytes[..8]);

        Ok((Self(eui), &bytes[8..]))
    }

    pub fn to_bytes(&self) -> [u8; 8] {
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

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Address {
    Nwk(Nwk),
    Eui64(Eui64),
}

#[derive(PartialEq, Copy, Clone)]
pub struct PanId(pub u16);

impl PanId {
    pub fn from_hex(text: &str) -> Self {
        // Strip off colons and a 0x prefix, if present
        let text = text.replace(":", "").replace("0x", "");

        if text.len() != 4 {
            panic!("Invalid PanId length");
        }

        let mut pan_id_bytes = [0; 2];
        hex::decode_to_slice(text, &mut pan_id_bytes).expect("Decoding failed");

        Self(u16::from_be_bytes(pan_id_bytes))
    }

    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 2 {
            return Err("Not enough data to parse PanId");
        }

        Ok((Self(u16::from_le_bytes([bytes[0], bytes[1]])), &bytes[2..]))
    }

    pub fn to_bytes(&self) -> [u8; 2] {
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

#[derive(Clone, PartialEq)]
pub struct Key(pub [u8; 16]);

impl Key {
    pub fn from_hex(text: &str) -> Self {
        // Strip off colons and a 0x prefix, if present
        let text = text.replace(":", "").replace("0x", "");

        if text.len() != 32 {
            panic!("Invalid key length");
        }

        let mut key = [0; 16];
        hex::decode_to_slice(text, &mut key).expect("Decoding failed");

        Self(key)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 16 {
            return Err("Invalid key length");
        }

        let mut key = [0; 16];
        key.copy_from_slice(&bytes);

        Ok(Self(key))
    }

    pub fn to_bytes(&self) -> [u8; 16] {
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
            write!(f, "{:02X}", b)?;
        } else {
            write!(f, ":{:02X}", b)?;
        }
    }
    Ok(())
}
