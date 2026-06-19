#![allow(clippy::useless_conversion)]

use abstract_bits::AbstractBits;
use abstract_bits::abstract_bits;
use abstract_bits::{BitReader, BitWriter};
use ziggurat_ieee_802154::types::{Eui64, Key, Nwk, format_hex};
use ziggurat_ieee_802154::{FrameBytes, MAX_PHY_PACKET_SIZE, extend_abstract_bits};

use num_enum::TryFromPrimitive;

use educe::Educe;

use crate::ParseError;

use crate::crypto::{DecryptionError, decrypt_ccm, encrypt_ccm};

pub const BROADCAST_ALL_DEVICES: Nwk = Nwk(0xFFFF);
pub const BROADCAST_RX_ON_WHEN_IDLE: Nwk = Nwk(0xFFFD);
pub const BROADCAST_ALL_ROUTERS_AND_COORDINATOR: Nwk = Nwk(0xFFFC);
pub const BROADCAST_LOW_POWER_ROUTERS: Nwk = Nwk(0xFFFB);

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum NwkFrameType {
    Data = 0b00,
    Command = 0b01,
    Interpan = 0b11,
}

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum NwkRouteDiscovery {
    Suppress = 0b00,
    Enable = 0b01,
    WithMulticast = 0b10,
}

#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NwkFrameControl {
    pub frame_type: NwkFrameType,
    pub protocol_version: u4,
    pub discover_route: NwkRouteDiscovery,
    pub multicast: bool,
    pub security: bool,
    pub source_route: bool,
    pub destination: bool,
    pub extended_source: bool,
    pub end_device_initiator: bool,
    pub reserved1: u2,
}

#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NwkSourceRoute {
    #[abstract_bits(length_of = relays)]
    relay_count: u8,
    pub relay_index: u8,
    pub relays: Vec<Nwk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NwkHeader {
    pub frame_control: NwkFrameControl,
    pub destination: Nwk,
    pub source: Nwk,
    pub radius: u8,
    pub sequence_number: u8,
    pub destination_ieee: Option<Eui64>,
    pub source_ieee: Option<Eui64>,
    pub multicast_control: Option<u8>,
    pub source_route: Option<NwkSourceRoute>,
}

impl NwkHeader {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        if bytes.len() < 8 {
            return Err(ParseError::UnexpectedEnd { ty: "NwkHeader" });
        }

        let mut reader = BitReader::from(bytes);
        let frame_control = NwkFrameControl::read_abstract_bits(&mut reader)?;
        let mut remaining = &bytes[reader.bytes_read()..];

        let destination;
        (destination, remaining) = Nwk::deserialize(remaining)?;

        let source;
        (source, remaining) = Nwk::deserialize(remaining)?;

        let radius = remaining[0];
        remaining = &remaining[1..];

        let sequence_number = remaining[0];
        remaining = &remaining[1..];

        let destination_ieee = match frame_control.destination {
            true => {
                let ieee;
                (ieee, remaining) = Eui64::deserialize(remaining)?;
                Some(ieee)
            }
            false => None,
        };

        let source_ieee = match frame_control.extended_source {
            true => {
                let ieee;
                (ieee, remaining) = Eui64::deserialize(remaining)?;
                Some(ieee)
            }
            false => None,
        };

        let multicast_control = match frame_control.multicast {
            true => {
                if remaining.is_empty() {
                    return Err(ParseError::UnexpectedEnd {
                        ty: "NWK multicast control",
                    });
                }

                let control = remaining[0];
                remaining = &remaining[1..];
                Some(control)
            }
            false => None,
        };

        let source_route = match frame_control.source_route {
            true => {
                let mut reader = BitReader::from(remaining);
                let source_route = NwkSourceRoute::read_abstract_bits(&mut reader)?;
                remaining = &remaining[reader.bytes_read()..];
                Some(source_route)
            }
            false => None,
        };

        Ok((
            Self {
                frame_control,
                destination,
                source,
                radius,
                sequence_number,
                destination_ieee,
                source_ieee,
                multicast_control,
                source_route,
            },
            remaining,
        ))
    }

    pub fn serialize_into(&self, bytes: &mut Vec<u8>) {
        extend_abstract_bits(bytes, &self.frame_control);
        bytes.extend(self.destination.to_bytes());
        bytes.extend(self.source.to_bytes());
        bytes.push(self.radius);
        bytes.push(self.sequence_number);

        if let Some(ieee) = &self.destination_ieee {
            bytes.extend(ieee.to_bytes());
        }

        if let Some(ieee) = &self.source_ieee {
            bytes.extend(ieee.to_bytes());
        }

        if let Some(control) = self.multicast_control {
            bytes.push(control);
        }

        if let Some(source_route) = &self.source_route {
            extend_abstract_bits(bytes, source_route);
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.serialize_into(&mut bytes);
        bytes
    }
}

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum NwkSecurityHeaderKeyId {
    DataKey = 0x00,
    NetworkKey = 0x01,
    KeyTransportKey = 0x02,
    KeyLoadKey = 0x03,
}

#[abstract_bits(bits = 3)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum NwkSecurityLevel {
    NoSecurity = 0x00,
    Mic32 = 0x01,
    Mic64 = 0x02,
    Mic128 = 0x03,
    Enc = 0x04,
    EncMic32 = 0x05,
    EncMic64 = 0x06,
    EncMic128 = 0x07,
}

#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NwkSecurityHeaderControlField {
    pub security_level: NwkSecurityLevel,
    pub key_id: NwkSecurityHeaderKeyId,
    pub extended_nonce: bool,
    pub require_verified_frame_counter: bool,
    reserved: u1,
}

impl NwkSecurityHeaderControlField {
    /// The field's single serialized byte, without `to_abstract_bits`'s allocation:
    /// it goes into every CCM* nonce.
    pub fn to_bytes(&self) -> [u8; 1] {
        let mut buffer = [0u8; 1];
        let mut writer = BitWriter::from(&mut buffer[..]);
        self.write_abstract_bits(&mut writer).unwrap();
        buffer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NwkAuxHeader {
    pub security_control: NwkSecurityHeaderControlField,
    pub frame_counter: u32,
    pub extended_source: Option<Eui64>,
    pub key_sequence_number: u8,
}

impl NwkAuxHeader {
    #[allow(clippy::useless_let_if_seq)]
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        if bytes.len() < 6 {
            return Err(ParseError::UnexpectedEnd { ty: "NwkAuxHeader" });
        }

        let mut reader = BitReader::from(bytes);
        let security_control = NwkSecurityHeaderControlField::read_abstract_bits(&mut reader)?;
        let mut remaining = &bytes[reader.bytes_read()..];

        let frame_counter =
            u32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]);
        remaining = &remaining[4..];

        let mut extended_source = None;

        if security_control.extended_nonce {
            let ieee;
            (ieee, remaining) = Eui64::deserialize(remaining)?;
            extended_source = Some(ieee);
        }

        if remaining.is_empty() {
            return Err(ParseError::UnexpectedEnd {
                ty: "NWK key sequence number",
            });
        }

        let key_sequence_number = remaining[0];
        remaining = &remaining[1..];

        Ok((
            Self {
                security_control,
                frame_counter,
                extended_source,
                key_sequence_number,
            },
            remaining,
        ))
    }

    pub fn serialize_into(&self, bytes: &mut Vec<u8>) {
        bytes.extend(self.security_control.to_bytes());
        bytes.extend(self.frame_counter.to_le_bytes());

        if let Some(ieee) = self.extended_source {
            bytes.extend(ieee.to_bytes());
        }

        bytes.push(self.key_sequence_number);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.serialize_into(&mut bytes);
        bytes
    }
}

#[derive(Educe, Clone, PartialEq, Eq)]
#[educe(Debug)]
pub struct EncryptedNwkFrame {
    pub nwk_header: NwkHeader,
    pub aux_header: Option<NwkAuxHeader>,
    #[educe(Debug(method(format_hex)))]
    pub ciphertext: FrameBytes,
}

#[derive(Educe, Clone, PartialEq, Eq)]
#[educe(Debug)]
pub struct NwkFrame {
    pub nwk_header: NwkHeader,
    pub aux_header: Option<NwkAuxHeader>,
    #[educe(Debug(method(format_hex)))]
    pub payload: FrameBytes,
}

/// Chainable overrides for the rare frames that deviate from the defaults set by
/// `ZigbeeStack::nwk_command_frame` / `nwk_data_frame`.
impl NwkFrame {
    pub const fn with_radius(mut self, radius: u8) -> Self {
        self.nwk_header.radius = radius;
        self
    }

    /// Frames sent via `transmit_*` (relays, retried route request broadcasts) keep
    /// this sequence number; frames sent via `send_*` have it rewritten.
    pub const fn with_sequence_number(mut self, sequence_number: u8) -> Self {
        self.nwk_header.sequence_number = sequence_number;
        self
    }

    /// For relayed frames, which preserve the originator's source address.
    pub const fn with_source(mut self, source: Nwk) -> Self {
        self.nwk_header.source = source;
        self
    }

    pub const fn with_destination_ieee(mut self, ieee: Option<Eui64>) -> Self {
        self.nwk_header.frame_control.destination = ieee.is_some();
        self.nwk_header.destination_ieee = ieee;
        self
    }

    pub const fn with_source_ieee(mut self, ieee: Option<Eui64>) -> Self {
        self.nwk_header.frame_control.extended_source = ieee.is_some();
        self.nwk_header.source_ieee = ieee;
        self
    }

    pub const fn with_discover_route(mut self, discover_route: NwkRouteDiscovery) -> Self {
        self.nwk_header.frame_control.discover_route = discover_route;
        self
    }

    /// Must be paired with `NwkSecurityMode::Unsecured` at the send call site.
    pub const fn unsecured(mut self) -> Self {
        self.nwk_header.frame_control.security = false;
        self
    }
}

impl EncryptedNwkFrame {
    pub fn get_modified_aux_header(&self, nib_security_level: NwkSecurityLevel) -> NwkAuxHeader {
        if self.aux_header.is_none() {
            panic!("Auxiliary header is missing");
        }

        let mut aux_header = self.aux_header.clone().unwrap();
        aux_header.security_control.security_level = nib_security_level;

        aux_header
    }

    #[allow(clippy::unnecessary_unwrap)]
    pub fn get_nonce(&self, aux_header: &NwkAuxHeader) -> [u8; 13] {
        let source;

        if aux_header.extended_source.is_some() {
            source = aux_header.extended_source.unwrap();
        } else if self.nwk_header.source_ieee.is_some() {
            source = self.nwk_header.source_ieee.unwrap();
        } else {
            // XXX: this can't happen
            panic!("Cannot compute nonce with no source address");
        }

        let mut nonce = [0; 13];
        nonce[..8].copy_from_slice(&source.to_bytes());
        nonce[8..12].copy_from_slice(&aux_header.frame_counter.to_le_bytes());
        nonce[12..13].copy_from_slice(&aux_header.security_control.to_bytes());

        nonce
    }

    #[allow(clippy::useless_let_if_seq)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        // A NWK frame rides inside a MAC frame, so it cannot exceed the PHY packet
        // size; a longer input parses into a frame too large to re-serialize
        if bytes.len() > MAX_PHY_PACKET_SIZE {
            return Err(ParseError::TooLong { ty: "NwkFrame" });
        }

        let mut remaining;
        let nwk_header;
        (nwk_header, remaining) = NwkHeader::deserialize(bytes)?;

        let mut aux_header = None;

        if nwk_header.frame_control.security {
            let unwrapped_aux_header;
            (unwrapped_aux_header, remaining) = NwkAuxHeader::deserialize(remaining)?;
            aux_header = Some(unwrapped_aux_header);
        }

        Ok(Self {
            nwk_header,
            aux_header,
            ciphertext: FrameBytes::from_slice(remaining)
                .map_err(|_| ParseError::TooLong { ty: "ciphertext" })?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        ziggurat_ieee_802154::FramePayload::extend_frame_bytes(self, &mut bytes);
        bytes
    }

    /// Consumes the frame: the ciphertext buffer is decrypted in place and becomes the
    /// payload, and the headers move into the decrypted frame.
    pub fn decrypt(self, key: &Key) -> Result<NwkFrame, DecryptionError> {
        let aux_header = self.get_modified_aux_header(NwkSecurityLevel::EncMic32);
        let nonce = self.get_nonce(&aux_header);

        let mut auth_data = Vec::new();
        self.nwk_header.serialize_into(&mut auth_data);
        aux_header.serialize_into(&mut auth_data);

        let payload = decrypt_ccm(key, &nonce, &auth_data, self.ciphertext)?;

        Ok(NwkFrame {
            nwk_header: self.nwk_header,
            aux_header: self.aux_header,
            payload,
        })
    }
}

impl ziggurat_ieee_802154::FramePayload for EncryptedNwkFrame {
    fn extend_frame_bytes(&self, bytes: &mut Vec<u8>) {
        self.nwk_header.serialize_into(bytes);

        if let Some(aux_header) = &self.aux_header {
            aux_header.serialize_into(bytes);
        }

        bytes.extend_from_slice(&self.ciphertext);
    }

    fn fmt_payload(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl NwkFrame {
    pub fn get_modified_aux_header(&self, nib_security_level: NwkSecurityLevel) -> NwkAuxHeader {
        if self.aux_header.is_none() {
            panic!("Auxiliary header is missing");
        }

        let mut aux_header = self.aux_header.clone().unwrap();
        aux_header.security_control.security_level = nib_security_level;

        aux_header
    }

    #[allow(clippy::unnecessary_unwrap)]
    pub fn get_nonce(&self, aux_header: &NwkAuxHeader) -> [u8; 13] {
        let source;

        if aux_header.extended_source.is_some() {
            source = aux_header.extended_source.unwrap();
        } else if self.nwk_header.source_ieee.is_some() {
            source = self.nwk_header.source_ieee.unwrap();
        } else {
            // XXX: this can't happen
            panic!("Cannot compute nonce with no source address");
        }

        let mut nonce = [0; 13];
        nonce[..8].copy_from_slice(&source.to_bytes());
        nonce[8..12].copy_from_slice(&aux_header.frame_counter.to_le_bytes());
        nonce[12..13].copy_from_slice(&aux_header.security_control.to_bytes());

        nonce
    }

    pub fn encrypt(&self, key: &Key) -> EncryptedNwkFrame {
        let aux_header = self.get_modified_aux_header(NwkSecurityLevel::EncMic32);
        let nonce = self.get_nonce(&aux_header);

        let mut auth_data = Vec::new();
        self.nwk_header.serialize_into(&mut auth_data);
        aux_header.serialize_into(&mut auth_data);

        EncryptedNwkFrame {
            nwk_header: self.nwk_header.clone(),
            aux_header: self.aux_header.clone(),
            ciphertext: encrypt_ccm(key, &nonce, &auth_data, self.payload.clone()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_nwk_decryption_unicast() {
        let bytes =
            hex!("0802426b00000f2e287a0a0000a8ef171e004b120000f7a7e37b47adb47593c8a375c98ba6");
        let nwk_frame = EncryptedNwkFrame::from_bytes(&bytes).unwrap();

        let expected_nwk_frame = EncryptedNwkFrame {
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Data,
                    protocol_version: 2,
                    discover_route: NwkRouteDiscovery::Suppress,
                    multicast: false,
                    security: true,
                    source_route: false,
                    destination: false,
                    extended_source: false,
                    end_device_initiator: false,
                    reserved1: 0,
                },
                destination: Nwk(0x6b42),
                source: Nwk(0x0000),
                radius: 15,
                sequence_number: 46,
                destination_ieee: None,
                source_ieee: None,
                multicast_control: None,
                source_route: None,
            },
            aux_header: Some(NwkAuxHeader {
                security_control: NwkSecurityHeaderControlField {
                    security_level: NwkSecurityLevel::NoSecurity,
                    key_id: NwkSecurityHeaderKeyId::NetworkKey,
                    extended_nonce: true,
                    require_verified_frame_counter: false,
                },
                frame_counter: 2682,
                extended_source: Some(Eui64::from_hex("00:12:4b:00:1e:17:ef:a8")),
                key_sequence_number: 0,
            }),
            ciphertext: FrameBytes::from_slice(&hex!("f7a7e37b47adb47593c8a375c98ba6")).unwrap(),
        };

        assert_eq!(nwk_frame, expected_nwk_frame);

        let key = Key::from_hex("e8785a1ed5996b3ef715cb3fbdd69187");
        let decrypted_nwk_frame = nwk_frame.clone().decrypt(&key).unwrap();

        let expected_decrypted_nwk_frame = NwkFrame {
            nwk_header: expected_nwk_frame.nwk_header,
            aux_header: expected_nwk_frame.aux_header,
            payload: FrameBytes::from_slice(&hex!("00010600040101a9015701")).unwrap(),
        };

        assert_eq!(decrypted_nwk_frame, expected_decrypted_nwk_frame);

        // Make sure encryption is round trip
        let re_encrypted_nwk_frame = decrypted_nwk_frame.encrypt(&key);
        assert_eq!(nwk_frame.to_bytes(), bytes);
        assert_eq!(re_encrypted_nwk_frame, nwk_frame);
        assert_eq!(re_encrypted_nwk_frame.to_bytes(), bytes);
    }

    #[test]
    fn test_source_route() {
        let bytes =
            hex!("0806e73c375f1dcc010039f9287ea30000023c710c01881700000b73db5468c7cbc47caf8705");
        let nwk_frame = EncryptedNwkFrame::from_bytes(&bytes).unwrap();

        let expected_nwk_frame = EncryptedNwkFrame {
            nwk_header: NwkHeader {
                frame_control: NwkFrameControl {
                    frame_type: NwkFrameType::Data,
                    protocol_version: 2,
                    discover_route: NwkRouteDiscovery::Suppress,
                    multicast: false,
                    security: true,
                    source_route: true,
                    destination: false,
                    extended_source: false,
                    end_device_initiator: false,
                    reserved1: 0,
                },
                destination: Nwk(0x3ce7),
                source: Nwk(0x5f37),
                radius: 29,
                sequence_number: 204,
                destination_ieee: None,
                source_ieee: None,
                multicast_control: None,
                source_route: Some(NwkSourceRoute {
                    relay_index: 0,
                    relays: vec![Nwk(0xf939)],
                }),
            },
            aux_header: Some(NwkAuxHeader {
                security_control: NwkSecurityHeaderControlField {
                    security_level: NwkSecurityLevel::NoSecurity,
                    key_id: NwkSecurityHeaderKeyId::NetworkKey,
                    extended_nonce: true,
                    require_verified_frame_counter: false,
                },
                frame_counter: 41854,
                extended_source: Some(Eui64::from_hex("00:17:88:01:0c:71:3c:02")),
                key_sequence_number: 0,
            }),
            ciphertext: FrameBytes::from_slice(&hex!("0b73db5468c7cbc47caf8705")).unwrap(),
        };

        assert_eq!(nwk_frame, expected_nwk_frame);

        let key = Key::from_hex("31908c7c51c2f01552bc90cc16e5443d");
        let decrypted_nwk_frame = nwk_frame.clone().decrypt(&key).unwrap();

        let expected_decrypted_nwk_frame = NwkFrame {
            nwk_header: expected_nwk_frame.nwk_header,
            aux_header: expected_nwk_frame.aux_header,
            payload: FrameBytes::from_slice(&hex!("020106000401405b")).unwrap(),
        };

        assert_eq!(decrypted_nwk_frame, expected_decrypted_nwk_frame);

        // Make sure encryption is round trip
        let re_encrypted_nwk_frame = decrypted_nwk_frame.encrypt(&key);
        assert_eq!(nwk_frame.to_bytes(), bytes);
        assert_eq!(re_encrypted_nwk_frame, nwk_frame);
        assert_eq!(re_encrypted_nwk_frame.to_bytes(), bytes);
    }
}
