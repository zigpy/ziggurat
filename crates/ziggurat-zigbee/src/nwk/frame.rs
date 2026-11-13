#![allow(clippy::useless_conversion)]
use alloc::vec::Vec;

use abstract_bits::AbstractBits;
use abstract_bits::abstract_bits;
use abstract_bits::{BitReader, BitWriter};
use ziggurat_ieee_802154::types::{Eui64, Key, Nwk, format_hex};
use ziggurat_ieee_802154::{
    FrameBytes, FramePayload, FrameWriter, MAX_PHY_PACKET_SIZE, Psdu, TooLong,
};

use num_enum::TryFromPrimitive;

use educe::Educe;

use crate::ParseError;
use crate::nwk::commands::NwkCommand;

use crate::crypto::{DecryptionError, decrypt_ccm, encrypt_ccm, split_mic};

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
    relay_count: u8,
    pub relay_index: u8,
    #[abstract_bits(length_from = relay_count)]
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

    pub fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        writer.bits(&self.frame_control)?;
        writer.extend(&self.destination.to_bytes())?;
        writer.extend(&self.source.to_bytes())?;
        writer.push(self.radius)?;
        writer.push(self.sequence_number)?;

        if let Some(ieee) = &self.destination_ieee {
            writer.extend(&ieee.to_bytes())?;
        }

        if let Some(ieee) = &self.source_ieee {
            writer.extend(&ieee.to_bytes())?;
        }

        if let Some(control) = self.multicast_control {
            writer.push(control)?;
        }

        if let Some(source_route) = &self.source_route {
            writer.bits(source_route)?;
        }

        Ok(())
    }

    pub fn to_bytes(&self) -> Psdu {
        let mut bytes = Psdu::new();
        self.serialize(&mut FrameWriter::new(&mut bytes, MAX_PHY_PACKET_SIZE))
            .expect("a NWK header is frame-bounded");
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
    /// The field's single serialized byte, without `to_abstract_bytes`'s allocation:
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

    pub fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        writer.extend(&self.security_control.to_bytes())?;
        writer.extend(&self.frame_counter.to_le_bytes())?;

        if let Some(ieee) = self.extended_source {
            writer.extend(&ieee.to_bytes())?;
        }

        writer.push(self.key_sequence_number)
    }
}

/// A received NWK frame before decryption.
#[derive(Educe, Clone, PartialEq, Eq)]
#[educe(Debug)]
pub struct EncryptedNwkFrame<'a> {
    pub nwk_header: NwkHeader,
    pub aux_header: Option<NwkAuxHeader>,
    /// The encrypted payload and the MIC, borrowed from the received frame
    #[educe(Debug(method(format_hex)))]
    pub ciphertext: &'a [u8],
}

/// The body of a decrypted NWK frame.
///
/// Either a typed command the NWK layer owns, or the bytes it forwards without
/// interpreting (an APS frame for data frames, an inter-PAN frame for inter-PAN frames).
/// Serialized into wire bytes only at encryption time.
#[derive(Clone, PartialEq, Eq)]
pub enum NwkPayload {
    /// A payload the NWK layer does not interpret, forwarded verbatim.
    Opaque(FrameBytes),
    /// A NWK command the NWK layer owns.
    Command(NwkCommand),
}

impl core::fmt::Debug for NwkPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Opaque(bytes) => {
                write!(f, "Opaque(")?;
                format_hex(bytes, f)?;
                write!(f, ")")
            }
            Self::Command(command) => f.debug_tuple("Command").field(command).finish(),
        }
    }
}

impl NwkPayload {
    /// Write the frame body, which is encrypted afterwards on a secured frame.
    pub fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        match self {
            Self::Opaque(bytes) => writer.extend(bytes),
            Self::Command(command) => command.serialize(writer),
        }
    }

    pub fn to_bytes(&self) -> FrameBytes {
        let mut bytes = FrameBytes::new();
        self.serialize(&mut FrameWriter::new(&mut bytes, MAX_PHY_PACKET_SIZE))
            .expect("a NWK payload is frame-bounded");
        bytes
    }

    /// Decode a decrypted frame body, using the frame type to decide whether it is a NWK
    /// command or a payload the NWK layer forwards without interpreting.
    pub fn from_bytes(frame_type: NwkFrameType, bytes: FrameBytes) -> Self {
        match frame_type {
            NwkFrameType::Command => Self::Command(NwkCommand::from_bytes(&bytes)),
            // Data and inter-PAN payloads are opaque to the NWK layer
            NwkFrameType::Data | NwkFrameType::Interpan => Self::Opaque(bytes),
        }
    }

    /// The forwarded payload bytes (an APS frame for a data frame), or `None` for a NWK
    /// command.
    pub const fn as_opaque(&self) -> Option<&FrameBytes> {
        match self {
            Self::Opaque(bytes) => Some(bytes),
            Self::Command(_) => None,
        }
    }
}

#[derive(Educe, Clone, PartialEq, Eq)]
#[educe(Debug)]
pub struct NwkFrame {
    pub nwk_header: NwkHeader,
    pub aux_header: Option<NwkAuxHeader>,
    pub payload: NwkPayload,
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

impl<'a> EncryptedNwkFrame<'a> {
    pub fn get_modified_aux_header(&self, nib_security_level: NwkSecurityLevel) -> NwkAuxHeader {
        if self.aux_header.is_none() {
            panic!("Auxiliary header is missing");
        }

        let mut aux_header = self.aux_header.clone().unwrap();
        aux_header.security_control.security_level = nib_security_level;

        aux_header
    }

    pub fn get_nonce(&self, aux_header: &NwkAuxHeader) -> [u8; 13] {
        let source = aux_header
            .extended_source
            .or(self.nwk_header.source_ieee)
            .expect("Cannot compute nonce with no source address");

        let mut nonce = [0; 13];
        nonce[..8].copy_from_slice(&source.to_bytes());
        nonce[8..12].copy_from_slice(&aux_header.frame_counter.to_le_bytes());
        nonce[12..13].copy_from_slice(&aux_header.security_control.to_bytes());

        nonce
    }

    #[allow(clippy::useless_let_if_seq)]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
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
            ciphertext: remaining,
        })
    }

    pub fn to_bytes(&self) -> Psdu {
        let mut bytes = Psdu::new();
        self.serialize(&mut FrameWriter::new(&mut bytes, MAX_PHY_PACKET_SIZE))
            .expect("a parsed NWK frame is frame-bounded");
        bytes
    }

    /// The ciphertext is copied into the payload of the decrypted frame and decrypted
    /// there.
    pub fn decrypt(&self, key: &Key) -> Result<NwkFrame, DecryptionError> {
        let aux_header = self.get_modified_aux_header(NwkSecurityLevel::EncMic32);
        let nonce = self.get_nonce(&aux_header);

        let mut auth_data = Psdu::new();
        let mut writer = FrameWriter::new(&mut auth_data, MAX_PHY_PACKET_SIZE);
        self.nwk_header
            .serialize(&mut writer)
            .and_then(|()| aux_header.serialize(&mut writer))
            .expect("a parsed NWK header is frame-bounded");

        let (ciphertext, mic) = split_mic(self.ciphertext)?;
        let mut plaintext =
            FrameBytes::from_slice(ciphertext).expect("a parsed NWK frame is frame-bounded");
        decrypt_ccm(key, &nonce, &auth_data, &mut plaintext, mic)?;
        let payload = NwkPayload::from_bytes(self.nwk_header.frame_control.frame_type, plaintext);

        Ok(NwkFrame {
            nwk_header: self.nwk_header.clone(),
            aux_header: self.aux_header.clone(),
            payload,
        })
    }
}

impl FramePayload for EncryptedNwkFrame<'_> {
    fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        self.nwk_header.serialize(writer)?;

        if let Some(aux_header) = &self.aux_header {
            aux_header.serialize(writer)?;
        }

        writer.extend(self.ciphertext)
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

    pub fn get_nonce(&self, aux_header: &NwkAuxHeader) -> [u8; 13] {
        let source = aux_header
            .extended_source
            .or(self.nwk_header.source_ieee)
            .expect("Cannot compute nonce with no source address");

        let mut nonce = [0; 13];
        nonce[..8].copy_from_slice(&source.to_bytes());
        nonce[8..12].copy_from_slice(&aux_header.frame_counter.to_le_bytes());
        nonce[12..13].copy_from_slice(&aux_header.security_control.to_bytes());

        nonce
    }

    /// Write the frame, encrypting it under `key` when one is given. A frame sent
    /// without a key goes out without its auxiliary header.
    pub fn serialize(&self, writer: &mut FrameWriter, key: Option<&Key>) -> Result<(), TooLong> {
        let header_offset = writer.len();
        self.nwk_header.serialize(writer)?;

        let Some(key) = key else {
            return self.payload.serialize(writer);
        };

        let aux_header = self.get_modified_aux_header(NwkSecurityLevel::EncMic32);
        let nonce = self.get_nonce(&aux_header);

        let security_control_offset = writer.len();
        aux_header.serialize(writer)?;
        let payload_offset = writer.len();
        self.payload.serialize(writer)?;

        let (auth_data, payload) =
            writer.written_mut()[header_offset..].split_at_mut(payload_offset - header_offset);
        let mic = encrypt_ccm(key, &nonce, auth_data, payload);
        writer.extend(&mic)?;

        // Spec 4.3.1.1 step 8: the frame is sent with security level 0, and the
        // receiver puts the network's level back before it decrypts
        let mut sent_aux_header = aux_header;
        sent_aux_header.security_control.security_level = NwkSecurityLevel::NoSecurity;
        writer.written_mut()[security_control_offset] =
            sent_aux_header.security_control.to_bytes()[0];

        Ok(())
    }

    /// The encrypted frame's bytes.
    pub fn encrypt(&self, key: &Key) -> Psdu {
        let mut bytes = Psdu::new();
        self.serialize(
            &mut FrameWriter::new(&mut bytes, MAX_PHY_PACKET_SIZE),
            Some(key),
        )
        .expect("the NWK frame fits in a PSDU");
        bytes
    }
}

/// A NWK frame ready to go into an 802.15.4 data frame, encrypted under `key` as it is
/// written. Unsecured frames have no key.
pub struct OutgoingNwkFrame<'a> {
    pub frame: &'a NwkFrame,
    pub key: Option<Key>,
}

impl FramePayload for OutgoingNwkFrame<'_> {
    fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        self.frame.serialize(writer, self.key.as_ref())
    }

    fn fmt_payload(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.frame)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
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
            ciphertext: &hex!("f7a7e37b47adb47593c8a375c98ba6"),
        };

        assert_eq!(nwk_frame, expected_nwk_frame);

        let key = Key::from_hex("e8785a1ed5996b3ef715cb3fbdd69187");
        let decrypted_nwk_frame = nwk_frame.decrypt(&key).unwrap();

        let expected_decrypted_nwk_frame = NwkFrame {
            nwk_header: expected_nwk_frame.nwk_header,
            aux_header: expected_nwk_frame.aux_header,
            payload: NwkPayload::Opaque(
                FrameBytes::from_slice(&hex!("00010600040101a9015701")).unwrap(),
            ),
        };

        assert_eq!(decrypted_nwk_frame, expected_decrypted_nwk_frame);

        // Make sure encryption is round trip
        assert_eq!(nwk_frame.to_bytes(), bytes);
        assert_eq!(decrypted_nwk_frame.encrypt(&key), bytes);
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
            ciphertext: &hex!("0b73db5468c7cbc47caf8705"),
        };

        assert_eq!(nwk_frame, expected_nwk_frame);

        let key = Key::from_hex("31908c7c51c2f01552bc90cc16e5443d");
        let decrypted_nwk_frame = nwk_frame.decrypt(&key).unwrap();

        let expected_decrypted_nwk_frame = NwkFrame {
            nwk_header: expected_nwk_frame.nwk_header,
            aux_header: expected_nwk_frame.aux_header,
            payload: NwkPayload::Opaque(FrameBytes::from_slice(&hex!("020106000401405b")).unwrap()),
        };

        assert_eq!(decrypted_nwk_frame, expected_decrypted_nwk_frame);

        // Make sure encryption is round trip
        assert_eq!(nwk_frame.to_bytes(), bytes);
        assert_eq!(decrypted_nwk_frame.encrypt(&key), bytes);
    }
}
