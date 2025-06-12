#![allow(dead_code)]

use ieee_802154::types::{Eui64, Key, Nwk, format_hex};

use std::convert::TryFrom;

use aes::Aes128;
use aes::Block;
use aes::cipher::BlockModeEncrypt;
use aes::cipher::KeyInit;
use aes::cipher::KeyIvInit;
use cbc::Encryptor;
use cbc::cipher::BlockCipherEncrypt;
use constant_time_eq::constant_time_eq;

use derivative::Derivative;

pub const BROADCAST_ALL_DEVICES: Nwk = Nwk(0xFFFF);
pub const BROADCAST_RX_ON_WHEN_IDLE: Nwk = Nwk(0xFFFD);
pub const BROADCAST_ALL_ROUTERS_AND_COORDINATOR: Nwk = Nwk(0xFFFC);
pub const BROADCAST_LOW_POWER_ROUTERS: Nwk = Nwk(0xFFFB);

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum NwkFrameType {
    Data = 0b00,
    Command = 0b01,
    Interpan = 0b11,
}

impl TryFrom<u8> for NwkFrameType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(NwkFrameType::Data),
            0b01 => Ok(NwkFrameType::Command),
            0b11 => Ok(NwkFrameType::Interpan),
            _ => Err("Invalid frame type"),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum NwkRouteDiscovery {
    Suppress = 0b00,
    Enable = 0b01,
    WithMulticast = 0b10,
}

impl TryFrom<u8> for NwkRouteDiscovery {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(NwkRouteDiscovery::Suppress),
            0b01 => Ok(NwkRouteDiscovery::Enable),
            0b10 => Ok(NwkRouteDiscovery::WithMulticast),
            _ => Err("Invalid route discovery"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NwkFrameControl {
    pub frame_type: NwkFrameType,
    pub protocol_version: u8,
    pub discover_route: NwkRouteDiscovery,
    pub multicast: bool,
    pub security: bool,
    pub source_route: bool,
    pub destination: bool,
    pub extended_source: bool,
    pub end_device_initiator: bool,
    pub reserved: u8,
}

impl NwkFrameControl {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 2 {
            return Err("Not enough data to parse NwkFrameControl");
        }

        Ok((
            Self {
                frame_type: NwkFrameType::try_from((bytes[0] >> 0) & 0b11)?,
                protocol_version: (bytes[0] >> 2) & 0b1111,
                discover_route: NwkRouteDiscovery::try_from((bytes[0] >> 6) & 0b11)?,
                multicast: (bytes[1] >> 0) & 0b1 == 1,
                security: (bytes[1] >> 1) & 0b1 == 1,
                source_route: (bytes[1] >> 2) & 0b1 == 1,
                destination: (bytes[1] >> 3) & 0b1 == 1,
                extended_source: (bytes[1] >> 4) & 0b1 == 1,
                end_device_initiator: (bytes[1] >> 5) & 0b1 == 1,
                reserved: (bytes[1] >> 6) & 0b11,
            },
            &bytes[2..],
        ))
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        [
            (((self.frame_type as u8) & 0b11) << 0)
                | (((self.protocol_version as u8) & 0b1111) << 2)
                | (((self.discover_route as u8) & 0b11) << 6),
            (((self.multicast as u8) & 0b1) << 0)
                | (((self.security as u8) & 0b1) << 1)
                | (((self.source_route as u8) & 0b1) << 2)
                | (((self.destination as u8) & 0b1) << 3)
                | (((self.extended_source as u8) & 0b1) << 4)
                | (((self.end_device_initiator as u8) & 0b1) << 5)
                | (((self.reserved as u8) & 0b11) << 6),
        ]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NwkSourceRoute {
    pub relay_count: u8, // Technically unnecessary to store but maybe we'll need it
    pub relay_index: u8,
    pub relays: Vec<Nwk>,
}

impl NwkSourceRoute {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 2 {
            return Err("Not enough data to parse NwkSourceRoute");
        }

        let relay_count = bytes[0];
        let relay_index = bytes[1];
        let mut remaining = &bytes[2..];

        let mut relays = Vec::new();

        for _ in 0..relay_count {
            let nwk;
            (nwk, remaining) = Nwk::deserialize(remaining)?;
            relays.push(nwk);
        }

        Ok((
            Self {
                relay_count: relay_count,
                relay_index: relay_index,
                relays: relays,
            },
            remaining,
        ))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if self.relay_count != self.relays.len() as u8 {
            panic!("Relay count does not match number of relays");
        }

        let mut bytes = Vec::new();

        bytes.push(self.relay_count);
        bytes.push(self.relay_index);

        for nwk in &self.relays {
            bytes.extend(nwk.to_bytes());
        }

        bytes
    }
}

#[derive(Debug, Clone, PartialEq)]
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
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 8 {
            return Err("Not enough data to parse NwkHeader");
        }

        let mut remaining = bytes;

        let frame_control;
        (frame_control, remaining) = NwkFrameControl::deserialize(remaining)?;

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
                let control = remaining[0];
                remaining = &remaining[1..];
                Some(control)
            }
            false => None,
        };

        let source_route = match frame_control.source_route {
            true => {
                let source_route;
                (source_route, remaining) = NwkSourceRoute::deserialize(remaining)?;
                Some(source_route)
            }
            false => None,
        };

        Ok((
            Self {
                frame_control: frame_control,
                destination: destination,
                source: source,
                radius: radius,
                sequence_number: sequence_number,
                destination_ieee: destination_ieee,
                source_ieee: source_ieee,
                multicast_control: multicast_control,
                source_route: source_route,
            },
            remaining,
        ))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.frame_control.to_bytes());
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
            bytes.extend(source_route.to_bytes());
        }

        bytes
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum NwkSecurityHeaderKeyId {
    DataKey = 0x00,
    NetworkKey = 0x01,
    KeyTransportKey = 0x02,
    KeyLoadKey = 0x03,
}

impl TryFrom<u8> for NwkSecurityHeaderKeyId {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(NwkSecurityHeaderKeyId::DataKey),
            0x01 => Ok(NwkSecurityHeaderKeyId::NetworkKey),
            0x02 => Ok(NwkSecurityHeaderKeyId::KeyTransportKey),
            0x03 => Ok(NwkSecurityHeaderKeyId::KeyLoadKey),
            _ => Err("Invalid Nwk security header key ID"),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
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

impl TryFrom<u8> for NwkSecurityLevel {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(NwkSecurityLevel::NoSecurity),
            0x01 => Ok(NwkSecurityLevel::Mic32),
            0x02 => Ok(NwkSecurityLevel::Mic64),
            0x03 => Ok(NwkSecurityLevel::Mic128),
            0x04 => Ok(NwkSecurityLevel::Enc),
            0x05 => Ok(NwkSecurityLevel::EncMic32),
            0x06 => Ok(NwkSecurityLevel::EncMic64),
            0x07 => Ok(NwkSecurityLevel::EncMic128),
            _ => Err("Invalid Nwk security level"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NwkSecurityHeaderControlField {
    pub security_level: NwkSecurityLevel,
    pub key_id: NwkSecurityHeaderKeyId,
    pub extended_nonce: bool,
    pub require_verified_frame_counter: bool,
    pub reserved: u8,
}

impl NwkSecurityHeaderControlField {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 1 {
            return Err("Not enough data to parse NwkSecurityHeaderControlField");
        }

        Ok((
            Self {
                security_level: NwkSecurityLevel::try_from((bytes[0] >> 0) & 0b111)?,
                key_id: NwkSecurityHeaderKeyId::try_from((bytes[0] >> 3) & 0b11)?,
                extended_nonce: (bytes[0] >> 5) & 0b1 == 1,
                require_verified_frame_counter: (bytes[0] >> 6) & 0b1 == 1,
                reserved: (bytes[0] >> 7) & 0b1,
            },
            &bytes[1..],
        ))
    }

    pub fn to_bytes(&self) -> [u8; 1] {
        [((self.security_level as u8) & 0b111)
            | (((self.key_id as u8) & 0b11) << 3)
            | ((self.extended_nonce as u8) << 5)
            | ((self.require_verified_frame_counter as u8) << 6)
            | ((self.reserved & 0b1) << 7)]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NwkAuxHeader {
    pub security_control: NwkSecurityHeaderControlField,
    pub frame_counter: u32,
    pub extended_source: Option<Eui64>,
    pub key_sequence_number: u8,
}

impl NwkAuxHeader {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if bytes.len() < 6 {
            return Err("Not enough data to parse NwkAuxHeader");
        }

        let mut remaining = bytes;

        let security_control;
        (security_control, remaining) = NwkSecurityHeaderControlField::deserialize(remaining)?;

        let frame_counter =
            u32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]);
        remaining = &remaining[4..];

        let mut extended_source = None;

        if security_control.extended_nonce {
            let ieee;
            (ieee, remaining) = Eui64::deserialize(remaining)?;
            extended_source = Some(ieee);
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.security_control.to_bytes());
        bytes.extend(self.frame_counter.to_le_bytes().to_vec());

        if let Some(ieee) = self.extended_source {
            bytes.extend(ieee.to_bytes());
        }

        bytes.push(self.key_sequence_number);

        bytes
    }
}

fn right_pad_to_multiple_of_16(data: &[u8]) -> Vec<Block> {
    // Pre-allocate enough blocks
    let mut blocks = Vec::<Block>::with_capacity((data.len() + 15) / 16);

    // Push all full 16-byte chunks
    for chunk in data.chunks_exact(16) {
        blocks.push(Block::try_from(chunk).expect("16-byte chunk is always valid"));
    }

    // If there's a remainder, copy it into a new block and pad the rest with zeros
    let remainder = data.len() % 16;
    if remainder != 0 {
        let offset = data.len() - remainder;

        let mut last_block = Block::default();
        last_block[..remainder].copy_from_slice(&data[offset..]);
        blocks.push(last_block);
    }

    blocks
}

pub struct NwkCrypto<const L: usize, const M: usize>;

impl<const L: usize, const M: usize> NwkCrypto<L, M> {
    pub fn split_mac_tag(&self, tagged_ciphertext: &[u8]) -> (Vec<u8>, [u8; M]) {
        let ciphertext = tagged_ciphertext[..tagged_ciphertext.len() - M].to_vec();

        let mut mac_tag = [0; M];
        mac_tag.copy_from_slice(&tagged_ciphertext[tagged_ciphertext.len() - M..]);

        (ciphertext, mac_tag)
    }

    pub fn compute_mac(
        &self,
        frame: &NwkFrame,
        key: &Key,
        plaintext: &[u8],
        aux_header: &NwkAuxHeader,
        nonce: &[u8; 13],
    ) -> [u8; M] {
        let mut auth_data = Vec::new();
        auth_data.extend(frame.nwk_header.to_bytes());
        auth_data.extend(aux_header.to_bytes());

        let encoded_auth_data_len = auth_data.len().to_be_bytes();
        let mut added_auth_data = Vec::new();
        added_auth_data.extend(&encoded_auth_data_len[encoded_auth_data_len.len() - L..]);
        added_auth_data.extend(&auth_data);

        let encoded_plaintext_len = plaintext.len().to_be_bytes();
        let mut b0 = Block::default();
        b0[0] = 0b0_1_001_001; // Flags
        b0[1..14].copy_from_slice(nonce);
        b0[14..16].copy_from_slice(&encoded_plaintext_len[encoded_plaintext_len.len() - L..]);

        let mut authed_plaintext = Vec::<Block>::new();
        authed_plaintext.extend(right_pad_to_multiple_of_16(&added_auth_data));
        authed_plaintext.extend(right_pad_to_multiple_of_16(&plaintext));

        let mut ciphertext_buffer = Vec::<Block>::new();
        ciphertext_buffer.push(b0);
        ciphertext_buffer.extend(&authed_plaintext);

        let iv = [0x00; 16];
        let mut encryptor = Encryptor::<Aes128>::new(&(key.0).into(), &iv.into());
        encryptor.encrypt_blocks(&mut ciphertext_buffer);

        let mut mac_tag = [0; M];
        mac_tag.copy_from_slice(&ciphertext_buffer[ciphertext_buffer.len() - 1][..M]);

        mac_tag
    }

    pub fn encrypt_decrypt(
        &self,
        key: &Key,
        nonce: &[u8; 13],
        mac_tag: &[u8; M],
        plaintext: &[u8],
    ) -> ([u8; M], Vec<u8>) {
        let cipher = Aes128::new(&(key.0).into());

        let mut tagged_plaintext_blocks = Vec::<Block>::new();
        tagged_plaintext_blocks.extend(right_pad_to_multiple_of_16(mac_tag));
        tagged_plaintext_blocks.extend(right_pad_to_multiple_of_16(plaintext));

        let mut tagged_ciphertext_blocks = Vec::<Block>::new();
        let mut buffer_block = Block::default();

        for (block_num, plaintext_block) in tagged_plaintext_blocks.iter().enumerate() {
            let encoded_block_num = block_num.to_be_bytes();
            let mut counter_block = Block::default();
            counter_block[0] = 0b0_0_000_001;
            counter_block[1..14].copy_from_slice(nonce);
            counter_block[14..16]
                .copy_from_slice(&encoded_block_num[encoded_block_num.len() - L..]);

            cipher.encrypt_block_b2b(&mut counter_block, &mut buffer_block);
            tagged_ciphertext_blocks.push(Block::from_fn(|i| buffer_block[i] ^ plaintext_block[i]));
        }

        // The first M bytes of the first block is the "encrypted_mac_tag":
        let mut encrypted_mac_tag = [0; M];
        encrypted_mac_tag.copy_from_slice(&tagged_ciphertext_blocks[0][0..M]);

        // The actual ciphertext portion starts at the second block
        let ciphertext_vec = Vec::<u8>::from(tagged_ciphertext_blocks[1..].concat());
        let ciphertext = ciphertext_vec[..plaintext.len()].to_vec();

        (encrypted_mac_tag, ciphertext)
    }
}

#[derive(Derivative)]
#[derivative(Debug, Clone, PartialEq)]
pub struct NwkFrame {
    pub nwk_header: NwkHeader,
    pub aux_header: Option<NwkAuxHeader>,
    #[derivative(Debug(format_with = "format_hex"))]
    pub payload: Vec<u8>,
    pub encrypted: bool,
}

impl NwkFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut remaining;
        let nwk_header;
        (nwk_header, remaining) = NwkHeader::deserialize(bytes)?;

        let mut aux_header = None;

        if nwk_header.frame_control.security {
            let unwrapped_aux_header;
            (unwrapped_aux_header, remaining) = NwkAuxHeader::deserialize(remaining)?;
            aux_header = Some(unwrapped_aux_header);
        }

        let encrypted = nwk_header.frame_control.security;

        Ok(Self {
            nwk_header: nwk_header,
            aux_header: aux_header,
            payload: remaining.to_vec(),
            encrypted: encrypted,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.nwk_header.to_bytes());

        if let Some(aux_header) = &self.aux_header {
            bytes.extend(aux_header.to_bytes());
        }

        bytes.extend(self.payload.clone());

        bytes
    }

    pub fn get_modified_aux_header(&self, nib_security_level: NwkSecurityLevel) -> NwkAuxHeader {
        if self.aux_header.is_none() {
            panic!("Auxiliary header is missing");
        }

        let mut aux_header = self.aux_header.clone().unwrap();
        aux_header.security_control.security_level = nib_security_level;

        aux_header
    }

    pub fn get_nonce(&self, aux_header: &NwkAuxHeader) -> [u8; 13] {
        let source;

        if !aux_header.extended_source.is_none() {
            source = aux_header.extended_source.unwrap();
        } else if !self.nwk_header.source_ieee.is_none() {
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

    pub fn get_crypto(&self) -> NwkCrypto<2, 4> {
        // Only a single configuration is supported but to keep the cryptography code
        // readable, it's useful to be generic here
        NwkCrypto::<2, 4>
    }

    pub fn decrypt(&self, key: &Key) -> Result<Self, &'static str> {
        if !self.encrypted {
            return Err("Cannot decrypt unencrypted frame");
        }

        let crypto = self.get_crypto();

        let aux_header = self.get_modified_aux_header(NwkSecurityLevel::EncMic32);
        let nonce = self.get_nonce(&aux_header);
        let (ciphertext, encrypted_mac_tag) = crypto.split_mac_tag(&self.payload);
        let (provided_mac_tag, plaintext) =
            crypto.encrypt_decrypt(key, &nonce, &encrypted_mac_tag, &ciphertext);
        let mac_tag = crypto.compute_mac(&self, key, &plaintext, &aux_header, &nonce);

        if !constant_time_eq(&provided_mac_tag, &mac_tag) {
            return Err("Decryption failed, invalid MAC tag");
        }

        Ok(Self {
            nwk_header: self.nwk_header.clone(),
            aux_header: self.aux_header.clone(),
            payload: plaintext,
            encrypted: false,
        })
    }

    pub fn encrypt(&self, key: &Key) -> Result<Self, &'static str> {
        if self.encrypted {
            return Err("Cannot encrypt already encrypted frame");
        }

        let crypto = self.get_crypto();

        let aux_header = self.get_modified_aux_header(NwkSecurityLevel::EncMic32);
        let nonce = self.get_nonce(&aux_header);
        let plaintext = &self.payload;

        let mac_tag = crypto.compute_mac(&self, key, &plaintext, &aux_header, &nonce);
        let (encrypted_mac_tag, ciphertext) =
            crypto.encrypt_decrypt(key, &nonce, &mac_tag, &plaintext);

        let mut payload = ciphertext;
        payload.extend(encrypted_mac_tag);

        Ok(Self {
            nwk_header: self.nwk_header.clone(),
            aux_header: self.aux_header.clone(),
            payload: payload,
            encrypted: true,
        })
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
        let nwk_frame = NwkFrame::from_bytes(&bytes).unwrap();

        let expected_nwk_frame = NwkFrame {
            encrypted: true,
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
                    reserved: 0b00,
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
                    reserved: 0b0,
                },
                frame_counter: 2682,
                extended_source: Some(Eui64::from_hex("00:12:4b:00:1e:17:ef:a8")),
                key_sequence_number: 0,
            }),
            payload: hex!("f7a7e37b47adb47593c8a375c98ba6").to_vec(),
        };

        assert_eq!(nwk_frame, expected_nwk_frame);

        let key = Key::from_hex("e8785a1ed5996b3ef715cb3fbdd69187");
        let decrypted_nwk_frame = nwk_frame.decrypt(&key).unwrap();

        let expected_decrypted_nwk_frame = NwkFrame {
            encrypted: false,
            nwk_header: expected_nwk_frame.nwk_header,
            aux_header: expected_nwk_frame.aux_header,
            payload: hex!("00010600040101a9015701").to_vec(),
        };

        assert_eq!(decrypted_nwk_frame, expected_decrypted_nwk_frame);

        // Make sure encryption is round trip
        let re_encrypted_nwk_frame = decrypted_nwk_frame.encrypt(&key).unwrap();
        assert_eq!(nwk_frame.to_bytes(), bytes);
        assert_eq!(re_encrypted_nwk_frame, nwk_frame);
        assert_eq!(re_encrypted_nwk_frame.to_bytes(), bytes);
    }

    #[test]
    fn test_source_route() {
        let bytes =
            hex!("0806e73c375f1dcc010039f9287ea30000023c710c01881700000b73db5468c7cbc47caf8705");
        let nwk_frame = NwkFrame::from_bytes(&bytes).unwrap();

        let expected_nwk_frame = NwkFrame {
            encrypted: true,
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
                    reserved: 0b00,
                },
                destination: Nwk(0x3ce7),
                source: Nwk(0x5f37),
                radius: 29,
                sequence_number: 204,
                destination_ieee: None,
                source_ieee: None,
                multicast_control: None,
                source_route: Some(NwkSourceRoute {
                    relay_count: 1,
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
                    reserved: 0b0,
                },
                frame_counter: 41854,
                extended_source: Some(Eui64::from_hex("00:17:88:01:0c:71:3c:02")),
                key_sequence_number: 0,
            }),
            payload: hex!("0b73db5468c7cbc47caf8705").to_vec(),
        };

        assert_eq!(nwk_frame, expected_nwk_frame);

        let key = Key::from_hex("31908c7c51c2f01552bc90cc16e5443d");
        let decrypted_nwk_frame = nwk_frame.decrypt(&key).unwrap();

        let expected_decrypted_nwk_frame = NwkFrame {
            encrypted: false,
            nwk_header: expected_nwk_frame.nwk_header,
            aux_header: expected_nwk_frame.aux_header,
            payload: hex!("020106000401405b").to_vec(),
        };

        assert_eq!(decrypted_nwk_frame, expected_decrypted_nwk_frame);

        // Make sure encryption is round trip
        let re_encrypted_nwk_frame = decrypted_nwk_frame.encrypt(&key).unwrap();
        assert_eq!(nwk_frame.to_bytes(), bytes);
        assert_eq!(re_encrypted_nwk_frame, nwk_frame);
        assert_eq!(re_encrypted_nwk_frame.to_bytes(), bytes);
    }
}
