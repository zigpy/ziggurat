use abstract_bits::{AbstractBits, abstract_bits};
use educe::Educe;
use ieee_802154::types::{Eui64, Key, Nwk, format_hex};
use ieee_802154::{FrameBytes, extend_abstract_bits};
use num_enum::TryFromPrimitive;

use crate::ParseError;
use crate::crypto::{decrypt_ccm, encrypt_ccm};
use crate::nwk::frame::{NwkSecurityHeaderControlField, NwkSecurityHeaderKeyId, NwkSecurityLevel};

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum ApsFrameType {
    Data = 0b00,
    Command = 0b01,
    Ack = 0b10,
    Interpan = 0b11,
}

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum ApsDeliveryMode {
    Unicast = 0b00,
    Broadcast = 0b10,
    Multicast = 0b11,
}

#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApsFrameControl {
    pub frame_type: ApsFrameType,
    pub delivery_mode: ApsDeliveryMode,
    pub reserved1: u1,
    pub security: bool,
    pub ack_request: bool,
    pub extended_header: bool,
}

#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApsAckFrameControl {
    pub frame_type: ApsFrameType,
    pub delivery_mode: ApsDeliveryMode,
    pub ack_format: bool,
    pub security: bool,
    pub ack_request: bool,
    pub extended_header: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApsAckFrame {
    pub frame_control: ApsAckFrameControl,
    pub destination_endpoint: Option<u8>,
    pub cluster_id: Option<u16>,
    pub profile_id: Option<u16>,
    pub source_endpoint: Option<u8>,
    pub counter: u8,
}

impl ApsAckFrame {
    #[allow(clippy::useless_let_if_seq)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.is_empty() {
            return Err(ParseError::UnexpectedEnd { ty: "ApsAckFrame" });
        }

        let frame_control = ApsAckFrameControl::from_abstract_bits(bytes)?;
        let remaining = &bytes[1..];

        if frame_control.frame_type != ApsFrameType::Ack {
            return Err(ParseError::Unsupported(
                "non-Ack frame type for ApsAckFrame",
            ));
        }

        let destination_endpoint;
        let cluster_id;
        let profile_id;
        let source_endpoint;
        let counter;

        // An ack-format ack (for an APS command) carries only frame control and a
        // counter; a data ack additionally carries the addressing fields
        if frame_control.ack_format {
            if remaining.is_empty() {
                return Err(ParseError::UnexpectedEnd { ty: "ApsAckFrame" });
            }
            destination_endpoint = None;
            cluster_id = None;
            profile_id = None;
            source_endpoint = None;
            counter = u8::from_le_bytes([remaining[0]]);
        } else {
            if remaining.len() < 7 {
                return Err(ParseError::UnexpectedEnd { ty: "ApsAckFrame" });
            }
            destination_endpoint = Some(u8::from_le_bytes([remaining[0]]));
            cluster_id = Some(u16::from_le_bytes([remaining[1], remaining[2]]));
            profile_id = Some(u16::from_le_bytes([remaining[3], remaining[4]]));
            source_endpoint = Some(u8::from_le_bytes([remaining[5]]));
            counter = u8::from_le_bytes([remaining[6]]);
        }

        Ok(Self {
            frame_control,
            destination_endpoint,
            cluster_id,
            profile_id,
            source_endpoint,
            counter,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        extend_abstract_bits(&mut bytes, &self.frame_control);

        if let Some(destination_endpoint) = self.destination_endpoint {
            bytes.extend(destination_endpoint.to_le_bytes());
        }
        if let Some(cluster_id) = self.cluster_id {
            bytes.extend(cluster_id.to_le_bytes());
        }
        if let Some(profile_id) = self.profile_id {
            bytes.extend(profile_id.to_le_bytes());
        }
        if let Some(source_endpoint) = self.source_endpoint {
            bytes.extend(source_endpoint.to_le_bytes());
        }
        bytes.extend(self.counter.to_le_bytes());

        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApsDataFrame {
    pub frame_control: ApsFrameControl,
    pub group_id: Option<u16>,
    pub destination_endpoint: Option<u8>,
    pub cluster_id: u16,
    pub profile_id: u16,
    pub source_endpoint: u8,
    pub counter: u8,
    pub asdu: FrameBytes,
}

impl ApsDataFrame {
    #[allow(clippy::useless_let_if_seq)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 8 {
            return Err(ParseError::UnexpectedEnd { ty: "ApsDataFrame" });
        }

        let frame_control = ApsFrameControl::from_abstract_bits(bytes)?;
        let mut remaining = &bytes[1..];

        // Spec 2.2.5: reserved fields SHALL be zero on reception; a nonzero value marks
        // a malformed frame, which is discarded.
        if frame_control.reserved1 != 0 {
            return Err(ParseError::Unsupported("APS frame control reserved bits"));
        }

        let group_id;
        let destination_endpoint;

        if frame_control.delivery_mode == ApsDeliveryMode::Multicast {
            // The 2-byte group address replaces the 1-byte destination endpoint,
            // shifting every subsequent field
            if remaining.len() < 8 {
                return Err(ParseError::UnexpectedEnd {
                    ty: "multicast ApsDataFrame",
                });
            }

            group_id = Some(u16::from_le_bytes([remaining[0], remaining[1]]));
            destination_endpoint = None;
            remaining = &remaining[2..];
        } else {
            group_id = None;
            destination_endpoint = Some(remaining[0]);
            remaining = &remaining[1..];
        }

        let cluster_id = u16::from_le_bytes([remaining[0], remaining[1]]);
        let profile_id = u16::from_le_bytes([remaining[2], remaining[3]]);
        let source_endpoint = remaining[4];
        let counter = remaining[5];
        let asdu = FrameBytes::from_slice(&remaining[6..])
            .map_err(|_| ParseError::TooLong { ty: "ASDU" })?;

        Ok(Self {
            frame_control,
            group_id,
            destination_endpoint,
            cluster_id,
            profile_id,
            source_endpoint,
            counter,
            asdu,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        extend_abstract_bits(&mut bytes, &self.frame_control);

        if let Some(group_id) = self.group_id {
            bytes.extend(group_id.to_le_bytes());
        }

        if let Some(destination_endpoint) = self.destination_endpoint {
            bytes.extend(destination_endpoint.to_le_bytes());
        }

        bytes.extend(self.cluster_id.to_le_bytes());
        bytes.extend(self.profile_id.to_le_bytes());
        bytes.extend(self.source_endpoint.to_le_bytes());
        bytes.extend(self.counter.to_le_bytes());
        bytes.extend_from_slice(&self.asdu);

        bytes
    }
}

/// Zigbee spec Table 2-27: APS status values used in command frames
pub const APS_STATUS_SUCCESS: u8 = 0x00;
pub const APS_STATUS_SECURITY_FAIL: u8 = 0xAD;

#[derive(Debug, Clone, PartialEq, Eq, TryFromPrimitive, Copy)]
#[repr(u8)]
pub enum ApsCommandId {
    // Command identifiers 0x01-0x04 are the deprecated SKKE handshake
    TransportKey = 0x05,
    UpdateDevice = 0x06,
    RemoveDevice = 0x07,
    RequestKey = 0x08,
    SwitchKey = 0x09,
    Tunnel = 0x0E,
    VerifyKey = 0x0F,
    ConfirmKey = 0x10,
    RelayMessageDownstream = 0x11,
    RelayMessageUpstream = 0x12,
}

// TransportKey command
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, PartialEq, Eq, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum ApsStandardKeyType {
    StandardNetworkKey = 0x01,
    ApplicationLinkKey = 0x03,
    TrustCenterLinkKey = 0x04,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[abstract_bits]
pub struct ApsTrustCenterLinkKeyDescriptor {
    pub key: Key,
    pub destination_address: Eui64,
    pub source_address: Eui64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[abstract_bits]
pub struct ApsNetworkKeyDescriptor {
    pub key: Key,
    pub sequence_number: u8,
    pub destination_address: Eui64,
    pub source_address: Eui64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[abstract_bits]
pub struct ApsApplicationLinkKeyDescriptor {
    pub key: Key,
    pub partner_address: Eui64,
    pub initiator_flag: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApsTransportKeyDescriptor {
    TrustCenterLinkKey(ApsTrustCenterLinkKeyDescriptor),
    NetworkKey(ApsNetworkKeyDescriptor),
    ApplicationLinkKey(ApsApplicationLinkKeyDescriptor),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApsTransportKeyCommandFrame {
    pub standard_key_type: ApsStandardKeyType,
    pub key_descriptor: ApsTransportKeyDescriptor,
}

impl ApsTransportKeyCommandFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 2 {
            return Err(ParseError::UnexpectedEnd {
                ty: "ApsTransportKeyCommandFrame",
            });
        }

        let standard_key_type = ApsStandardKeyType::try_from(bytes[0]).map_err(|_| {
            ParseError::InvalidDiscriminant {
                ty: "ApsStandardKeyType",
                got: bytes[0],
            }
        })?;

        let key_descriptor = match standard_key_type {
            ApsStandardKeyType::StandardNetworkKey => ApsTransportKeyDescriptor::NetworkKey(
                ApsNetworkKeyDescriptor::from_abstract_bits(&bytes[1..])?,
            ),
            ApsStandardKeyType::ApplicationLinkKey => {
                ApsTransportKeyDescriptor::ApplicationLinkKey(
                    ApsApplicationLinkKeyDescriptor::from_abstract_bits(&bytes[1..])?,
                )
            }
            ApsStandardKeyType::TrustCenterLinkKey => {
                ApsTransportKeyDescriptor::TrustCenterLinkKey(
                    ApsTrustCenterLinkKeyDescriptor::from_abstract_bits(&bytes[1..])?,
                )
            }
        };

        Ok(Self {
            standard_key_type,
            key_descriptor,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.standard_key_type as u8);

        match &self.key_descriptor {
            ApsTransportKeyDescriptor::TrustCenterLinkKey(desc) => {
                bytes.extend(desc.to_abstract_bits().unwrap());
            }
            ApsTransportKeyDescriptor::NetworkKey(desc) => {
                bytes.extend(desc.to_abstract_bits().unwrap());
            }
            ApsTransportKeyDescriptor::ApplicationLinkKey(desc) => {
                bytes.extend(desc.to_abstract_bits().unwrap());
            }
        }

        bytes
    }
}

/// Zigbee spec 4.4.11.2: Update Device Command
#[abstract_bits(bits = 8)]
#[derive(Debug, Clone, PartialEq, Eq, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum ApsUpdateDeviceStatus {
    StandardDeviceSecuredRejoin = 0x00,
    StandardDeviceUnsecuredJoin = 0x01,
    DeviceLeft = 0x02,
    StandardDeviceTrustCenterRejoin = 0x03,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[abstract_bits]
pub struct ApsUpdateDeviceCommandFrame {
    pub device_address: Eui64,
    pub device_short_address: Nwk,
    pub status: ApsUpdateDeviceStatus,
}

/// Zigbee spec 4.4.11.3: Remove Device Command
#[derive(Debug, Clone, PartialEq, Eq)]
#[abstract_bits]
pub struct ApsRemoveDeviceCommandFrame {
    pub target_address: Eui64,
}

/// Zigbee spec 4.4.11.4: Request-Key Command. Note that the key type enumeration
/// (Table 4-19) is distinct from `ApsStandardKeyType` (Table 4-9).
#[derive(Debug, Clone, PartialEq, Eq, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum ApsRequestKeyType {
    ApplicationLinkKey = 0x02,
    TrustCenterLinkKey = 0x04,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApsRequestKeyCommandFrame {
    pub key_type: ApsRequestKeyType,
    /// Only present when an application link key is requested
    pub partner_address: Option<Eui64>,
}

impl ApsRequestKeyCommandFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.is_empty() {
            return Err(ParseError::UnexpectedEnd {
                ty: "ApsRequestKeyCommandFrame",
            });
        }

        let key_type =
            ApsRequestKeyType::try_from(bytes[0]).map_err(|_| ParseError::InvalidDiscriminant {
                ty: "ApsRequestKeyType",
                got: bytes[0],
            })?;

        let partner_address = match key_type {
            ApsRequestKeyType::ApplicationLinkKey => Some(Eui64::deserialize(&bytes[1..])?.0),
            ApsRequestKeyType::TrustCenterLinkKey => None,
        };

        Ok(Self {
            key_type,
            partner_address,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.key_type as u8];

        if let Some(partner_address) = self.partner_address {
            bytes.extend(partner_address.to_bytes());
        }

        bytes
    }
}

/// Zigbee spec 4.4.11.5: Switch-Key Command
#[derive(Debug, Clone, PartialEq, Eq)]
#[abstract_bits]
pub struct ApsSwitchKeyCommandFrame {
    pub sequence_number: u8,
}

/// Zigbee spec 4.4.11.6: Tunnel Command
#[derive(Educe, Clone, PartialEq, Eq)]
#[educe(Debug)]
pub struct ApsTunnelCommandFrame {
    pub destination_address: Eui64,
    /// The complete APS frame to relay: APS header, auxiliary header, encrypted
    /// command, and MIC
    #[educe(Debug(method(format_hex)))]
    pub tunneled_frame: FrameBytes,
}

impl ApsTunnelCommandFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let (destination_address, remaining) = Eui64::deserialize(bytes)?;

        Ok(Self {
            destination_address,
            tunneled_frame: FrameBytes::from_slice(remaining).map_err(|_| ParseError::TooLong {
                ty: "tunneled frame",
            })?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.destination_address.to_bytes());
        bytes.extend(self.tunneled_frame.clone());

        bytes
    }
}

/// Zigbee spec 4.4.11.7: Verify-Key Command
#[derive(Debug, Clone, PartialEq, Eq)]
#[abstract_bits]
pub struct ApsVerifyKeyCommandFrame {
    pub standard_key_type: ApsStandardKeyType,
    pub source_address: Eui64,
    /// The keyed hash (spec B.1.4) of the link key under verification, computed with
    /// the 1-octet input string 0x03
    pub initiator_verify_key_hash: Key,
}

/// Zigbee spec 4.4.11.8: Confirm-Key Command
#[derive(Debug, Clone, PartialEq, Eq)]
#[abstract_bits]
pub struct ApsConfirmKeyCommandFrame {
    pub status: u8,
    pub standard_key_type: ApsStandardKeyType,
    pub destination_address: Eui64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApsCommandFrameCommand {
    TransportKey(ApsTransportKeyCommandFrame),
    UpdateDevice(ApsUpdateDeviceCommandFrame),
    RemoveDevice(ApsRemoveDeviceCommandFrame),
    RequestKey(ApsRequestKeyCommandFrame),
    SwitchKey(ApsSwitchKeyCommandFrame),
    Tunnel(ApsTunnelCommandFrame),
    VerifyKey(ApsVerifyKeyCommandFrame),
    ConfirmKey(ApsConfirmKeyCommandFrame),
}

// Main command frame struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApsCommandFrame {
    pub frame_control: ApsFrameControl,
    pub counter: u8,
    pub command_id: ApsCommandId,
    pub command: ApsCommandFrameCommand,
}

impl ApsCommandFrame {
    #[allow(clippy::useless_let_if_seq)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 3 {
            return Err(ParseError::UnexpectedEnd {
                ty: "ApsCommandFrame",
            });
        }

        let frame_control = ApsFrameControl::from_abstract_bits(bytes)?;
        let remaining = &bytes[1..];

        let counter = u8::from_le_bytes([remaining[0]]);
        let command_id =
            ApsCommandId::try_from(remaining[1]).map_err(|_| ParseError::InvalidDiscriminant {
                ty: "ApsCommandId",
                got: remaining[1],
            })?;
        let payload = &remaining[2..];

        let command = match command_id {
            ApsCommandId::TransportKey => ApsCommandFrameCommand::TransportKey(
                ApsTransportKeyCommandFrame::from_bytes(payload)?,
            ),
            ApsCommandId::UpdateDevice => ApsCommandFrameCommand::UpdateDevice(
                ApsUpdateDeviceCommandFrame::from_abstract_bits(payload)?,
            ),
            ApsCommandId::RemoveDevice => ApsCommandFrameCommand::RemoveDevice(
                ApsRemoveDeviceCommandFrame::from_abstract_bits(payload)?,
            ),
            ApsCommandId::RequestKey => {
                ApsCommandFrameCommand::RequestKey(ApsRequestKeyCommandFrame::from_bytes(payload)?)
            }
            ApsCommandId::SwitchKey => ApsCommandFrameCommand::SwitchKey(
                ApsSwitchKeyCommandFrame::from_abstract_bits(payload)?,
            ),
            ApsCommandId::Tunnel => {
                ApsCommandFrameCommand::Tunnel(ApsTunnelCommandFrame::from_bytes(payload)?)
            }
            ApsCommandId::VerifyKey => ApsCommandFrameCommand::VerifyKey(
                ApsVerifyKeyCommandFrame::from_abstract_bits(payload)?,
            ),
            ApsCommandId::ConfirmKey => ApsCommandFrameCommand::ConfirmKey(
                ApsConfirmKeyCommandFrame::from_abstract_bits(payload)?,
            ),
            _ => {
                return Err(ParseError::Unsupported("command ID for ApsCommandFrame"));
            }
        };

        Ok(Self {
            frame_control,
            counter,
            command_id,
            command,
        })
    }

    /// The APS command identifier and command payload, i.e. the portion of the frame
    /// that is encrypted when APS security is applied.
    pub fn payload_to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.command_id as u8];

        bytes.extend(match &self.command {
            ApsCommandFrameCommand::TransportKey(cmd) => cmd.to_bytes(),
            ApsCommandFrameCommand::UpdateDevice(cmd) => cmd.to_abstract_bits().unwrap(),
            ApsCommandFrameCommand::RemoveDevice(cmd) => cmd.to_abstract_bits().unwrap(),
            ApsCommandFrameCommand::RequestKey(cmd) => cmd.to_bytes(),
            ApsCommandFrameCommand::SwitchKey(cmd) => cmd.to_abstract_bits().unwrap(),
            ApsCommandFrameCommand::Tunnel(cmd) => cmd.to_bytes(),
            ApsCommandFrameCommand::VerifyKey(cmd) => cmd.to_abstract_bits().unwrap(),
            ApsCommandFrameCommand::ConfirmKey(cmd) => cmd.to_abstract_bits().unwrap(),
        });

        bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        extend_abstract_bits(&mut bytes, &self.frame_control);
        bytes.push(self.counter);
        bytes.extend(self.payload_to_bytes());

        bytes
    }

    /// The APS frame control byte and counter, i.e. the cleartext header preceding the
    /// auxiliary header when APS security is applied.
    fn header_to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        extend_abstract_bits(&mut bytes, &self.frame_control);
        bytes.push(self.counter);

        bytes
    }

    pub fn encrypt(&self, key: &Key, aux_header: &ApsAuxHeader) -> EncryptedApsCommandFrame {
        let ciphertext = encrypt_aps_payload(
            key,
            aux_header,
            &self.header_to_bytes(),
            &self.payload_to_bytes(),
        );

        EncryptedApsCommandFrame {
            frame_control: self.frame_control.clone(),
            counter: self.counter,
            aux_header: aux_header.clone(),
            ciphertext,
        }
    }
}

/// Zigbee spec 4.5.1: the APS auxiliary frame header. Unlike its NWK counterpart, the
/// key sequence number is only present when the frame is secured with a network key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApsAuxHeader {
    pub security_control: NwkSecurityHeaderControlField,
    pub frame_counter: u32,
    pub extended_source: Option<Eui64>,
    pub key_sequence_number: Option<u8>,
}

impl ApsAuxHeader {
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        if bytes.len() < 5 {
            return Err(ParseError::UnexpectedEnd { ty: "ApsAuxHeader" });
        }

        let security_control = NwkSecurityHeaderControlField::from_abstract_bits(bytes)?;
        let mut remaining = &bytes[1..];

        let frame_counter =
            u32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]);
        remaining = &remaining[4..];

        let extended_source = if security_control.extended_nonce {
            let ieee;
            (ieee, remaining) = Eui64::deserialize(remaining)?;
            Some(ieee)
        } else {
            None
        };

        let mut key_sequence_number = None;
        if security_control.key_id == NwkSecurityHeaderKeyId::NetworkKey {
            if remaining.is_empty() {
                return Err(ParseError::UnexpectedEnd {
                    ty: "ApsAuxHeader key sequence number",
                });
            }

            key_sequence_number = Some(remaining[0]);
            remaining = &remaining[1..];
        }

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

        if let Some(key_sequence_number) = self.key_sequence_number {
            bytes.push(key_sequence_number);
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.serialize_into(&mut bytes);
        bytes
    }

    pub fn get_modified(&self, security_level: NwkSecurityLevel) -> Self {
        let mut aux_header = self.clone();
        aux_header.security_control.security_level = security_level;

        aux_header
    }

    /// The CCM* nonce (spec 4.5.2.2). The frame originator's EUI64 must be passed in:
    /// frames without an extended nonce do not carry it (spec 4.4.1.2 step 2 resolves
    /// it through the address map).
    pub fn get_nonce(&self, source: Eui64) -> [u8; 13] {
        let mut nonce = [0; 13];
        nonce[..8].copy_from_slice(&source.to_bytes());
        nonce[8..12].copy_from_slice(&self.frame_counter.to_le_bytes());
        nonce[12..13].copy_from_slice(&self.security_control.to_bytes());

        nonce
    }
}

/// CCM*-protect an APS frame payload (spec 4.4.1.1): the cleartext APS header and
/// auxiliary header are authenticated, the payload is encrypted, and the encrypted MIC
/// is appended. The security level is fixed network-wide and transmitted as 0 in the
/// auxiliary header, so the real level is patched in for the computation.
fn encrypt_aps_payload(
    key: &Key,
    aux_header: &ApsAuxHeader,
    header: &[u8],
    plaintext: &[u8],
) -> FrameBytes {
    let modified_aux_header = aux_header.get_modified(NwkSecurityLevel::EncMic32);
    let source = aux_header
        .extended_source
        .expect("outgoing secured APS frames always carry an extended nonce");
    let nonce = modified_aux_header.get_nonce(source);

    let mut auth_data = header.to_vec();
    modified_aux_header.serialize_into(&mut auth_data);

    let buffer = FrameBytes::from_slice(plaintext).expect("plaintext is frame-bounded");
    encrypt_ccm(key, &nonce, &auth_data, buffer)
}

/// Reverse of [`encrypt_aps_payload`]: verify the MIC and return the decrypted payload.
/// `source` is the frame originator's EUI64, used for the CCM* nonce when the frame
/// carries no extended nonce.
fn decrypt_aps_payload(
    key: &Key,
    aux_header: &ApsAuxHeader,
    source: Eui64,
    header: &[u8],
    tagged_ciphertext: &[u8],
) -> Result<FrameBytes, ParseError> {
    let modified_aux_header = aux_header.get_modified(NwkSecurityLevel::EncMic32);
    let nonce = modified_aux_header.get_nonce(aux_header.extended_source.unwrap_or(source));

    let mut auth_data = header.to_vec();
    modified_aux_header.serialize_into(&mut auth_data);

    let buffer = FrameBytes::from_slice(tagged_ciphertext).expect("ciphertext is frame-bounded");
    Ok(decrypt_ccm(key, &nonce, &auth_data, buffer)?)
}

#[derive(Educe, Clone, PartialEq, Eq)]
#[educe(Debug)]
pub struct EncryptedApsCommandFrame {
    pub frame_control: ApsFrameControl,
    pub counter: u8,
    pub aux_header: ApsAuxHeader,
    #[educe(Debug(method(format_hex)))]
    pub ciphertext: FrameBytes,
}

impl EncryptedApsCommandFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 7 {
            return Err(ParseError::UnexpectedEnd {
                ty: "EncryptedApsCommandFrame",
            });
        }

        let frame_control = ApsFrameControl::from_abstract_bits(bytes)?;
        let counter = bytes[1];
        let (aux_header, remaining) = ApsAuxHeader::deserialize(&bytes[2..])?;

        Ok(Self {
            frame_control,
            counter,
            aux_header,
            ciphertext: FrameBytes::from_slice(remaining)
                .map_err(|_| ParseError::TooLong { ty: "ciphertext" })?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        extend_abstract_bits(&mut bytes, &self.frame_control);
        bytes.push(self.counter);
        self.aux_header.serialize_into(&mut bytes);
        bytes.extend_from_slice(&self.ciphertext);

        bytes
    }

    pub fn decrypt(&self, key: &Key) -> Result<ApsCommandFrame, ParseError> {
        // Spec 4.4.1.1 step 4a: APS commands always carry an extended nonce
        let source = self
            .aux_header
            .extended_source
            .ok_or(ParseError::Unsupported(
                "APS command frames without an extended nonce",
            ))?;

        let mut header = Vec::new();
        extend_abstract_bits(&mut header, &self.frame_control);
        header.push(self.counter);

        let plaintext =
            decrypt_aps_payload(key, &self.aux_header, source, &header, &self.ciphertext)?;

        let mut frame_bytes = header;
        frame_bytes.extend(plaintext);

        ApsCommandFrame::from_bytes(&frame_bytes)
    }
}

/// An APS-secured data frame (spec 4.4.1.1): the APS header is cleartext, the ASDU is
/// encrypted.
#[derive(Educe, Clone, PartialEq, Eq)]
#[educe(Debug)]
pub struct EncryptedApsDataFrame {
    /// The cleartext APS header fields; its `asdu` is empty
    pub header: ApsDataFrame,
    pub aux_header: ApsAuxHeader,
    #[educe(Debug(method(format_hex)))]
    pub ciphertext: FrameBytes,
}

impl ApsDataFrame {
    pub fn encrypt(&self, key: &Key, aux_header: &ApsAuxHeader) -> EncryptedApsDataFrame {
        let header = Self {
            asdu: FrameBytes::new(),
            ..self.clone()
        };
        let ciphertext = encrypt_aps_payload(key, aux_header, &header.to_bytes(), &self.asdu);

        EncryptedApsDataFrame {
            header,
            aux_header: aux_header.clone(),
            ciphertext,
        }
    }
}

impl EncryptedApsDataFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut header = ApsDataFrame::from_bytes(bytes)?;
        let (aux_header, remaining) = ApsAuxHeader::deserialize(&header.asdu)?;
        let ciphertext = FrameBytes::from_slice(remaining)
            .map_err(|_| ParseError::TooLong { ty: "ciphertext" })?;
        header.asdu = FrameBytes::new();

        Ok(Self {
            header,
            aux_header,
            ciphertext,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        self.aux_header.serialize_into(&mut bytes);
        bytes.extend_from_slice(&self.ciphertext);

        bytes
    }

    /// `source` is the frame originator's EUI64, used for the CCM* nonce when the frame
    /// carries no extended nonce.
    pub fn decrypt(&self, key: &Key, source: Eui64) -> Result<ApsDataFrame, ParseError> {
        let asdu = decrypt_aps_payload(
            key,
            &self.aux_header,
            source,
            &self.header.to_bytes(),
            &self.ciphertext,
        )?;

        Ok(ApsDataFrame {
            asdu,
            ..self.header.clone()
        })
    }
}

/// An APS-secured acknowledgement frame. ACKs carry no payload, so the ciphertext is
/// just the encrypted MIC authenticating the headers.
#[derive(Educe, Clone, PartialEq, Eq)]
#[educe(Debug)]
pub struct EncryptedApsAckFrame {
    pub header: ApsAckFrame,
    pub aux_header: ApsAuxHeader,
    #[educe(Debug(method(format_hex)))]
    pub ciphertext: FrameBytes,
}

impl ApsAckFrame {
    pub fn encrypt(&self, key: &Key, aux_header: &ApsAuxHeader) -> EncryptedApsAckFrame {
        let ciphertext = encrypt_aps_payload(key, aux_header, &self.to_bytes(), &[]);

        EncryptedApsAckFrame {
            header: self.clone(),
            aux_header: aux_header.clone(),
            ciphertext,
        }
    }
}

impl EncryptedApsAckFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let header = ApsAckFrame::from_bytes(bytes)?;
        // `ApsAckFrame::from_bytes` ignores trailing bytes; the aux header starts
        // right after the fixed header fields, whose length only the ACK format
        // determines (see `ApsAckFrame::to_bytes`)
        let header_len = if header.frame_control.ack_format {
            2
        } else {
            8
        };
        let (aux_header, remaining) = ApsAuxHeader::deserialize(&bytes[header_len..])?;

        Ok(Self {
            header,
            aux_header,
            ciphertext: FrameBytes::from_slice(remaining)
                .map_err(|_| ParseError::TooLong { ty: "ciphertext" })?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        self.aux_header.serialize_into(&mut bytes);
        bytes.extend_from_slice(&self.ciphertext);

        bytes
    }

    /// `source` is the frame originator's EUI64, used for the CCM* nonce when the frame
    /// carries no extended nonce.
    pub fn decrypt(&self, key: &Key, source: Eui64) -> Result<ApsAckFrame, ParseError> {
        decrypt_aps_payload(
            key,
            &self.aux_header,
            source,
            &self.header.to_bytes(),
            &self.ciphertext,
        )?;

        Ok(self.header.clone())
    }
}

pub enum ApsFrame {
    Data(ApsDataFrame),
    EncryptedData(EncryptedApsDataFrame),
    Ack(ApsAckFrame),
    EncryptedAck(EncryptedApsAckFrame),
    Command(ApsCommandFrame),
    EncryptedCommand(EncryptedApsCommandFrame),
}

pub fn parse_aps_frame(bytes: &[u8]) -> Result<ApsFrame, ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::UnexpectedEnd { ty: "ApsFrame" });
    }

    let frame_type =
        ApsFrameType::try_from(bytes[0] & 0b11).map_err(|_| ParseError::InvalidDiscriminant {
            ty: "ApsFrameType",
            got: bytes[0] & 0b11,
        })?;
    let security = bytes[0] & 0b0010_0000 != 0;

    match (frame_type, security) {
        (ApsFrameType::Command, true) => Ok(ApsFrame::EncryptedCommand(
            EncryptedApsCommandFrame::from_bytes(bytes)?,
        )),
        (ApsFrameType::Command, false) => {
            Ok(ApsFrame::Command(ApsCommandFrame::from_bytes(bytes)?))
        }
        (ApsFrameType::Data, true) => Ok(ApsFrame::EncryptedData(
            EncryptedApsDataFrame::from_bytes(bytes)?,
        )),
        (ApsFrameType::Ack, true) => Ok(ApsFrame::EncryptedAck(EncryptedApsAckFrame::from_bytes(
            bytes,
        )?)),
        (ApsFrameType::Data, false) => Ok(ApsFrame::Data(ApsDataFrame::from_bytes(bytes)?)),
        (ApsFrameType::Ack, false) => Ok(ApsFrame::Ack(ApsAckFrame::from_bytes(bytes)?)),
        (ApsFrameType::Interpan, _) => Err(ParseError::Unsupported("Interpan")),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_aps_parsing_unicast() {
        let data = hex!("4001060004010103015a00");
        let aps_frame = ApsDataFrame::from_bytes(&data).unwrap();

        let expected_aps_frame = ApsDataFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Data,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved1: 0b0,
                security: false,
                ack_request: true,
                extended_header: false,
            },
            group_id: None,
            destination_endpoint: Some(1),
            cluster_id: 0x0006,
            profile_id: 0x0104,
            source_endpoint: 1,
            counter: 3,
            asdu: FrameBytes::from_slice(&hex!("01 5a 00")).unwrap(),
        };

        assert_eq!(aps_frame, expected_aps_frame);
        assert_eq!(aps_frame.to_bytes(), data.to_vec());
    }

    #[test]
    fn test_aps_parsing_broadcast() {
        let aps_frame =
            ApsDataFrame::from_bytes(&hex!("080013000000000000426b4fdeb726004b12008e")).unwrap();

        let expected_aps_frame = ApsDataFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Data,
                delivery_mode: ApsDeliveryMode::Broadcast,
                reserved1: 0b0,
                security: false,
                ack_request: false,
                extended_header: false,
            },
            group_id: None,
            destination_endpoint: Some(0),
            cluster_id: 0x0013,
            profile_id: 0x0000,
            source_endpoint: 0,
            counter: 0,
            asdu: FrameBytes::from_slice(&hex!("00426b4fdeb726004b12008e")).unwrap(),
        };

        assert_eq!(aps_frame, expected_aps_frame);
    }

    #[test]
    fn test_aps_parsing_acks() {
        let aps_frame = ApsAckFrame::from_bytes(&hex!("0201060004010100")).unwrap();

        let expected_aps_frame = ApsAckFrame {
            frame_control: ApsAckFrameControl {
                frame_type: ApsFrameType::Ack,
                delivery_mode: ApsDeliveryMode::Unicast,
                ack_format: false,
                security: false,
                ack_request: false,
                extended_header: false,
            },
            destination_endpoint: Some(1),
            cluster_id: Some(0x0006),
            profile_id: Some(0x0104),
            source_endpoint: Some(1),
            counter: 0,
        };

        assert_eq!(aps_frame, expected_aps_frame);
    }

    #[test]
    fn test_aps_command_encryption_round_trip() {
        use crate::crypto::key_transport_key;

        let command_frame = ApsCommandFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Command,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved1: 0b0,
                security: true,
                ack_request: false,
                extended_header: false,
            },
            counter: 5,
            command_id: ApsCommandId::TransportKey,
            command: ApsCommandFrameCommand::TransportKey(ApsTransportKeyCommandFrame {
                standard_key_type: ApsStandardKeyType::StandardNetworkKey,
                key_descriptor: ApsTransportKeyDescriptor::NetworkKey(ApsNetworkKeyDescriptor {
                    key: Key::from_hex("550000fffdfe00fa07fc09f233ea04f9"),
                    sequence_number: 85,
                    destination_address: Eui64::from_hex("bc:02:6e:ff:fe:49:4a:31"),
                    source_address: Eui64::from_hex("00:07:81:00:00:9a:8f:3b"),
                }),
            }),
        };

        let aux_header = ApsAuxHeader {
            security_control: NwkSecurityHeaderControlField {
                security_level: NwkSecurityLevel::NoSecurity,
                key_id: NwkSecurityHeaderKeyId::KeyTransportKey,
                extended_nonce: true,
                require_verified_frame_counter: false,
            },
            frame_counter: 42,
            extended_source: Some(Eui64::from_hex("00:07:81:00:00:9a:8f:3b")),
            key_sequence_number: None,
        };

        let key = key_transport_key(&Key::from_hex("5a6967426565416c6c69616e63653039"));
        let encrypted = command_frame.encrypt(&key, &aux_header);

        let reparsed = EncryptedApsCommandFrame::from_bytes(&encrypted.to_bytes()).unwrap();
        assert_eq!(reparsed, encrypted);

        let Ok(ApsFrame::EncryptedCommand(parsed)) = parse_aps_frame(&encrypted.to_bytes()) else {
            panic!("Expected an encrypted command frame");
        };
        assert_eq!(parsed, encrypted);

        let decrypted = reparsed.decrypt(&key).unwrap();
        assert_eq!(decrypted, command_frame);

        let wrong_key = Key::from_hex("00000000000000000000000000000000");
        assert!(reparsed.decrypt(&wrong_key).is_err());
    }

    fn test_aux_header(extended_source: Option<Eui64>) -> ApsAuxHeader {
        ApsAuxHeader {
            security_control: NwkSecurityHeaderControlField {
                security_level: NwkSecurityLevel::NoSecurity,
                key_id: NwkSecurityHeaderKeyId::DataKey,
                extended_nonce: extended_source.is_some(),
                require_verified_frame_counter: false,
            },
            frame_counter: 42,
            extended_source,
            key_sequence_number: None,
        }
    }

    #[test]
    fn test_aps_data_encryption_round_trip() {
        let source = Eui64::from_hex("00:07:81:00:00:9a:8f:3b");

        let data_frame = ApsDataFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Data,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved1: 0b0,
                security: true,
                ack_request: true,
                extended_header: false,
            },
            group_id: None,
            destination_endpoint: Some(1),
            cluster_id: 0x0101,
            profile_id: 0x0104,
            source_endpoint: 1,
            counter: 77,
            asdu: FrameBytes::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]).unwrap(),
        };

        let key = Key::from_hex("5a6967426565416c6c69616e63653039");
        let encrypted = data_frame.encrypt(&key, &test_aux_header(Some(source)));

        let Ok(ApsFrame::EncryptedData(parsed)) = parse_aps_frame(&encrypted.to_bytes()) else {
            panic!("Expected an encrypted data frame");
        };
        assert_eq!(parsed, encrypted);

        // The extended nonce makes the passed-in source irrelevant
        let other = Eui64::from_hex("ff:ff:ff:ff:ff:ff:ff:ff");
        let decrypted = parsed.decrypt(&key, other).unwrap();
        assert_eq!(decrypted, data_frame);

        let wrong_key = Key::from_hex("00000000000000000000000000000000");
        assert!(parsed.decrypt(&wrong_key, source).is_err());
    }

    #[test]
    fn test_aps_ack_encryption_round_trip() {
        let source = Eui64::from_hex("00:07:81:00:00:9a:8f:3b");

        let ack_frame = ApsAckFrame {
            frame_control: ApsAckFrameControl {
                frame_type: ApsFrameType::Ack,
                delivery_mode: ApsDeliveryMode::Unicast,
                ack_format: false,
                security: true,
                ack_request: false,
                extended_header: false,
            },
            destination_endpoint: Some(1),
            cluster_id: Some(0x0101),
            profile_id: Some(0x0104),
            source_endpoint: Some(1),
            counter: 77,
        };

        let key = Key::from_hex("5a6967426565416c6c69616e63653039");
        let encrypted = ack_frame.encrypt(&key, &test_aux_header(Some(source)));

        let Ok(ApsFrame::EncryptedAck(parsed)) = parse_aps_frame(&encrypted.to_bytes()) else {
            panic!("Expected an encrypted ACK frame");
        };
        assert_eq!(parsed, encrypted);

        let decrypted = parsed.decrypt(&key, source).unwrap();
        assert_eq!(decrypted, ack_frame);

        // The MIC covers the headers even though there is no payload
        let mut tampered = parsed;
        tampered.header.counter = 78;
        assert!(tampered.decrypt(&key, source).is_err());
    }

    #[test]
    fn test_aps_transport_key_plaintext_round_trip() {
        // The plaintext (decrypted) form of a Standard Network Key transport command
        let expected_aps_frame = ApsCommandFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Command,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved1: 0b0,
                security: false,
                ack_request: false,
                extended_header: false,
            },
            counter: 5,
            command_id: ApsCommandId::TransportKey,
            command: ApsCommandFrameCommand::TransportKey(ApsTransportKeyCommandFrame {
                standard_key_type: ApsStandardKeyType::StandardNetworkKey,
                key_descriptor: ApsTransportKeyDescriptor::NetworkKey(ApsNetworkKeyDescriptor {
                    key: Key::from_hex("550000fffdfe00fa07fc09f233ea04f9"),
                    sequence_number: 85,
                    destination_address: Eui64::from_hex("bc:02:6e:ff:fe:49:4a:31"),
                    source_address: Eui64::from_hex("00:07:81:00:00:9a:8f:3b"),
                }),
            }),
        };

        let bytes = expected_aps_frame.to_bytes();

        // The third byte is the APS command identifier: Transport Key is 0x05, not the
        // deprecated SKKE-4 (0x04) that an off-by-one would produce
        assert_eq!(bytes[2], 0x05);

        assert_eq!(
            ApsCommandFrame::from_bytes(&bytes).unwrap(),
            expected_aps_frame
        );
    }

    #[test]
    fn test_aps_tunnel_round_trip() {
        use crate::crypto::key_transport_key;

        let inner_frame = ApsCommandFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Command,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved1: 0b0,
                security: true,
                ack_request: false,
                extended_header: false,
            },
            counter: 12,
            command_id: ApsCommandId::TransportKey,
            command: ApsCommandFrameCommand::TransportKey(ApsTransportKeyCommandFrame {
                standard_key_type: ApsStandardKeyType::StandardNetworkKey,
                key_descriptor: ApsTransportKeyDescriptor::NetworkKey(ApsNetworkKeyDescriptor {
                    key: Key::from_hex("550000fffdfe00fa07fc09f233ea04f9"),
                    sequence_number: 85,
                    destination_address: Eui64::from_hex("bc:02:6e:ff:fe:49:4a:31"),
                    source_address: Eui64::from_hex("00:07:81:00:00:9a:8f:3b"),
                }),
            }),
        };

        let aux_header = ApsAuxHeader {
            security_control: NwkSecurityHeaderControlField {
                security_level: NwkSecurityLevel::NoSecurity,
                key_id: NwkSecurityHeaderKeyId::KeyTransportKey,
                extended_nonce: true,
                require_verified_frame_counter: false,
            },
            frame_counter: 9,
            extended_source: Some(Eui64::from_hex("00:07:81:00:00:9a:8f:3b")),
            key_sequence_number: None,
        };

        let key = key_transport_key(&Key::from_hex("5a6967426565416c6c69616e63653039"));
        let encrypted_inner = inner_frame.encrypt(&key, &aux_header);

        let tunnel_frame = ApsCommandFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Command,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved1: 0b0,
                security: false,
                ack_request: false,
                extended_header: false,
            },
            counter: 13,
            command_id: ApsCommandId::Tunnel,
            command: ApsCommandFrameCommand::Tunnel(ApsTunnelCommandFrame {
                destination_address: Eui64::from_hex("bc:02:6e:ff:fe:49:4a:31"),
                tunneled_frame: FrameBytes::from_slice(&encrypted_inner.to_bytes()).unwrap(),
            }),
        };

        let Ok(ApsFrame::Command(reparsed)) = parse_aps_frame(&tunnel_frame.to_bytes()) else {
            panic!("Expected a plaintext command frame");
        };
        assert_eq!(reparsed, tunnel_frame);

        // The tunneled payload is a complete encrypted APS frame that the joiner parses
        let ApsCommandFrameCommand::Tunnel(reparsed_tunnel) = &reparsed.command else {
            panic!("Expected a tunnel command");
        };
        let reparsed_inner =
            EncryptedApsCommandFrame::from_bytes(&reparsed_tunnel.tunneled_frame).unwrap();
        assert_eq!(reparsed_inner.decrypt(&key).unwrap(), inner_frame);
    }

    #[test]
    fn test_aps_confirm_key_encryption_round_trip() {
        // Confirm key commands are encrypted with the link key itself as the data key
        let link_key = Key::from_hex("0f234c0f234c0f234c0f234c0f234c0f");

        let confirm_frame = ApsCommandFrame {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Command,
                delivery_mode: ApsDeliveryMode::Unicast,
                reserved1: 0b0,
                security: true,
                ack_request: false,
                extended_header: false,
            },
            counter: 3,
            command_id: ApsCommandId::ConfirmKey,
            command: ApsCommandFrameCommand::ConfirmKey(ApsConfirmKeyCommandFrame {
                status: APS_STATUS_SUCCESS,
                standard_key_type: ApsStandardKeyType::TrustCenterLinkKey,
                destination_address: Eui64::from_hex("bc:02:6e:ff:fe:49:4a:31"),
            }),
        };

        let aux_header = ApsAuxHeader {
            security_control: NwkSecurityHeaderControlField {
                security_level: NwkSecurityLevel::NoSecurity,
                key_id: NwkSecurityHeaderKeyId::DataKey,
                extended_nonce: true,
                require_verified_frame_counter: false,
            },
            frame_counter: 77,
            extended_source: Some(Eui64::from_hex("00:07:81:00:00:9a:8f:3b")),
            key_sequence_number: None,
        };

        let encrypted = confirm_frame.encrypt(&link_key, &aux_header);
        let Ok(ApsFrame::EncryptedCommand(reparsed)) = parse_aps_frame(&encrypted.to_bytes())
        else {
            panic!("Expected an encrypted command frame");
        };
        assert_eq!(reparsed.decrypt(&link_key).unwrap(), confirm_frame);
    }
}
