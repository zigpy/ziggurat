use std::collections::HashMap;

use constant_time_eq::constant_time_eq;
use ieee_802154::types::{Eui64, Key};

use crate::crypto::{key_load_key, key_transport_key, verify_key_hash};
use crate::zigbee_aps::{ApsAuxHeader, ApsCommandFrame, EncryptedApsCommandFrame};
use crate::zigbee_nwk::{NwkSecurityHeaderControlField, NwkSecurityHeaderKeyId, NwkSecurityLevel};

/// The `KeyAttributes` of an `apsDeviceKeyPairSet` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAttributes {
    /// Provisioned out of band before the device joined, e.g. derived from an
    /// install code; replaces the well-known key for that device's join.
    Provisional = 0x00,
    /// Issued to the device but not yet proven via a Verify-Key exchange
    Unverified = 0x01,
    Verified = 0x02,
}

/// A single entry of the `apsDeviceKeyPairSet`: a link key shared with one device.
///
/// Devices start out sharing the well-known global link key (which is not stored here)
/// and request a unique key after joining.
#[derive(Debug, Clone)]
pub struct DeviceLinkKey {
    pub key: Key,
    pub attributes: KeyAttributes,
}

/// The APS security layer: the spec's `apsDeviceKeyPairSet`, link-key derivation, and
/// APS command frame encryption/decryption.
///
/// IO-free by design: pure state and computation — no locks, no async, no radio — so
/// every key exchange is testable without hardware. Per-device APS data encryption and
/// R23 dynamic link keys will land here.
#[derive(Debug)]
pub struct ApsSecurity {
    /// The well-known key devices join with (usually "ZigBeeAlliance09")
    global_link_key: Key,
    local_eui64: Eui64,
    /// Unique trust center link keys negotiated with individual devices
    device_keys: HashMap<Eui64, DeviceLinkKey>,
    /// The outgoing security frame counter shared by all frames encrypted with keys
    /// derived from link keys
    outgoing_frame_counter: u32,
}

impl ApsSecurity {
    pub fn new(global_link_key: Key, local_eui64: Eui64) -> Self {
        Self {
            global_link_key,
            local_eui64,
            device_keys: HashMap::new(),
            outgoing_frame_counter: 0,
        }
    }

    /// Restore a key negotiated in an earlier session and persisted by the client.
    pub fn restore_device_key(&mut self, eui64: Eui64, key: Key) {
        self.device_keys.insert(
            eui64,
            DeviceLinkKey {
                key,
                attributes: KeyAttributes::Verified,
            },
        );
    }

    /// Register a link key provisioned out of band (derived from an install code)
    /// for a device expected to join: an `apsDeviceKeyPairSet` entry with
    /// `PROVISIONAL_KEY` attributes, replacing the well-known key for that device.
    pub fn set_provisional_key(&mut self, eui64: Eui64, key: Key) {
        self.device_keys.insert(
            eui64,
            DeviceLinkKey {
                key,
                attributes: KeyAttributes::Provisional,
            },
        );
    }

    /// A device is joining fresh. A provisional (install-code) entry is its
    /// pre-configured link key and survives the join, returned for the client to
    /// persist; any other key on record is stale, since a factory-new device only
    /// knows the well-known link key.
    pub fn begin_join(&mut self, eui64: Eui64) -> Option<Key> {
        match self.device_keys.get(&eui64) {
            Some(entry) if entry.attributes == KeyAttributes::Provisional => {
                Some(entry.key.clone())
            }
            Some(_) => {
                self.device_keys.remove(&eui64);
                None
            }
            None => None,
        }
    }

    pub fn has_device_key(&self, eui64: Eui64) -> bool {
        self.device_keys.contains_key(&eui64)
    }

    pub fn device_key_count(&self) -> usize {
        self.device_keys.len()
    }

    /// Issue a fresh unique link key for a device, replacing any previous one. The key
    /// is unverified until the device proves possession via a Verify-Key exchange.
    pub fn issue_device_key(&mut self, eui64: Eui64) -> Key {
        let key = Key(rand::random());

        self.device_keys.insert(
            eui64,
            DeviceLinkKey {
                key: key.clone(),
                attributes: KeyAttributes::Unverified,
            },
        );

        key
    }

    /// The link key currently shared with a device: its negotiated unique key, falling
    /// back to the well-known global key.
    pub fn device_link_key(&self, eui64: Eui64) -> Key {
        self.device_keys
            .get(&eui64)
            .map_or_else(|| self.global_link_key.clone(), |entry| entry.key.clone())
    }

    /// Zigbee spec 4.4.8.1: check a device's keyed hash proving possession of its link
    /// key, marking the key verified on success. `None` means no key is on record.
    pub fn verify_device_key(&mut self, eui64: Eui64, hash: &[u8; 16]) -> Option<bool> {
        let entry = self.device_keys.get_mut(&eui64)?;

        if constant_time_eq(&verify_key_hash(&entry.key), hash) {
            entry.attributes = KeyAttributes::Verified;
            Some(true)
        } else {
            Some(false)
        }
    }

    /// Security frame counters must never wrap: that would reuse a CCM* nonce.
    const fn next_outgoing_frame_counter(&mut self) -> u32 {
        self.outgoing_frame_counter = self.outgoing_frame_counter.checked_add(1).unwrap();
        self.outgoing_frame_counter
    }

    /// The key a given key identifier selects, derived from a device link key.
    /// `NetworkKey` is NWK security material and is not derived from link keys.
    fn select_key(link_key: &Key, key_id: NwkSecurityHeaderKeyId) -> Option<Key> {
        match key_id {
            NwkSecurityHeaderKeyId::KeyTransportKey => Some(key_transport_key(link_key)),
            NwkSecurityHeaderKeyId::KeyLoadKey => Some(key_load_key(link_key)),
            NwkSecurityHeaderKeyId::DataKey => Some(link_key.clone()),
            NwkSecurityHeaderKeyId::NetworkKey => None,
        }
    }

    /// Encrypt an APS command for a device, with the key class selected by `key_id`
    /// derived from the device's current link key.
    pub fn encrypt_command(
        &mut self,
        destination: Eui64,
        key_id: NwkSecurityHeaderKeyId,
        command: &ApsCommandFrame,
    ) -> EncryptedApsCommandFrame {
        let link_key = self.device_link_key(destination);
        self.encrypt_command_with_link_key(&link_key, key_id, command)
    }

    /// Encrypt an APS command with an explicitly provided link key. Needed when the
    /// command must be protected with a key other than the device's current one, e.g.
    /// delivering a new link key encrypted with the key it replaces.
    pub fn encrypt_command_with_link_key(
        &mut self,
        link_key: &Key,
        key_id: NwkSecurityHeaderKeyId,
        command: &ApsCommandFrame,
    ) -> EncryptedApsCommandFrame {
        let key = Self::select_key(link_key, key_id)
            .expect("APS commands are encrypted with link key classes, not the network key");

        let aux_header = ApsAuxHeader {
            security_control: NwkSecurityHeaderControlField {
                // The real security level is fixed network-wide and transmitted as 0
                security_level: NwkSecurityLevel::NoSecurity,
                key_id,
                extended_nonce: true,
                require_verified_frame_counter: false,
            },
            frame_counter: self.next_outgoing_frame_counter(),
            extended_source: Some(self.local_eui64),
            key_sequence_number: None,
        };

        command.encrypt(&key, &aux_header)
    }

    /// Try to decrypt an APS command from a device. Devices encrypt with the well-known
    /// key until their key exchange completes, so retried frames may still use it even
    /// when a unique key is on record.
    pub fn decrypt_command(
        &self,
        source: Eui64,
        frame: &EncryptedApsCommandFrame,
        network_key: &Key,
    ) -> Option<ApsCommandFrame> {
        let key_id = frame.aux_header.security_control.key_id;

        if key_id == NwkSecurityHeaderKeyId::NetworkKey {
            return frame.decrypt(network_key).ok();
        }

        let mut candidate_keys = vec![self.device_link_key(source)];
        if candidate_keys[0] != self.global_link_key {
            candidate_keys.push(self.global_link_key.clone());
        }

        for link_key in &candidate_keys {
            let key = Self::select_key(link_key, key_id).expect("NetworkKey is handled above");

            if let Ok(command_frame) = frame.decrypt(&key) {
                return Some(command_frame);
            }
        }

        None
    }
}
