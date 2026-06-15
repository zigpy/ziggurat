use std::collections::HashMap;

use ieee_802154::types::{Eui64, Key};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::aps::frame::{
    ApsAckFrame, ApsAuxHeader, ApsCommandFrame, ApsDataFrame, EncryptedApsAckFrame,
    EncryptedApsCommandFrame, EncryptedApsDataFrame,
};
use crate::crypto::{ezsp_tclk, key_load_key, key_transport_key, verify_key_hash, zstack_tclk};
use crate::nwk::frame::{NwkSecurityHeaderControlField, NwkSecurityHeaderKeyId, NwkSecurityLevel};

/// Which stack's seed-to-key transformation a TCLK seed uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TclkFlavor {
    ZStack,
    Ezsp,
}

/// A trust center link key "seed" carried over from a microcontroller stack.
///
/// Both Z-Stack and EmberZNet derive unique link keys from a single seed plus the
/// device's EUI64 instead of storing random per-device keys, each with its own
/// transformation. Issuing keys from the same seed keeps the network migratable back
/// to the original stack.
#[derive(Debug, Clone)]
pub struct TclkSeed {
    pub seed: Key,
    pub flavor: TclkFlavor,
}

impl TclkSeed {
    /// The key this seed issues to a device.
    pub fn derive(&self, eui64: Eui64) -> Key {
        match self.flavor {
            TclkFlavor::ZStack => zstack_tclk(&self.seed, eui64, 0),
            TclkFlavor::Ezsp => ezsp_tclk(&self.seed, eui64),
        }
    }
}

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

/// What we track per peer device. The two have independent lifetimes (a seed-derived
/// device has a counter but no stored key, and reissuing a key
/// (`issue_device_key`) must not reset the counter) so each field is independently
/// optional. An entry with both fields empty is pruned.
#[derive(Debug, Default)]
struct DeviceState {
    /// The unique trust center link key negotiated with this device, if any. Absent
    /// when the device still uses the well-known key or a seed-derived one.
    key: Option<DeviceLinkKey>,
    /// Incoming security frame counter, spec 4.4.1.2 steps 4 and 9: a frame secured
    /// with a unique link key must carry a counter no smaller than this stored value,
    /// which is one past the last accepted counter. Kept in memory only: losing it
    /// across a restart merely suspends replay protection until the next valid frame.
    incoming_frame_counter: Option<u32>,
}

/// The APS security layer: the spec's `apsDeviceKeyPairSet`, link-key derivation, and
/// APS frame encryption/decryption (commands, data, and ACKs).
#[derive(Debug)]
pub struct ApsSecurity {
    /// The well-known key devices join with (usually "ZigBeeAlliance09")
    global_link_key: Key,
    local_eui64: Eui64,
    /// Per-device link keys and replay counters, keyed by peer EUI64
    devices: HashMap<Eui64, DeviceState>,
    /// When set, unique link keys are derived from this seed instead of generated
    /// randomly, mirroring the stack the network was taken over from
    tclk_seed: Option<TclkSeed>,
    /// The outgoing security frame counter shared by all frames encrypted with keys
    /// derived from link keys
    outgoing_frame_counter: u32,
}

impl ApsSecurity {
    pub fn new(global_link_key: Key, local_eui64: Eui64, tclk_seed: Option<TclkSeed>) -> Self {
        Self {
            global_link_key,
            local_eui64,
            devices: HashMap::new(),
            tclk_seed,
            outgoing_frame_counter: 0,
        }
    }

    /// Drop an entry that no longer holds either a key or a replay counter.
    fn prune_if_empty(&mut self, eui64: Eui64) {
        if let Some(entry) = self.devices.get(&eui64)
            && entry.key.is_none()
            && entry.incoming_frame_counter.is_none()
        {
            self.devices.remove(&eui64);
        }
    }

    /// Restore a key negotiated in an earlier session and persisted by the client.
    pub fn restore_device_key(&mut self, eui64: Eui64, key: Key) {
        self.devices.entry(eui64).or_default().key = Some(DeviceLinkKey {
            key,
            attributes: KeyAttributes::Verified,
        });
    }

    /// Register a link key provisioned out of band (derived from an install code)
    /// for a device expected to join: an `apsDeviceKeyPairSet` entry with
    /// `PROVISIONAL_KEY` attributes, replacing the well-known key for that device.
    pub fn set_provisional_key(&mut self, eui64: Eui64, key: Key) {
        self.devices.entry(eui64).or_default().key = Some(DeviceLinkKey {
            key,
            attributes: KeyAttributes::Provisional,
        });
    }

    /// A device is joining fresh. A provisional (install-code) entry is its
    /// pre-configured link key and survives the join, returned for the client to
    /// persist; any other key on record is stale, since a factory-new device only
    /// knows the well-known link key.
    pub fn begin_join(&mut self, eui64: Eui64) -> Option<Key> {
        let entry = self.devices.get_mut(&eui64)?;
        match &entry.key {
            Some(link_key) if link_key.attributes == KeyAttributes::Provisional => {
                Some(link_key.key.clone())
            }
            Some(_) => {
                entry.key = None;
                self.prune_if_empty(eui64);
                None
            }
            None => None,
        }
    }

    /// Whether a device shares a key with us other than the well-known one. With a
    /// TCLK seed configured every device implicitly does.
    pub fn has_unique_link_key(&self, eui64: Eui64) -> bool {
        self.devices.get(&eui64).is_some_and(|e| e.key.is_some()) || self.tclk_seed.is_some()
    }

    pub fn device_key_count(&self) -> usize {
        self.devices.values().filter(|e| e.key.is_some()).count()
    }

    /// The unique trust center link keys on record, for the client to persist.
    pub fn device_keys(&self) -> impl Iterator<Item = (Eui64, &DeviceLinkKey)> {
        self.devices
            .iter()
            .filter_map(|(eui64, entry)| entry.key.as_ref().map(|key| (*eui64, key)))
    }

    /// Issue a fresh unique link key for a device, replacing any previous one. The key
    /// is unverified until the device proves possession via a Verify-Key exchange.
    /// `fresh_key` is caller-generated randomness, used only when no TCLK seed is
    /// configured.
    pub fn issue_device_key(&mut self, eui64: Eui64, fresh_key: Key) -> Key {
        let key = self
            .tclk_seed
            .as_ref()
            .map_or(fresh_key, |seed| seed.derive(eui64));

        self.devices.entry(eui64).or_default().key = Some(DeviceLinkKey {
            key: key.clone(),
            attributes: KeyAttributes::Unverified,
        });

        key
    }

    /// The link key currently shared with an on-network device: its negotiated unique
    /// key, the key a configured TCLK seed issued to it (possibly before we took over
    /// the network — devices keep using their seed-derived keys across a trust center
    /// swap without ever rejoining), or the well-known global key.
    ///
    /// Only joining devices share the well-known key: fresh joins use
    /// [`Self::join_link_key`] instead.
    pub fn device_link_key(&self, eui64: Eui64) -> Key {
        if let Some(link_key) = self.devices.get(&eui64).and_then(|e| e.key.as_ref()) {
            return link_key.key.clone();
        }

        if let Some(seed) = &self.tclk_seed {
            return seed.derive(eui64);
        }

        self.global_link_key.clone()
    }

    /// The key a factory-new joiner shares with us before any key exchange: its
    /// provisional install-code key if one was registered, otherwise the well-known
    /// key. A joiner never holds a seed-derived key yet.
    pub fn join_link_key(&self, eui64: Eui64) -> Key {
        self.devices
            .get(&eui64)
            .and_then(|e| e.key.as_ref())
            .map_or_else(
                || self.global_link_key.clone(),
                |link_key| link_key.key.clone(),
            )
    }

    /// Zigbee spec 4.4.8.1: check a device's keyed hash proving possession of its link
    /// key, marking the key verified on success. `None` means no key is on record.
    pub fn verify_device_key(&mut self, eui64: Eui64, hash: &[u8; 16]) -> Option<bool> {
        let entry = self.devices.get_mut(&eui64)?.key.as_mut()?;

        if verify_key_hash(&entry.key).ct_eq(hash).into() {
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
        let aux_header = self.next_aux_header(key_id);

        command.encrypt(&key, &aux_header)
    }

    /// The key allowed to APS-encrypt outgoing data frames and ACKs for a device.
    /// Spec 4.4.1.1 step 1a: only provisional or verified `apsDeviceKeyPairSet`
    /// entries may encrypt; a key issued to a device but not yet verified may not.
    fn data_link_key(&self, eui64: Eui64) -> Option<Key> {
        match self.devices.get(&eui64).and_then(|e| e.key.as_ref()) {
            Some(entry) if entry.attributes == KeyAttributes::Unverified => None,
            Some(entry) => Some(entry.key.clone()),
            None => Some(
                self.tclk_seed
                    .as_ref()
                    .map_or_else(|| self.global_link_key.clone(), |seed| seed.derive(eui64)),
            ),
        }
    }

    /// APS-encrypt a data frame for a device with its current link key (key identifier
    /// `DataKey`, spec 4.4.1.1 step 1a). `None` when the device's key may not be used
    /// for encryption yet.
    pub fn encrypt_data(
        &mut self,
        destination: Eui64,
        frame: &ApsDataFrame,
    ) -> Option<EncryptedApsDataFrame> {
        let key = self.data_link_key(destination)?;
        let aux_header = self.next_aux_header(NwkSecurityHeaderKeyId::DataKey);

        Some(frame.encrypt(&key, &aux_header))
    }

    /// APS-encrypt an acknowledgement; ACKs mirror the security of the frame they
    /// acknowledge. `None` when the device's key may not be used for encryption yet.
    pub fn encrypt_ack(
        &mut self,
        destination: Eui64,
        ack: &ApsAckFrame,
    ) -> Option<EncryptedApsAckFrame> {
        let key = self.data_link_key(destination)?;
        let aux_header = self.next_aux_header(NwkSecurityHeaderKeyId::DataKey);

        Some(ack.encrypt(&key, &aux_header))
    }

    /// The auxiliary header for the next outgoing link-key-secured frame.
    const fn next_aux_header(&mut self, key_id: NwkSecurityHeaderKeyId) -> ApsAuxHeader {
        ApsAuxHeader {
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
        }
    }

    /// Try the keys an inbound APS frame from a device may be secured with: the network
    /// key when the auxiliary header says so, otherwise the `key_id` derivative of the
    /// device's link key, falling back to the well-known key (devices encrypt with the
    /// well-known key until their key exchange completes, so retried frames may still
    /// use it even when a unique key is on record). Frames secured with a unique link
    /// key are checked against the incoming frame counter to reject replays.
    fn decrypt_frame<T>(
        &mut self,
        source: Eui64,
        aux_header: &ApsAuxHeader,
        network_key: &Key,
        decrypt: impl Fn(&Key) -> Option<T>,
    ) -> Option<T> {
        // Spec 4.4.1.2 step 1: the maximum frame counter value is never valid
        if aux_header.frame_counter == u32::MAX {
            return None;
        }

        let key_id = aux_header.security_control.key_id;

        if key_id == NwkSecurityHeaderKeyId::NetworkKey {
            return decrypt(network_key);
        }

        let mut candidate_keys = vec![self.device_link_key(source)];
        if candidate_keys[0] != self.global_link_key {
            candidate_keys.push(self.global_link_key.clone());
        }

        let (link_key, frame) = candidate_keys.iter().find_map(|link_key| {
            let key = Self::select_key(link_key, key_id).expect("NetworkKey is handled above");
            decrypt(&key).map(|frame| (link_key, frame))
        })?;

        // Spec 4.4.1.2 steps 4 and 9: replay protection applies to unique link keys
        if *link_key != self.global_link_key {
            if let Some(minimum) = self
                .devices
                .get(&source)
                .and_then(|e| e.incoming_frame_counter)
                && aux_header.frame_counter < minimum
            {
                tracing::warn!(
                    "Rejecting replayed APS frame counter {} from {source:?}",
                    aux_header.frame_counter
                );
                return None;
            }

            self.devices
                .entry(source)
                .or_default()
                .incoming_frame_counter = Some(aux_header.frame_counter + 1);
        }

        Some(frame)
    }

    pub fn decrypt_command(
        &mut self,
        source: Eui64,
        frame: &EncryptedApsCommandFrame,
        network_key: &Key,
    ) -> Option<ApsCommandFrame> {
        self.decrypt_frame(source, &frame.aux_header, network_key, |key| {
            frame.decrypt(key).ok()
        })
    }

    pub fn decrypt_data(
        &mut self,
        source: Eui64,
        frame: &EncryptedApsDataFrame,
        network_key: &Key,
    ) -> Option<ApsDataFrame> {
        self.decrypt_frame(source, &frame.aux_header, network_key, |key| {
            frame.decrypt(key, source).ok()
        })
    }

    pub fn decrypt_ack(
        &mut self,
        source: Eui64,
        frame: &EncryptedApsAckFrame,
        network_key: &Key,
    ) -> Option<ApsAckFrame> {
        self.decrypt_frame(source, &frame.aux_header, network_key, |key| {
            frame.decrypt(key, source).ok()
        })
    }
}
