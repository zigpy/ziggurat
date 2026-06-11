use std::collections::HashMap;
use std::sync::LazyLock;

use aes::Aes128;
use aes::Block;
use aes::cipher::BlockCipherEncrypt;
use aes::cipher::KeyInit;
use ccm::Ccm;
use ccm::aead::AeadInOut;
use ccm::consts::{U4, U13};
use parking_lot::Mutex;
use thiserror::Error;

use ieee_802154::types::{Eui64, Key};

/// AES-MMO (Matyas-Meyer-Oseas) cryptographic hash, Zigbee spec B.1.3/B.4. Only the
/// short-message padding scheme is implemented (inputs below 2^16 bits).
pub fn aes_mmo_hash(data: &[u8]) -> [u8; 16] {
    assert!(data.len() < 8192);

    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 16 != 14 {
        padded.push(0x00);
    }
    padded.extend(((data.len() * 8) as u16).to_be_bytes());

    let mut digest = [0u8; 16];

    for chunk in padded.chunks_exact(16) {
        let cipher = Aes128::new(&digest.into());
        let block = Block::try_from(chunk).expect("16-byte chunk is always valid");

        let mut encrypted = Block::default();
        cipher.encrypt_block_b2b(&block, &mut encrypted);

        for (digest_byte, (encrypted_byte, block_byte)) in
            digest.iter_mut().zip(encrypted.iter().zip(block.iter()))
        {
            *digest_byte = encrypted_byte ^ block_byte;
        }
    }

    digest
}

/// HMAC (FIPS Pub 198) instantiated with the AES-MMO hash, Zigbee spec B.1.4.
pub fn keyed_hash(key: &Key, input: &[u8]) -> [u8; 16] {
    let mut inner = Vec::with_capacity(16 + input.len());
    inner.extend(key.0.iter().map(|b| b ^ 0x36));
    inner.extend(input);

    let mut outer = Vec::with_capacity(32);
    outer.extend(key.0.iter().map(|b| b ^ 0x5C));
    outer.extend(aes_mmo_hash(&inner));

    aes_mmo_hash(&outer)
}

/// Zigbee spec 4.5.3: 1-octet input strings fed to the keyed hash to derive values from
/// a link key.
const KEY_TRANSPORT_KEY_HASH_INPUT: u8 = 0x00;
const KEY_LOAD_KEY_HASH_INPUT: u8 = 0x02;
const VERIFY_KEY_HASH_INPUT: u8 = 0x03;

/// Zigbee spec 4.5.3: the key used to protect transported network keys.
pub fn key_transport_key(link_key: &Key) -> Key {
    Key(keyed_hash(link_key, &[KEY_TRANSPORT_KEY_HASH_INPUT]))
}

/// Zigbee spec 4.5.3: the key used to protect transported link keys.
pub fn key_load_key(link_key: &Key) -> Key {
    Key(keyed_hash(link_key, &[KEY_LOAD_KEY_HASH_INPUT]))
}

/// Zigbee spec 4.4.11.7: the hash sent in a Verify-Key command to prove possession of a
/// link key without revealing it.
pub fn verify_key_hash(link_key: &Key) -> [u8; 16] {
    keyed_hash(link_key, &[VERIFY_KEY_HASH_INPUT])
}

/// Z-Stack derives unique trust center link keys from a 16-byte "TCLK seed" instead of
/// storing them: the seed, rotated left by a per-device shift, is XORed with the
/// device's EUI64 repeated twice.
///
/// The shift only becomes nonzero when a device's key is updated, which nothing does
/// in practice, so keys are issued with a shift of 0.
pub fn zstack_tclk(seed: &Key, eui64: Eui64, shift: usize) -> Key {
    let eui64 = eui64.to_bytes();
    Key(std::array::from_fn(|i| {
        seed.0[(i + shift) % 16] ^ eui64[i % 8]
    }))
}

/// EmberZNet's "hashed link key": unique trust center link keys are the keyed hash of
/// the device's EUI64 under a seed, so any device's key can be recomputed on demand.
pub fn ezsp_tclk(seed: &Key, eui64: Eui64) -> Key {
    Key(keyed_hash(seed, &eui64.to_bytes()))
}

/// Zigbee CCM* at security level 5 (spec annex A): AES-128 CCM with a 4-byte MIC and
/// a 13-byte nonce. CCM* only differs from standard CCM at the unencrypted security
/// levels, which are never used on the air.
type ZigbeeCcm = Ccm<Aes128, U4, U13>;

pub const MIC_LENGTH: usize = 4;

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("Invalid MAC tag")]
    InvalidMacTag,
    #[error("Ciphertext too short to contain a MAC tag")]
    CiphertextTooShort,
}

impl From<DecryptionError> for &'static str {
    fn from(err: DecryptionError) -> Self {
        match err {
            DecryptionError::InvalidMacTag => "Invalid MAC tag",
            DecryptionError::CiphertextTooShort => "Ciphertext too short to contain a MAC tag",
        }
    }
}

/// The AES key schedule costs more than encrypting an entire typical frame, so cipher
/// instances are cached: there are only ever a handful of keys (the network key plus
/// a link key per device) and they live for the lifetime of the process.
static CIPHER_CACHE: LazyLock<Mutex<HashMap<[u8; 16], ZigbeeCcm>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn cipher_for(key: &Key) -> ZigbeeCcm {
    CIPHER_CACHE
        .lock()
        .entry(key.0)
        .or_insert_with(|| ZigbeeCcm::new(&key.0.into()))
        .clone()
}

/// CCM*-protect a payload: `auth_data` is authenticated, `plaintext` is encrypted, and
/// the encrypted MIC ("MAC tag") is appended.
pub fn encrypt_ccm(key: &Key, nonce: &[u8; 13], auth_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(plaintext.len() + MIC_LENGTH);
    buffer.extend_from_slice(plaintext);
    let mic = cipher_for(key)
        .encrypt_inout_detached(&(*nonce).into(), auth_data, buffer.as_mut_slice().into())
        .expect("frames are far below the CCM length limits");
    buffer.extend_from_slice(&mic);
    buffer
}

/// Reverse of [`encrypt_ccm`]: verify the MIC and return the decrypted payload.
pub fn decrypt_ccm(
    key: &Key,
    nonce: &[u8; 13],
    auth_data: &[u8],
    tagged_ciphertext: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    let ciphertext_len = tagged_ciphertext
        .len()
        .checked_sub(MIC_LENGTH)
        .ok_or(DecryptionError::CiphertextTooShort)?;
    let (ciphertext, mic) = tagged_ciphertext.split_at(ciphertext_len);

    let mut buffer = ciphertext.to_vec();
    cipher_for(key)
        .decrypt_inout_detached(
            &(*nonce).into(),
            auth_data,
            buffer.as_mut_slice().into(),
            mic.try_into().expect("the MIC is exactly MIC_LENGTH bytes"),
        )
        .map_err(|_| DecryptionError::InvalidMacTag)?;

    Ok(buffer)
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    /// Zigbee spec C.5.1
    #[test]
    fn test_aes_mmo_hash_single_octet() {
        assert_eq!(
            aes_mmo_hash(&hex!("C0")),
            hex!("AE3A102A28D43EE0D4A09E22788B206C")
        );
    }

    /// Zigbee spec C.5.2, also Table 4-44 (hash of the Trust Center link key)
    #[test]
    fn test_aes_mmo_hash_full_block() {
        assert_eq!(
            aes_mmo_hash(&hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")),
            hex!("A7977E88BC0B61E8210827109A228F2D")
        );
    }

    /// Zigbee spec C.6.1
    #[test]
    fn test_keyed_hash() {
        assert_eq!(
            keyed_hash(
                &Key::from_hex("404142434445464748494A4B4C4D4E4F"),
                &hex!("C0")
            ),
            hex!("4512807BF94CB3400F0E2C25FB76E999")
        );
    }

    /// Cross-validated against zigpy-znp's `compute_key`
    #[test]
    fn test_zstack_tclk() {
        let seed = Key::from_hex("0011223344556677889900AABBCCDDEE");
        let eui64 = Eui64::from_hex("00124b001cdd5b88");

        assert_eq!(
            zstack_tclk(&seed, eui64, 0),
            Key::from_hex("884aff2f441e747700c2ddb6bb87cfee")
        );
    }

    /// Cross-validated against zigpy's `aes_mmo_hash`
    #[test]
    fn test_ezsp_tclk() {
        let eui64 = Eui64::from_hex("00124b001cdd5b88");

        assert_eq!(
            ezsp_tclk(&Key::from_hex("0011223344556677889900AABBCCDDEE"), eui64),
            Key::from_hex("7b5f66c194034b877607ba312627634b")
        );
        assert_eq!(
            ezsp_tclk(&Key::from_hex("5a6967426565416c6c69616e63653039"), eui64),
            Key::from_hex("35373a9861b18802c2aef128330a92bb")
        );
    }
}
