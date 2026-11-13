use aes::Aes128;
use aes::cipher::array::Array;
use aes::cipher::consts::{U1, U16};
use aes::cipher::{
    Block, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut,
    KeyInit, KeySizeUser, ParBlocksSizeUser,
};
use alloc::boxed::Box;
use ccm::Ccm;
use ccm::aead::AeadInOut;
use ccm::consts::{U4, U13};
use once_cell::race::OnceBox;
use thiserror::Error;

use ziggurat_ieee_802154::types::{Eui64, Key};

static SOFTWARE_BACKEND: SoftwareBackend = SoftwareBackend;

/// The installed backend, or unset for the software default.
static BACKEND: OnceBox<&'static dyn CryptoBackend> = OnceBox::new();

/// Install the platform crypto backend. Call once during startup, before any frames are
/// processed. The host leaves this unset and runs everything in software.
pub fn install(backend: &'static dyn CryptoBackend) {
    let _ = BACKEND.set(Box::new(backend));
}

fn backend() -> &'static dyn CryptoBackend {
    BACKEND.get().copied().unwrap_or(&SOFTWARE_BACKEND)
}

/// A complete platform crypto backend. The host and tests use [`SoftwareBackend`]; MCU
/// targets [`install`] one backed by their hardware.
///
/// Implementors must provide the AES-128 block primitive. CCM* defaults to a software
/// implementation built on that block, so a backend whose accelerator offers only block
/// modes (like the ESP32-C6, whose AES accelerator has no CCM mode) gets hardware-backed
/// CCM* for free; an SoC with a dedicated CCM* engine overrides the two methods.
pub trait CryptoBackend: Sync {
    /// AES-128 ECB, one block, encrypted in place.
    fn aes128_encrypt_block(&self, key: &[u8; 16], block: &mut [u8; 16]);

    /// CCM*-protect a payload in place: `auth_data` is authenticated, `payload` is
    /// encrypted, and the encrypted MIC ("MAC tag") is returned.
    fn encrypt_ccm(
        &self,
        key: &Key,
        nonce: &[u8; 13],
        auth_data: &[u8],
        payload: &mut [u8],
    ) -> [u8; MIC_LENGTH] {
        software_encrypt_ccm(key, nonce, auth_data, payload)
    }

    /// Reverse of [`encrypt_ccm`](CryptoBackend::encrypt_ccm): verify `mic` and decrypt
    /// `payload` in place.
    fn decrypt_ccm(
        &self,
        key: &Key,
        nonce: &[u8; 13],
        auth_data: &[u8],
        payload: &mut [u8],
        mic: &[u8; MIC_LENGTH],
    ) -> Result<(), DecryptionError> {
        software_decrypt_ccm(key, nonce, auth_data, payload, mic)
    }
}

/// Pure-software backend (RustCrypto `aes`/`ccm`), used until an MCU installs its own.
pub struct SoftwareBackend;

impl CryptoBackend for SoftwareBackend {
    fn aes128_encrypt_block(&self, key: &[u8; 16], block: &mut [u8; 16]) {
        let cipher = Aes128::new(&(*key).into());
        let mut buffer: Array<u8, U16> = (*block).into();
        cipher.encrypt_block(&mut buffer);
        *block = buffer.into();
    }
}

/// A RustCrypto block cipher that delegates each AES-128 block to the installed
/// [`CryptoBackend`], so the software `ccm` implementation transparently uses hardware
/// AES when a backend is installed.
#[derive(Clone)]
struct BackendAes {
    key: [u8; 16],
}

impl KeySizeUser for BackendAes {
    type KeySize = U16;
}

impl KeyInit for BackendAes {
    fn new(key: &aes::cipher::Key<Self>) -> Self {
        Self { key: (*key).into() }
    }
}

impl BlockSizeUser for BackendAes {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for BackendAes {
    type ParBlocksSize = U1;
}

impl BlockCipherEncBackend for BackendAes {
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut buffer: [u8; 16] = (*block.get_in()).into();
        backend().aes128_encrypt_block(&self.key, &mut buffer);
        *block.get_out() = buffer.into();
    }
}

impl BlockCipherEncrypt for BackendAes {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }
}

/// AES-MMO (Matyas-Meyer-Oseas) cryptographic hash, Zigbee spec B.1.3/B.4. Only the
/// short-message padding scheme is implemented (inputs below 2^16 bits).
pub fn aes_mmo_hash(data: &[u8]) -> [u8; 16] {
    aes_mmo_hash_parts(&[data])
}

/// [`aes_mmo_hash`] of the concatenation of `parts`, hashed block by block as it is
/// read.
fn aes_mmo_hash_parts(parts: &[&[u8]]) -> [u8; 16] {
    let len: usize = parts.iter().map(|part| part.len()).sum();
    assert!(len < 8192);

    // The message, a 1 bit, zeros up to 14 bytes past a block boundary, then the
    // message length in bits
    let zeros = (14 + 16 - (len + 1) % 16) % 16;
    let padded = parts
        .iter()
        .flat_map(|part| part.iter().copied())
        .chain([0x80])
        .chain(core::iter::repeat_n(0x00, zeros))
        .chain(((len * 8) as u16).to_be_bytes());

    let backend = backend();
    let mut digest = [0u8; 16];
    let mut block = [0u8; 16];

    for (index, byte) in padded.enumerate() {
        block[index % 16] = byte;
        if index % 16 != 15 {
            continue;
        }

        // MMO: encrypt the message block under the running digest as the key, then XOR the
        // ciphertext with the plaintext block.
        let mut encrypted = block;
        backend.aes128_encrypt_block(&digest, &mut encrypted);

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
    let inner_pad = key.0.map(|b| b ^ 0x36);
    let outer_pad = key.0.map(|b| b ^ 0x5C);

    let inner = aes_mmo_hash_parts(&[&inner_pad, input]);
    aes_mmo_hash_parts(&[&outer_pad, &inner])
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
    Key(core::array::from_fn(|i| {
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
/// levels, which are never used on the air. The underlying AES blocks route through the
/// installed [`CryptoBackend`], so this picks up hardware AES automatically.
type ZigbeeCcm = Ccm<BackendAes, U4, U13>;

pub const MIC_LENGTH: usize = 4;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum DecryptionError {
    #[error("Invalid MAC tag")]
    InvalidMacTag,
    #[error("Ciphertext too short to contain a MAC tag")]
    CiphertextTooShort,
}

/// CCM*-protect a payload in place: `auth_data` is authenticated, `payload` is
/// encrypted, and the encrypted MIC ("MAC tag") is returned.
pub fn encrypt_ccm(
    key: &Key,
    nonce: &[u8; 13],
    auth_data: &[u8],
    payload: &mut [u8],
) -> [u8; MIC_LENGTH] {
    backend().encrypt_ccm(key, nonce, auth_data, payload)
}

fn software_encrypt_ccm(
    key: &Key,
    nonce: &[u8; 13],
    auth_data: &[u8],
    payload: &mut [u8],
) -> [u8; MIC_LENGTH] {
    ZigbeeCcm::new(&key.0.into())
        .encrypt_inout_detached(&(*nonce).into(), auth_data, payload.into())
        .expect("frames are far below the CCM length limits")
        .into()
}

/// Split a received ciphertext into the encrypted payload and the MIC that ends it.
pub fn split_mic(tagged_ciphertext: &[u8]) -> Result<(&[u8], &[u8; MIC_LENGTH]), DecryptionError> {
    let ciphertext_len = tagged_ciphertext
        .len()
        .checked_sub(MIC_LENGTH)
        .ok_or(DecryptionError::CiphertextTooShort)?;
    let (ciphertext, mic) = tagged_ciphertext.split_at(ciphertext_len);

    Ok((
        ciphertext,
        mic.try_into().expect("the MIC is exactly MIC_LENGTH bytes"),
    ))
}

/// Reverse of [`encrypt_ccm`]: verify `mic` and decrypt `payload` in place.
pub fn decrypt_ccm(
    key: &Key,
    nonce: &[u8; 13],
    auth_data: &[u8],
    payload: &mut [u8],
    mic: &[u8; MIC_LENGTH],
) -> Result<(), DecryptionError> {
    backend().decrypt_ccm(key, nonce, auth_data, payload, mic)
}

fn software_decrypt_ccm(
    key: &Key,
    nonce: &[u8; 13],
    auth_data: &[u8],
    payload: &mut [u8],
    mic: &[u8; MIC_LENGTH],
) -> Result<(), DecryptionError> {
    ZigbeeCcm::new(&key.0.into())
        .decrypt_inout_detached(&(*nonce).into(), auth_data, payload.into(), mic.into())
        .map_err(|_| DecryptionError::InvalidMacTag)
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

    /// CCM* round-trips through the backend-delegating block cipher and rejects tampering.
    #[test]
    fn test_ccm_round_trip() {
        let key = Key::from_hex("0011223344556677889900aabbccddee");
        let nonce = hex!("000102030405060708090a0b0c");
        let aad = hex!("aabbccdd");
        let plaintext = hex!("decafbad01020304");

        let mut ciphertext = [0u8; 12];
        ciphertext[..8].copy_from_slice(&plaintext);
        let mic = encrypt_ccm(&key, &nonce, &aad, &mut ciphertext[..8]);
        ciphertext[8..].copy_from_slice(&mic);
        assert_ne!(&ciphertext[..8], &plaintext[..]);

        let (encrypted, mic) = split_mic(&ciphertext).unwrap();
        let mut decrypted = [0u8; 8];
        decrypted.copy_from_slice(encrypted);
        assert_eq!(decrypt_ccm(&key, &nonce, &aad, &mut decrypted, mic), Ok(()));
        assert_eq!(decrypted, plaintext);

        let mut tampered = [0u8; 8];
        tampered.copy_from_slice(encrypted);
        tampered[0] ^= 0xff;
        assert_eq!(
            decrypt_ccm(&key, &nonce, &aad, &mut tampered, mic),
            Err(DecryptionError::InvalidMacTag)
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
