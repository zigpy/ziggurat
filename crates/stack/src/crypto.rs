use aes::Aes128;
use aes::Block;
use aes::cipher::BlockModeEncrypt;
use aes::cipher::KeyInit;
use aes::cipher::KeyIvInit;
use cbc::Encryptor;
use cbc::cipher::BlockCipherEncrypt;

use ieee_802154::types::Key;

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

fn right_pad_to_multiple_of_16(data: &[u8]) -> Vec<Block> {
    // Pre-allocate enough blocks
    let mut blocks = Vec::<Block>::with_capacity(data.len().div_ceil(16));

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
    /// Returns `None` if the tagged ciphertext is too short to contain a MAC tag.
    pub fn split_mac_tag(&self, tagged_ciphertext: &[u8]) -> Option<(Vec<u8>, [u8; M])> {
        let ciphertext_len = tagged_ciphertext.len().checked_sub(M)?;
        let ciphertext = tagged_ciphertext[..ciphertext_len].to_vec();

        let mut mac_tag = [0; M];
        mac_tag.copy_from_slice(&tagged_ciphertext[ciphertext_len..]);

        Some((ciphertext, mac_tag))
    }

    #[allow(clippy::unusual_byte_groupings)]
    pub fn compute_mac(
        &self,
        auth_data: &Vec<u8>,
        key: &Key,
        plaintext: &[u8],
        nonce: &[u8; 13],
    ) -> [u8; M] {
        let encoded_auth_data_len = auth_data.len().to_be_bytes();
        let mut added_auth_data = Vec::new();
        added_auth_data.extend(&encoded_auth_data_len[encoded_auth_data_len.len() - L..]);
        added_auth_data.extend(auth_data);

        let encoded_plaintext_len = plaintext.len().to_be_bytes();
        let mut b0 = Block::default();
        b0[0] = 0b0_1_001_001; // Flags
        b0[1..14].copy_from_slice(nonce);
        b0[14..16].copy_from_slice(&encoded_plaintext_len[encoded_plaintext_len.len() - L..]);

        let mut authed_plaintext = Vec::<Block>::new();
        authed_plaintext.extend(right_pad_to_multiple_of_16(&added_auth_data));
        authed_plaintext.extend(right_pad_to_multiple_of_16(plaintext));

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

    #[allow(clippy::unusual_byte_groupings)]
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

            cipher.encrypt_block_b2b(&counter_block, &mut buffer_block);
            tagged_ciphertext_blocks.push(Block::from_fn(|i| buffer_block[i] ^ plaintext_block[i]));
        }

        // The first M bytes of the first block is the "encrypted_mac_tag":
        let mut encrypted_mac_tag = [0; M];
        encrypted_mac_tag.copy_from_slice(&tagged_ciphertext_blocks[0][0..M]);

        // The actual ciphertext portion starts at the second block
        let ciphertext_vec = tagged_ciphertext_blocks[1..].concat();
        let ciphertext = ciphertext_vec[..plaintext.len()].to_vec();

        (encrypted_mac_tag, ciphertext)
    }
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
}
