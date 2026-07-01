//! Zigbee crypto backed by the EFR32 RADIOAES hardware engine (`sli_ccm_zigbee` for CCM*,
//! `sli_aes_crypt_ecb_radio` for the AES-128 block). Installed into `ziggurat_zigbee::crypto`
//! so the whole stack's NWK/APS encryption runs on hardware (~91x faster than software).
//!
//! Each operation is synchronous: the RADIOAES DMA is kicked and the call busy-waits for
//! completion (~29 us) — see `sli_radioaes_run_operation`. The management stub's `acquire`
//! waits for the engine to be idle first, so this is safe alongside the radio's own use.

use ziggurat_ieee_802154::FrameBytes;
use ziggurat_ieee_802154::types::Key;
use ziggurat_rail_sys as rail;
use ziggurat_zigbee::crypto::{self, CryptoBackend, DecryptionError, MIC_LENGTH};

/// Max 802.15.4 PHY payload; bounds the scratch buffer.
const MAX_FRAME: usize = 128;

struct RadioAesBackend;

impl CryptoBackend for RadioAesBackend {
    fn aes128_encrypt_block(&self, key: &[u8; 16], block: &mut [u8; 16]) {
        let mut out = [0u8; 16];
        unsafe {
            rail::sli_aes_crypt_ecb_radio(true, key.as_ptr(), 128, block.as_ptr(), out.as_mut_ptr());
        }
        *block = out;
    }

    fn encrypt_ccm(&self, key: &Key, nonce: &[u8; 13], auth_data: &[u8], mut buffer: FrameBytes) -> FrameBytes {
        let len = buffer.len();
        let mut out = [0u8; MAX_FRAME];
        let mut tag = [0u8; MIC_LENGTH];
        unsafe {
            rail::sli_ccm_zigbee(
                true,
                buffer.as_ptr(),
                out.as_mut_ptr(),
                len,
                key.0.as_ptr(),
                nonce.as_ptr(),
                auth_data.as_ptr(),
                auth_data.len(),
                tag.as_mut_ptr(),
                MIC_LENGTH,
            );
        }
        buffer[..len].copy_from_slice(&out[..len]);
        buffer.extend_from_slice(&tag).expect("a frame always has room for its MIC");
        buffer
    }

    fn decrypt_ccm(
        &self,
        key: &Key,
        nonce: &[u8; 13],
        auth_data: &[u8],
        mut tagged_ciphertext: FrameBytes,
    ) -> Result<FrameBytes, DecryptionError> {
        let ct_len = tagged_ciphertext
            .len()
            .checked_sub(MIC_LENGTH)
            .ok_or(DecryptionError::CiphertextTooShort)?;
        let mut tag = [0u8; MIC_LENGTH];
        tag.copy_from_slice(&tagged_ciphertext[ct_len..]);
        let mut out = [0u8; MAX_FRAME];
        let status = unsafe {
            rail::sli_ccm_zigbee(
                false,
                tagged_ciphertext.as_ptr(),
                out.as_mut_ptr(),
                ct_len,
                key.0.as_ptr(),
                nonce.as_ptr(),
                auth_data.as_ptr(),
                auth_data.len(),
                tag.as_mut_ptr(),
                MIC_LENGTH,
            )
        };
        if status != 0 {
            return Err(DecryptionError::InvalidMacTag);
        }
        tagged_ciphertext.truncate(ct_len);
        tagged_ciphertext[..ct_len].copy_from_slice(&out[..ct_len]);
        Ok(tagged_ciphertext)
    }
}

static BACKEND: RadioAesBackend = RadioAesBackend;

/// Route all Zigbee crypto through the RADIOAES hardware. Call once at startup, before the
/// stack processes any frame.
pub fn init() {
    unsafe { rail::sli_protocol_crypto_init() };
    crypto::install(&BACKEND);
}
