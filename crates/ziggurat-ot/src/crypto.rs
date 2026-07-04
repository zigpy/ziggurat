//! Zigbee crypto routed through the import vtable: the glue backs `ccm_crypt` /
//! `aes128_encrypt_block` with the platform's hardware AES (RADIOAES via `sli_*` on
//! EFR32, or `otPlatCryptoAesEncrypt` on platforms without a CCM engine). Mirrors
//! `ziggurat-efr32/src/hw_crypto.rs`.

use ziggurat_ieee_802154::FrameBytes;
use ziggurat_ieee_802154::types::Key;
use ziggurat_zigbee::crypto::{self, CryptoBackend, DecryptionError, MIC_LENGTH};

use crate::imports::imports;

/// Max 802.15.4 PHY payload; bounds the scratch buffer.
const MAX_FRAME: usize = 128;

struct VtableCryptoBackend;

impl CryptoBackend for VtableCryptoBackend {
    fn aes128_encrypt_block(&self, key: &[u8; 16], block: &mut [u8; 16]) {
        unsafe { (imports().aes128_encrypt_block)(key.as_ptr(), block.as_mut_ptr()) };
    }

    fn encrypt_ccm(
        &self,
        key: &Key,
        nonce: &[u8; 13],
        auth_data: &[u8],
        mut buffer: FrameBytes,
    ) -> FrameBytes {
        let len = buffer.len();
        let mut out = [0u8; MAX_FRAME];
        let mut tag = [0u8; MIC_LENGTH];
        unsafe {
            (imports().ccm_crypt)(
                true,
                key.0.as_ptr(),
                nonce.as_ptr(),
                auth_data.as_ptr(),
                auth_data.len(),
                buffer.as_ptr(),
                out.as_mut_ptr(),
                len,
                tag.as_mut_ptr(),
                MIC_LENGTH,
            );
        }
        buffer[..len].copy_from_slice(&out[..len]);
        buffer
            .extend_from_slice(&tag)
            .expect("a frame always has room for its MIC");
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
            (imports().ccm_crypt)(
                false,
                key.0.as_ptr(),
                nonce.as_ptr(),
                auth_data.as_ptr(),
                auth_data.len(),
                tagged_ciphertext.as_ptr(),
                out.as_mut_ptr(),
                ct_len,
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

static BACKEND: VtableCryptoBackend = VtableCryptoBackend;

/// Route all Zigbee crypto through the vtable. Call once at startup, before the stack
/// processes any frame.
pub fn init() {
    crypto::install(&BACKEND);
}
