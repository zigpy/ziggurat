//! Zigbee crypto routed through the platform layer: the glue backs `ziggurat_platform_ccm_crypt`
//! / `ziggurat_platform_aes128_encrypt_block` with the platform's hardware AES (RADIOAES via
//! `sli_*` on EFR32, or `otPlatCryptoAesEncrypt` on platforms without a CCM engine).

use ziggurat_ieee_802154::types::Key;
use ziggurat_zigbee::crypto::{self, CryptoBackend, DecryptionError, MIC_LENGTH};

use crate::platform;

/// Max 802.15.4 PHY payload; bounds the scratch buffer.
const MAX_FRAME: usize = 128;

struct PlatformCryptoBackend;

impl CryptoBackend for PlatformCryptoBackend {
    fn aes128_encrypt_block(&self, key: &[u8; 16], block: &mut [u8; 16]) {
        unsafe {
            platform::ziggurat_platform_aes128_encrypt_block(key.as_ptr(), block.as_mut_ptr())
        };
    }

    fn encrypt_ccm(
        &self,
        key: &Key,
        nonce: &[u8; 13],
        auth_data: &[u8],
        payload: &mut [u8],
    ) -> [u8; MIC_LENGTH] {
        let len = payload.len();
        let mut out = [0u8; MAX_FRAME];
        let mut tag = [0u8; MIC_LENGTH];
        unsafe {
            platform::ziggurat_platform_ccm_crypt(
                true,
                key.0.as_ptr(),
                nonce.as_ptr(),
                auth_data.as_ptr(),
                auth_data.len(),
                payload.as_ptr(),
                out.as_mut_ptr(),
                len,
                tag.as_mut_ptr(),
                MIC_LENGTH,
            );
        }
        payload.copy_from_slice(&out[..len]);
        tag
    }

    fn decrypt_ccm(
        &self,
        key: &Key,
        nonce: &[u8; 13],
        auth_data: &[u8],
        payload: &mut [u8],
        mic: &[u8; MIC_LENGTH],
    ) -> Result<(), DecryptionError> {
        let len = payload.len();
        let mut tag = *mic;
        let mut out = [0u8; MAX_FRAME];
        let status = unsafe {
            platform::ziggurat_platform_ccm_crypt(
                false,
                key.0.as_ptr(),
                nonce.as_ptr(),
                auth_data.as_ptr(),
                auth_data.len(),
                payload.as_ptr(),
                out.as_mut_ptr(),
                len,
                tag.as_mut_ptr(),
                MIC_LENGTH,
            )
        };
        if status != 0 {
            return Err(DecryptionError::InvalidMacTag);
        }
        payload.copy_from_slice(&out[..len]);
        Ok(())
    }
}

static BACKEND: PlatformCryptoBackend = PlatformCryptoBackend;

/// Route all Zigbee crypto through the platform layer. Call once at startup, before the
/// stack processes any frame.
pub fn init() {
    crypto::install(&BACKEND);
}
