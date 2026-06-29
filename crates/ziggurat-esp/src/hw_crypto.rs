//! Hardware-accelerated crypto backend: routes the stack's AES-128 block primitive to
//! the ESP32-C6 AES peripheral via `esp_hal::aes`. CCM* and AES-MMO both ride this
//! block, so all Zigbee crypto runs on the accelerator instead of software AES on the
//! RISC-V core.

use core::cell::RefCell;

use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use esp_hal::aes::Aes;
use esp_hal::peripherals::AES;
use esp_println::println;

use ziggurat_zigbee::crypto::{self, CryptoBackend};

/// The AES peripheral is a singleton shared by every task that does crypto, so it lives
/// behind a critical-section mutex. The peripheral re-loads the key on each block.
static HW_AES: Mutex<CriticalSectionRawMutex, RefCell<Option<Aes<'static>>>> =
    Mutex::new(RefCell::new(None));

/// The C6 AES accelerator has no CCM mode (only block modes), and `esp_hal` exposes
/// just single-block ECB, so this backend implements only the block primitive and
/// inherits the software CCM* default.
struct EspCrypto;

impl CryptoBackend for EspCrypto {
    fn aes128_encrypt_block(&self, key: &[u8; 16], block: &mut [u8; 16]) {
        HW_AES.lock(|cell| {
            let mut guard = cell.borrow_mut();
            let aes = guard.as_mut().expect("hw_crypto::init was never called");
            aes.encrypt(block, *key);
        });
    }
}

static BACKEND: EspCrypto = EspCrypto;

/// Claim the AES peripheral and install the hardware crypto backend. Call once during
/// startup, before the stack processes any frames.
pub fn init(aes: AES<'static>) {
    let hw = Aes::new(aes);

    HW_AES.lock(|cell| *cell.borrow_mut() = Some(hw));
    crypto::install(&BACKEND);
    println!("hw_crypto: AES hardware acceleration enabled");
}
