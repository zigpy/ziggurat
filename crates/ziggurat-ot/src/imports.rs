//! The import vtable: everything Ziggurat needs from the surrounding firmware, as C
//! function pointers. The glue fills one `zig_imports_t` (see `include/ziggurat.h`) and
//! hands it to `zig_start`, which copies it here.

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

/// Radio programming, mirrored from `ziggurat_phy::RadioConfig` plus the derived
/// PAN-coordinator flag. Extended address in little-endian (OT/over-the-air) byte order.
#[repr(C)]
pub struct ZigRadioConfig {
    pub channel: u8,
    pub tx_power_dbm: i8,
    pub short_address: u16,
    pub pan_id: u16,
    pub extended_address: [u8; 8],
    pub promiscuous: bool,
    pub rx_on_when_idle: bool,
    pub pan_coordinator: bool,
}

/// Keep in sync with `zig_imports_t` in `include/ziggurat.h`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZigImports {
    // Time: a monotonic microsecond clock (otPlatTimeGet) and a single one-shot timer
    // (an ot::TimerMicro in the glue). `timer_arm(u64::MAX)` cancels; firing calls
    // `zig_timer_fired`.
    pub time_now_us: unsafe extern "C" fn() -> u64,
    pub timer_arm: unsafe extern "C" fn(deadline_us: u64),

    // Request a `zig_process` call from the main loop soon (otSysEventSignalPending).
    pub wake: unsafe extern "C" fn(),

    pub entropy: unsafe extern "C" fn(buf: *mut u8, len: usize),

    // AES-128 ECB one-block encrypt, in place.
    pub aes128_encrypt_block: unsafe extern "C" fn(key: *const u8, block: *mut u8),
    // CCM* with a 13-byte nonce. On encrypt, writes `len` ciphertext bytes to `output`
    // and the MIC to `tag`; on decrypt, writes `len` plaintext bytes and verifies `tag`,
    // returning nonzero on mismatch.
    pub ccm_crypt: unsafe extern "C" fn(
        encrypt: bool,
        key: *const u8,
        nonce: *const u8,
        auth: *const u8,
        auth_len: usize,
        input: *const u8,
        output: *mut u8,
        len: usize,
        tag: *mut u8,
        tag_len: usize,
    ) -> i32,

    // Queue one control-protocol frame to the host (the vendor Spinel property).
    // Returns false when the NCP buffer is full; `zig_host_send_ready` signals a retry.
    pub host_send: unsafe extern "C" fn(data: *const u8, len: usize) -> bool,

    // Radio operations on Ziggurat's otInstance (otLinkRaw*). Nonzero return = failure.
    pub radio_configure: unsafe extern "C" fn(config: *const ZigRadioConfig) -> i32,
    pub radio_set_channel: unsafe extern "C" fn(channel: u8) -> i32,
    pub radio_set_promiscuous: unsafe extern "C" fn(promiscuous: bool) -> i32,
    pub radio_src_match_clear: unsafe extern "C" fn(),
    pub radio_src_match_add_short: unsafe extern "C" fn(address: u16) -> i32,
    pub radio_src_match_add_ext: unsafe extern "C" fn(address: *const u8) -> i32,
    // Submit one frame (PSDU without FCS; the glue accounts for the FCS in mLength).
    // Completion arrives via `zig_radio_tx_done`.
    pub radio_transmit: unsafe extern "C" fn(
        psdu: *const u8,
        len: usize,
        channel: u8,
        csma_ca: bool,
        max_frame_retries: u8,
        max_csma_backoffs: u8,
    ) -> i32,
    pub radio_energy_scan: unsafe extern "C" fn(channel: u8, duration_ms: u16) -> i32,

    // The factory EUI-64 (otPlatRadioGetIeeeEui64), written to `out` in little-endian
    // byte order.
    pub hw_eui64: unsafe extern "C" fn(out: *mut u8),

    // Reboot the MCU. Must not return.
    pub hard_reset: unsafe extern "C" fn(),

    // Fatal error reporting (panic message), before the firmware's crash handling.
    pub panic: unsafe extern "C" fn(msg: *const u8, len: usize),
}

static mut IMPORTS: MaybeUninit<ZigImports> = MaybeUninit::uninit();
static READY: AtomicBool = AtomicBool::new(false);

pub fn install(imports: &ZigImports) {
    unsafe {
        (*core::ptr::addr_of_mut!(IMPORTS)).write(*imports);
    }
    READY.store(true, Ordering::Release);
}

pub fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// The installed vtable. Must not be called before [`install`].
pub fn imports() -> &'static ZigImports {
    assert!(ready());
    unsafe { (*core::ptr::addr_of!(IMPORTS)).assume_init_ref() }
}
