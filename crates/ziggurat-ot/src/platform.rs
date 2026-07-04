//! The platform layer: everything Ziggurat needs from the surrounding firmware, as
//! directly-linked `ziggurat_platform_*` C functions (see `include/ziggurat.h`). The glue
//! defines them; a missing implementation is a link error.

/// Radio programming, mirrored from `ziggurat_phy::RadioConfig` plus the derived
/// PAN-coordinator flag. Extended address in little-endian (OT/over-the-air) byte order.
#[repr(C)]
pub struct ZigguratRadioConfig {
    pub channel: u8,
    pub tx_power_dbm: i8,
    pub short_address: u16,
    pub pan_id: u16,
    pub extended_address: [u8; 8],
    pub promiscuous: bool,
    pub rx_on_when_idle: bool,
    pub pan_coordinator: bool,
}

// Keep in sync with the `ziggurat_platform_*` declarations in `include/ziggurat.h`.
unsafe extern "C" {
    // Time: a monotonic microsecond clock (otPlatTimeGet) and a single one-shot timer
    // (an ot::Timer in the glue). `ziggurat_platform_timer_arm(u64::MAX)` cancels; firing
    // calls `ziggurat_timer_fired`.
    pub fn ziggurat_platform_time_now_us() -> u64;
    pub fn ziggurat_platform_timer_arm(deadline_us: u64);

    // Request a `ziggurat_process` call from the main loop soon
    // (otSysEventSignalPending).
    pub fn ziggurat_platform_wake();

    pub fn ziggurat_platform_entropy(buf: *mut u8, len: usize);

    // AES-128 ECB one-block encrypt, in place.
    pub fn ziggurat_platform_aes128_encrypt_block(key: *const u8, block: *mut u8);
    // CCM* with a 13-byte nonce. On encrypt, writes `len` ciphertext bytes to `output`
    // and the MIC to `tag`; on decrypt, writes `len` plaintext bytes and verifies `tag`,
    // returning nonzero on mismatch.
    pub fn ziggurat_platform_ccm_crypt(
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
    ) -> i32;

    // Queue one control-protocol frame to the host (the vendor Spinel property).
    // Returns false when the NCP buffer is full; `ziggurat_host_send_ready` signals a
    // retry.
    pub fn ziggurat_platform_host_send(data: *const u8, len: usize) -> bool;

    // Radio operations on Ziggurat's otInstance (otLinkRaw*). Nonzero return = failure.
    pub fn ziggurat_platform_radio_configure(config: *const ZigguratRadioConfig) -> i32;
    pub fn ziggurat_platform_radio_set_channel(channel: u8) -> i32;
    pub fn ziggurat_platform_radio_set_promiscuous(promiscuous: bool) -> i32;
    pub fn ziggurat_platform_radio_src_match_clear();
    pub fn ziggurat_platform_radio_src_match_add_short(address: u16) -> i32;
    pub fn ziggurat_platform_radio_src_match_add_ext(address: *const u8) -> i32;
    // Submit one frame (PSDU without FCS; the glue accounts for the FCS in mLength).
    // Completion arrives via `ziggurat_radio_tx_done`.
    pub fn ziggurat_platform_radio_transmit(
        psdu: *const u8,
        len: usize,
        channel: u8,
        csma_ca: bool,
        max_frame_retries: u8,
        max_csma_backoffs: u8,
    ) -> i32;
    pub fn ziggurat_platform_radio_energy_scan(channel: u8, duration_ms: u16) -> i32;

    // The factory EUI-64 (otPlatRadioGetIeeeEui64), written to `out` in little-endian
    // byte order.
    pub fn ziggurat_platform_hw_eui64(out: *mut u8);

    // Reboot the MCU. Must not return.
    pub fn ziggurat_platform_hard_reset();

    // Fatal error reporting (panic message), before the firmware's crash handling.
    pub fn ziggurat_platform_panic(msg: *const u8, len: usize);
}
