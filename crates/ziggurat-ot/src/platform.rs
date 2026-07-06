//! The platform layer: everything Ziggurat needs from the surrounding firmware, as
//! directly-linked `ziggurat_platform_*` C functions. The glue defines them; a
//! missing implementation is a link error. `include/ziggurat.h` is generated from
//! this file and `lib.rs` by cbindgen.

/// Radio programming, mirrored from `ziggurat_phy::RadioConfig` plus the derived
/// PAN-coordinator flag. Extended address in little-endian (OT/over-the-air) byte
/// order.
#[repr(C)]
pub struct ZigguratRadioConfig {
    pub channel: u8,
    pub tx_power_dbm: i8,
    pub short_address: u16,
    pub pan_id: u16,
    pub extended_address: [u8; 8],
    pub promiscuous: bool,
    pub rx_on_when_idle: bool,
}

/// `ziggurat_radio_tx_done` status values.
#[repr(u8)]
pub enum ZigguratTxStatus {
    Acked = 0,
    NoAck = 1,
    ChannelAccessFailure = 2,
    Aborted = 3,
    Failed = 4,
}

unsafe extern "C" {
    /// Monotonic microseconds (otPlatTimeGet).
    pub fn ziggurat_platform_time_now_us() -> u64;

    /// Arm the one-shot timer for an absolute deadline in the time_now_us domain;
    /// UINT64_MAX cancels. Expiry must call `ziggurat_timer_fired`.
    pub fn ziggurat_platform_timer_arm(deadline_us: u64);

    /// Request a `ziggurat_process` call from the main loop soon
    /// (otSysEventSignalPending). Must be safe to call from within any
    /// `ziggurat_*` call.
    pub fn ziggurat_platform_wake();

    /// Fill `buf` with `len` random bytes (otPlatEntropyGet).
    pub fn ziggurat_platform_entropy(buf: *mut u8, len: usize);

    /// AES-128 ECB one-block encrypt of the 16-byte `block` with the 16-byte
    /// `key`, in place.
    pub fn ziggurat_platform_aes128_encrypt_block(key: *const u8, block: *mut u8);

    /// CCM* with a 16-byte `key` and a 13-byte `nonce` (sli_ccm_zigbee on EFR32).
    /// Encrypt: read `len` plaintext bytes from `input`, write ciphertext to
    /// `output` and the MIC to `tag`. Decrypt: the reverse, verifying `tag`;
    /// return nonzero on mismatch. `input`/`output` may alias.
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

    /// Queue one control-protocol frame to the host (unsolicited PROP_VALUE_IS on
    /// the ziggurat stream property). Return false when the NCP buffer is full;
    /// call `ziggurat_host_send_ready` once space frees up.
    pub fn ziggurat_platform_host_send(data: *const u8, len: usize) -> bool;

    /// Program the radio for ziggurat's interface (otLinkRaw*). Nonzero = failure.
    pub fn ziggurat_platform_radio_configure(config: *const ZigguratRadioConfig) -> i32;

    /// Change the receive channel. Nonzero = failure.
    pub fn ziggurat_platform_radio_set_channel(channel: u8) -> i32;

    /// Enable or disable promiscuous reception. Nonzero = failure.
    pub fn ziggurat_platform_radio_set_promiscuous(promiscuous: bool) -> i32;

    /// Clear the source-address match table (frame-pending for sleepy children).
    pub fn ziggurat_platform_radio_src_match_clear();

    /// Add a short address to the source-address match table. Nonzero = failure.
    pub fn ziggurat_platform_radio_src_match_add_short(address: u16) -> i32;

    /// Add an 8-byte extended address (little-endian) to the source-address match
    /// table. Nonzero = failure.
    pub fn ziggurat_platform_radio_src_match_add_ext(address: *const u8) -> i32;

    /// Submit one frame; `psdu` excludes the FCS (account for it in mLength).
    /// Completion must call `ziggurat_radio_tx_done`. One in flight at a time.
    /// Nonzero = failure.
    pub fn ziggurat_platform_radio_transmit(
        psdu: *const u8,
        len: usize,
        channel: u8,
        csma_ca: bool,
        max_frame_retries: u8,
        max_csma_backoffs: u8,
    ) -> i32;

    /// Start an energy scan; completion must call
    /// `ziggurat_radio_energy_scan_done`. Nonzero = failure.
    pub fn ziggurat_platform_radio_energy_scan(channel: u8, duration_ms: u16) -> i32;

    /// The factory EUI-64 (otPlatRadioGetIeeeEui64), written to the 8-byte `out`
    /// in little-endian byte order.
    pub fn ziggurat_platform_hw_eui64(out: *mut u8);

    /// Reboot the MCU. Must not return.
    pub fn ziggurat_platform_hard_reset();

    /// Fatal error: `msg` is the panic message (not NUL-terminated). Must record
    /// the message and reset; on EFR32 this routes through the OpenThread crash
    /// handler's assert machinery so the reset classifies as a crash. Must not
    /// return.
    pub fn ziggurat_platform_panic(msg: *const u8, len: usize);

    /// Post-mortem: describe the previous reset if it was abnormal (a panic,
    /// assert, or fault dump), writing up to `cap` UTF-8 bytes into `buf` and
    /// returning the length. Zero when the previous reset was clean or already
    /// reported.
    pub fn ziggurat_platform_last_reset(buf: *mut u8, cap: usize) -> usize;
}
