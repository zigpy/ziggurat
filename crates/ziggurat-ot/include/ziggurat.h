/*
 * Ziggurat embedded-in-OpenThread-RCP C API (libziggurat_ot.a).
 *
 * The firmware glue fills a zig_imports_t and calls zig_start() once, after the
 * OpenThread instance and NCP exist. From then on:
 *
 *  - glue -> ziggurat: the zig_* functions below, ALL from OpenThread main-loop
 *    context (never an ISR);
 *  - ziggurat -> glue: the zig_imports_t function pointers. `wake` may be called
 *    re-entrantly from within any zig_* call; it must only set a flag /
 *    otSysEventSignalPending() and return.
 *
 * The superloop contract: whenever `wake` was called, call zig_process() from the
 * main loop (extra calls are harmless).
 *
 * Struct layouts must match crates/ziggurat-ot/src/imports.rs exactly.
 */

#ifndef ZIGGURAT_H_
#define ZIGGURAT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Radio programming for ziggurat's interface. Extended address is little-endian
 * (over-the-air) byte order. */
typedef struct zig_radio_config {
    uint8_t  channel;
    int8_t   tx_power_dbm;
    uint16_t short_address;
    uint16_t pan_id;
    uint8_t  extended_address[8];
    bool     promiscuous;
    bool     rx_on_when_idle;
    /* Accept frames with no destination addressing (Zigbee coordinator). No
     * otPlatRadio equivalent: on EFR32, sl_rail_ieee802154_set_pan_coordinator(). */
    bool     pan_coordinator;
} zig_radio_config_t;

/* zig_radio_tx_done() status values. */
typedef enum zig_tx_status {
    ZIG_TX_ACKED                  = 0,
    ZIG_TX_NO_ACK                 = 1,
    ZIG_TX_CHANNEL_ACCESS_FAILURE = 2,
    ZIG_TX_ABORTED                = 3,
    ZIG_TX_FAILED                 = 4,
} zig_tx_status_t;

typedef struct zig_imports {
    /* Monotonic microseconds (otPlatTimeGet). */
    uint64_t (*time_now_us)(void);
    /* Arm the one-shot timer for an absolute deadline in the time_now_us domain;
     * UINT64_MAX cancels. Expiry must call zig_timer_fired(). */
    void (*timer_arm)(uint64_t deadline_us);

    /* Request a zig_process() call from the main loop soon
     * (otSysEventSignalPending). Must be safe to call from within any zig_* call. */
    void (*wake)(void);

    /* Fill `buf` with `len` random bytes (otPlatEntropyGet). */
    void (*entropy)(uint8_t *buf, size_t len);

    /* AES-128 ECB one-block encrypt, in place. */
    void (*aes128_encrypt_block)(const uint8_t key[16], uint8_t block[16]);
    /* CCM* with a 13-byte nonce (sli_ccm_zigbee on EFR32). Encrypt: read `len`
     * plaintext bytes from `input`, write ciphertext to `output` and the MIC to
     * `tag`. Decrypt: the reverse, verifying `tag`; return nonzero on mismatch.
     * `input`/`output` may alias. */
    int32_t (*ccm_crypt)(bool encrypt, const uint8_t key[16], const uint8_t nonce[13],
                         const uint8_t *auth, size_t auth_len,
                         const uint8_t *input, uint8_t *output, size_t len,
                         uint8_t *tag, size_t tag_len);

    /* Queue one control-protocol frame to the host (unsolicited PROP_VALUE_IS on
     * the ziggurat stream property). Return false when the NCP buffer is full;
     * call zig_host_send_ready() once space frees up. */
    bool (*host_send)(const uint8_t *data, size_t len);

    /* Radio operations on ziggurat's otInstance (otLinkRaw*). Nonzero = failure. */
    int32_t (*radio_configure)(const zig_radio_config_t *config);
    int32_t (*radio_set_channel)(uint8_t channel);
    int32_t (*radio_set_promiscuous)(bool promiscuous);
    void (*radio_src_match_clear)(void);
    int32_t (*radio_src_match_add_short)(uint16_t address);
    int32_t (*radio_src_match_add_ext)(const uint8_t address[8]);
    /* Submit one frame; `psdu` excludes the FCS (account for it in mLength).
     * Completion must call zig_radio_tx_done(). One in flight at a time. */
    int32_t (*radio_transmit)(const uint8_t *psdu, size_t len, uint8_t channel,
                              bool csma_ca, uint8_t max_frame_retries,
                              uint8_t max_csma_backoffs);
    /* Start an energy scan; completion must call zig_radio_energy_scan_done(). */
    int32_t (*radio_energy_scan)(uint8_t channel, uint16_t duration_ms);

    /* The factory EUI-64 (otPlatRadioGetIeeeEui64), little-endian byte order. */
    void (*hw_eui64)(uint8_t out[8]);

    /* Reboot the MCU. Must not return. */
    void (*hard_reset)(void);

    /* Fatal error: `msg` is the panic message (not NUL-terminated). Should log
     * and reset. */
    void (*panic)(const uint8_t *msg, size_t len);
} zig_imports_t;

/* Initialize and start the embedded stack; the vtable is copied. Call once — there
 * is no stop: switching the firmware back to plain-RCP use is done by resetting the
 * MCU. The stack idles until the first host frame (a `configure` request) arrives. */
void zig_start(const zig_imports_t *imports);

/* Poll the async executor. Call from the superloop whenever `wake` requested it. */
void zig_process(void);

/* One inbound control-protocol frame (a JSON request line, no trailing newline). */
void zig_host_frame(const uint8_t *data, size_t len);

/* NCP buffer space freed (VendorHandleFrameRemovedFromNcpBuffer): retry sends. */
void zig_host_send_ready(void);

/* The one-shot timer armed via `timer_arm` fired. */
void zig_timer_fired(void);

/* A frame was received on ziggurat's instance. `psdu` excludes the FCS;
 * `timestamp_us` is the sync-word-end time in the time_now_us domain. */
void zig_radio_rx(const uint8_t *psdu, size_t len, uint8_t channel, int8_t rssi,
                  uint8_t lqi, uint64_t timestamp_us);

/* The in-flight transmit finished. */
void zig_radio_tx_done(uint8_t status);

/* The energy scan finished with this peak RSSI. */
void zig_radio_energy_scan_done(int8_t max_rssi_dbm);

#ifdef __cplusplus
}
#endif

#endif /* ZIGGURAT_H_ */
