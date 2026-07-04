/*
 * Ziggurat embedded-in-OpenThread-RCP C API (libziggurat_ot.a).
 *
 * The firmware glue implements the ziggurat_platform_* functions below and calls
 * ziggurat_start() once, after the OpenThread instance and NCP exist. From then on:
 *
 *  - glue -> ziggurat: the ziggurat_* functions, ALL from OpenThread main-loop
 *    context (never an ISR);
 *  - ziggurat -> glue: the ziggurat_platform_* functions. `ziggurat_platform_wake`
 *    may be called re-entrantly from within any ziggurat_* call; it must only set a
 *    flag / otSysEventSignalPending() and return.
 *
 * The superloop contract: whenever `ziggurat_platform_wake` was called, call
 * ziggurat_process() from the main loop (extra calls are harmless).
 *
 * A missing ziggurat_platform_* implementation is a link error. Signatures must
 * match crates/ziggurat-ot/src/platform.rs exactly.
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
typedef struct ziggurat_radio_config {
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
} ziggurat_radio_config_t;

/* ziggurat_radio_tx_done() status values. */
typedef enum ziggurat_tx_status {
    ZIGGURAT_TX_ACKED                  = 0,
    ZIGGURAT_TX_NO_ACK                 = 1,
    ZIGGURAT_TX_CHANNEL_ACCESS_FAILURE = 2,
    ZIGGURAT_TX_ABORTED                = 3,
    ZIGGURAT_TX_FAILED                 = 4,
} ziggurat_tx_status_t;

/*
 * Functions the firmware must provide.
 */

/* Monotonic microseconds (otPlatTimeGet). */
uint64_t ziggurat_platform_time_now_us(void);
/* Arm the one-shot timer for an absolute deadline in the time_now_us domain;
 * UINT64_MAX cancels. Expiry must call ziggurat_timer_fired(). */
void ziggurat_platform_timer_arm(uint64_t deadline_us);

/* Request a ziggurat_process() call from the main loop soon
 * (otSysEventSignalPending). Must be safe to call from within any ziggurat_* call. */
void ziggurat_platform_wake(void);

/* Fill `buf` with `len` random bytes (otPlatEntropyGet). */
void ziggurat_platform_entropy(uint8_t *buf, size_t len);

/* AES-128 ECB one-block encrypt, in place. */
void ziggurat_platform_aes128_encrypt_block(const uint8_t key[16], uint8_t block[16]);
/* CCM* with a 13-byte nonce (sli_ccm_zigbee on EFR32). Encrypt: read `len`
 * plaintext bytes from `input`, write ciphertext to `output` and the MIC to
 * `tag`. Decrypt: the reverse, verifying `tag`; return nonzero on mismatch.
 * `input`/`output` may alias. */
int32_t ziggurat_platform_ccm_crypt(bool encrypt, const uint8_t key[16],
                                    const uint8_t nonce[13],
                                    const uint8_t *auth, size_t auth_len,
                                    const uint8_t *input, uint8_t *output, size_t len,
                                    uint8_t *tag, size_t tag_len);

/* Queue one control-protocol frame to the host (unsolicited PROP_VALUE_IS on
 * the ziggurat stream property). Return false when the NCP buffer is full;
 * call ziggurat_host_send_ready() once space frees up. */
bool ziggurat_platform_host_send(const uint8_t *data, size_t len);

/* Radio operations on ziggurat's otInstance (otLinkRaw*). Nonzero = failure. */
int32_t ziggurat_platform_radio_configure(const ziggurat_radio_config_t *config);
int32_t ziggurat_platform_radio_set_channel(uint8_t channel);
int32_t ziggurat_platform_radio_set_promiscuous(bool promiscuous);
void ziggurat_platform_radio_src_match_clear(void);
int32_t ziggurat_platform_radio_src_match_add_short(uint16_t address);
int32_t ziggurat_platform_radio_src_match_add_ext(const uint8_t address[8]);
/* Submit one frame; `psdu` excludes the FCS (account for it in mLength).
 * Completion must call ziggurat_radio_tx_done(). One in flight at a time. */
int32_t ziggurat_platform_radio_transmit(const uint8_t *psdu, size_t len,
                                         uint8_t channel, bool csma_ca,
                                         uint8_t max_frame_retries,
                                         uint8_t max_csma_backoffs);
/* Start an energy scan; completion must call ziggurat_radio_energy_scan_done(). */
int32_t ziggurat_platform_radio_energy_scan(uint8_t channel, uint16_t duration_ms);

/* The factory EUI-64 (otPlatRadioGetIeeeEui64), little-endian byte order. */
void ziggurat_platform_hw_eui64(uint8_t out[8]);

/* Reboot the MCU. Must not return. */
void ziggurat_platform_hard_reset(void);

/* Fatal error: `msg` is the panic message (not NUL-terminated). Should log
 * and reset. */
void ziggurat_platform_panic(const uint8_t *msg, size_t len);

/*
 * Functions the library provides.
 */

/* Initialize and start the embedded stack. Call once — there is no stop: switching
 * the firmware back to plain-RCP use is done by resetting the MCU. The stack idles
 * until the first host frame (a `configure` request) arrives. */
void ziggurat_start(void);

/* Poll the async executor. Call from the superloop whenever
 * `ziggurat_platform_wake` requested it. */
void ziggurat_process(void);

/* One inbound control-protocol frame (a JSON request line, no trailing newline). */
void ziggurat_host_frame(const uint8_t *data, size_t len);

/* NCP buffer space freed (VendorHandleFrameRemovedFromNcpBuffer): retry sends. */
void ziggurat_host_send_ready(void);

/* The one-shot timer armed via `ziggurat_platform_timer_arm` fired. */
void ziggurat_timer_fired(void);

/* A frame was received on ziggurat's instance. `psdu` excludes the FCS;
 * `timestamp_us` is the sync-word-end time in the time_now_us domain. */
void ziggurat_radio_rx(const uint8_t *psdu, size_t len, uint8_t channel, int8_t rssi,
                       uint8_t lqi, uint64_t timestamp_us);

/* The in-flight transmit finished. */
void ziggurat_radio_tx_done(uint8_t status);

/* The energy scan finished with this peak RSSI. */
void ziggurat_radio_energy_scan_done(int8_t max_rssi_dbm);

#ifdef __cplusplus
}
#endif

#endif /* ZIGGURAT_H_ */
