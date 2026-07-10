/*
 * The ziggurat_platform_* implementation over OpenThread primitives: otPlatTime,
 * ot::Timer, ot::Tasklet, ot::Crypto, and otLinkRaw radio operations on the RCP's
 * single otInstance. All Ziggurat callbacks run from OpenThread main-loop context.
 *
 * Platform-specific remainder (ESP_PLATFORM selects ESP-IDF, otherwise the Silabs
 * EFR32 build): the otInstance accessor, panic capture, and post-mortem reporting.
 */

#include "openthread-core-config.h"

#include <stdio.h>
#include <string.h>

#include <openthread/instance.h>
#include <openthread/link.h>
#include <openthread/link_raw.h>
#include <openthread/platform/entropy.h>
#include <openthread/platform/misc.h>
#include <openthread/platform/radio.h>
#include <openthread/platform/time.h>

#include "common/code_utils.hpp"
#include "common/new.hpp"
#include "common/tasklet.hpp"
#include "common/timer.hpp"
#include "crypto/aes_ccm.hpp"
#include "crypto/aes_ecb.hpp"
#include "instance/instance.hpp"

#include "ziggurat.h"
#include "ziggurat_glue.h"

#if defined(ESP_PLATFORM)

#include "esp_openthread.h"
#include "esp_system.h"

#else // Silabs EFR32

// The legacy-HAL fault dump: sl_ot_crash_handler_init() classifies every reset and
// the fault handlers (faults.s/diagnostic.c) capture registers into `halCrashInfo`,
// a .noinit struct that survives the reset.
extern "C" {
#include PLATFORM_HEADER
#include "crash_handler.h"
extern HalCrashInfoType halCrashInfo;
}

extern "C" otInstance *otGetInstance(void); // app.c

#endif

namespace {

bool sStarted;

otInstance *instance(void)
{
#if defined(ESP_PLATFORM)
    return esp_openthread_get_instance();
#else
    return otGetInstance();
#endif
}

// -- process tasklet --------------------------------------------------------------

// Wake = post the tasklet (idempotent while pending); it runs from the OT main
// loop after the current tasklet/event completes.
void handleProcess(ot::Tasklet &aTasklet)
{
    OT_UNUSED_VARIABLE(aTasklet);
    ziggurat_process();
}

OT_DEFINE_ALIGNED_VAR(sProcessRaw, sizeof(ot::Tasklet), uint64_t);
ot::Tasklet *sProcess;

// -- timer ------------------------------------------------------------------------

void handleTimer(ot::Timer &aTimer);

#if OPENTHREAD_CONFIG_PLATFORM_USEC_TIMER_ENABLE
typedef ot::TimerMicro ZigguratTimer;
constexpr uint64_t kTicksPerUs = 1;
#else
typedef ot::TimerMilli ZigguratTimer;
constexpr uint64_t kTicksPerUs = 1000;
#endif

OT_DEFINE_ALIGNED_VAR(sTimerRaw, sizeof(ZigguratTimer), uint64_t);
ZigguratTimer *sTimer;

void handleTimer(ot::Timer &aTimer)
{
    OT_UNUSED_VARIABLE(aTimer);
    ziggurat_timer_fired();
}

// -- radio callbacks (otLinkRaw on the single instance) -----------------------------

void handleRxDone(otInstance *aInstance, otRadioFrame *aFrame, otError aError)
{
    OT_UNUSED_VARIABLE(aInstance);

    if (aError != OT_ERROR_NONE || aFrame == nullptr || aFrame->mLength < 2)
    {
        return;
    }

    // OT frames include the 2-byte FCS; ziggurat PSDUs never do.
    ziggurat_radio_rx(aFrame->mPsdu,
                      aFrame->mLength - 2,
                      aFrame->mChannel,
                      aFrame->mInfo.mRxInfo.mRssi,
                      aFrame->mInfo.mRxInfo.mLqi,
                      aFrame->mInfo.mRxInfo.mTimestamp);
}

void handleTxDone(otInstance *aInstance, otRadioFrame *aFrame, otRadioFrame *aAckFrame, otError aError)
{
    OT_UNUSED_VARIABLE(aInstance);
    OT_UNUSED_VARIABLE(aFrame);
    OT_UNUSED_VARIABLE(aAckFrame);

    ziggurat_tx_status status;

    switch (aError)
    {
    case OT_ERROR_NONE:
        status = ZIGGURAT_TX_STATUS_ACKED;
        break;
    case OT_ERROR_NO_ACK:
        status = ZIGGURAT_TX_STATUS_NO_ACK;
        break;
    case OT_ERROR_CHANNEL_ACCESS_FAILURE:
        status = ZIGGURAT_TX_STATUS_CHANNEL_ACCESS_FAILURE;
        break;
    case OT_ERROR_ABORT:
        status = ZIGGURAT_TX_STATUS_ABORTED;
        break;
    default:
        status = ZIGGURAT_TX_STATUS_FAILED;
        break;
    }

    ziggurat_radio_tx_done(status);
}

void handleEnergyScanDone(otInstance *aInstance, int8_t aMaxRssi)
{
    OT_UNUSED_VARIABLE(aInstance);
    ziggurat_radio_energy_scan_done(aMaxRssi);
}

int32_t status(otError aError)
{
    return aError == OT_ERROR_NONE ? 0 : -1;
}

} // namespace

// -- the platform layer -------------------------------------------------------------

extern "C" uint64_t ziggurat_platform_time_now_us(void)
{
    return otPlatTimeGet();
}

extern "C" void ziggurat_platform_timer_arm(uint64_t deadline_us)
{
    if (deadline_us == UINT64_MAX)
    {
        sTimer->Stop();
        return;
    }

    uint64_t now   = otPlatTimeGet();
    uint64_t delay = deadline_us > now ? (deadline_us - now) / kTicksPerUs : 0;

    // Chunk far deadlines; on expiry ziggurat re-services its queue and re-arms.
    if (delay > (1u << 30))
    {
        delay = 1u << 30;
    }

    sTimer->Start(static_cast<uint32_t>(delay));
}

extern "C" void ziggurat_platform_wake(void)
{
    sProcess->Post();
}

extern "C" void ziggurat_platform_entropy(uint8_t *buf, size_t len)
{
    IgnoreError(otPlatEntropyGet(buf, static_cast<uint16_t>(len)));
}

extern "C" void ziggurat_platform_hw_eui64(uint8_t *out)
{
    otExtAddress eui64;

    otPlatRadioGetIeeeEui64(instance(), eui64.m8);
    // The platform reports the factory EUI-64 big-endian; ziggurat stores
    // little-endian (over-the-air) byte order.
    for (size_t i = 0; i < sizeof(eui64.m8); i++)
    {
        out[i] = eui64.m8[sizeof(eui64.m8) - 1 - i];
    }
}

extern "C" void ziggurat_platform_hard_reset(void)
{
    otPlatReset(instance());
    while (true)
    {
    }
}

// -- panic capture & post-mortem (platform-specific) ----------------------------------

#if defined(ESP_PLATFORM)

extern "C" void ziggurat_platform_panic(const uint8_t *msg, size_t len)
{
    // IDF's fatal path: the panic handler runs (coredump if configured) and the
    // reboot classifies as ESP_RST_PANIC. The message itself does not survive the
    // reboot — surfacing it post-mortem needs the coredump partition machinery.
    static char sMessage[256];
    size_t      n = len < sizeof(sMessage) - 1 ? len : sizeof(sMessage) - 1;

    memcpy(sMessage, msg, n);
    sMessage[n] = '\0';

    esp_system_abort(sMessage);
}

extern "C" size_t ziggurat_platform_last_reset(uint8_t *buf, size_t cap)
{
    static bool sReported;

    const char *what = nullptr;

    if (sReported)
    {
        return 0;
    }
    sReported = true;

    switch (otPlatGetResetReason(instance()))
    {
    case OT_PLAT_RESET_REASON_FAULT:
        what = "fault";
        break;
    case OT_PLAT_RESET_REASON_CRASH:
        what = "crash";
        break;
    case OT_PLAT_RESET_REASON_ASSERT:
        what = "assert";
        break;
    case OT_PLAT_RESET_REASON_WATCHDOG:
        what = "watchdog";
        break;
    default:
        return 0;
    }

    int len = snprintf(reinterpret_cast<char *>(buf), cap, "abnormal reset (%s)", what);

    if (len < 0)
    {
        return 0;
    }

    return static_cast<size_t>(len) < cap ? static_cast<size_t>(len) : cap - 1;
}

#else // Silabs EFR32

// The formatted Rust panic message. The crash handler's assert machinery persists
// only a pointer (HalAssertInfoType.file), so the string itself lives in the
// linker's no-init region to stay valid across the reset.
__attribute__((section(".noinit"), used)) volatile char ziggurat_panic_message[256];

extern "C" void ziggurat_platform_panic(const uint8_t *msg, size_t len)
{
    size_t n = len < sizeof(ziggurat_panic_message) - 1 ? len : sizeof(ziggurat_panic_message) - 1;
    for (size_t i = 0; i < n; i++)
    {
        ziggurat_panic_message[i] = static_cast<char>(msg[i]);
    }
    ziggurat_panic_message[n] = '\0';

    // Route through the OpenThread crash handler's assert path by executing its
    // ASSERT_USAGE_OPCODE (0xDE42) opcode.
    INTERRUPTS_OFF();

    register const char *file asm("r0") = const_cast<const char *>(ziggurat_panic_message);
    register uint32_t    line asm("r1") = 0;
    asm volatile(".short 0xDE42" : : "r"(file), "r"(line));

    while (true)
    {
    }
}

extern "C" size_t ziggurat_platform_last_reset(uint8_t *buf, size_t cap)
{
    static bool sReported;

    char *out = reinterpret_cast<char *>(buf);
    int   len = 0;

    if (sReported || !halResetWasCrash())
    {
        return 0;
    }
    sReported = true;

    if (halGetExtendedResetInfo() == RESET_CRASH_ASSERT)
    {
        const HalAssertInfoType *assertInfo = halGetAssertInfo();

        if (assertInfo->file == const_cast<const char *>(ziggurat_panic_message))
        {
            len = snprintf(out, cap, "panic: %s", assertInfo->file);
        }
        else
        {
            len = snprintf(out,
                           cap,
                           "assert %s:%lu",
                           assertInfo->file,
                           static_cast<unsigned long>(assertInfo->line));
        }
    }
    else if (halGetResetInfo() == RESET_FAULT)
    {
        const HalCrashInfoType *c = &halCrashInfo;

        len = snprintf(out,
                       cap,
                       "%s reset (ext 0x%04x): PC=%08lx LR=%08lx CFSR=%08lx HFSR=%08lx "
                       "FAR=%08lx stack used=%lu ret=[%08lx %08lx %08lx %08lx %08lx %08lx]",
                       halGetResetString(),
                       halGetExtendedResetInfo(),
                       static_cast<unsigned long>(c->PC),
                       static_cast<unsigned long>(c->LR),
                       static_cast<unsigned long>(c->cfsr.word),
                       static_cast<unsigned long>(c->hfsr.word),
                       static_cast<unsigned long>(c->faultAddress),
                       static_cast<unsigned long>(c->mainSPUsed),
                       static_cast<unsigned long>(c->returns[0]),
                       static_cast<unsigned long>(c->returns[1]),
                       static_cast<unsigned long>(c->returns[2]),
                       static_cast<unsigned long>(c->returns[3]),
                       static_cast<unsigned long>(c->returns[4]),
                       static_cast<unsigned long>(c->returns[5]));
    }
    else
    {
        // Crash-classified reset (e.g. watchdog) with no fault-handler capture.
        len = snprintf(out, cap, "%s reset (ext 0x%04x)", halGetResetString(), halGetExtendedResetInfo());
    }

    if (len < 0)
    {
        return 0;
    }

    return static_cast<size_t>(len) < cap ? static_cast<size_t>(len) : cap - 1;
}

#endif // platform-specific

// -- crypto ---------------------------------------------------------------------------

extern "C" void ziggurat_platform_aes128_encrypt_block(const uint8_t *key, uint8_t *block)
{
    ot::Crypto::AesEcb ecb;
    ot::Crypto::Key    aesKey;
    uint8_t            out[ot::Crypto::AesEcb::kBlockSize];

    aesKey.Set(key, 16);
    ecb.SetKey(aesKey);
    ecb.Encrypt(block, out);
    memcpy(block, out, sizeof(out));
}

extern "C" int32_t ziggurat_platform_ccm_crypt(bool           encrypt,
                                               const uint8_t *key,
                                               const uint8_t *nonce,
                                               const uint8_t *auth,
                                               size_t         auth_len,
                                               const uint8_t *input,
                                               uint8_t       *output,
                                               size_t         len,
                                               uint8_t       *tag,
                                               size_t         tag_len)
{
    ot::Crypto::AesCcm ccm;

    ccm.SetKey(key, 16);
    ccm.Init(auth_len, len, static_cast<uint8_t>(tag_len), nonce, 13);
    ccm.Header(auth, auth_len);

    if (encrypt)
    {
        ccm.Payload(const_cast<uint8_t *>(input), output, len, ot::Crypto::AesCcm::kEncrypt);
        ccm.Finalize(tag);
        return 0;
    }

    uint8_t expected[16];

    ccm.Payload(output, const_cast<uint8_t *>(input), len, ot::Crypto::AesCcm::kDecrypt);
    ccm.Finalize(expected);
    return memcmp(expected, tag, tag_len) == 0 ? 0 : -1;
}

// -- host tunnel ------------------------------------------------------------------------

extern "C" bool ziggurat_platform_host_send(const uint8_t *data, size_t len)
{
    return ziggurat_ncp_host_send(data, len);
}

// -- radio operations ---------------------------------------------------------------------

extern "C" int32_t ziggurat_platform_radio_configure(const ziggurat_radio_config_t *config)
{
    otInstance  *inst = instance();
    otExtAddress ext;
    otError      error = OT_ERROR_NONE;

    memcpy(ext.m8, config->extended_address, sizeof(ext.m8));

    SuccessOrExit(error = otLinkRawSetReceiveDone(inst, handleRxDone));
    SuccessOrExit(error = otLinkSetPanId(inst, config->pan_id));
    SuccessOrExit(error = otLinkSetExtendedAddress(inst, &ext));
    SuccessOrExit(error = otLinkRawSetShortAddress(inst, config->short_address));
    SuccessOrExit(error = otLinkRawSetPromiscuous(inst, config->promiscuous));
    SuccessOrExit(error = otPlatRadioSetTransmitPower(inst, config->tx_power_dbm));
    SuccessOrExit(error = otLinkRawSrcMatchEnable(inst, true));
    SuccessOrExit(error = otLinkSetChannel(inst, config->channel));
    SuccessOrExit(error = otLinkRawReceive(inst));

exit:
    return status(error);
}

extern "C" int32_t ziggurat_platform_radio_set_channel(uint8_t channel)
{
    otInstance *inst  = instance();
    otError     error = OT_ERROR_NONE;

    SuccessOrExit(error = otLinkSetChannel(inst, channel));
    SuccessOrExit(error = otLinkRawReceive(inst));

exit:
    return status(error);
}

extern "C" int32_t ziggurat_platform_radio_set_promiscuous(bool promiscuous)
{
    return status(otLinkRawSetPromiscuous(instance(), promiscuous));
}

extern "C" void ziggurat_platform_radio_src_match_clear(void)
{
    otInstance *inst = instance();

    IgnoreError(otLinkRawSrcMatchClearShortEntries(inst));
    IgnoreError(otLinkRawSrcMatchClearExtEntries(inst));
}

extern "C" int32_t ziggurat_platform_radio_src_match_add_short(uint16_t address)
{
    return status(otLinkRawSrcMatchAddShortEntry(instance(), address));
}

extern "C" int32_t ziggurat_platform_radio_src_match_add_ext(const uint8_t *address)
{
    otExtAddress ext;

    memcpy(ext.m8, address, sizeof(ext.m8));
    return status(otLinkRawSrcMatchAddExtEntry(instance(), &ext));
}

extern "C" int32_t ziggurat_platform_radio_transmit(const uint8_t *psdu,
                                                    size_t         len,
                                                    uint8_t        channel,
                                                    bool           csma_ca,
                                                    uint8_t        max_frame_retries,
                                                    uint8_t        max_csma_backoffs)
{
    otInstance   *inst  = instance();
    otRadioFrame *frame = otLinkRawGetTransmitBuffer(inst);

    if (frame == nullptr)
    {
        return -1;
    }

    memcpy(frame->mPsdu, psdu, len);
    frame->mLength                        = static_cast<uint16_t>(len + 2); // radio appends the FCS
    frame->mChannel                       = channel;
    frame->mInfo.mTxInfo.mCsmaCaEnabled   = csma_ca;
    frame->mInfo.mTxInfo.mMaxFrameRetries = max_frame_retries;
    frame->mInfo.mTxInfo.mMaxCsmaBackoffs = max_csma_backoffs;
    frame->mInfo.mTxInfo.mTxDelay         = 0;
    frame->mInfo.mTxInfo.mTxDelayBaseTime = 0;
    frame->mInfo.mTxInfo.mRxChannelAfterTxDone = channel;
    frame->mInfo.mTxInfo.mIsSecurityProcessed  = true; // ziggurat frames arrive encrypted
    frame->mInfo.mTxInfo.mIsHeaderUpdated      = true;

    return status(otLinkRawTransmit(inst, handleTxDone));
}

extern "C" int32_t ziggurat_platform_radio_energy_scan(uint8_t channel, uint16_t duration_ms)
{
    return status(otLinkRawEnergyScan(instance(), channel, duration_ms, handleEnergyScanDone));
}

// -- lifecycle -----------------------------------------------------------------------

extern "C" void ziggurat_glue_start(void)
{
    if (sStarted)
    {
        return;
    }

    ot::Instance &inst = ot::AsCoreType(instance());

    sProcess = new (&sProcessRaw) ot::Tasklet(inst, handleProcess);
    sTimer   = new (&sTimerRaw) ZigguratTimer(inst, handleTimer);

    // Enable link-raw up front: energy scans are radio operations that must work
    // before any network is configured.
    IgnoreError(otLinkRawSetReceiveDone(instance(), handleRxDone));

    ziggurat_start();
    sStarted = true;
}

extern "C" bool ziggurat_glue_started(void)
{
    return sStarted;
}
