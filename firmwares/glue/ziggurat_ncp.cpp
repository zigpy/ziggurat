/*
 * Ziggurat NCP vendor hook.
 *
 * Compiled with OPENTHREAD_ENABLE_NCP_VENDOR_HOOK=1: NCP construction and the
 * vendor Spinel property range belong to this file. On the Silabs build this
 * also provides otAppNcpInit over otPlatUart (conflicting with the Silabs
 * ot_ncp_vendor_extension component); on ESP-IDF, Espressif's otAppNcpInit and
 * transport are reused and only otNcpHdlcInit is replaced.
 *
 * Properties:
 *   +0x20 ZIGGURAT_VERSION  (GET)      presence/version probe
 *   +0x21 ZIGGURAT_ENABLE   (GET/SET)  start the stack (enable-once; reset to leave)
 *   +0x22 ZIGGURAT_STREAM   (SET, unsolicited VALUE_IS) the binary control tunnel
 */

#include "openthread-core-config.h"

#include <openthread/ncp.h>

#include "common/code_utils.hpp"
#include "common/debug.hpp"
#include "common/new.hpp"
#include "ncp/ncp_base.hpp"
#include "ncp/ncp_config.h"
#include "ncp/ncp_hdlc.hpp"

#if !defined(ESP_PLATFORM)
#include "utils/uart.h"
#endif

#include "ziggurat.h"
#include "ziggurat_glue.h"

#if OPENTHREAD_ENABLE_NCP_VENDOR_HOOK

namespace ot {
namespace Ncp {

static constexpr spinel_prop_key_t kPropZigguratVersion =
    static_cast<spinel_prop_key_t>(SPINEL_PROP_VENDOR__BEGIN + 0x20);
static constexpr spinel_prop_key_t kPropZigguratEnable =
    static_cast<spinel_prop_key_t>(SPINEL_PROP_VENDOR__BEGIN + 0x21);
static constexpr spinel_prop_key_t kPropZigguratStream =
    static_cast<spinel_prop_key_t>(SPINEL_PROP_VENDOR__BEGIN + 0x22);

static const char kZigguratVersion[] = "ziggurat-rcp/0.1.0";

class NcpZiggurat : public NcpHdlc
{
public:
    NcpZiggurat(Instance *aInstance, otNcpHdlcSendCallback aSendCallback)
        : NcpHdlc(aInstance, aSendCallback)
    {
    }

    bool SendZigguratStream(const uint8_t *aData, uint16_t aLength)
    {
        otError error  = OT_ERROR_NONE;
        uint8_t header = SPINEL_HEADER_FLAG | SPINEL_HEADER_IID_0;

        SuccessOrExit(error = mEncoder.BeginFrame(header, SPINEL_CMD_PROP_VALUE_IS, kPropZigguratStream));
        SuccessOrExit(error = mEncoder.WriteDataWithLen(aData, aLength));
        SuccessOrExit(error = mEncoder.EndFrame());

    exit:
        return error == OT_ERROR_NONE;
    }
};

static NcpZiggurat *sNcpZiggurat;

static OT_DEFINE_ALIGNED_VAR(sNcpRaw, sizeof(NcpZiggurat), uint64_t);

extern "C" void otNcpHdlcInit(otInstance *aInstance, otNcpHdlcSendCallback aSendCallback)
{
    NcpZiggurat *ncp = new (&sNcpRaw) NcpZiggurat(static_cast<Instance *>(aInstance), aSendCallback);

    if (ncp == nullptr || ncp != NcpBase::GetNcpInstance())
    {
        OT_ASSERT(false);
    }

    sNcpZiggurat = ncp;
}

#if !defined(ESP_PLATFORM)

static int NcpSend(const uint8_t *aBuf, uint16_t aBufLength)
{
    IgnoreError(otPlatUartSend(aBuf, aBufLength));
    return aBufLength;
}

extern "C" void otAppNcpInit(otInstance *aInstance)
{
    IgnoreError(otPlatUartEnable());
    otNcpHdlcInit(aInstance, NcpSend);
}

#endif // !defined(ESP_PLATFORM)

extern "C" bool ziggurat_ncp_host_send(const uint8_t *data, size_t len)
{
    return sNcpZiggurat != nullptr && sNcpZiggurat->SendZigguratStream(data, static_cast<uint16_t>(len));
}

otError NcpBase::VendorCommandHandler(uint8_t aHeader, unsigned int aCommand)
{
    OT_UNUSED_VARIABLE(aCommand);

    return PrepareLastStatusResponse(aHeader, SPINEL_STATUS_INVALID_COMMAND);
}

void NcpBase::VendorHandleFrameRemovedFromNcpBuffer(Spinel::Buffer::FrameTag aFrameTag)
{
    OT_UNUSED_VARIABLE(aFrameTag);

    if (ziggurat_glue_started())
    {
        ziggurat_host_send_ready();
    }
}

otError NcpBase::VendorGetPropertyHandler(spinel_prop_key_t aPropKey)
{
    otError error = OT_ERROR_NONE;

    switch (aPropKey)
    {
    case kPropZigguratVersion:
        error = mEncoder.WriteUtf8(kZigguratVersion);
        break;

    case kPropZigguratEnable:
        error = mEncoder.WriteBool(ziggurat_glue_started());
        break;

    case kPropZigguratStream:
        // SET responses are built from this handler; the stream carries no
        // retrievable state.
        break;

    default:
        error = OT_ERROR_NOT_FOUND;
        break;
    }

    return error;
}

otError NcpBase::VendorSetPropertyHandler(spinel_prop_key_t aPropKey)
{
    otError error = OT_ERROR_NONE;

    switch (aPropKey)
    {
    case kPropZigguratEnable:
    {
        bool enable = false;

        SuccessOrExit(error = mDecoder.ReadBool(enable));
        // Enable-once: there is no detach. Switching the firmware back to plain-RCP
        // use is a reset (which clients perform per-session anyway).
        VerifyOrExit(enable, error = OT_ERROR_INVALID_ARGS);
        ziggurat_glue_start();
        break;
    }

    case kPropZigguratStream:
    {
        const uint8_t *data = nullptr;
        uint16_t       len  = 0;

        SuccessOrExit(error = mDecoder.ReadDataWithLen(data, len));
        VerifyOrExit(ziggurat_glue_started(), error = OT_ERROR_INVALID_STATE);
        ziggurat_host_frame(data, len);
        break;
    }

    default:
        error = OT_ERROR_NOT_FOUND;
        break;
    }

exit:
    return error;
}

} // namespace Ncp
} // namespace ot

#endif // OPENTHREAD_ENABLE_NCP_VENDOR_HOOK
