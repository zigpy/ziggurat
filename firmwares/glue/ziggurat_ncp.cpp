/*
 * Ziggurat NCP vendor hook.
 *
 * Compiled with OPENTHREAD_ENABLE_NCP_VENDOR_HOOK=1: NCP construction and the
 * vendor Spinel property range belong to this file. On the Silabs build this
 * also provides otAppNcpInit over otPlatUart (conflicting with the Silabs
 * ot_ncp_vendor_extension component); on ESP-IDF, Espressif's otAppNcpInit and
 * transport are reused and only otNcpHdlcInit is replaced.
 *
 * One property:
 *   +0x20 ZIGGURAT  GET (empty value) is the presence probe; a plain RCP returns
 *                   PROP_NOT_FOUND instead. SET tunnels one binary control frame,
 *                   starting the embedded stack on first use. Unsolicited VALUE_IS
 *                   carries frames back to the host. The firmware version lives in
 *                   the binary protocol (get_firmware_info / hello), not here.
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

static constexpr spinel_prop_key_t kPropZiggurat =
    static_cast<spinel_prop_key_t>(SPINEL_PROP_VENDOR__BEGIN + 346);  // 0x3D5A

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

        SuccessOrExit(error = mEncoder.BeginFrame(header, SPINEL_CMD_PROP_VALUE_IS, kPropZiggurat));
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
    return aPropKey == kPropZiggurat ? OT_ERROR_NONE : OT_ERROR_NOT_FOUND;
}

otError NcpBase::VendorSetPropertyHandler(spinel_prop_key_t aPropKey)
{
    otError error = OT_ERROR_NONE;

    switch (aPropKey)
    {
    case kPropZiggurat:
    {
        const uint8_t *data = nullptr;
        uint16_t       len  = 0;

        SuccessOrExit(error = mDecoder.ReadDataWithLen(data, len));
        // Start the embedded stack on first use (idempotent), then tunnel the frame.
        // The stack stays started until a reset; a plain-RCP host never writes here.
        ziggurat_glue_start();
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
