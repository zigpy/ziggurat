// Minimal single-user replacement for sli_radioaes_management (the SDK's full version
// pulls in PSA/mbedTLS + an OS abstraction, all gated on SLI_PSEC_THREADING which we don't
// define). sli_protocol_crypto_radioaes.c needs only these four hooks; it self-contains
// sli_radioaes_run_operation, sli_ccm_zigbee, sli_aes_crypt_ecb_radio, etc.
//
// acquire enables the RADIOAES clock (mirroring the SDK acquire). save/restore are no-ops:
// valid when the RADIOAES is not contended by RAIL. RAIL coexistence (real save/restore)
// is a later step; for now callers must not use RADIOAES concurrently with an active radio
// operation that also uses it.

#include "em_device.h"
#include "sli_radioaes_management.h"
#include "sli_protocol_crypto.h"

// No-op without SLI_PSEC_THREADING (the SDK version only sets up an OS lock in that case).
sl_status_t sli_protocol_crypto_init(void)
{
  return SL_STATUS_OK;
}

sl_status_t sli_radioaes_acquire(void)
{
#if defined(_CMU_CLKEN0_MASK)
  CMU->CLKEN0 |= CMU_CLKEN0_RADIOAES;
#endif
  CMU->RADIOCLKCTRL |= CMU_RADIOCLKCTRL_EN;

  while (RADIOAES->STATUS
         & (AES_STATUS_FETCHERBSY | AES_STATUS_PUSHERBSY | AES_STATUS_SOFTRSTBSY)) {
  }

  return SL_STATUS_OK;
}

sl_status_t sli_radioaes_release(void)
{
  return SL_STATUS_OK;
}

sl_status_t sli_radioaes_save_state(sli_radioaes_state_t *ctx)
{
  (void)ctx;
  return SL_STATUS_OK;
}

sl_status_t sli_radioaes_restore_state(sli_radioaes_state_t *ctx)
{
  (void)ctx;
  return SL_STATUS_OK;
}
