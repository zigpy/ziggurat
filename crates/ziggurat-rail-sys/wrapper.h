// bindgen entry point: the public RAIL API plus the IEEE 802.15.4 protocol layer.
#include "sl_rail.h"
#include "sl_rail_ieee802154.h"
// Clock Manager: needed to bring up HFXO (the radio reference clock) the safe way
// (enable -> wait-ready -> switch) before RAIL init.
#include "sl_clock_manager.h"
#include "sl_clock_manager_init.h"
// Hardware AES-CCM* / AES-ECB on the RADIOAES peripheral (Zigbee crypto acceleration).
#include "sli_protocol_crypto.h"
// PA / TX power configuration (needed to transmit).
#include "sl_rail_util_pa_conversions.h"
