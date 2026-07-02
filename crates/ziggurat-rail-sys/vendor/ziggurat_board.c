// Accessors that surface the board's compile-time RF config macros to Rust, so the values
// live in the vendored SLC config headers (per board) rather than being duplicated in the
// Rust source. Retargeting a board is then just a config-header swap.
#include <stdint.h>

#include "sl_rail_util_pa_config.h"

uint16_t ziggurat_pa_voltage_mv(void) {
  return SL_RAIL_UTIL_PA_VOLTAGE_MV;
}

uint16_t ziggurat_pa_ramp_time_us(void) {
  return SL_RAIL_UTIL_PA_RAMP_TIME_US;
}
