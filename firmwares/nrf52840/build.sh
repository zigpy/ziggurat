#!/bin/sh
# Build the nRF52840 Dongle (PCA10059) unified OpenThread RCP + embedded Ziggurat firmware.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ZIGGURAT="$(cd "$HERE/../.." && pwd)"
OT_NRF="${OT_NRF:-$HOME/Projects/ot-nrf528xx}"
RUST_TARGET=thumbv7em-none-eabihf
BUILD="$HERE/build"

[ -x "$OT_NRF/script/build" ] || {
    echo "ot-nrf528xx not found at $OT_NRF (set OT_NRF)" >&2
    exit 1
}

# 1. The Rust stack as a Cortex-M4F staticlib (also regenerates include/ziggurat.h).
(cd "$ZIGGURAT/crates/ziggurat-ot" && cargo build --release --target "$RUST_TARGET" --features nrf52)

# 2. ot-rcp with USB CDC transport, linked for the Dongle's USB DFU bootloader.
cd "$OT_NRF"
OT_CMAKE_BUILD_DIR="$BUILD" OT_CMAKE_NINJA_TARGET=ot-rcp ./script/build nrf52840 USB_trans \
    -DOT_BOOTLOADER=USB \
    -DOT_NCP_VENDOR_HOOK_SOURCE="$HERE/ziggurat_vendor_hook.cpp" \
    -DCMAKE_PROJECT_ot-nrf528xx_INCLUDE="$HERE/ziggurat.cmake"

# 3. A DFU package for the Dongle's bootloader.
arm-none-eabi-objcopy -O ihex "$BUILD/bin/ot-rcp" "$BUILD/ot-rcp.hex"
nrfutil nrf5sdk-tools pkg generate --hw-version 52 --sd-req 0x00 \
    --application "$BUILD/ot-rcp.hex" --application-version 1 "$BUILD/ot-rcp.zip"

echo
echo "flash: press the Dongle's RESET button (red LED pulses), then"
echo "  nrfutil nrf5sdk-tools dfu usb-serial -pkg $BUILD/ot-rcp.zip -p <port>"
