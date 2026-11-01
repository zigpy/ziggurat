#!/bin/sh
# Build the ESP32-C6 unified OpenThread RCP + embedded Ziggurat firmware.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ZIGGURAT="$(cd "$HERE/../.." && pwd)"
IDF_PATH="${IDF_PATH:-$HOME/esp-idf}"
export IDF_PATH
RUST_TARGET=riscv32imac-unknown-none-elf

[ -f "$IDF_PATH/export.sh" ] || {
    echo "ESP-IDF not found at $IDF_PATH (set IDF_PATH)" >&2
    exit 1
}

# 1. The Rust stack as a RISC-V staticlib (also regenerates include/ziggurat.h).
rustup target add "$RUST_TARGET" 2>/dev/null
(cd "$ZIGGURAT/crates/ziggurat-ot" && cargo build --release --target "$RUST_TARGET" --features esp-idf)

# 2. Project-local override of the IDF openthread component: a copy with patches/
#    applied and the ziggurat NCP hook and glue dropped in. The openthread
#    submodule and prebuilt libs are symlinked, not copied.
OT_SRC="$IDF_PATH/components/openthread"
OT_DST="$HERE/components/openthread"
rm -rf "$OT_DST"
mkdir -p "$OT_DST"
for entry in "$OT_SRC"/*; do
    name="$(basename "$entry")"
    case "$name" in
    openthread | lib) ln -s "$entry" "$OT_DST/$name" ;;
    *) cp -R "$entry" "$OT_DST/$name" ;;
    esac
done

# Deliberate edits to the copied component live in patches/ (unified diffs rooted
# at the component). A rejected hunk means ESP-IDF changed shape: fix the patch.
for patch_file in "$HERE"/patches/*.patch; do
    patch -p1 -d "$OT_DST" --no-backup-if-mismatch < "$patch_file"
done

cp "$ZIGGURAT/firmwares/glue/ziggurat_ncp.cpp" "$OT_DST/src/ncp/esp_openthread_ncp_hdlc.cpp"
# The platform glue (shared with the EFR32 build) compiles inside the component:
# it uses OT core C++ headers (ot::Timer, ot::Tasklet, ot::Crypto).
cp "$ZIGGURAT/firmwares/glue/ziggurat_glue.cpp" "$OT_DST/src/ncp/ziggurat_glue.cpp"

# 3. The IDF build.
. "$IDF_PATH/export.sh" >/dev/null
cd "$HERE"
[ -f sdkconfig ] || idf.py set-target esp32c6
idf.py build

echo
echo "flash with: cd $HERE && idf.py -p <port> flash"
