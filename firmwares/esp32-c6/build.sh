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
(cd "$ZIGGURAT/crates/ziggurat-ot" && cargo build --release --target "$RUST_TARGET")

# 2. Project-local override of the IDF openthread component: identical except the
#    NCP vendor hook is ours (Espressif's SPINEL_PROP_VENDOR_ESP_* handlers and
#    plain-NcpHdlc otNcpHdlcInit give way to the ziggurat tunnel). The openthread
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

# Espressif's NcpBase vendor handlers are the ot:: namespace tail of this file;
# compile them out (ziggurat_ncp.cpp provides ours).
python3 - "$OT_DST/src/ncp/esp_openthread_ncp.cpp" <<'EOF'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
src = path.read_text()
marker = "\nnamespace ot {"
assert src.count(marker) == 1, "esp_openthread_ncp.cpp changed shape; fix build.sh"
src = src.replace(marker, "\n#if 0 // ziggurat owns the NCP vendor hook (ziggurat_ncp.cpp)" + marker)
src += "\n#endif // ziggurat owns the NCP vendor hook\n"
path.write_text(src)
EOF

cp "$ZIGGURAT/firmwares/glue/ziggurat_ncp.cpp" "$OT_DST/src/ncp/esp_openthread_ncp_hdlc.cpp"

# The platform glue (shared with the EFR32 build) compiles inside the component:
# it uses OT core C++ headers (ot::Timer, ot::Tasklet, ot::Crypto).
cp "$ZIGGURAT/firmwares/glue/ziggurat_glue.cpp" "$OT_DST/src/ncp/ziggurat_glue.cpp"
python3 - "$OT_DST/srcs_radio.cmake" <<'EOF'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
src = path.read_text()
marker = "src/ncp/esp_openthread_ncp.cpp"
assert src.count(marker) == 1, "srcs_radio.cmake changed shape; fix build.sh"
src = src.replace(marker, marker + "\n    src/ncp/ziggurat_glue.cpp")
path.write_text(src)
EOF

# 3. The IDF build.
. "$IDF_PATH/export.sh" >/dev/null
cd "$HERE"
[ -f sdkconfig ] || idf.py set-target esp32c6
idf.py build

echo
echo "flash with: cd $HERE && idf.py -p <port> flash"
