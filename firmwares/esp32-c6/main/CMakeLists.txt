idf_component_register(SRCS "esp_ziggurat_rcp.c"
                       INCLUDE_DIRS "."
                       PRIV_REQUIRES openthread nvs_flash esp_event vfs)

# The embedded Rust stack; its ziggurat_* entry points are called from the
# openthread component override, its ziggurat_platform_* imports resolve there.
add_prebuilt_library(ziggurat_ot
    "${CMAKE_CURRENT_LIST_DIR}/../../../crates/ziggurat-ot/target/riscv32imac-unknown-none-elf/release/libziggurat_ot.a")
target_link_libraries(${COMPONENT_LIB} PUBLIC ziggurat_ot)
