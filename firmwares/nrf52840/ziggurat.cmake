# Included at the end of ot-nrf528xx's project() call (CMAKE_PROJECT_ot-nrf528xx_INCLUDE).
# The targets do not exist yet at that point, so the wiring runs deferred, after the
# top-level CMakeLists.txt finishes.

get_filename_component(ZIGGURAT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

# ot-rcp is defined in another directory. A function keeps the policies in effect where
# it is defined, so this applies inside ziggurat_wire.
cmake_policy(SET CMP0079 NEW)

function(ziggurat_wire)
    target_include_directories(openthread-rcp PRIVATE
        ${ZIGGURAT_ROOT}/crates/ziggurat-ot/include
        ${ZIGGURAT_ROOT}/firmwares/glue
        ${PROJECT_SOURCE_DIR}/openthread/examples/platforms
    )
    target_compile_definitions(openthread-rcp PRIVATE ZIGGURAT_NRF52=1)

    # With USB CDC, otPlatReset defaults to a pseudo-reset: OpenThread restarts in
    # software and the USB link stays up. The embedded stack's state would survive that,
    # so every reset is a system reset.
    target_compile_definitions(openthread-${NRF_PLATFORM}-transport PRIVATE OPENTHREAD_PLATFORM_USE_PSEUDO_RESET=0)

    # The staticlib and the glue in openthread-rcp reference each other.
    target_link_libraries(ot-rcp PRIVATE
        ${ZIGGURAT_ROOT}/crates/ziggurat-ot/target/thumbv7em-none-eabihf/release/libziggurat_ot.a
        openthread-rcp
    )
endfunction()

cmake_language(DEFER DIRECTORY ${CMAKE_SOURCE_DIR} CALL ziggurat_wire)
