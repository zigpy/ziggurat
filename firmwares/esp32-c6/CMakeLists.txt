cmake_minimum_required(VERSION 3.16)

# The openthread component override assembled by build.sh shadows the IDF one.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# ziggurat.h (cbindgen-generated) and the shared glue header, visible to the
# openthread component override (which compiles the glue and the NCP vendor hook).
idf_build_set_property(COMPILE_OPTIONS "-I${CMAKE_CURRENT_LIST_DIR}/../../crates/ziggurat-ot/include" APPEND)
idf_build_set_property(COMPILE_OPTIONS "-I${CMAKE_CURRENT_LIST_DIR}/../glue" APPEND)

project(ziggurat_rcp)
