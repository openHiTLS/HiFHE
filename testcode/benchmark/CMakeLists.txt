# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(HiFHEBenchmark C)

get_filename_component(HIFHE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
# The shared library setup uses PROJECT_SOURCE_DIR for library include paths.
set(PROJECT_SOURCE_DIR "${HIFHE_ROOT}")
list(APPEND CMAKE_MODULE_PATH "${HIFHE_ROOT}/cmake")
include(GNUInstallDirs)
set(HIFHE_CUSTOM_PARAM ON CACHE BOOL "Build full benchmark features" FORCE)
set(HITLS_PROVIDER ON CACHE BOOL "Build benchmark provider operations" FORCE)
include(hifhe_options)
include(hifhe_dependencies)
include(hifhe_generate_config)
include(hifhe_build_options)
include(hifhe_helpers)
add_subdirectory("${HIFHE_ROOT}/src" "${CMAKE_CURRENT_BINARY_DIR}/src")
get_property(HIFHE_OBJECT_TARGETS GLOBAL PROPERTY HIFHE_OBJECT_TARGETS)
foreach(OBJECT_TARGET ${HIFHE_OBJECT_TARGETS})
    list(APPEND HIFHE_OBJECTS $<TARGET_OBJECTS:${OBJECT_TARGET}>)
endforeach()

add_executable(hifhe_benchmark benchmark.c bgv_bench.c ${HIFHE_OBJECTS})
target_include_directories(hifhe_benchmark PRIVATE
    ${PROJECT_SOURCE_DIR}/src/bgv/include
    ${PROJECT_SOURCE_DIR}/src/bgv/src
    ${PROJECT_SOURCE_DIR}/src/bgv/src/include
    ${HITLS_ROOT_PATH}/config/macro_config
    ${HITLS_ROOT_PATH}/crypto/include)
target_compile_options(hifhe_benchmark PRIVATE -O2 -g
    -include "${PROJECT_SOURCE_DIR}/src/common/bgv_adapter_types.h")
target_link_libraries(hifhe_benchmark PRIVATE _hifhe_public_headers _hifhe_compile_options
    ${HITLS_CRYPTO_LIB} ${HITLS_BSL_LIB} pthread m)
set_target_properties(hifhe_benchmark PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/testcode/output"
    BUILD_RPATH "${HITLS_LIB_DIR}")
