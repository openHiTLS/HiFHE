# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set(HITLS_ROOT_PATH "${PROJECT_SOURCE_DIR}/platform/openhitls" CACHE PATH
    "openHiTLS source directory")
set(HITLS_LIB_DIR "${HITLS_ROOT_PATH}/build" CACHE PATH
    "openHiTLS library directory")

option(HIFHE_BUILD_SHARED "Build the shared provider library" ON)
option(HIFHE_BUILD_STATIC "Build the static provider library" ON)
option(HIFHE_BGV "Build BGV" ON)
option(HIFHE_ERR "Record errors in a thread-local stack" ON)
option(HIFHE_CUSTOM_PARAM "Enable custom parameters, interchange encoding and evaluation operations" ON)
option(HITLS_PROVIDER "Build openHiTLS Provider integration and BSL adapters" OFF)

include(CheckCSourceCompiles)
check_c_source_compiles("int main(void) { unsigned __int128 value = 1; return (int)value; }"
    HIFHE_COMPILER_HAS_INT128)
option(HIFHE_INT128 "Use native 128-bit integer arithmetic" ${HIFHE_COMPILER_HAS_INT128})
if(HIFHE_INT128 AND NOT HIFHE_COMPILER_HAS_INT128)
    message(FATAL_ERROR "HIFHE_INT128 is enabled, but the compiler does not support __int128")
endif()

message(STATUS "[HiFHE] HIFHE_CUSTOM_PARAM=${HIFHE_CUSTOM_PARAM} HITLS_PROVIDER=${HITLS_PROVIDER}")

if(NOT HIFHE_BGV)
    message(FATAL_ERROR "BGV is the only algorithm and cannot be disabled")
endif()

if(NOT HIFHE_BUILD_SHARED AND NOT HIFHE_BUILD_STATIC)
    message(FATAL_ERROR "At least one provider library type must be enabled")
endif()
