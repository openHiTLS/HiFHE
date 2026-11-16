# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.16)
project(HiFHETest C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

get_filename_component(HIFHE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
if(NOT DEFINED HIFHE_CUSTOM_PARAM)
    set(HIFHE_CUSTOM_PARAM ON CACHE BOOL "Enable custom parameters in test builds")
endif()
if(NOT DEFINED HITLS_PROVIDER)
    set(HITLS_PROVIDER ON CACHE BOOL "Enable Provider integration in test builds")
endif()
add_subdirectory("${HIFHE_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/hifhe")

set(HIFHE_CONFIG_DIR "${CMAKE_BINARY_DIR}/include")
set(HITLS_ROOT_DIR "${HITLS_ROOT_PATH}")
get_property(HIFHE_OBJECT_TARGETS GLOBAL PROPERTY HIFHE_OBJECT_TARGETS)
foreach(OBJECT_TARGET ${HIFHE_OBJECT_TARGETS})
    list(APPEND HIFHE_OBJECTS $<TARGET_OBJECTS:${OBJECT_TARGET}>)
endforeach()
find_package(Threads REQUIRED)
add_compile_options(-Wall -Wextra -Werror -Wno-enum-conversion)

include(ExternalProject)
ExternalProject_Add(gen_testcase
    SOURCE_DIR "${HIFHE_ROOT}/testcode/framework/gen_test"
    BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/gen_testcase"
    CONFIGURE_COMMAND ${CMAKE_COMMAND}
        -DHITLS_ROOT_DIR=${HITLS_ROOT_DIR}
        -DPRINT_TO_TERMINAL=ON
        <SOURCE_DIR>
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR>
    INSTALL_COMMAND ""
    UPDATE_COMMAND ""
    EXCLUDE_FROM_ALL TRUE
)

add_custom_target(hifhe_testcode)

option(BUILD_DEMO "Build the demos alongside the test suites" OFF)

add_subdirectory(sdv)
if(BUILD_DEMO)
    add_subdirectory(demo)
endif()
