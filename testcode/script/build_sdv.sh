#!/usr/bin/env bash

set -euo pipefail

HIFHE_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-}
HITLS_LIB_DIR=${HITLS_LIB_DIR:-}
HIFHE_PROVIDER_DIR=${HIFHE_PROVIDER_DIR:-"${HIFHE_ROOT_DIR}/testcode/build"}
BUILD_ARGS=""
LINK_ARGS=""
CMAKE_OVERRIDE_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        debug) CMAKE_OVERRIDE_ARGS+=("-DCMAKE_BUILD_TYPE=Debug"); shift ;;
        asan)
            BUILD_ARGS="${BUILD_ARGS} -fsanitize=address -fno-omit-frame-pointer"
            LINK_ARGS="${LINK_ARGS} -fsanitize=address"
            shift
            ;;
        gcov)
            BUILD_ARGS="${BUILD_ARGS} --coverage"
            LINK_ARGS="${LINK_ARGS} --coverage"
            shift
            ;;
        add-options=*) BUILD_ARGS="${BUILD_ARGS} ${1#add-options=}"; shift ;;
        --enable|--disable)
            [[ $# -ge 2 ]] || { echo "Missing feature" >&2; exit 1; }
            [[ "$1" == "--enable" ]] && STATE=ON || STATE=OFF
            case "${2,,}" in
                err) MACRO=HIFHE_ERR ;;
                custom-param) MACRO=HIFHE_CUSTOM_PARAM ;;
                provider) MACRO=HITLS_PROVIDER ;;
                int128) MACRO=HIFHE_INT128 ;;
                *) echo "Unknown feature: $2" >&2; exit 1 ;;
            esac
            CMAKE_OVERRIDE_ARGS+=("-D${MACRO}=${STATE}")
            shift 2
            ;;
        list-suites)
            find "${HIFHE_ROOT_DIR}/testcode/sdv" -name '*.data' -printf '%f\n' | sed 's/\.data$//'
            exit 0
            ;;
        clean)
            rm -f "${HIFHE_ROOT_DIR}/testcode/output/"test_suite*
            exit 0
            ;;
        -h|--help)
            echo "Usage: $0 [debug] [asan] [gcov] [add-options=FLAGS] [--enable|--disable err|custom-param|provider|int128] [list-suites] [clean]"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

HIFHE_BUILD_CACHE="${HIFHE_ROOT_DIR}/build/CMakeCache.txt"
HITLS_CACHED_ROOT=""
if [[ -f "${HIFHE_BUILD_CACHE}" ]]; then
    HITLS_CACHED_ROOT=$(sed -n 's/^HITLS_ROOT_PATH:PATH=//p' "${HIFHE_BUILD_CACHE}")
fi
HITLS_ROOT_DIR=$(realpath "${HITLS_ROOT_DIR:-${HITLS_CACHED_ROOT:-"${HIFHE_ROOT_DIR}/platform/openhitls"}}")
if [[ -z "${HITLS_LIB_DIR}" && "${HITLS_ROOT_DIR}" -ef "${HITLS_CACHED_ROOT}" ]]; then
    HITLS_LIB_DIR=$(sed -n 's/^HITLS_LIB_DIR:PATH=//p' "${HIFHE_BUILD_CACHE}")
fi
HITLS_LIB_DIR=$(realpath "${HITLS_LIB_DIR:-"${HITLS_ROOT_DIR}/build"}")

HIFHE_CONFIG_HEADER="${HIFHE_ROOT_DIR}/build/include/hifhe_config.h"
CMAKE_ARGS=()
if [[ -f "${HIFHE_CONFIG_HEADER}" ]]; then
    for MACRO in HIFHE_CUSTOM_PARAM HIFHE_ERR HIFHE_INT128 HITLS_PROVIDER; do
        if grep -Eq "^#define[[:space:]]+${MACRO}([[:space:]]|$)" "${HIFHE_CONFIG_HEADER}"; then
            VALUE=ON
        else
            VALUE=OFF
        fi
        CMAKE_ARGS+=("-D${MACRO}=${VALUE}")
    done
fi
if [[ -f "${HIFHE_BUILD_CACHE}" ]]; then
    while IFS= read -r ENTRY; do
        CMAKE_ARGS+=("-D${ENTRY%%:*}=${ENTRY#*=}")
    done < <(grep -E '^(CMAKE_BUILD_TYPE|HIFHE_BUILD_SHARED|HIFHE_BUILD_STATIC):' "${HIFHE_BUILD_CACHE}")
fi
rm -f "${HIFHE_ROOT_DIR}/testcode/output/"test_suite*
cmake -S "${HIFHE_ROOT_DIR}/testcode" -B "${HIFHE_PROVIDER_DIR}" \
    -DHITLS_ROOT_PATH="${HITLS_ROOT_DIR}" \
    -DBUILD_DEMO=ON \
    -DHITLS_LIB_DIR="${HITLS_LIB_DIR}" \
    -UHITLS_CRYPTO_LIB -UHITLS_BSL_LIB \
    -DCMAKE_C_FLAGS="${BUILD_ARGS}" \
    -DCMAKE_EXE_LINKER_FLAGS="${LINK_ARGS}" \
    -DCMAKE_SHARED_LINKER_FLAGS="${LINK_ARGS}" \
    "${CMAKE_ARGS[@]}" "${CMAKE_OVERRIDE_ARGS[@]}"
cmake --build "${HIFHE_PROVIDER_DIR}" --target hifhe_testcode --parallel
