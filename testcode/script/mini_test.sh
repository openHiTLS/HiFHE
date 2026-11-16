#!/usr/bin/env bash
# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set -euo pipefail

HIFHE_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hitls_dir)
            [[ $# -ge 2 && -d "$2" ]] || { echo "Invalid openHiTLS directory" >&2; exit 1; }
            HITLS_ROOT_DIR=$(realpath "$2")
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--hitls_dir PATH]"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "${HITLS_ROOT_DIR}" && -f "${HIFHE_ROOT_DIR}/build/base_path.txt" ]]; then
    HITLS_ROOT_DIR=$(<"${HIFHE_ROOT_DIR}/build/base_path.txt")
fi
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-"${HIFHE_ROOT_DIR}/platform/openhitls"}
if [[ ! -f "${HITLS_ROOT_DIR}/build/libhitls_crypto.so" ||
      ! -f "${HITLS_ROOT_DIR}/build/libhitls_bsl.so" ]]; then
    echo "openHiTLS shared libraries not found under ${HITLS_ROOT_DIR}/build" >&2
    exit 1
fi

MINI_BUILD_ROOT="${HIFHE_ROOT_DIR}/testcode/build/mini-test"
# Add trim features here; cover each alone, each disabled, and all disabled.
FEATURES=(HIFHE_ERR HIFHE_CUSTOM_PARAM HITLS_PROVIDER)
FULL_CONFIG=()
ALL_OFF_CONFIG=()
for _ in "${FEATURES[@]}"; do
    FULL_CONFIG+=(ON)
    ALL_OFF_CONFIG+=(OFF)
done
CONFIGS=("${ALL_OFF_CONFIG[*]}")
for i in "${!FEATURES[@]}"; do
    CONFIG=("${FULL_CONFIG[@]}")
    CONFIG[$i]=OFF
    CONFIGS+=("${CONFIG[*]}")
    CONFIG=("${ALL_OFF_CONFIG[@]}")
    CONFIG[$i]=ON
    if [[ "${CONFIG[*]}" != "${FULL_CONFIG[*]}" ]]; then
        CONFIGS+=("${CONFIG[*]}")
    fi
done
mapfile -t CONFIGS < <(printf '%s\n' "${CONFIGS[@]}" | sort -u)
declare -A SIZES=()
rm -rf "${MINI_BUILD_ROOT}"

build_and_run()
{
    local states=("$@")
    local build_dir="${MINI_BUILD_ROOT}"
    local label=""
    local -a feature_args=()

    for i in "${!FEATURES[@]}"; do
        local feature_label=${FEATURES[$i]#*_}
        feature_label=${feature_label,,}
        feature_label=${feature_label//_/-}
        label+="${label:+ }${feature_label}=${states[$i]}"
        feature_args+=("-D${FEATURES[$i]}=${states[$i]}")
    done
    echo "Mini test: ${label}"
    rm -f "${HIFHE_ROOT_DIR}/testcode/output/"test_suite*
    cmake -S "${HIFHE_ROOT_DIR}/testcode" -B "${build_dir}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
        -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
        -DHITLS_ROOT_PATH="${HITLS_ROOT_DIR}" \
        -DHIFHE_BUILD_SHARED=ON \
        -DHIFHE_BUILD_STATIC=OFF \
        -DBUILD_DEMO=ON \
        "${feature_args[@]}"
    cmake --build "${build_dir}" --target hifhe_testcode --parallel
    HITLS_ROOT_DIR="${HITLS_ROOT_DIR}" HIFHE_PROVIDER_DIR="${build_dir}" \
        bash "${HIFHE_ROOT_DIR}/testcode/script/execute_sdv.sh"

    SIZES["${states[*]}"]=$(wc -c < "${build_dir}/libhifhe.so")
}

for config in "${CONFIGS[@]}"; do
    read -r -a states <<< "${config}"
    build_and_run "${states[@]}"
done

printf 'libhifhe.so bytes (ASan):\n'
for config in "${CONFIGS[@]}"; do
    read -r -a states <<< "${config}"
    key="${states[*]}"
    label=""
    for i in "${!FEATURES[@]}"; do
        feature_label=${FEATURES[$i]#*_}
        feature_label=${feature_label,,}
        feature_label=${feature_label//_/-}
        label+="${label:+ }${feature_label}=${states[$i]}"
    done
    printf '%s %s\n' "${label}" "${SIZES["${key}"]}"
done
ALL_OFF_KEY="${ALL_OFF_CONFIG[*]}"
for config in "${CONFIGS[@]}"; do
    if [[ "${config}" == "${ALL_OFF_KEY}" ]]; then
        continue
    fi
    if (( ${SIZES["${ALL_OFF_KEY}"]} >= ${SIZES["${config}"]} )); then
        echo "All trimming features disabled did not reduce libhifhe.so compared with ${config}" >&2
        exit 1
    fi
done
