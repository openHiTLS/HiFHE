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
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD=${HIFHE_BUILD_DIR:-"${ROOT}/build"}
HITLS=${HITLS_ROOT_DIR:-"${ROOT}/platform/openhitls"}
OUT=${CT_OUTPUT_DIR:-"${ROOT}/testcode/build/constant-time"}
MODE=${1:---taint}
mkdir -p "${OUT}"
FLAGS=()
case "${MODE}" in
    --taint)
        FLAGS+=(-DHIFHE_CT_VALGRIND)
        if [[ -n "${VALGRIND_INCLUDE_DIR:-}" ]]; then
            FLAGS+=("-I${VALGRIND_INCLUDE_DIR}")
        fi
        ;;
    --timing) ;;
    *) echo "Usage: $0 [--taint|--timing]" >&2; exit 2 ;;
esac
"${CC:-cc}" -std=c11 -O2 -g -Wall -Wextra -Werror -fno-strict-aliasing \
    "${FLAGS[@]}" \
    -I"${ROOT}/include" -I"${BUILD}/include" -I"${ROOT}/src/common" \
    -I"${ROOT}/src/bgv/include" -I"${ROOT}/src/bgv/src" -I"${ROOT}/src/bgv/src/include" \
    -I"${HITLS}/include/crypto" -I"${HITLS}/include/bsl" \
    "${ROOT}/testcode/ct/ct_bgv.c" "${BUILD}/libhifhe.a" \
    -L"${HITLS}/build" -Wl,-rpath,"${HITLS}/build" \
    -lhitls_crypto -lhitls_bsl -lm -lpthread -o "${OUT}/ct_bgv"
# Archive the actual Release objects as well as the compiler and flags.
"${CC:-cc}" --version > "${OUT}/compiler.txt"
cp "${BUILD}/CMakeCache.txt" "${OUT}/CMakeCache.txt"
objdump -dr "${BUILD}/libhifhe.a" > "${OUT}/release-assembly.txt"
if [[ "${MODE}" == --taint ]]; then
    DEBUG_FLAGS=()
    if [[ -n "${VALGRIND_EXTRA_DEBUG_DIR:-}" ]]; then
        DEBUG_FLAGS+=("--extra-debuginfo-path=${VALGRIND_EXTRA_DEBUG_DIR}")
    fi
    "${VALGRIND:-valgrind}" "${DEBUG_FLAGS[@]}" --tool=memcheck --track-origins=yes \
        --error-exitcode=99 --log-file="${OUT}/taint.log" "${OUT}/ct_bgv"
else
    "${OUT}/ct_bgv" --timing | tee "${OUT}/timing.log"
fi
