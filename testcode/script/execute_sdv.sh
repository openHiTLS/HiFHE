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
HIFHE_PROVIDER_DIR=$(realpath "${HIFHE_PROVIDER_DIR:-"${HIFHE_ROOT_DIR}/testcode/build"}")
TEST_OUTPUT_DIR="${HIFHE_ROOT_DIR}/testcode/output"
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-}
if [[ -z "${HITLS_ROOT_DIR}" && -f "${HIFHE_PROVIDER_DIR}/CMakeCache.txt" ]]; then
    HITLS_ROOT_DIR=$(sed -n 's/^HITLS_ROOT_PATH:PATH=//p' "${HIFHE_PROVIDER_DIR}/CMakeCache.txt")
fi
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-"${HIFHE_ROOT_DIR}/platform/openhitls"}
HITLS_LIB_DIR=${HITLS_LIB_DIR:-}
if [[ -z "${HITLS_LIB_DIR}" && -f "${HIFHE_PROVIDER_DIR}/CMakeCache.txt" ]]; then
    HITLS_LIB_DIR=$(sed -n 's/^HITLS_LIB_DIR:PATH=//p' "${HIFHE_PROVIDER_DIR}/CMakeCache.txt")
fi
HITLS_LIB_DIR=$(realpath "${HITLS_LIB_DIR:-"${HITLS_ROOT_DIR}/build"}")

if [[ ! -d "${TEST_OUTPUT_DIR}" ]]; then
    echo "SDV output directory not found; run build_sdv.sh first" >&2
    exit 1
fi

export LD_LIBRARY_PATH="${HIFHE_PROVIDER_DIR}:${HITLS_LIB_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export HIFHE_PROVIDER_PATH="${HIFHE_PROVIDER_DIR}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1}"
cd "${TEST_OUTPUT_DIR}"
rm -f result.log result.xml tmp.txt asan.log* log/*

status=0
RUN_ALL=1
if [[ $# -gt 0 ]]; then
    RUN_ALL=0
    IFS='|' read -ra SUITES <<< "$1"
else
    mapfile -t SUITES < <(find . -maxdepth 1 -type f -executable -name 'test_suite*' -printf '%f\n' | sort)
fi

if [[ ${#SUITES[@]} -eq 0 ]]; then
    echo "No SDV suites found; run build_sdv.sh first" >&2
    exit 1
fi

for SUITE in "${SUITES[@]}"; do
    if [[ ! -x "./${SUITE}" ]]; then
        echo "SDV suite not found: ${SUITE}" >&2
        status=1
        continue
    fi
    echo "Running ${SUITE}"
    if ! "./${SUITE}" NO_DETAIL; then
        status=1
    fi
done

run_demo()
{
    local demo="$1"
    shift
    local output

    echo "Running $(basename "${demo}")"
    if ! output=$("${demo}" 2>&1); then
        printf '%s\n' "${output}"
        echo "Demo failed: ${demo}" >&2
        status=1
        return
    fi
    printf '%s\n' "${output}"
    for expected in "$@"; do
        if ! grep -Fqx -- "${expected}" <<< "${output}"; then
            echo "Demo output missing: ${expected}" >&2
            status=1
        fi
    done
}

run_demos()
{
    local cache="${HIFHE_PROVIDER_DIR}/CMakeCache.txt"
    local demo_dir="${TEST_OUTPUT_DIR}/demo"
    local demo
    local -a demos

    if [[ ! -f "${cache}" ]] || ! grep -qx 'BUILD_DEMO:BOOL=ON' "${cache}"; then
        return
    fi
    mapfile -t demos < <(find "${demo_dir}" -maxdepth 1 -type f -executable | sort)
    if [[ ${#demos[@]} -eq 0 ]]; then
        echo "No demos found; run build_sdv.sh first" >&2
        status=1
        return
    fi
    for demo in "${demos[@]}"; do
        case "${demo##*/}" in
            hifhe_bgv_demo) run_demo "${demo}" 'hit: index 7' 'miss: no match' ;;
            hifhe_bgv_provider_demo) run_demo "${demo}" '  find match at [7]' '  find match at [none]' ;;
            *) run_demo "${demo}" ;;
        esac
    done
}

if [[ "${RUN_ALL}" -eq 1 ]]; then
    run_demos
fi

if [[ -x ./gen_testcase ]]; then
    ./gen_testcase GenReport || status=1
fi
if [[ -f result.log ]]; then
    read -r total passed skipped < <(awk '{n++; if ($NF == "PASS") p++; else if ($NF == "SKIP") s++} END {print n+0, p+0, s+0}' result.log)
    failed=$((total - passed - skipped))
    printf 'TestCase Num is %d Pass is %d Skip is %d Fail is %d\n' \
        "${total}" "${passed}" "${skipped}" "${failed}"
    if [[ ${failed} -ne 0 ]]; then
        status=1
    fi
fi
exit "${status}"
