#!/usr/bin/env bash

set -euo pipefail

HIFHE_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-}
HIFHE_PROVIDER_DIR=${HIFHE_PROVIDER_DIR:-"${HIFHE_ROOT_DIR}/build"}
RUN_TESTS=""
HIFHE_ENABLE_ASAN=OFF
HIFHE_ENABLE_GCOV=OFF
HIFHE_PROVIDER_FEATURE=""

if [[ -z "${HITLS_ROOT_DIR}" && -f "${HIFHE_PROVIDER_DIR}/base_path.txt" ]]; then
    HITLS_ROOT_DIR=$(<"${HIFHE_PROVIDER_DIR}/base_path.txt")
fi
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-"${HIFHE_ROOT_DIR}/platform/openhitls"}

while [[ $# -gt 0 ]]; do
    case "$1" in
        asan) HIFHE_ENABLE_ASAN=ON; shift ;;
        gcov) HIFHE_ENABLE_GCOV=ON; shift ;;
        --enable|--disable)
            [[ $# -ge 2 ]] || { echo "Missing feature" >&2; exit 1; }
            [[ "$1" == "--enable" ]] && STATE=ON || STATE=OFF
            case "${2,,}" in
                provider) HIFHE_PROVIDER_FEATURE=${STATE} ;;
                *) echo "Unknown feature: $2" >&2; exit 1 ;;
            esac
            shift 2
            ;;
        run-tests=*) RUN_TESTS=${1#run-tests=}; shift ;;
        list-suites)
            find "${HIFHE_ROOT_DIR}/testcode/sdv" -name '*.data' -printf '%f\n' | sed 's/\.data$//'
            exit 0
            ;;
        clean)
            rm -f "${HIFHE_ROOT_DIR}/testcode/output/"test_suite*
            exit 0
            ;;
        -h|--help)
            echo "Usage: $0 [asan] [gcov] [--enable|--disable provider] [run-tests=name|name] [list-suites] [clean]"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

CMAKE_PROVIDER_ARGS=()
if [[ -n "${HIFHE_PROVIDER_FEATURE}" ]]; then
    CMAKE_PROVIDER_ARGS+=("-DHITLS_PROVIDER=${HIFHE_PROVIDER_FEATURE}")
fi

TEST_SUITES=""
if [[ -n "${RUN_TESTS}" ]]; then
    IFS='|' read -ra NAMES <<< "${RUN_TESTS}"
    for NAME in "${NAMES[@]}"; do
        SUITE=$(find "${HIFHE_ROOT_DIR}/testcode/sdv" -name "${NAME}.data" -print -quit)
        [[ -n "${SUITE}" ]] || { echo "Test not found: ${NAME}" >&2; exit 1; }
        TEST_SUITES+="${SUITE%.data} "
    done
else
    while IFS= read -r SUITE; do
        TEST_SUITES+="${SUITE%.data} "
    done < <(find "${HIFHE_ROOT_DIR}/testcode/sdv" -name '*.data' -print)
fi

cmake -S "${HIFHE_ROOT_DIR}" -B "${HIFHE_PROVIDER_DIR}" \
    -DHITLS_ROOT_PATH="${HITLS_ROOT_DIR}" \
    -DHIFHE_BUILD_TESTS=ON \
    -DHIFHE_ENABLE_ASAN="${HIFHE_ENABLE_ASAN}" \
    -DHIFHE_ENABLE_GCOV="${HIFHE_ENABLE_GCOV}" \
    "${CMAKE_PROVIDER_ARGS[@]}" \
    -DGEN_TEST_FILES="${TEST_SUITES}"
cmake --build "${HIFHE_PROVIDER_DIR}" --parallel
