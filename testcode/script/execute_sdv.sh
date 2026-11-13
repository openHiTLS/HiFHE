#!/usr/bin/env bash

set -euo pipefail

HIFHE_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HIFHE_PROVIDER_DIR=${HIFHE_PROVIDER_DIR:-"${HIFHE_ROOT_DIR}/build"}
if [[ $# -gt 0 ]]; then
    IFS='|' read -ra SUITES <<< "$1"
    for SUITE in "${SUITES[@]}"; do
        ctest --test-dir "${HIFHE_PROVIDER_DIR}" --verbose --output-on-failure --no-tests=error -L sdv -R "^${SUITE}$" 2>&1 |
            sed -u -E '/^[0-9]+: (Test command:|Working Directory:|Environment variables:)/d; /^[0-9]+:  (LD_LIBRARY_PATH|HIFHE_PROVIDER_PATH|ASAN_OPTIONS)=/d'
    done
else
    ctest --test-dir "${HIFHE_PROVIDER_DIR}" --verbose --output-on-failure --no-tests=error -L sdv 2>&1 |
        sed -u -E '/^[0-9]+: (Test command:|Working Directory:|Environment variables:)/d; /^[0-9]+:  (LD_LIBRARY_PATH|HIFHE_PROVIDER_PATH|ASAN_OPTIONS)=/d'
fi
