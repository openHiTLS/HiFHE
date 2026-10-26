# HiFHE

HiFHE is a homomorphic-encryption provider library for openHiTLS. It currently
provides CKKS and BGV.

## Features

- One `libhifhe.so` provides a native C API and an openHiTLS Provider.
- Opaque `HIFHE_Ctx` and `HIFHE_HEText` types in [hifhe.h](include/hifhe.h).
  Compute with objects; serialize for transport.
- BGV: presets, integer encoding, key generation, encryption/decryption, addition,
  ciphertext/plaintext multiplication, negation, and rerandomization.
- Custom parameter objects, key import/export, and ciphertext/ciphertext
  multiplication are omitted from the public API.
- CKKS: existing Provider complex-vector encryption/decryption is retained;
  native CKKS presets and complex encoding are unavailable.
- Random and Hash/XOF operations use the built-in openHiTLS implementation.

Initialize openHiTLS before using HiFHE, as shown in the demos. The native demo
initializes CPU, BSL, and RAND; the Provider demo also initializes its framework.
Algorithm internals retain their original randomness, sampling, and encryption code.

## Build

Requirements: CMake 3.16 or newer, a C11 compiler, and openHiTLS. The helper
script clones and builds openHiTLS when `--hitls_dir` is omitted. By default it
builds both `libhifhe.so` and `libhifhe.a`.

```sh
bash testcode/script/build_hifhe.sh
```

Use an existing openHiTLS checkout:

```sh
bash testcode/script/build_hifhe.sh --hitls_dir /path/to/openHiTLS
# This workspace:
bash testcode/script/build_hifhe.sh --hitls_dir /usr1/cq/openhitls/openhitls
```

Build one library type:

```sh
bash testcode/script/build_hifhe.sh shared
bash testcode/script/build_hifhe.sh static
```

Use CMake directly with an already-built openHiTLS checkout:

```sh
cmake -S . -B build \
    -DHITLS_ROOT_PATH=/path/to/openHiTLS \
    -DHITLS_LIB_DIR=/path/to/openHiTLS/build \
    -DHIFHE_BUILD_SHARED=ON \
    -DHIFHE_BUILD_STATIC=ON \
    -DHIFHE_CKKS=ON \
    -DHIFHE_BGV=ON \
    -DHIFHE_ENABLE_ASAN=OFF \
    -DHIFHE_ENABLE_GCOV=OFF
cmake --build build --parallel
```

CMake options:

| Variable | Default | Description |
| --- | --- | --- |
| `HITLS_ROOT_PATH` | `platform/openhitls` | openHiTLS source directory |
| `HITLS_LIB_DIR` | `${HITLS_ROOT_PATH}/build` | `hitls_crypto` and `hitls_bsl` directory |
| `HIFHE_BUILD_SHARED` | `ON` | Build `libhifhe.so` |
| `HIFHE_BUILD_STATIC` | `ON` | Build `libhifhe.a` |
| `HIFHE_CKKS` | `ON` | Compile CKKS into the provider |
| `HIFHE_BGV` | `ON` | Compile BGV into the provider |
| `HITLS_PROVIDER` | `ON` | Build openHiTLS Provider integration |
| `HIFHE_BUILD_TESTS` | `OFF` | Build native tests and internal regressions |
| `HIFHE_ENABLE_ASAN` | `OFF` | Enable AddressSanitizer |
| `HIFHE_ENABLE_GCOV` | `OFF` | Enable coverage |

At least one library type must be enabled. CKKS and BGV can be selected
independently:

```sh
bash testcode/script/build_hifhe.sh --enable ckks
bash testcode/script/build_hifhe.sh --disable ckks
bash testcode/script/build_hifhe.sh --enable bgv
bash testcode/script/build_hifhe.sh --disable bgv
bash testcode/script/build_hifhe.sh --disable provider
```

`HIFHE_CKKS=OFF` or `HIFHE_BGV=OFF` excludes the corresponding sources and
records the result in the generated `build/include/hifhe_config.h`.

Install with `cmake --install build --prefix /path/to/prefix`.

Provider applications using the installed SDK must define `HITLS_PROVIDER`
when compiling and add the openHiTLS header paths:

```sh
cc -DHITLS_PROVIDER -I/path/to/prefix/include \
    -I/path/to/openHiTLS/include/crypto -I/path/to/openHiTLS/include/bsl -c app.c
```

This exposes Provider attributes, parameter keys, and the initialization
declaration; it does not enable Provider support in a library built without it.
Applications linking the `hifhe_provider` CMake target through `add_subdirectory`
inherit this definition when Provider support is enabled. Native applications
using the installed SDK do not need this definition.

## Test

All tests use the shared SDV assertions and runner, with `.c + .data` files under `testcode/sdv`.
Set `-DHIFHE_BUILD_TESTS=ON` to build all suites supported by the selected features:

```sh
cmake -S . -B build -DHIFHE_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Public API tests link the production library, kernel tests link implementation objects,
and Provider tests load the production library dynamically. The scripts run the same suites:

```sh
bash testcode/script/build_sdv.sh
bash testcode/script/execute_sdv.sh
```

Separate Provider and native API demos cover one encryption, a server with no
keys, byte transport, and client decryption:

```sh
bash testcode/script/build_demo.sh
./testcode/output/demo/hifhe_leakstr_demo         # Provider
./testcode/output/demo/hifhe_leakstr_native_demo  # Native API
```

Random and Hash operations use the built-in openHiTLS implementation.

Native parameters use `HIFHE_SetParaById`; custom parameter objects and key
import/export are omitted. `HIFHE_Mul` supports ciphertext/plaintext products.
Native APIs do not use `BSL_Param`. `-DHITLS_PROVIDER=OFF` removes the Provider, BSL adapters,
and their tests.
