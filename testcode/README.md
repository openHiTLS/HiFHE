# HiFHE tests

Tests use the openHiTLS generated SDV framework ported from PQCP.

Each suite has matching `.c` and `.data` files under `sdv/`.
Feature-dependent cases query the loaded provider and skip at runtime.

```sh
bash testcode/script/build_sdv.sh
bash testcode/script/build_sdv.sh run-tests=test_suite_sdv_hifhe_bgv_api
bash testcode/script/execute_sdv.sh
```

The two options are independent. Test builds default to `HIFHE_CUSTOM_PARAM=ON` and `HITLS_PROVIDER=ON`; explicit CMake `-D` settings take precedence. The benchmark script always builds full features in a separate directory.

With `HIFHE_CUSTOM_PARAM=OFF`, the `hifhe_no_custom_param` test checks the trimmed entry points;
feature-dependent SDV cases skip only operations removed by that switch.
Build benchmarks separately with `bash testcode/script/build_benchmark.sh` and
run them with `bash testcode/script/execute_benchmark.sh`.


Build options:

| Option | Default | Effect |
| --- | --- | --- |
| `HIFHE_CUSTOM_PARAM` | `OFF`; `ON` with `HIFHE_BUILD_TESTS=ON` | `OFF` selects simple mode, removing custom parameters, prime search and validation, native-API interchange format selection, evaluation keys, key switching, ciphertext/ciphertext multiplication, rotations and slot map. `ON` enables these features. |
| `HITLS_PROVIDER` | `OFF` in release builds, `ON` in test builds | Builds the openHiTLS provider integration and BSL parameter adapters, including `hifhe_provider_objects` in `libhifhe.so` / `libhifhe.a`, and enables provider-dependent SDV suites in test builds (the provider loading suite requires the shared library). |

Explicit CMake `-D` values take precedence. For a full release build, run from the repository root:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DHIFHE_CUSTOM_PARAM=ON -DHITLS_PROVIDER=ON
cmake --build build --parallel
```
