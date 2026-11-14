# HiFHE tests

Tests use the openHiTLS generated SDV framework ported from PQCP.

Each suite has matching `.c` and `.data` files under `sdv/`.
Feature-dependent cases query the loaded provider and skip at runtime.

```sh
bash testcode/script/build_sdv.sh
bash testcode/script/build_sdv.sh run-tests=test_suite_sdv_hifhe_bgv_api
bash testcode/script/execute_sdv.sh
```

The options are independent. Test builds default `HIFHE_CUSTOM_PARAM` to `ON`; `HITLS_PROVIDER` defaults to `OFF` regardless of test mode. Explicit `-D` values and existing CMake cache values take precedence. The ASan workflow passes its provider matrix mode to the SDV build script. The benchmark script builds full features in a separate directory.

With `HIFHE_CUSTOM_PARAM=OFF`, the `hifhe_no_custom_param` test checks the trimmed entry points;
feature-dependent SDV cases skip only operations removed by that switch.
Build benchmarks separately with `bash testcode/script/build_benchmark.sh` and
run them with `bash testcode/script/execute_benchmark.sh`.


Build options:

| Option | Default | Effect |
| --- | --- | --- |
| `HIFHE_CUSTOM_PARAM` | `OFF`; `ON` with `HIFHE_BUILD_TESTS=ON` | `OFF` selects simple mode, removing custom parameters, prime search and validation, native-API interchange format selection, evaluation keys, key switching, ciphertext/ciphertext multiplication, rotations and slot map. `ON` enables these features. |
| `HITLS_PROVIDER` | `OFF` | Builds the openHiTLS provider integration and BSL parameter adapters, including `hifhe_provider_objects` in `libhifhe.so` / `libhifhe.a`. Provider-dependent SDV cases are skipped when disabled; the provider loading suite also requires the shared library. |

Explicit CMake `-D` values take precedence. For a full release build, run from the repository root:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DHIFHE_CUSTOM_PARAM=ON -DHITLS_PROVIDER=ON
cmake --build build --parallel
```
