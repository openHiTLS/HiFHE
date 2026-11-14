# HiFHE benchmark

Timing and footprint benchmarks for BGV. Timing results use CSV;
the `slots` column reports `polyDegree`.

## Building

Links implementation objects directly to measure kernel and adapter operations.

```sh
bash testcode/script/build_benchmark.sh          # build
bash testcode/script/build_benchmark.sh asan     # build with AddressSanitizer
bash testcode/script/build_benchmark.sh clean
```

The script configures `testcode/benchmark` as a standalone CMake project in
`build/benchmark` (override with `HIFHE_BENCHMARK_DIR`). It enables
`HIFHE_CUSTOM_PARAM` and `HITLS_PROVIDER` in this separate build. The benchmark
and library objects compile at `-O2` with `-Werror`.
The binary lands in `testcode/output/hifhe_benchmark`.

## Running

```sh
bash testcode/script/execute_benchmark.sh    # every module, every preset
```

Arguments pass straight through, so the binary can also be driven directly:

```sh
cd testcode/output
./hifhe_benchmark                       # every module, every preset
./hifhe_benchmark -a Kernel             # one module
./hifhe_benchmark -a Bgv-Encrypt        # one operation
./hifhe_benchmark -a '*NttForward'      # cipher/plain forward NTTs
./hifhe_benchmark -p bgv-2048-48-17bit  # one preset
./hifhe_benchmark -s 3                  # 3 seconds per row instead of a fixed count
./hifhe_benchmark -m                    # memory footprint report
./hifhe_benchmark -h
```

## Modules

Both live in `bgv_bench.c`.

**`Kernel`** — NTT transforms and modular arithmetic, without serialization
or key management.

`NttForward` / `NttInverse` run under the first ciphertext modulus,
`PlainNttForward` / `PlainNttInverse` under the plaintext modulus,
`TableBuild` is the twiddle-table cost for one modulus, and `MulDot` / `Add`
are the pointwise operations that make up a ciphertext product.

`Add` performs addition with conditional subtraction of the modulus.
`MulDot` performs modular multiplication; their timing difference includes
both multiplication and reduction costs.

Transforms run in place without resetting inputs between iterations.

**`Bgv`** — `CRYPT_BGV_*` adapter operations. Encryption, decryption and homomorphic
operations include input deserialization and output serialization. `Encode`
serializes output; `Decode` deserializes input. Key generation and context
creation do not serialize objects.

Each context owns its NTT tables. Setup builds the parameters and tables
before timed operations; `CtxCreate+Free` measures that full construction.

`MulCtCt (+relin)` includes relinearization when a relin key is installed.
`Relinearize` uses a size-3 ciphertext saved before generating that key.

Rows that do not apply are skipped rather than failed: `ModSwitch` on a
single-limb chain, `Rotate` without Galois keys.

## Footprint report

`-m` estimates twiddle-table and slot-map sizes from the parameters, including
the slot map before allocation. Plaintext, ciphertext and public-key columns
report wire sizes.

## Adding a module

Define its operations with `DEFINE_HIFHE_OPS` and its parameter list with
`DEFINE_BENCH_CTX_TIMES`, then add `X(<Name>)` to the algorithm's list in
`benchmark_registry.h`.

A module belongs in its algorithm's file, so another BGV module goes in
`bgv_bench.c` alongside `Kernel` and `Bgv`. A new algorithm gets its own
`<alg>_bench.c`, listed in `CMakeLists.txt` under that algorithm's switch.
