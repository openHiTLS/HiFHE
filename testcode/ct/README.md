# Secret-data dependency checks

Build the Release static library first (`bash testcode/script/build_hifhe.sh`).
Run with GCC-compatible tools, Valgrind and its development headers installed:

```sh
bash testcode/script/check_constant_time.sh --taint
bash testcode/script/check_constant_time.sh --timing
```

`HIFHE_BUILD_DIR`, `HITLS_ROOT_DIR` and `CT_OUTPUT_DIR` select the existing
build, dependency source and artifact directory. `VALGRIND`,
`VALGRIND_INCLUDE_DIR`, `VALGRIND_LIB` and `VALGRIND_EXTRA_DEBUG_DIR` support a
local Valgrind installation. Matching libc debug symbols may also be needed.
Repeat with `-DHIFHE_INT128=OFF` to exercise portable arithmetic.

The taint probe marks coefficient arrays, signed small polynomials, secret
keys and deterministic sampler seeds as undefined using Memcheck client
requests. It checks NTT in both directions, centered CRT reduction and
lifting, signed RNS conversion, ternary/fixed-weight/CBD sampling, and
multi-limb decryption. It makes outputs defined only after the operation
under test. There are no suppression rules. Rejection sampling of uniform
public polynomial coefficients is not part of this probe. It does not establish
constant time for all random-generation, validation or protocol paths.

The timing probe measures NTT forward/inverse with fixed public parameters,
randomly ordered zero-vs-random input classes, 1,000 warm-up iterations and
40,000 measurements. It reports Welch's t and fails for nonfinite statistics
or |t| > 10. Investigate a failure on a quiet, pinned CPU before attributing
it to an exploitable leak. A passing run is not a constant-time proof, nor
is it evidence for operations other than those measured.

The script also records compiler information, CMake configuration and the
Release archive's disassembly. Review secret-data flow into conditional
branches, memory addresses and variable-latency instructions for each target
architecture/compiler. A division instruction in parameter setup is not a
secret-data division. Dynamic checks cannot establish instruction latency
properties. CI can invoke both commands after building; retain their logs
and disassembly when changing compilers or arithmetic code.
