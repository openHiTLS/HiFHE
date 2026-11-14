# HiFHE demos

Two leaked-string demos using public headers only. The Provider demo requires
`HITLS_PROVIDER=ON` and a shared library; neither demo requires
`HIFHE_CUSTOM_PARAM`.

| Source | Executable | FHE calls |
|---|---|---|
| hifhe_bgv_provider_demo.c | hifhe_bgv_provider_demo | openHiTLS EAL through the HiFHE Provider |
| hifhe_bgv_demo.c | hifhe_bgv_demo | Native HIFHE_* object APIs |

```sh
bash testcode/script/build_hifhe.sh --enable provider
bash testcode/script/build_sdv.sh
bash testcode/script/execute_sdv.sh
```

The SDV build includes both demos. The SDV runner executes them and checks the
matching and absent-query results. The Provider executable loads libhifhe.so
from the SDV build; the native executable links it directly.

Both use N=4096, t=65537, slots=4096, and mulDepth=0. A generates a key pair;
B generates and imports no keys. A encodes and encrypts once per query:

```text
A: SHA3-256(secret)[0..7] -> four 16-bit fields -> Encode -> Encrypt -> B
B: Encode(bucket) -> bucket-query -> multiply by nonzero masks -> add noise -> A
A: Decrypt -> Decode -> find the entry whose four fields are zero
```

Slot 4i+j of the reply is zero exactly when field j of entry i matched, so A
learns, per entry, which of its four fields it guessed, not only whether the
whole entry matched; with one ciphertext and no rotation, a slot can only
depend on its own field. This does not protect bucket contents against
clients that craft ciphertexts either: A holds the secret key, and
RERANDOMIZE adds bounded noise and provides no circuit privacy. These are
arithmetic demonstrations, not a secure private set-membership protocol.

The Provider version uses SetParaById, HEMsgEncode, Encrypt, HEAdd, HEMul,
Ctrl, Decrypt, and HEMsgDecode. NEGATE and the bucket plaintext share one HEAdd.
Buffer capacities come from length queries; the host DRBG uses system entropy.
It checks that B has no private key.

The native version uses SetParaById and HEText objects. Ctrl
sets the query's negation flag; one Add computes bucket-query. Serialize and
Deserialize explicitly transfer the request and response as bytes.

Both exit successfully only when hunter2 matches index 7 and the absent
query produces no match.

Both demos initialize openHiTLS before creating FHE contexts.
