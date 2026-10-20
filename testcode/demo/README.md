# testcode/demo

End-to-end programs that drive the HiFHE provider through the public
openHiTLS EAL surface only. No private algorithm header is on the include
path, so a demo compiles against `include/` plus openHiTLS and nothing else.

One executable per `*.c`, named `hifhe_<file stem>`, dropped in
`testcode/output/demo`.

## Build

```bash
bash build_hifhe.sh                      # provider first
bash testcode/script/build_demo.sh       # or: asan, clean
```

The binaries carry an rpath to the provider and openHiTLS build directories,
so they run without `LD_LIBRARY_PATH`. The provider directory comes from
`$HIFHE_PROVIDER_PATH`, otherwise `<repo>/build` relative to the binary.

The demos also build as part of the test tree:

```bash
cmake -S testcode -B testcode/build -DHITLS_ROOT_DIR=... -DBUILD_DEMO=ON
```

## hifhe_leakstr_demo

Leaked-string detection between a client and a server. The client asks
whether its secret is in the server's leak bucket. The server sees a
ciphertext and a bucket id. The client learns one index.

No arguments. The bucket, the bucket id and the queried secret are hardcoded
at the top of the file: `g_bucket`, `BUCKET_ID`, `MATCH_INDEX`.

### Protocol

`t` = plainMod, 4 slots per entry.

```
client  h   = SHA3-256(secret)[0..7]
        q   = the four 16-bit fields of h, repeated over every entry slot
        ctQ = Encrypt(Encode(q)), sent with BUCKET_ID
server  pt  = Encode(bucket entry fields, 4 slots per entry)
        r   = Encode(one random value in [1, t) per slot)
        ct  = Rerandomize(r * (pt - ctQ)), sent back
client  m   = Decode(Decrypt(ct))
        entry i matched when m[4i .. 4i+3] are all 0
```

`t` is prime and both operands are below `t`, so a slot is 0 exactly when the
two 16-bit fields were equal. Four fields per entry give a 2^-64
false-positive rate per entry.

Calls used, all on the EAL surface:

| step | call |
| --- | --- |
| preset | `CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_SET_PARA_BY_ID, HIFHE_BGV_2048_48_17BIT)` |
| seed | `CRYPT_EAL_PkeyCtrl(HIFHE_CTRL_BGV_SET_SEED)` |
| buffer sizes | `CRYPT_EAL_PkeyCtrl(HIFHE_CTRL_BGV_GET_*)` |
| encode, decode | `CRYPT_EAL_PkeyHEMsgEncode`, `CRYPT_EAL_PkeyHEMsgDecode` |
| encrypt, decrypt | `CRYPT_EAL_PkeyEncrypt`, `CRYPT_EAL_PkeyDecrypt` |
| negate, add | `CRYPT_EAL_PkeyHEAdd` with `HIFHE_PARAM_BGV_NEGATE`, then with `HIFHE_PARAM_BGV_PLAINTEXT` |
| mask | `CRYPT_EAL_PkeyHEMul` with `HIFHE_PARAM_BGV_PLAINTEXT` |
| rerandomize | `CRYPT_EAL_PkeyCtrl(HIFHE_CTRL_BGV_HE_RERANDOMIZE)` |

`NEGATE` and `PLAINTEXT` in one `HEAdd` drop the plaintext, so the negation is
a separate call.

### Structure

Two contexts, one per party, both `Party`. Each allocates its buffers once in
`PartyInit` and reuses them for every query: one message vector, one
plaintext, one ciphertext, plus a second ciphertext on the server to
ping-pong the four homomorphic steps across. The server encodes the bucket and
the mask into the same plaintext buffer, the bucket being consumed by the time
the mask is drawn.

| | |
| --- | --- |
| `ClientQuery` | secret to query ciphertext |
| `ServerAnswer` | query ciphertext to response ciphertext |
| `ClientFind` | response ciphertext to matched index |
| `RunQuery` | one exchange, called twice from `main` |

### Keys

The two parties install unrelated seeds. The server never runs
`CRYPT_EAL_PkeyGen`: `HEAdd`, `HEMul` and `HE_RERANDOMIZE` take no key, and
`HEMsgEncode` needs the parameter context, which `SET_SEED` builds. The demo
prints the result of asking the server context for a private key, which is
`HIFHE_KEY_NOT_SET`.

Both sides must hold the same preset. Giving the server the client's seed would
hand it the client's secret key and the plaintext answer with it.

### Run

```
$ testcode/output/demo/hifhe_leakstr_demo
=== HiFHE leaked-string detection, client and server ===
ring   : N=2048 t=65537 slots/entry=4
bucket : id 36, 16 entries
client : secret key from its own seed
server : no key, GetPrv reports KEY_NOT_SET

query "hunter2"
  set match at [7]
  client -> server : bucket 36, 32844 byte ciphertext
  server -> client : 32844 byte ciphertext
  find match at [7]
  result : LEAK_DETECTED

query "a-string-not-in-the-bucket"
  set match at [none]
  client -> server : bucket 36, 32844 byte ciphertext
  server -> client : 32844 byte ciphertext
  find match at [none]
  result : NOT_FOUND
```

`set match` is the index the demo planted, `find match` is the index the
client recovered. A disagreement prints `MISMATCH` and exits non-zero.
