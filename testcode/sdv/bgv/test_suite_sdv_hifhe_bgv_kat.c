/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 */

/* BEGIN_HEADER */
#include "hifhe_config.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "hifhe.h"
#include "crypt_eal_init.h"
#ifdef HITLS_PROVIDER
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_params.h"
#include "crypt_algid.h"
#include "crypt_eal_md.h"
#include "crypt_bgv.h"
#include "crypt_eal_provider.h"
#include "crypt_types.h"

#include "bgv_adapter_types.h"
#endif
#include "hifhe_types.h"
#include "hifhe_err.h"
#include "crypto_test_util.h"
#include "test.h"
/* END_HEADER */

/*
 * BGV KATs compare fixed-input output digests through CRYPT_BGV_*.
 * Baselines come from 66378e2 or the later optimisation work, as marked in .data.
 * A digest covers the whole serialised output, header included, so it carries the
 * algorithm id: when HIFHE_BGV moved to 0x90000001 every affected digest was
 * re-derived after checking that it still matched with the previous id put back.
 * Native arithmetic vectors check decoded slots against modular arithmetic.
 */

#define KAT_SK        0
#define KAT_PK        1
#define KAT_ENCODE    2
#define KAT_DECODE    3
#define KAT_ADD_CTCT  4
#define KAT_ADD_CTPT  5
#define KAT_NEGATE    6
#define KAT_MUL_CTPT  7
#define KAT_MUL_CTCT  8
#define KAT_MODSWITCH 9
#define KAT_DECRYPT   10
#define KAT_RELIN     11
#define KAT_ROTATE    12

#define KAT_DIGEST_LEN 32u

#ifdef HITLS_PROVIDER
typedef struct {
    CRYPT_BGV_Ctx *ctx;
    uint32_t n;
    uint32_t level;
    uint64_t t;
    uint32_t ptLen;
    uint32_t ctLen;
    uint32_t msgLen;
} KatEnv;

static uint64_t KatNext(uint64_t *s)
{
    uint64_t z = (*s += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

static uint64_t KatLoadU64(const uint8_t *p)
{
    uint64_t v = 0u;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | p[i];
    }
    return v;
}

static void KatStoreU64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static void KatEnvFree(KatEnv *e)
{
    CRYPT_BGV_FreeCtx(e->ctx);
    e->ctx = NULL;
}

/* A context for `preset` whose keys derive from a fixed seed. */
static int KatEnvInit(KatEnv *e, int32_t preset)
{
    memset(e, 0, sizeof(*e));
    e->ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    if (e->ctx == NULL) {
        return -1;
    }
    uint8_t seed[HIFHE_BGV_SEED_LEN];
    for (uint32_t i = 0; i < HIFHE_BGV_SEED_LEN; ++i) {
        seed[i] = (uint8_t)(0xa5u ^ (i * 7u));
    }
    if (CRYPT_BGV_Ctrl(e->ctx, CRYPT_CTRL_SET_PARA_BY_ID, &preset, sizeof(preset)) != HIFHE_SUCCESS ||
        CRYPT_BGV_Ctrl(e->ctx, HIFHE_CTRL_BGV_SET_SEED, seed, sizeof(seed)) != HIFHE_SUCCESS ||
        CRYPT_BGV_Gen(e->ctx) != HIFHE_SUCCESS ||
        CRYPT_BGV_Ctrl(e->ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &e->n, sizeof(e->n)) != HIFHE_SUCCESS ||
        CRYPT_BGV_Ctrl(e->ctx, HIFHE_CTRL_BGV_GET_LEVEL, &e->level, sizeof(e->level)) != HIFHE_SUCCESS ||
        CRYPT_BGV_Ctrl(e->ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &e->t, sizeof(e->t)) != HIFHE_SUCCESS ||
        CRYPT_BGV_Ctrl(e->ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &e->ptLen, sizeof(e->ptLen)) != HIFHE_SUCCESS ||
        CRYPT_BGV_Ctrl(e->ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &e->ctLen, sizeof(e->ctLen)) != HIFHE_SUCCESS ||
        CRYPT_BGV_Ctrl(e->ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &e->msgLen, sizeof(e->msgLen)) != HIFHE_SUCCESS) {
        KatEnvFree(e);
        return -1;
    }
    return 0;
}

/* Encode a message of uniform values mod t drawn from stream `s`. */
static int KatEncode(KatEnv *e, uint64_t s, uint8_t *pt, uint32_t *ptLen)
{
    uint64_t *msg = (uint64_t *)BSL_SAL_Malloc(e->msgLen);
    if (msg == NULL) {
        return -1;
    }
    for (uint32_t i = 0; i < e->n; ++i) {
        msg[i] = KatNext(&s) % e->t;
    }
    BSL_Param in[] = {{HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, msg, e->msgLen, 0}, BSL_PARAM_END};
    uint32_t out = e->ptLen;
    int32_t rc = CRYPT_BGV_HEMsgEncode(e->ctx, in, pt, &out);
    BSL_SAL_Free(msg);
    if (rc != HIFHE_SUCCESS) {
        return -1;
    }
    *ptLen = out;
    return 0;
}

/* Overwrite the coefficient words at the end of a serialised plaintext or
 * ciphertext with values drawn from stream `s`, each reduced by the limb
 * modulus listed just before them. `polys` is 1 for a plaintext and the
 * component count for a ciphertext. */
static void KatFillBody(const KatEnv *e, uint8_t *buf, uint32_t len, uint32_t polys, uint64_t s)
{
    uint32_t words = polys * e->level * e->n;
    uint8_t *data = buf + len - (size_t)words * 8u;
    const uint8_t *mods = data - (size_t)e->level * 8u;
    for (uint32_t k = 0; k < polys; ++k) {
        for (uint32_t i = 0; i < e->level; ++i) {
            uint64_t q = KatLoadU64(mods + (size_t)i * 8u);
            uint8_t *slice = data + ((size_t)k * e->level + i) * e->n * 8u;
            for (uint32_t j = 0; j < e->n; ++j) {
                KatStoreU64(slice + (size_t)j * 8u, KatNext(&s) % q);
            }
        }
    }
}

/* A fixed ciphertext: the shape of a fresh encryption with its seed field
 * cleared and both components replaced by stream `s`. */
static int KatCiphertext(KatEnv *e, uint64_t s, uint8_t *ct, uint32_t *ctLen)
{
    uint8_t *pt = (uint8_t *)BSL_SAL_Malloc(e->ptLen);
    if (pt == NULL) {
        return -1;
    }
    uint32_t ptL = 0u;
    int rc = KatEncode(e, s, pt, &ptL);
    uint32_t out = e->ctLen;
    if (rc == 0 && CRYPT_BGV_Encrypt(e->ctx, pt, ptL, ct, &out) != HIFHE_SUCCESS) {
        rc = -1;
    }
    BSL_SAL_Free(pt);
    if (rc != 0) {
        return -1;
    }
    /* header(12) | size(4) | correction(8) | seed | N(4) | rns(4) | dtype(4) | moduli | data */
    uint32_t dataOff = out - 2u * e->level * e->n * 8u;
    uint32_t seedEnd = dataOff - e->level * 8u - 12u;
    memset(ct + 24, 0, seedEnd - 24u);
    KatFillBody(e, ct, out, 2u, s ^ 0x5eedull);
    *ctLen = out;
    return 0;
}

static int KatGenRotateKey(KatEnv *e)
{
    int32_t step = 1;
    BSL_Param gk[] = {{HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_OCTETS, &step, (uint32_t)sizeof(step), 0},
                      BSL_PARAM_END};
    return (CRYPT_BGV_Ctrl(e->ctx, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, gk, 0u) == HIFHE_SUCCESS) ? 0 : -1;
}

/* Run `op` on fixed inputs and leave its serialised result in `out`. */
static int KatRun(KatEnv *e, int op, uint8_t *out, uint32_t cap, uint32_t *outLen)
{
    uint8_t *ct1 = NULL, *ct2 = NULL, *pt = NULL;
    uint32_t ct1L = 0u, ct2L = 0u, ptL = 0u, len = cap;
    int rc = -1;

    ct1 = (uint8_t *)BSL_SAL_Malloc(e->ctLen);
    ct2 = (uint8_t *)BSL_SAL_Malloc(e->ctLen);
    pt = (uint8_t *)BSL_SAL_Malloc(e->ptLen);
    if (ct1 == NULL || ct2 == NULL || pt == NULL) {
        goto EXIT;
    }
    if (KatCiphertext(e, 0x1111ull, ct1, &ct1L) != 0 || KatCiphertext(e, 0x2222ull, ct2, &ct2L) != 0 ||
        KatEncode(e, 0x3333ull, pt, &ptL) != 0) {
        goto EXIT;
    }

    switch (op) {
        case KAT_SK: {
            BSL_Param g[] = {{HIFHE_PARAM_BGV_PRVKEY, BSL_PARAM_TYPE_OCTETS, out, cap, 0}, BSL_PARAM_END};
            if (CRYPT_BGV_GetPrvKeyEx(e->ctx, g) != HIFHE_SUCCESS) {
                goto EXIT;
            }
            len = g[0].useLen;
            break;
        }
        case KAT_PK: {
            BSL_Param g[] = {{HIFHE_PARAM_BGV_PUBKEY, BSL_PARAM_TYPE_OCTETS, out, cap, 0}, BSL_PARAM_END};
            if (CRYPT_BGV_GetPubKeyEx(e->ctx, g) != HIFHE_SUCCESS) {
                goto EXIT;
            }
            len = g[0].useLen;
            break;
        }
        case KAT_ENCODE:
            if (ptL > cap) {
                goto EXIT;
            }
            memcpy(out, pt, ptL);
            len = ptL;
            break;
        case KAT_DECODE: {
            KatFillBody(e, pt, ptL, 1u, 0x4444ull);
            BSL_Param in[] = {{HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, pt, ptL, 0}, BSL_PARAM_END};
            len = e->msgLen;
            if (len > cap || CRYPT_BGV_HEMsgDecode(e->ctx, in, out, &len) != HIFHE_SUCCESS) {
                goto EXIT;
            }
            break;
        }
        case KAT_ADD_CTCT:
        case KAT_MUL_CTCT:
        case KAT_RELIN: {
            if (op == KAT_RELIN &&
                CRYPT_BGV_Ctrl(e->ctx, HIFHE_CTRL_BGV_GEN_RELIN_KEY, NULL, 0u) != HIFHE_SUCCESS) {
                goto EXIT;
            }
            BSL_Param in[] = {{HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
                              {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ct2, ct2L, 0},
                              BSL_PARAM_END};
            int32_t r = (op == KAT_ADD_CTCT) ? CRYPT_BGV_HEAdd(e->ctx, in, out, &len) :
                                               CRYPT_BGV_HEMul(e->ctx, in, out, &len);
            if (r != HIFHE_SUCCESS) {
                goto EXIT;
            }
            break;
        }
        case KAT_ADD_CTPT:
        case KAT_MUL_CTPT: {
            BSL_Param in[] = {{HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
                              {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, pt, ptL, 0},
                              BSL_PARAM_END};
            int32_t r = (op == KAT_ADD_CTPT) ? CRYPT_BGV_HEAdd(e->ctx, in, out, &len) :
                                               CRYPT_BGV_HEMul(e->ctx, in, out, &len);
            if (r != HIFHE_SUCCESS) {
                goto EXIT;
            }
            break;
        }
        case KAT_NEGATE: {
            uint8_t marker = 1u;
            BSL_Param in[] = {{HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
                              {HIFHE_PARAM_BGV_NEGATE, BSL_PARAM_TYPE_OCTETS, &marker, 1u, 0},
                              BSL_PARAM_END};
            if (CRYPT_BGV_HEAdd(e->ctx, in, out, &len) != HIFHE_SUCCESS) {
                goto EXIT;
            }
            break;
        }
        case KAT_MODSWITCH: {
            BSL_Param in[] = {{HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
                              {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, out, cap, 0},
                              BSL_PARAM_END};
            if (CRYPT_BGV_Ctrl(e->ctx, HIFHE_CTRL_BGV_HE_MODSWITCH, in, 0u) != HIFHE_SUCCESS) {
                goto EXIT;
            }
            len = in[1].useLen;
            break;
        }
        case KAT_DECRYPT:
            if (CRYPT_BGV_Decrypt(e->ctx, ct1, ct1L, out, &len) != HIFHE_SUCCESS) {
                goto EXIT;
            }
            break;
        case KAT_ROTATE: {
            if (KatGenRotateKey(e) != 0) {
                goto EXIT;
            }
            int32_t step = 1;
            BSL_Param in[] = {{HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
                              {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_INT32, &step, (uint32_t)sizeof(step), 0},
                              {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, out, cap, 0},
                              BSL_PARAM_END};
            if (CRYPT_BGV_Ctrl(e->ctx, HIFHE_CTRL_BGV_HE_ROTATE_STEP, in, 0u) != HIFHE_SUCCESS) {
                goto EXIT;
            }
            len = in[2].useLen;
            break;
        }
        default:
            goto EXIT;
    }
    *outLen = len;
    rc = 0;
EXIT:
    BSL_SAL_Free(ct1);
    BSL_SAL_Free(ct2);
    BSL_SAL_Free(pt);
    return rc;
}

static void KatPrintDigest(int32_t preset, int op, const uint8_t *d)
{
    char hex[KAT_DIGEST_LEN * 2u + 1u];
    for (uint32_t i = 0; i < KAT_DIGEST_LEN; ++i) {
        (void)sprintf(hex + 2u * i, "%02x", d[i]);
    }
    Print("KAT preset=%d op=%d digest=%s\n", (int)preset, op, hex);
}
#endif

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_KAT_TC001
* @title  A BGV operation on fixed keys and inputs produces the expected SHA-256.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_KAT_TC001(int preset, int op, Hex *digest)
{
#ifndef HIFHE_CUSTOM_PARAM
    if (op == KAT_MUL_CTCT || op == KAT_RELIN || op == KAT_ROTATE) {
        SKIP_TEST();
    }
#endif
#ifdef HITLS_PROVIDER
    KatEnv e = {0};
    uint8_t *out = NULL;
    uint8_t md[KAT_DIGEST_LEN];
    uint32_t mdLen = sizeof(md);
    uint32_t outLen = 0u;

    TestMemInit();
    TestRandInit();
    ASSERT_EQ(digest->len, KAT_DIGEST_LEN);
    ASSERT_EQ(KatEnvInit(&e, (int32_t)preset), 0);
    /* Room for a size-3 product, a full key or a decoded message. */
    uint32_t cap = 4u * e.ctLen + e.msgLen;
    out = (uint8_t *)BSL_SAL_Malloc(cap);
    ASSERT_TRUE(out != NULL);
    ASSERT_EQ(KatRun(&e, op, out, cap, &outLen), 0);
    ASSERT_EQ(CRYPT_EAL_Md(CRYPT_MD_SHA256, out, outLen, md, &mdLen), CRYPT_SUCCESS);
    if (memcmp(md, digest->x, KAT_DIGEST_LEN) != 0) {
        KatPrintDigest((int32_t)preset, op, md);
    }
    ASSERT_COMPARE("kat digest", md, mdLen, digest->x, digest->len);
EXIT:
    BSL_SAL_Free(out);
    KatEnvFree(&e);
    TestRandDeInit();
#else
    (void)preset;
    (void)op;
    (void)digest;
    SKIP_TEST();
#endif
}
/* END_CASE */

static uint32_t VectorNext(uint32_t *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 17;
    *s ^= *s << 5;
    return *s;
}

static bool CheckVectorResult(HIFHE_Ctx *ctx, HIFHE_HEText *ct, const uint64_t *a, const uint64_t *b, uint32_t n, bool mul)
{
    bool valid = false;
    HIFHE_HEText *pt = NULL;
    uint64_t *out = NULL;
    if (HIFHE_Decrypt(ctx, ct, &pt) != HIFHE_SUCCESS) {
        goto EXIT;
    }
    out = calloc(n, sizeof(*out));
    if (out == NULL) {
        goto EXIT;
    }
    uint32_t count = n;
    if (HIFHE_Decode(ctx, pt, out, &count) != HIFHE_SUCCESS || count != n) {
        goto EXIT;
    }
    for (uint32_t i = 0; i < n; i++) {
        uint64_t expected = mul ? a[i] * b[i] : a[i] + b[i];
        if (out[i] != expected % 65537) {
            goto EXIT;
        }
    }
    valid = true;
EXIT:
    HIFHE_HETextFree(pt);
    free(out);
    return valid;
}

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_VECTOR_API_TC001(int id, int slots, int pattern)
{
    HIFHE_Ctx *a = NULL, *b = NULL;
    HIFHE_HEText *xp = NULL, *yp = NULL, *xc = NULL, *yc = NULL, *sum = NULL, *product = NULL, *bad = NULL;
    uint64_t *x = NULL, *y = NULL;
    uint32_t n = (uint32_t)slots;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    a = HIFHE_New(HIFHE_BGV);
    b = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(a != NULL && b != NULL);
    ASSERT_EQ(HIFHE_SetParaById(a, (uint32_t)id), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_SetParaById(b, (uint32_t)id), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(a), HIFHE_SUCCESS);
    x = calloc(n, sizeof(*x));
    y = calloc(n, sizeof(*y));
    ASSERT_TRUE(x != NULL && y != NULL);
    uint32_t state = 0x12345678;
    for (uint32_t i = 0; i < n; i++) {
        if (pattern == 0) {
            x[i] = y[i] = 0;
        }
        if (pattern == 1) {
            x[i] = y[i] = 1;
        }
        if (pattern == 2) {
            x[i] = y[i] = 65536;
        }
        if (pattern == 3) {
            x[i] = (i == 0 || i == n / 2 || i == n - 1) ? 17 : 0;
            y[i] = i == 0 ? 29 : 0;
        }
        if (pattern == 4) {
            x[i] = i % 65537;
            y[i] = (i * 7 + 3) % 65537;
        }
        if (pattern == 5) {
            x[i] = VectorNext(&state) % 65537;
            y[i] = VectorNext(&state) % 65537;
        }
    }
    ASSERT_EQ(HIFHE_Encode(a, x, n, &xp), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encode(a, y, n, &yp), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(a, xp, &xc), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(a, yp, &yc), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Add(b, xc, yc, &sum), HIFHE_SUCCESS);
    ASSERT_TRUE(CheckVectorResult(a, sum, x, y, n, false));
    ASSERT_EQ(HIFHE_Mul(b, xc, yp, &product), HIFHE_SUCCESS);
    ASSERT_TRUE(CheckVectorResult(a, product, x, y, n, true));
    ASSERT_TRUE(HIFHE_Mul(b, xc, yc, &bad) == HIFHE_NOT_SUPPORTED);
    ASSERT_TRUE(bad == NULL);
EXIT:
    HIFHE_HETextFree(bad);
    HIFHE_HETextFree(xp);
    HIFHE_HETextFree(yp);
    HIFHE_HETextFree(xc);
    HIFHE_HETextFree(yc);
    HIFHE_HETextFree(sum);
    HIFHE_HETextFree(product);
    HIFHE_Free(a);
    HIFHE_Free(b);
    free(x);
    free(y);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/*
 * Legacy compatibility known-answer vectors.
 *
 * The .data vectors were produced by an earlier, independent BGV implementation
 * with the same interchange format, for preset 2048_48_17BIT (N = 2048,
 * t = 65537, one 48-bit modulus), slot encoding, fixed key seed and a fixed
 * encryption random stream. They are fixed inputs here, not regenerated:
 *   sk, pk      the keys as that implementation exports them
 *   pt1, pt2    its encodings of m1 and m2
 *   ct1         its public-key encryption of pt1
 *   ctAdd/ctMul its ct1 + pt2 and ct1 * pt2
 * m1 and m2 are not stored: OcMsgFill below is the formula the vectors were
 * made from and must not change.
 *
 * Everything here reads and writes the interchange wire format, so a build
 * without it skips these cases.
 */

#ifdef HIFHE_CUSTOM_PARAM
#define OC_N 2048u
#define OC_T 65537u
/* Interchange header: magic(4) | algorithm id(4) | version(2) | type(2). Each
 * implementation stamps its own algorithm id there; everything after it is shared. */
#define OC_HDR_BODY 8u

#define OC_INIT (CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND)

/* m1 covers [0, t) with a stride walk, m2 with a quadratic one; both start with
 * the edge values 0, 1, t/2, t/2 + 1 and t - 1. */
static void OcMsgFill(uint64_t *m, uint32_t n, uint64_t t, int which)
{
    for (uint32_t i = 0; i < n; i++) {
        uint64_t x = i;
        m[i] = (which == 1) ? (x * 40503u + 7u) % t : (x * x * 31u + x * 977u + 3u) % t;
    }
    if (which == 1) {
        m[0] = 0; m[1] = 1; m[2] = t / 2; m[3] = t / 2 + 1; m[4] = t - 1;
    } else {
        m[0] = t - 1; m[1] = t / 2 + 1; m[2] = t / 2; m[3] = 1; m[4] = 0; m[5] = t - 1;
    }
}

static void OcExpect(uint64_t *out, const uint64_t *a, const uint64_t *b, uint32_t n, int mul)
{
    for (uint32_t i = 0; i < n; i++) {
        out[i] = mul ? (a[i] * b[i]) % OC_T : (a[i] + b[i]) % OC_T;
    }
}

/* A context for `preset` that writes the interchange format. */
static HIFHE_Ctx *OcCtx(int preset)
{
    HIFHE_Ctx *ctx = HIFHE_New(HIFHE_BGV);
    uint32_t fmt = HIFHE_WIRE_INTERCHANGE;
    uint32_t n = 0;
    if (ctx == NULL || HIFHE_SetParaById(ctx, (uint32_t)preset) != HIFHE_SUCCESS ||
        HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_SET_WIRE_FORMAT, NULL, &fmt, sizeof(fmt)) != HIFHE_SUCCESS ||
        HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, NULL, &n, sizeof(n)) != HIFHE_SUCCESS || n != OC_N) {
        HIFHE_Free(ctx);
        return NULL;
    }
    return ctx;
}

/* OcCtx with the vector keys installed; either may be NULL. */
static HIFHE_Ctx *OcKeyed(int preset, const Hex *sk, const Hex *pk)
{
    HIFHE_Ctx *ctx = OcCtx(preset);
    if (ctx == NULL) {
        return NULL;
    }
    if ((sk != NULL && HIFHE_ImportPrvKey(ctx, sk->x, sk->len) != HIFHE_SUCCESS) ||
        (pk != NULL && HIFHE_ImportPubKey(ctx, pk->x, pk->len) != HIFHE_SUCCESS)) {
        HIFHE_Free(ctx);
        return NULL;
    }
    return ctx;
}

static uint8_t *OcExport(const HIFHE_Ctx *ctx, int pub, uint32_t *len)
{
    uint32_t n = 0;
    int32_t r = pub ? HIFHE_ExportPubKey(ctx, NULL, &n) : HIFHE_ExportPrvKey(ctx, NULL, &n);
    if ((r != HIFHE_SUCCESS && r != HIFHE_BUFFER_TOO_SMALL) || n == 0) {
        return NULL;
    }
    uint8_t *out = malloc(n);
    if (out == NULL) {
        return NULL;
    }
    r = pub ? HIFHE_ExportPubKey(ctx, out, &n) : HIFHE_ExportPrvKey(ctx, out, &n);
    if (r != HIFHE_SUCCESS) {
        free(out);
        return NULL;
    }
    *len = n;
    return out;
}

static uint8_t *OcSerialize(const HIFHE_Ctx *ctx, const HIFHE_HEText *obj, uint32_t *len)
{
    uint32_t n = 0;
    int32_t r = HIFHE_Serialize(ctx, obj, NULL, &n);
    if ((r != HIFHE_SUCCESS && r != HIFHE_BUFFER_TOO_SMALL) || n == 0) {
        return NULL;
    }
    uint8_t *out = malloc(n);
    if (out == NULL) {
        return NULL;
    }
    if (HIFHE_Serialize(ctx, obj, out, &n) != HIFHE_SUCCESS) {
        free(out);
        return NULL;
    }
    *len = n;
    return out;
}

/* Number of slots of `pt` that differ from `exp`, or -1 if it cannot be decoded. */
static int32_t OcDecodeDiff(const HIFHE_Ctx *ctx, const HIFHE_HEText *pt, const uint64_t *exp)
{
    uint64_t *got = calloc(OC_N, sizeof(*got));
    uint32_t count = OC_N;
    int32_t bad = -1;
    if (got != NULL && HIFHE_Decode(ctx, pt, got, &count) == HIFHE_SUCCESS && count == OC_N) {
        bad = 0;
        for (uint32_t i = 0; i < OC_N; i++) {
            bad += got[i] != exp[i];
        }
        if (bad != 0) {
            for (uint32_t i = 0; i < OC_N; i++) {
                if (got[i] != exp[i]) {
                    Print("first differing slot %u: got %llu, expected %llu (%d slots differ)\n", i,
                          (unsigned long long)got[i], (unsigned long long)exp[i], (int)bad);
                    break;
                }
            }
        }
    }
    free(got);
    return bad;
}

/* Slots of decrypt(ct) that differ from `exp`, or -1 on an error. */
static int32_t OcDecryptDiff(HIFHE_Ctx *ctx, const HIFHE_HEText *ct, const uint64_t *exp)
{
    HIFHE_HEText *pt = NULL;
    int32_t bad = -1;
    if (HIFHE_Decrypt(ctx, ct, &pt) == HIFHE_SUCCESS) {
        bad = OcDecodeDiff(ctx, pt, exp);
    }
    HIFHE_HETextFree(pt);
    return bad;
}

/* Deserialize a vector ciphertext and compare its decryption with `exp`. */
static int32_t OcVectorDiff(HIFHE_Ctx *ctx, const Hex *ct, const uint64_t *exp)
{
    HIFHE_HEText *c = NULL;
    int32_t bad = -1;
    if (HIFHE_Deserialize(ctx, ct->x, ct->len, &c) == HIFHE_SUCCESS) {
        bad = OcDecryptDiff(ctx, c, exp);
    }
    HIFHE_HETextFree(c);
    return bad;
}
#endif

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_OLD_COMPATIBILITY_TEST_TC001
* @title  Legacy secret and public keys import; re-exporting them gives the same bytes.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_OLD_COMPATIBILITY_TEST_TC001(int preset, Hex *sk, Hex *pk)
{
#ifdef HIFHE_CUSTOM_PARAM
    HIFHE_Ctx *ctx = NULL, *again = NULL;
    uint8_t *skOut = NULL, *pkOut = NULL, *skAgain = NULL, *pkAgain = NULL;
    uint32_t skLen = 0, pkLen = 0, skAgainLen = 0, pkAgainLen = 0;

    ASSERT_EQ(CRYPT_EAL_Init(OC_INIT), HIFHE_SUCCESS);
    ctx = OcKeyed(preset, sk, pk);
    ASSERT_TRUE(ctx != NULL);
    skOut = OcExport(ctx, 0, &skLen);
    pkOut = OcExport(ctx, 1, &pkLen);
    ASSERT_TRUE(skOut != NULL && pkOut != NULL);
    /* Every byte but the header's algorithm id, which names the writer. */
    ASSERT_EQ(skLen, sk->len);
    ASSERT_EQ(pkLen, pk->len);
    ASSERT_COMPARE("sk magic", skOut, 4, sk->x, 4);
    ASSERT_COMPARE("pk magic", pkOut, 4, pk->x, 4);
    ASSERT_COMPARE("sk", skOut + OC_HDR_BODY, skLen - OC_HDR_BODY, sk->x + OC_HDR_BODY, sk->len - OC_HDR_BODY);
    ASSERT_COMPARE("pk", pkOut + OC_HDR_BODY, pkLen - OC_HDR_BODY, pk->x + OC_HDR_BODY, pk->len - OC_HDR_BODY);

    /* What HiFHE wrote reads back and is written again unchanged. */
    again = OcCtx(preset);
    ASSERT_TRUE(again != NULL);
    ASSERT_EQ(HIFHE_ImportPrvKey(again, skOut, skLen), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_ImportPubKey(again, pkOut, pkLen), HIFHE_SUCCESS);
    skAgain = OcExport(again, 0, &skAgainLen);
    pkAgain = OcExport(again, 1, &pkAgainLen);
    ASSERT_TRUE(skAgain != NULL && pkAgain != NULL);
    ASSERT_COMPARE("sk re-export", skAgain, skAgainLen, skOut, skLen);
    ASSERT_COMPARE("pk re-export", pkAgain, pkAgainLen, pkOut, pkLen);
EXIT:
    HIFHE_Free(ctx);
    HIFHE_Free(again);
    free(skOut);
    free(pkOut);
    free(skAgain);
    free(pkAgain);
    CRYPT_EAL_Cleanup(OC_INIT);
#else
    (void)preset;
    (void)sk;
    (void)pk;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_OLD_COMPATIBILITY_TEST_TC002
* @title  A legacy ciphertext deserializes and decrypts to m1 under the legacy secret key.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_OLD_COMPATIBILITY_TEST_TC002(int preset, Hex *sk, Hex *ct1)
{
#ifdef HIFHE_CUSTOM_PARAM
    HIFHE_Ctx *ctx = NULL;
    uint64_t m1[OC_N];

    ASSERT_EQ(CRYPT_EAL_Init(OC_INIT), HIFHE_SUCCESS);
    OcMsgFill(m1, OC_N, OC_T, 1);
    ctx = OcKeyed(preset, sk, NULL);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(OcVectorDiff(ctx, ct1, m1), 0);
EXIT:
    HIFHE_Free(ctx);
    CRYPT_EAL_Cleanup(OC_INIT);
#else
    (void)preset;
    (void)sk;
    (void)ct1;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_OLD_COMPATIBILITY_TEST_TC003
* @title  Legacy plaintexts decode to m1 and m2; HiFHE's own encoding of m2 decodes alike.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_OLD_COMPATIBILITY_TEST_TC003(int preset, Hex *pt1, Hex *pt2)
{
#ifdef HIFHE_CUSTOM_PARAM
    HIFHE_Ctx *ctx = NULL;
    HIFHE_HEText *p1 = NULL, *p2 = NULL, *own = NULL, *ownBack = NULL;
    uint8_t *wire = NULL;
    uint32_t wireLen = 0;
    uint64_t m1[OC_N], m2[OC_N];

    ASSERT_EQ(CRYPT_EAL_Init(OC_INIT), HIFHE_SUCCESS);
    OcMsgFill(m1, OC_N, OC_T, 1);
    OcMsgFill(m2, OC_N, OC_T, 2);
    ctx = OcCtx(preset);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HIFHE_Deserialize(ctx, pt1->x, pt1->len, &p1), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Deserialize(ctx, pt2->x, pt2->len, &p2), HIFHE_SUCCESS);
    ASSERT_EQ(OcDecodeDiff(ctx, p1, m1), 0);
    ASSERT_EQ(OcDecodeDiff(ctx, p2, m2), 0);

    /* HiFHE's own encoding of m2. The two encoders may pick different (equivalent)
     * coefficient representatives, so the plaintexts are compared by what they
     * decode to: both give m2. */
    ASSERT_EQ(HIFHE_Encode(ctx, m2, OC_N, &own), HIFHE_SUCCESS);
    ASSERT_EQ(OcDecodeDiff(ctx, own, m2), 0);
    /* Its interchange bytes have the legacy plaintext's shape and read back. */
    wire = OcSerialize(ctx, own, &wireLen);
    ASSERT_TRUE(wire != NULL);
    ASSERT_EQ(wireLen, pt2->len);
    ASSERT_COMPARE("pt magic", wire, 4, pt2->x, 4);
    ASSERT_EQ(HIFHE_Deserialize(ctx, wire, wireLen, &ownBack), HIFHE_SUCCESS);
    ASSERT_EQ(OcDecodeDiff(ctx, ownBack, m2), 0);
EXIT:
    HIFHE_HETextFree(p1);
    HIFHE_HETextFree(p2);
    HIFHE_HETextFree(own);
    HIFHE_HETextFree(ownBack);
    HIFHE_Free(ctx);
    free(wire);
    CRYPT_EAL_Cleanup(OC_INIT);
#else
    (void)preset;
    (void)pt1;
    (void)pt2;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_OLD_COMPATIBILITY_TEST_TC004
* @title  Legacy ct + pt and ct * pt results decrypt to the slot-wise sum and product mod t.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_OLD_COMPATIBILITY_TEST_TC004(int preset, Hex *sk, Hex *ctAdd, Hex *ctMul)
{
#ifdef HIFHE_CUSTOM_PARAM
    HIFHE_Ctx *ctx = NULL;
    uint64_t m1[OC_N], m2[OC_N], sum[OC_N], prod[OC_N];

    ASSERT_EQ(CRYPT_EAL_Init(OC_INIT), HIFHE_SUCCESS);
    OcMsgFill(m1, OC_N, OC_T, 1);
    OcMsgFill(m2, OC_N, OC_T, 2);
    OcExpect(sum, m1, m2, OC_N, 0);
    OcExpect(prod, m1, m2, OC_N, 1);
    ctx = OcKeyed(preset, sk, NULL);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(OcVectorDiff(ctx, ctAdd, sum), 0);
    ASSERT_EQ(OcVectorDiff(ctx, ctMul, prod), 0);
EXIT:
    HIFHE_Free(ctx);
    CRYPT_EAL_Cleanup(OC_INIT);
#else
    (void)preset;
    (void)sk;
    (void)ctAdd;
    (void)ctMul;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_OLD_COMPATIBILITY_TEST_TC005
* @title  HiFHE computes ct + pt and ct * pt on mixed legacy and own operands correctly.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_OLD_COMPATIBILITY_TEST_TC005(int preset, Hex *sk, Hex *pk, Hex *ct1, Hex *pt2)
{
#ifdef HIFHE_CUSTOM_PARAM
    HIFHE_Ctx *ctx = NULL, *enc = NULL;
    HIFHE_HEText *legCt = NULL, *legPt = NULL, *ownPt2 = NULL, *ownPt1 = NULL, *encCt = NULL, *ownCt = NULL;
    HIFHE_HEText *r[6] = {NULL};
    uint8_t *wire = NULL;
    uint32_t wireLen = 0;
    uint64_t m1[OC_N], m2[OC_N], sum[OC_N], prod[OC_N];

    ASSERT_EQ(CRYPT_EAL_Init(OC_INIT), HIFHE_SUCCESS);
    OcMsgFill(m1, OC_N, OC_T, 1);
    OcMsgFill(m2, OC_N, OC_T, 2);
    OcExpect(sum, m1, m2, OC_N, 0);
    OcExpect(prod, m1, m2, OC_N, 1);
    ctx = OcKeyed(preset, sk, pk);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HIFHE_Deserialize(ctx, ct1->x, ct1->len, &legCt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Deserialize(ctx, pt2->x, pt2->len, &legPt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encode(ctx, m2, OC_N, &ownPt2), HIFHE_SUCCESS);

    /* Legacy ciphertext, legacy plaintext. */
    ASSERT_EQ(HIFHE_Add(ctx, legCt, legPt, &r[0]), HIFHE_SUCCESS);
    ASSERT_EQ(OcDecryptDiff(ctx, r[0], sum), 0);
    ASSERT_EQ(HIFHE_Mul(ctx, legCt, legPt, &r[1]), HIFHE_SUCCESS);
    ASSERT_EQ(OcDecryptDiff(ctx, r[1], prod), 0);
    /* Legacy ciphertext, HiFHE-encoded plaintext. */
    ASSERT_EQ(HIFHE_Add(ctx, legCt, ownPt2, &r[2]), HIFHE_SUCCESS);
    ASSERT_EQ(OcDecryptDiff(ctx, r[2], sum), 0);
    ASSERT_EQ(HIFHE_Mul(ctx, legCt, ownPt2, &r[3]), HIFHE_SUCCESS);
    ASSERT_EQ(OcDecryptDiff(ctx, r[3], prod), 0);

    /* HiFHE ciphertext under the legacy public key (a context holding that key
     * alone encrypts, so this is a public-key encryption), legacy plaintext. */
    enc = OcKeyed(preset, NULL, pk);
    ASSERT_TRUE(enc != NULL);
    ASSERT_EQ(HIFHE_Encode(enc, m1, OC_N, &ownPt1), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(enc, ownPt1, &encCt), HIFHE_SUCCESS);
    wire = OcSerialize(enc, encCt, &wireLen);
    ASSERT_TRUE(wire != NULL);
    ASSERT_EQ(HIFHE_Deserialize(ctx, wire, wireLen, &ownCt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Add(ctx, ownCt, legPt, &r[4]), HIFHE_SUCCESS);
    ASSERT_EQ(OcDecryptDiff(ctx, r[4], sum), 0);
    ASSERT_EQ(HIFHE_Mul(ctx, ownCt, legPt, &r[5]), HIFHE_SUCCESS);
    ASSERT_EQ(OcDecryptDiff(ctx, r[5], prod), 0);
EXIT:
    for (uint32_t i = 0; i < sizeof(r) / sizeof(r[0]); i++) {
        HIFHE_HETextFree(r[i]);
    }
    HIFHE_HETextFree(legCt);
    HIFHE_HETextFree(legPt);
    HIFHE_HETextFree(ownPt2);
    HIFHE_HETextFree(ownPt1);
    HIFHE_HETextFree(encCt);
    HIFHE_HETextFree(ownCt);
    HIFHE_Free(ctx);
    HIFHE_Free(enc);
    free(wire);
    CRYPT_EAL_Cleanup(OC_INIT);
#else
    (void)preset;
    (void)sk;
    (void)pk;
    (void)ct1;
    (void)pt2;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_OLD_COMPATIBILITY_TEST_TC006
* @title  HiFHE encrypts under the legacy public key; the interchange bytes decrypt to m1.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_OLD_COMPATIBILITY_TEST_TC006(int preset, Hex *sk, Hex *pk)
{
#ifdef HIFHE_CUSTOM_PARAM
    HIFHE_Ctx *enc = NULL, *dec = NULL;
    HIFHE_HEText *pt = NULL, *ct = NULL, *back = NULL;
    uint8_t *wire = NULL;
    uint32_t wireLen = 0, expectLen = 0;
    uint64_t m1[OC_N];

    ASSERT_EQ(CRYPT_EAL_Init(OC_INIT), HIFHE_SUCCESS);
    OcMsgFill(m1, OC_N, OC_T, 1);
    enc = OcKeyed(preset, NULL, pk);
    dec = OcKeyed(preset, sk, NULL);
    ASSERT_TRUE(enc != NULL && dec != NULL);
    ASSERT_EQ(HIFHE_Encode(enc, m1, OC_N, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(enc, pt, &ct), HIFHE_SUCCESS);
    wire = OcSerialize(enc, ct, &wireLen);
    ASSERT_TRUE(wire != NULL);
    /* Interchange framing, sized as the format says: the bytes themselves are
     * randomized, so they are not compared. */
    ASSERT_EQ(HIFHE_Ctrl(enc, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, NULL, &expectLen, sizeof(expectLen)),
              HIFHE_SUCCESS);
    ASSERT_EQ(wireLen, expectLen);
    ASSERT_COMPARE("ct magic", wire, 4, pk->x, 4);
    /* A context that only holds the legacy secret key reads and decrypts them. */
    ASSERT_EQ(HIFHE_Deserialize(dec, wire, wireLen, &back), HIFHE_SUCCESS);
    ASSERT_EQ(OcDecryptDiff(dec, back, m1), 0);
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(back);
    HIFHE_Free(enc);
    HIFHE_Free(dec);
    free(wire);
    CRYPT_EAL_Cleanup(OC_INIT);
#else
    (void)preset;
    (void)sk;
    (void)pk;
    SKIP_TEST();
#endif
}
/* END_CASE */
