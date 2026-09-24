/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 */

/* BEGIN_HEADER */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_params.h"
#include "crypt_algid.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
#include "crypt_types.h"

#include "hifhe_provider.h"
#include "hifhe_types.h"
#include "hifhe_err.h"
#include "crypto_test_util.h"
#include "test.h"
/* END_HEADER */

/*
 * Known-answer tests for the BGV provider. Every input is fixed: keys come
 * from HIFHE_CTRL_BGV_SET_SEED, ciphertext and plaintext bodies from a
 * seeded SplitMix64 stream, messages likewise. Each case runs one operation
 * through the EAL surface and compares the SHA-256 of the serialised output
 * with the expected digest in the .data file.
 *
 * Only public EAL calls are used, so the suite builds against any release
 * of the provider. Vectors marked "baseline" were produced by the provider
 * before the BGV optimisation work (66378e2) and still hold; those marked
 * "post-optimisation" cover decryption output and seeded relinearisation
 * and Galois keys, which that work deliberately changed.
 */

#define KAT_SK            0
#define KAT_PK            1
#define KAT_ENCODE        2
#define KAT_DECODE        3
#define KAT_ADD_CTCT      4
#define KAT_ADD_CTPT      5
#define KAT_NEGATE        6
#define KAT_MUL_CTPT      7
#define KAT_MUL_CTCT      8
#define KAT_MODSWITCH     9
#define KAT_DECRYPT       10
#define KAT_RELIN         11
#define KAT_ROTATE        12

#define KAT_DIGEST_LEN    32u

typedef struct {
    CRYPT_EAL_PkeyCtx *ctx;
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
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

static void KatStoreU64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

static void KatEnvFree(KatEnv *e)
{
    CRYPT_EAL_PkeyFreeCtx(e->ctx);
    e->ctx = NULL;
}

/* A context for `preset` whose keys derive from a fixed seed. */
static int KatEnvInit(KatEnv *e, int32_t preset)
{
    memset(e, 0, sizeof(*e));
    e->ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_PKEY_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE,
                                          HIFHE_PROVIDER_ATTR);
    if (e->ctx == NULL) return -1;
    uint8_t seed[HIFHE_BGV_SEED_LEN];
    for (uint32_t i = 0; i < HIFHE_BGV_SEED_LEN; ++i) seed[i] = (uint8_t)(0xa5u ^ (i * 7u));
    if (CRYPT_EAL_PkeyCtrl(e->ctx, CRYPT_CTRL_SET_PARA_BY_ID, &preset, sizeof(preset)) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyCtrl(e->ctx, HIFHE_CTRL_BGV_SET_SEED, seed, sizeof(seed)) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyGen(e->ctx) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyCtrl(e->ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &e->n, sizeof(e->n)) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyCtrl(e->ctx, HIFHE_CTRL_BGV_GET_LEVEL, &e->level, sizeof(e->level)) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyCtrl(e->ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &e->t, sizeof(e->t)) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyCtrl(e->ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &e->ptLen, sizeof(e->ptLen)) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyCtrl(e->ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &e->ctLen, sizeof(e->ctLen)) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyCtrl(e->ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &e->msgLen, sizeof(e->msgLen)) != HIFHE_SUCCESS) {
        KatEnvFree(e);
        return -1;
    }
    return 0;
}

/* Encode a message of uniform values mod t drawn from stream `s`. */
static int KatEncode(KatEnv *e, uint64_t s, uint8_t *pt, uint32_t *ptLen)
{
    uint64_t *msg = (uint64_t *)BSL_SAL_Malloc(e->msgLen);
    if (msg == NULL) return -1;
    for (uint32_t i = 0; i < e->n; ++i) msg[i] = KatNext(&s) % e->t;
    BSL_Param in[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, msg, e->msgLen, 0}, BSL_PARAM_END };
    uint32_t out = e->ptLen;
    int32_t rc = CRYPT_EAL_PkeyHEMsgEncode(e->ctx, in, pt, &out);
    BSL_SAL_Free(msg);
    if (rc != HIFHE_SUCCESS) return -1;
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
            for (uint32_t j = 0; j < e->n; ++j) KatStoreU64(slice + (size_t)j * 8u, KatNext(&s) % q);
        }
    }
}

/* A fixed ciphertext: the shape of a fresh encryption with its seed field
 * cleared and both components replaced by stream `s`. */
static int KatCiphertext(KatEnv *e, uint64_t s, uint8_t *ct, uint32_t *ctLen)
{
    uint8_t *pt = (uint8_t *)BSL_SAL_Malloc(e->ptLen);
    if (pt == NULL) return -1;
    uint32_t ptL = 0u;
    int rc = KatEncode(e, s, pt, &ptL);
    uint32_t out = e->ctLen;
    if (rc == 0 && CRYPT_EAL_PkeyEncrypt(e->ctx, pt, ptL, ct, &out) != HIFHE_SUCCESS) rc = -1;
    BSL_SAL_Free(pt);
    if (rc != 0) return -1;
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
    BSL_Param gk[] = {
        {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_OCTETS, &step, (uint32_t)sizeof(step), 0},
        BSL_PARAM_END
    };
    return (CRYPT_EAL_PkeyCtrl(e->ctx, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, gk, 0u) == HIFHE_SUCCESS) ? 0 : -1;
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
    if (ct1 == NULL || ct2 == NULL || pt == NULL) goto EXIT;
    if (KatCiphertext(e, 0x1111ull, ct1, &ct1L) != 0 || KatCiphertext(e, 0x2222ull, ct2, &ct2L) != 0 ||
        KatEncode(e, 0x3333ull, pt, &ptL) != 0) {
        goto EXIT;
    }

    switch (op) {
        case KAT_SK: {
            BSL_Param g[] = { {HIFHE_PARAM_BGV_PRVKEY, BSL_PARAM_TYPE_OCTETS, out, cap, 0}, BSL_PARAM_END };
            if (CRYPT_EAL_PkeyGetPrvEx(e->ctx, g) != HIFHE_SUCCESS) goto EXIT;
            len = g[0].useLen;
            break;
        }
        case KAT_PK: {
            BSL_Param g[] = { {HIFHE_PARAM_BGV_PUBKEY, BSL_PARAM_TYPE_OCTETS, out, cap, 0}, BSL_PARAM_END };
            if (CRYPT_EAL_PkeyGetPubEx(e->ctx, g) != HIFHE_SUCCESS) goto EXIT;
            len = g[0].useLen;
            break;
        }
        case KAT_ENCODE:
            if (ptL > cap) goto EXIT;
            memcpy(out, pt, ptL);
            len = ptL;
            break;
        case KAT_DECODE: {
            KatFillBody(e, pt, ptL, 1u, 0x4444ull);
            BSL_Param in[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, pt, ptL, 0}, BSL_PARAM_END };
            len = e->msgLen;
            if (len > cap || CRYPT_EAL_PkeyHEMsgDecode(e->ctx, in, out, &len) != HIFHE_SUCCESS) goto EXIT;
            break;
        }
        case KAT_ADD_CTCT:
        case KAT_MUL_CTCT:
        case KAT_RELIN: {
            if (op == KAT_RELIN && CRYPT_EAL_PkeyCtrl(e->ctx, HIFHE_CTRL_BGV_GEN_RELIN_KEY, NULL, 0u) != HIFHE_SUCCESS) {
                goto EXIT;
            }
            BSL_Param in[] = {
                {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
                {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ct2, ct2L, 0},
                BSL_PARAM_END
            };
            int32_t r = (op == KAT_ADD_CTCT) ? CRYPT_EAL_PkeyHEAdd(e->ctx, in, out, &len)
                                             : CRYPT_EAL_PkeyHEMul(e->ctx, in, out, &len);
            if (r != HIFHE_SUCCESS) goto EXIT;
            break;
        }
        case KAT_ADD_CTPT:
        case KAT_MUL_CTPT: {
            BSL_Param in[] = {
                {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
                {HIFHE_PARAM_BGV_PLAINTEXT,   BSL_PARAM_TYPE_OCTETS, pt, ptL, 0},
                BSL_PARAM_END
            };
            int32_t r = (op == KAT_ADD_CTPT) ? CRYPT_EAL_PkeyHEAdd(e->ctx, in, out, &len)
                                             : CRYPT_EAL_PkeyHEMul(e->ctx, in, out, &len);
            if (r != HIFHE_SUCCESS) goto EXIT;
            break;
        }
        case KAT_NEGATE: {
            uint8_t marker = 1u;
            BSL_Param in[] = {
                {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
                {HIFHE_PARAM_BGV_NEGATE,      BSL_PARAM_TYPE_OCTETS, &marker, 1u, 0},
                BSL_PARAM_END
            };
            if (CRYPT_EAL_PkeyHEAdd(e->ctx, in, out, &len) != HIFHE_SUCCESS) goto EXIT;
            break;
        }
        case KAT_MODSWITCH: {
            BSL_Param in[] = {
                {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
                {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, out, cap, 0},
                BSL_PARAM_END
            };
            if (CRYPT_EAL_PkeyCtrl(e->ctx, HIFHE_CTRL_BGV_HE_MODSWITCH, in, 0u) != HIFHE_SUCCESS) goto EXIT;
            len = in[1].useLen;
            break;
        }
        case KAT_DECRYPT:
            if (CRYPT_EAL_PkeyDecrypt(e->ctx, ct1, ct1L, out, &len) != HIFHE_SUCCESS) goto EXIT;
            break;
        case KAT_ROTATE: {
            if (KatGenRotateKey(e) != 0) goto EXIT;
            int32_t step = 1;
            BSL_Param in[] = {
                {HIFHE_PARAM_BGV_CIPHERTEXT1,  BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
                {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_INT32,  &step, (uint32_t)sizeof(step), 0},
                {HIFHE_PARAM_BGV_CIPHERTEXT2,  BSL_PARAM_TYPE_OCTETS, out, cap, 0},
                BSL_PARAM_END
            };
            if (CRYPT_EAL_PkeyCtrl(e->ctx, HIFHE_CTRL_BGV_HE_ROTATE_STEP, in, 0u) != HIFHE_SUCCESS) goto EXIT;
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
    for (uint32_t i = 0; i < KAT_DIGEST_LEN; ++i) (void)sprintf(hex + 2u * i, "%02x", d[i]);
    Print("KAT preset=%d op=%d digest=%s\n", (int)preset, op, hex);
}

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_KAT_TC001
* @title  An EAL operation on fixed keys and inputs serialises to the expected SHA-256.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_KAT_TC001(int preset, int op, Hex *digest)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
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
}
/* END_CASE */
