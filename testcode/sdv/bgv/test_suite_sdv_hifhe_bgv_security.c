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

#include "crypt_errno.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_params.h"
#include "crypt_eal_rand.h"
#include "crypt_algid.h"
#include "crypt_bgv.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_init.h"
#include "crypt_types.h"
#include "crypt_params_key.h"

#include "hifhe.h"
#include "bgv_adapter_types.h"
#include "hifhe_types.h"
#include "hifhe_err.h"
#include "hifhe_err_internal.h"
#include "bgv_local.h"
#include "hifhe_local.h"
/* HIFHE_BGV_MAX_CIPHERTEXT_SIZE, and the modular helpers the key-recovery
 * attempt needs to do its own arithmetic on the wire. */
#include "bgv/bgv.h"
#include "bgv/evaluator.h"
#include "bgv/ciphertext.h"
#include "kernel/modulus.h"
#include "crypto_test_util.h"
#include "test.h"
/* END_HEADER */

/* Wire layout, per the format comment at the top of bgv_adapter_serdes.c:
 *   header(12)   magic(4) algId(4) format(2) type(2)
 *   plaintext    scaleFactor(8) polyDegree(4) rnsSize(4) dtype(4)
 *                | rnsBase[rnsSize](8) | data[rnsSize * polyDegree](8)
 *   ciphertext   ciphertextSize(4) correctionFactor(8) seed[4](8)
 *                | polyDegree(4) rnsSize(4) dtype(4)
 *                | rnsBase[rnsSize](8) | data[ciphertextSize * rnsSize * polyDegree](8) */
#define WIRE_HDR        12u
#define WIRE_PT_FIXED   20u
#define WIRE_CT_FIXED   56u
#define WIRE_CT_SZ_OFF  (WIRE_HDR) /* ciphertextSize field */
#define WIRE_CT_RNS_OFF (WIRE_HDR + 48u)
#define WIRE_PT_RNS_OFF (WIRE_HDR + 12u)

#ifdef HITLS_PROVIDER
static const uint8_t SEC_SEED_A[HIFHE_BGV_SEED_LEN] = {1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4,
                                                       5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8};
static const uint8_t SEC_SEED_B[HIFHE_BGV_SEED_LEN] = {0x9f, 0x2e, 0x77, 0x10, 0xab, 0xcd, 0xef, 0x01, 55, 44, 33,
                                                       22,   11,   66,   77,   88,   99,   12,   34,   56, 78, 90,
                                                       21,   43,   65,   87,   9,    8,    7,    6,    5,  4};

static uint32_t SecRdU32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint64_t SecRdU64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static void SecWrU32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, sizeof(v));
}

/* data region of each wire object, after the variable-length rnsBase */
static const uint8_t *SecCtData(const uint8_t *b)
{
    return b + WIRE_CT_FIXED + WIRE_HDR + 8u * SecRdU32(b + WIRE_CT_RNS_OFF);
}

static const uint8_t *SecPtData(const uint8_t *b)
{
    return b + WIRE_PT_FIXED + WIRE_HDR + 8u * SecRdU32(b + WIRE_PT_RNS_OFF);
}

static CRYPT_BGV_Ctx *SecNewCtx(int32_t preset, const uint8_t *seed, int gen)
{
    CRYPT_BGV_Ctx *ctx =
        CRYPT_BGV_NewCtx(HIFHE_BGV);
    if (ctx == NULL) {
        return NULL;
    }
    if (CRYPT_BGV_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &preset, sizeof(preset)) != HIFHE_SUCCESS) {
        CRYPT_BGV_FreeCtx(ctx);
        return NULL;
    }
    if (seed != NULL && CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_SET_SEED, (void *)(uintptr_t)seed, HIFHE_BGV_SEED_LEN) !=
                            HIFHE_SUCCESS) {
        CRYPT_BGV_FreeCtx(ctx);
        return NULL;
    }
    if (gen && CRYPT_BGV_Gen(ctx) != HIFHE_SUCCESS) {
        CRYPT_BGV_FreeCtx(ctx);
        return NULL;
    }
    return ctx;
}

typedef struct {
    uint32_t n;
    uint32_t ptLen;
    uint32_t ctLen;
    uint32_t msgLen;
    uint64_t t;
} SecDims;

static int SecDimsGet(CRYPT_BGV_Ctx *ctx, SecDims *d)
{
    memset(d, 0, sizeof(*d));
    if (CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &d->n, sizeof(d->n)) != HIFHE_SUCCESS ||
        CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &d->ptLen, sizeof(d->ptLen)) != HIFHE_SUCCESS ||
        CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &d->ctLen, sizeof(d->ctLen)) != HIFHE_SUCCESS ||
        CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &d->msgLen, sizeof(d->msgLen)) != HIFHE_SUCCESS ||
        CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &d->t, sizeof(d->t)) != HIFHE_SUCCESS) {
        return -1;
    }
    return 0;
}

static int SecEncode(CRYPT_BGV_Ctx *ctx, const uint64_t *msg, uint32_t msgLen, uint8_t *pt, uint32_t cap,
                     uint32_t *ptLen)
{
    BSL_Param in[] = {{HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, (void *)(uintptr_t)msg, msgLen, 0}, BSL_PARAM_END};
    uint32_t out = cap;
    if (CRYPT_BGV_HEMsgEncode(ctx, in, pt, &out) != HIFHE_SUCCESS) {
        return -1;
    }
    *ptLen = out;
    return 0;
}

static int SecDecode(CRYPT_BGV_Ctx *ctx, const uint8_t *pt, uint32_t ptLen, uint64_t *msg, uint32_t msgLen)
{
    BSL_Param in[] = {{HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, (void *)(uintptr_t)pt, ptLen, 0},
                      BSL_PARAM_END};
    uint32_t out = msgLen;
    if (CRYPT_BGV_HEMsgDecode(ctx, in, (uint8_t *)msg, &out) != HIFHE_SUCCESS) {
        return -1;
    }
    return 0;
}

/* Encrypt the same message under two independent keys and report whether the
 * bytes Decrypt hands back depend on which key was used. */
static int SecNoKeyLeakProbe(int32_t preset, int *ctDiffer, int *decSame, int *decIsEncoded)
{
    CRYPT_BGV_Ctx *a = NULL, *b = NULL;
    uint64_t *msg = NULL;
    uint8_t *ptA = NULL, *ptB = NULL, *ctA = NULL, *ctB = NULL, *dA = NULL, *dB = NULL;
    SecDims d;
    int rc = -1;

    *ctDiffer = 0;
    *decSame = 0;
    *decIsEncoded = 0;

    a = SecNewCtx(preset, SEC_SEED_A, 1);
    b = SecNewCtx(preset, SEC_SEED_B, 1);
    if (a == NULL || b == NULL) {
        goto DONE;
    }
    if (SecDimsGet(a, &d) != 0) {
        goto DONE;
    }

    msg = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    ptA = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ptB = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ctA = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctB = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    dA = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    dB = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    if (msg == NULL || ptA == NULL || ptB == NULL || ctA == NULL || ctB == NULL || dA == NULL || dB == NULL) {
        goto DONE;
    }
    for (uint32_t i = 0; i < d.n; ++i) {
        msg[i] = (i * 13u + 5u) % d.t;
    }

    uint32_t ptALen = 0u, ptBLen = 0u;
    if (SecEncode(a, msg, d.msgLen, ptA, d.ptLen, &ptALen) != 0) {
        goto DONE;
    }
    if (SecEncode(b, msg, d.msgLen, ptB, d.ptLen, &ptBLen) != 0) {
        goto DONE;
    }

    uint32_t ctALen = d.ctLen, ctBLen = d.ctLen;
    if (CRYPT_BGV_Encrypt(a, ptA, ptALen, ctA, &ctALen) != HIFHE_SUCCESS) {
        goto DONE;
    }
    if (CRYPT_BGV_Encrypt(b, ptB, ptBLen, ctB, &ctBLen) != HIFHE_SUCCESS) {
        goto DONE;
    }

    uint32_t dALen = d.ptLen, dBLen = d.ptLen;
    if (CRYPT_BGV_Decrypt(a, ctA, ctALen, dA, &dALen) != HIFHE_SUCCESS) {
        goto DONE;
    }
    if (CRYPT_BGV_Decrypt(b, ctB, ctBLen, dB, &dBLen) != HIFHE_SUCCESS) {
        goto DONE;
    }

    /* The two keys must really be distinct, or the comparison below proves
     * nothing. */
    *ctDiffer = (ctALen != ctBLen || memcmp(ctA, ctB, ctALen) != 0) ? 1 : 0;
    *decSame = (dALen == dBLen && memcmp(dA, dB, dALen) == 0) ? 1 : 0;
    *decIsEncoded = (dALen == ptALen && memcmp(dA, ptA, dALen) == 0) ? 1 : 0;
    rc = 0;

DONE:
    BSL_SAL_Free(msg);
    BSL_SAL_Free(ptA);
    BSL_SAL_Free(ptB);
    BSL_SAL_Free(ctA);
    BSL_SAL_Free(ctB);
    BSL_SAL_Free(dA);
    BSL_SAL_Free(dB);
    CRYPT_BGV_FreeCtx(a);
    CRYPT_BGV_FreeCtx(b);
    return rc;
}
#endif

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_DECRYPT_NO_KEY_LEAK_TC001
* @title  Decrypt output carries no key-dependent data, one limb.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_DECRYPT_NO_KEY_LEAK_TC001(void)
{
#ifndef HITLS_PROVIDER
    SKIP_TEST();
#else
    int ctDiffer = 0, decSame = 0, decIsEncoded = 0;
    TestMemInit();
    TestRandInit();
    ASSERT_EQ(SecNoKeyLeakProbe(HIFHE_BGV_2048_48_17BIT, &ctDiffer, &decSame, &decIsEncoded), 0);
    ASSERT_EQ(ctDiffer, 1);
    ASSERT_EQ(decSame, 1);
    ASSERT_EQ(decIsEncoded, 1);
EXIT:;
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_DECRYPT_NO_KEY_LEAK_TC002
* @title  Decrypt output carries no key-dependent data across a four-limb chain.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_DECRYPT_NO_KEY_LEAK_TC002(void)
{
#ifndef HITLS_PROVIDER
    SKIP_TEST();
#else
    int ctDiffer = 0, decSame = 0, decIsEncoded = 0;
    TestMemInit();
    TestRandInit();
    ASSERT_EQ(SecNoKeyLeakProbe(HIFHE_BGV_8192_44x4_17BIT, &ctDiffer, &decSame, &decIsEncoded), 0);
    ASSERT_EQ(ctDiffer, 1);
    ASSERT_EQ(decSame, 1);
    ASSERT_EQ(decIsEncoded, 1);
EXIT:;
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_PHASE_NOT_RECOVERABLE_TC001
* @title  Coordinate-wise secret recovery from a ciphertext and its decrypt output fails.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_PHASE_NOT_RECOVERABLE_TC001(void)
{
#ifndef HITLS_PROVIDER
    SKIP_TEST();
#else
    CRYPT_BGV_Ctx *victim = NULL, *attacker = NULL;
    uint64_t *m1 = NULL, *m2 = NULL, *guess = NULL, *x = NULL;
    uint8_t *pt1 = NULL, *pt2 = NULL, *ct1 = NULL, *ct2 = NULL;
    uint8_t *dec1 = NULL, *dec2 = NULL, *pred = NULL;
    SecDims d;

    TestMemInit();
    TestRandInit();
    victim = SecNewCtx(HIFHE_BGV_2048_48_17BIT, SEC_SEED_A, 1);
    ASSERT_TRUE(victim != NULL);
    ASSERT_EQ(SecDimsGet(victim, &d), 0);

    m1 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    m2 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    guess = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt1 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    pt2 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct1 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ct2 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    dec1 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    dec2 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    pred = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(m1 && m2 && guess && pt1 && pt2 && ct1 && ct2 && dec1 && dec2 && pred);

    for (uint32_t i = 0; i < d.n; ++i) {
        m1[i] = (i * 7u + 1u) % d.t;
        m2[i] = (i * 31u + 12345u) % d.t;
    }

    uint32_t pt1Len = 0u, pt2Len = 0u;
    ASSERT_EQ(SecEncode(victim, m1, d.msgLen, pt1, d.ptLen, &pt1Len), 0);
    ASSERT_EQ(SecEncode(victim, m2, d.msgLen, pt2, d.ptLen, &pt2Len), 0);
    uint32_t ct1Len = d.ctLen, ct2Len = d.ctLen;
    ASSERT_EQ(CRYPT_BGV_Encrypt(victim, pt1, pt1Len, ct1, &ct1Len), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Encrypt(victim, pt2, pt2Len, ct2, &ct2Len), HIFHE_SUCCESS);
    /* the victim releases the raw bytes Decrypt returned for both */
    uint32_t dec1Len = d.ptLen, dec2Len = d.ptLen;
    ASSERT_EQ(CRYPT_BGV_Decrypt(victim, ct1, ct1Len, dec1, &dec1Len), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Decrypt(victim, ct2, ct2Len, dec2, &dec2Len), HIFHE_SUCCESS);

    /* From here on nothing holds a key. If Decrypt exposed the phase
     * P = c0 + c1*s, then X = (P - c0) * inv(c1) would be the secret and the
     * phase of any other ciphertext would follow from it. The per-limb
     * Montgomery factor the wire applies is public and cancels between the
     * two steps, so no knowledge of the internal domain is needed. */
    uint32_t sz = SecRdU32(ct1 + WIRE_CT_SZ_OFF);
    uint32_t lc = SecRdU32(ct1 + WIRE_CT_RNS_OFF);
    ASSERT_EQ(sz, 2u);
    ASSERT_TRUE(lc >= 1u);

    const uint8_t *d1 = SecCtData(ct1), *d2 = SecCtData(ct2);
    const uint8_t *f1 = SecPtData(dec1), *f2 = SecPtData(dec2);
    x = (uint64_t *)BSL_SAL_Malloc((uint32_t)(lc * d.n * sizeof(uint64_t)));
    ASSERT_TRUE(x != NULL);

    memcpy(pred, dec1, dec1Len); /* reuse the header and shape */
    uint32_t wordMatches = 0u;
    for (uint32_t i = 0; i < lc; ++i) {
        Modulus q = SecRdU64(ct1 + WIRE_HDR + WIRE_CT_FIXED + 8u * i);
        for (uint32_t j = 0; j < d.n; ++j) {
            uint64_t c0 = SecRdU64(d1 + ((size_t)(0u * lc + i) * d.n + j) * 8u) % q;
            uint64_t c1 = SecRdU64(d1 + ((size_t)(1u * lc + i) * d.n + j) * 8u) % q;
            uint64_t p = SecRdU64(f1 + ((size_t)i * d.n + j) * 8u) % q;
            x[(size_t)i * d.n + j] = (c1 == 0u) ? 0u : Kernel_MulMod((p + q - c0) % q, Kernel_ModInv(c1, q), q);

            uint64_t e0 = SecRdU64(d2 + ((size_t)(0u * lc + i) * d.n + j) * 8u) % q;
            uint64_t e1 = SecRdU64(d2 + ((size_t)(1u * lc + i) * d.n + j) * 8u) % q;
            uint64_t want = SecRdU64(f2 + ((size_t)i * d.n + j) * 8u) % q;
            uint64_t guessWord = (e0 + Kernel_MulMod(e1, x[(size_t)i * d.n + j], q)) % q;
            if (guessWord == want) {
                wordMatches++;
            }
            memcpy((uint8_t *)SecPtData(pred) + ((size_t)i * d.n + j) * 8u, &guessWord, sizeof(guessWord));
        }
    }
    /* Not one predicted word may match the real decrypt output. */
    ASSERT_EQ(wordMatches, 0u);

    /* Decoding needs no key, so the attacker gets to try it on its guess. */
    attacker = SecNewCtx(HIFHE_BGV_2048_48_17BIT, SEC_SEED_A, 0);
    ASSERT_TRUE(attacker != NULL);
    if (SecDecode(attacker, pred, dec1Len, guess, d.msgLen) == 0) {
        uint32_t slotMatches = 0u;
        for (uint32_t j = 0; j < d.n; ++j) {
            if (guess[j] == m2[j]) {
                slotMatches++;
            }
        }
        /* Unrelated slots collide with probability 1/t, so anything near a
         * recovery is far above this bound. */
        ASSERT_TRUE(slotMatches < d.n / 8u);
    }

EXIT:
    BSL_SAL_Free(m1);
    BSL_SAL_Free(m2);
    BSL_SAL_Free(guess);
    BSL_SAL_Free(x);
    BSL_SAL_Free(pt1);
    BSL_SAL_Free(pt2);
    BSL_SAL_Free(ct1);
    BSL_SAL_Free(ct2);
    BSL_SAL_Free(dec1);
    BSL_SAL_Free(dec2);
    BSL_SAL_Free(pred);
    CRYPT_BGV_FreeCtx(victim);
    CRYPT_BGV_FreeCtx(attacker);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_CT_DEGREE_BOUND_TC001
* @title  A wire ciphertext whose component count exceeds the supported degree is rejected.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_CT_DEGREE_BOUND_TC001(void)
{
#ifndef HITLS_PROVIDER
    SKIP_TEST();
#else
    CRYPT_BGV_Ctx *ctx = NULL;
    uint64_t *msg = NULL;
    uint8_t *pt = NULL, *ct = NULL, *out = NULL;
    SecDims d;

    TestMemInit();
    TestRandInit();
    ctx = SecNewCtx(HIFHE_BGV_2048_48_17BIT, SEC_SEED_A, 1);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(SecDimsGet(ctx, &d), 0);

    msg = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    out = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(msg && pt && ct && out);
    for (uint32_t i = 0; i < d.n; ++i) {
        msg[i] = i % 97u;
    }

    uint32_t ptLen = 0u;
    ASSERT_EQ(SecEncode(ctx, msg, d.msgLen, pt, d.ptLen, &ptLen), 0);
    uint32_t ctLen = d.ctLen;
    ASSERT_EQ(CRYPT_BGV_Encrypt(ctx, pt, ptLen, ct, &ctLen), HIFHE_SUCCESS);

    /* control: untouched, the same buffer decrypts */
    uint32_t outLen = d.ptLen;
    ASSERT_EQ(CRYPT_BGV_Decrypt(ctx, ct, ctLen, out, &outLen), HIFHE_SUCCESS);
    ASSERT_EQ(SecRdU32(ct + WIRE_CT_SZ_OFF), 2u);

    /* one past the supported degree, a large degree, and a degree below two:
     * every one rejected before any secret-key arithmetic */
    const uint32_t bad[] = {HIFHE_BGV_MAX_CIPHERTEXT_SIZE + 1u, 1024u, 0u, 1u};
    for (uint32_t k = 0; k < sizeof(bad) / sizeof(bad[0]); ++k) {
        SecWrU32(ct + WIRE_CT_SZ_OFF, bad[k]);
        outLen = d.ptLen;
        ASSERT_EQ(CRYPT_BGV_Decrypt(ctx, ct, ctLen, out, &outLen), HIFHE_SERDES_FAIL);
    }

    /* restoring the one field it changed makes the buffer good again, so the
     * rejections above are attributable to that field alone */
    SecWrU32(ct + WIRE_CT_SZ_OFF, 2u);
    outLen = d.ptLen;
    ASSERT_EQ(CRYPT_BGV_Decrypt(ctx, ct, ctLen, out, &outLen), HIFHE_SUCCESS);

EXIT:
    BSL_SAL_Free(msg);
    BSL_SAL_Free(pt);
    BSL_SAL_Free(ct);
    BSL_SAL_Free(out);
    CRYPT_BGV_FreeCtx(ctx);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_GALOIS_STEP_COUNT_TC001
* @title  A rotation-step list longer than the ring degree is refused before it is sized.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_GALOIS_STEP_COUNT_TC001(void)
{
#if !defined(HITLS_PROVIDER) || !defined(HIFHE_CUSTOM_PARAM)
    SKIP_TEST();
#else
    CRYPT_BGV_Ctx *ctx = NULL;
    int32_t *steps = NULL;
    uint64_t *elts = NULL;
    SecDims d;

    TestMemInit();
    TestRandInit();
    ctx = SecNewCtx(HIFHE_BGV_2048_48_17BIT, SEC_SEED_A, 1);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(SecDimsGet(ctx, &d), 0);

    /* control: a single step is accepted */
    int32_t one = 1;
    BSL_Param ok[] = {{HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_OCTETS, &one, (uint32_t)sizeof(one), 0},
                      BSL_PARAM_END};
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, ok, 0u), HIFHE_SUCCESS);

    /* There are only n distinct odd Galois elements mod 2n, so n+1 steps are
     * malformed and must be refused before the list is widened to 64-bit
     * elements or any key is generated. */
    uint32_t tooMany = d.n + 1u;
    steps = (int32_t *)BSL_SAL_Calloc(tooMany, (uint32_t)sizeof(int32_t));
    ASSERT_TRUE(steps != NULL);
    BSL_Param wide[] = {
        {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_OCTETS, steps, (uint32_t)(tooMany * sizeof(int32_t)), 0},
        BSL_PARAM_END};
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, wide, 0u), HIFHE_PARAM_INVALID);

    /* the same bound applies when the elements are named directly */
    elts = (uint64_t *)BSL_SAL_Calloc(tooMany, (uint32_t)sizeof(uint64_t));
    ASSERT_TRUE(elts != NULL);
    BSL_Param wideElts[] = {
        {HIFHE_PARAM_BGV_GALOIS_ELTS, BSL_PARAM_TYPE_OCTETS, elts, (uint32_t)(tooMany * sizeof(uint64_t)), 0},
        BSL_PARAM_END};
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, wideElts, 0u), HIFHE_PARAM_INVALID);

EXIT:
    BSL_SAL_Free(steps);
    BSL_SAL_Free(elts);
    CRYPT_BGV_FreeCtx(ctx);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_ENCODE_MISALIGNED_MSG_TC001
* @title  Encoding a misaligned message buffer matches the aligned result and leaves the caller buffer untouched.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_ENCODE_MISALIGNED_MSG_TC001(void)
{
#ifndef HITLS_PROVIDER
    SKIP_TEST();
#else
    CRYPT_BGV_Ctx *ctx = NULL;
    uint64_t *aligned = NULL;
    uint8_t *slab = NULL, *refOut = NULL, *misOut = NULL;
    SecDims d;

    TestMemInit();
    TestRandInit();
    ctx = SecNewCtx(HIFHE_BGV_2048_48_17BIT, SEC_SEED_A, 0);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(SecDimsGet(ctx, &d), 0);

    aligned = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    slab = (uint8_t *)BSL_SAL_Malloc(d.msgLen + 8u);
    refOut = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    misOut = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(aligned && slab && refOut && misOut);
    for (uint32_t i = 0; i < d.n; ++i) {
        aligned[i] = (i * 17u + 3u) % d.t;
    }
    ASSERT_EQ((uintptr_t)aligned % sizeof(uint64_t), 0u);

    uint32_t refLen = 0u;
    ASSERT_EQ(SecEncode(ctx, aligned, d.msgLen, refOut, d.ptLen, &refLen), 0);

    /* Every misalignment takes the internal copy path. The result must equal
     * the aligned one, and the caller's buffer must come back untouched and
     * still owned by the caller; an asan build fails here if the provider
     * releases it. */
    for (uint32_t off = 1u; off < 8u; ++off) {
        uint8_t *mis = slab + off;
        if (((uintptr_t)mis % sizeof(uint64_t)) == 0u) {
            continue;
        }
        memcpy(mis, aligned, d.msgLen);
        uint32_t misLen = 0u;
        ASSERT_EQ(SecEncode(ctx, (const uint64_t *)mis, d.msgLen, misOut, d.ptLen, &misLen), 0);
        ASSERT_EQ(misLen, refLen);
        ASSERT_EQ(memcmp(misOut, refOut, refLen), 0);
        ASSERT_EQ(memcmp(mis, aligned, d.msgLen), 0);
    }

EXIT:
    BSL_SAL_Free(aligned);
    BSL_SAL_Free(slab);
    BSL_SAL_Free(refOut);
    BSL_SAL_Free(misOut);
    CRYPT_BGV_FreeCtx(ctx);
#endif
}
/* END_CASE */

/* ---- recording allocator ----------------------------------------------- */

/* BSL_SAL memory hooks. While armed they track every block the library takes,
 * so a case can fail the n-th allocation, check the balance afterwards, and
 * look inside a block on its way to free(). Blocks taken before arming are
 * passed straight through. */
#define SEC_ALLOC_SLOTS 4096u

typedef struct {
    void *ptr;
    uint32_t size;
    int zeroed;
} SecBlock;

static SecBlock g_secBlocks[SEC_ALLOC_SLOTS];
static uint32_t g_secLive;
static uint32_t g_secSeen;
static uint32_t g_secFailAt; /* 0: fail nothing */
static int g_secArmed;
static int g_secOverflow;
static const uint8_t *g_secNeedle; /* compared against every tracked block */
static uint32_t g_secNeedleLen;
static int g_secNeedleSeen;

static void SecBlockAdd(void *p, uint32_t size)
{
    for (uint32_t i = 0; i < SEC_ALLOC_SLOTS; ++i) {
        if (g_secBlocks[i].ptr == NULL) {
            g_secBlocks[i].ptr = p;
            g_secBlocks[i].size = size;
            g_secLive++;
            return;
        }
    }
    g_secOverflow = 1;
}

/* Size of a tracked block, 0 when it is not one. */
static uint32_t SecBlockTake(void *p)
{
    for (uint32_t i = 0; i < SEC_ALLOC_SLOTS; ++i) {
        if (g_secBlocks[i].ptr == p) {
            uint32_t size = g_secBlocks[i].size;
            const uint8_t *bytes = p;
            uint8_t nonzero = 0u;
            for (uint32_t j = 0; j < size; ++j) {
                nonzero |= bytes[j];
            }
            g_secBlocks[i].zeroed = nonzero == 0u;
            g_secBlocks[i].ptr = NULL;
            g_secBlocks[i].size = 0u;
            g_secLive--;
            return size;
        }
    }
    return 0u;
}

static void *SecMallocHook(uint32_t size)
{
    if (size == 0u) {
        return NULL;
    }
    if (g_secArmed) {
        g_secSeen++;
        if (g_secFailAt != 0u && g_secSeen == g_secFailAt) {
            return NULL;
        }
    }
    void *p = malloc(size);
    if (p != NULL && g_secArmed) {
        SecBlockAdd(p, size);
    }
    return p;
}

static void SecFreeHook(void *p)
{
    if (p == NULL) {
        return;
    }
    uint32_t size = SecBlockTake(p);
    if (g_secNeedle != NULL && size >= g_secNeedleLen && g_secNeedleLen > 0u &&
        memcmp(p, g_secNeedle, g_secNeedleLen) == 0) {
        g_secNeedleSeen = 1;
    }
    free(p);
}

static void SecAllocReset(void)
{
    memset(g_secBlocks, 0, sizeof(g_secBlocks));
    g_secLive = 0u;
    g_secSeen = 0u;
    g_secFailAt = 0u;
    g_secArmed = 0;
    g_secOverflow = 0;
    g_secNeedle = NULL;
    g_secNeedleLen = 0u;
    g_secNeedleSeen = 0;
}

static int SecAllocHookInstall(void)
{
    SecAllocReset();
    if (HIFHE_SetMemFuncs(SecMallocHook, SecFreeHook) != HIFHE_SUCCESS) {
        return -1;
    }
    return 0;
}

/* Both NULL restores malloc and free. */
static void SecAllocHookRemove(void)
{
    g_secArmed = 0;
    g_secNeedle = NULL;
    (void)HIFHE_SetMemFuncs(NULL, NULL);
}

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_ENCODE_ALLOC_FAILURE_TC001
* @title  An allocation failure at any point inside message encoding releases every block the call took.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_ENCODE_ALLOC_FAILURE_TC001(void)
{
#ifndef HITLS_PROVIDER
    SKIP_TEST();
#else
    CRYPT_BGV_Ctx *ctx = NULL;
    uint64_t *msg = NULL;
    uint8_t *pt = NULL;
    SecDims d;
    int installed = 0;
    uint32_t tried = 0u, errors = 0u;

    TestMemInit();
    TestRandInit();
    ctx = SecNewCtx(HIFHE_BGV_2048_48_17BIT, SEC_SEED_A, 0);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(SecDimsGet(ctx, &d), 0);
    msg = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(msg != NULL && pt != NULL);
    for (uint32_t i = 0; i < d.n; ++i) {
        msg[i] = (i * 7u + 1u) % d.t;
    }

    /* One unmeasured encode first: the lazy plaintext NTT tables it builds
     * belong to the context, not to the call under test. */
    uint32_t warmLen = 0u;
    ASSERT_EQ(SecEncode(ctx, msg, d.msgLen, pt, d.ptLen, &warmLen), 0);

    ASSERT_EQ(SecAllocHookInstall(), 0);
    installed = 1;

    /* Fail the k-th allocation of the call for every k the call reaches.
     * Whatever it returns, nothing it allocated may still be held. */
    for (uint32_t k = 1u; k <= 64u; ++k) {
        BSL_Param in[] = {{HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, msg, d.msgLen, 0}, BSL_PARAM_END};
        uint32_t outLen = d.ptLen;
        SecAllocReset();
        g_secFailAt = k;
        g_secArmed = 1;
        int32_t r = CRYPT_BGV_HEMsgEncode(ctx, in, pt, &outLen);
        uint32_t seen = g_secSeen;
        uint32_t live = g_secLive;
        int overflow = g_secOverflow;
        g_secArmed = 0;
        tried = k;
        ASSERT_EQ(overflow, 0);
        ASSERT_EQ(live, 0u);
        if (r != HIFHE_SUCCESS) {
            errors++;
        }
        if (seen < k) {
            break; /* past the last allocation the call makes */
        }
    }
    /* A sweep that never injected anything would pass vacuously. */
    ASSERT_TRUE(tried > 1u);
    ASSERT_TRUE(errors > 0u);

EXIT:
    if (installed) {
        SecAllocHookRemove();
    }
    BSL_SAL_Free(msg);
    BSL_SAL_Free(pt);
    CRYPT_BGV_FreeCtx(ctx);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_GALOIS_SECRET_WIPED_TC001
* @title  Galois key generation does not release the secret key image it builds without wiping it.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_GALOIS_SECRET_WIPED_TC001(void)
{
#if !defined(HITLS_PROVIDER) || !defined(HIFHE_CUSTOM_PARAM)
    SKIP_TEST();
#else
    CRYPT_BGV_Ctx *ctx = NULL;
    CRYPT_BGV_Ctx *inner = NULL;
    uint8_t *needle = NULL;
    uint64_t *msg = NULL;
    uint8_t *pt = NULL, *ct = NULL, *back = NULL;
    SecDims d;
    int installed = 0;

    TestMemInit();
    TestRandInit();
    ctx = SecNewCtx(HIFHE_BGV_2048_48_17BIT, SEC_SEED_A, 1);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(SecDimsGet(ctx, &d), 0);
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_INNER_CTX, &inner, (uint32_t)sizeof(inner)), HIFHE_SUCCESS);
    ASSERT_TRUE(inner != NULL);
    ASSERT_TRUE(inner->bgv.keygen.sk != NULL);

    /* Galois element 1 is the identity permutation, so the key image the
     * generator builds, transforms and then frees ends up holding the key's
     * own NTT representation. That is what to look for in released blocks. */
    uint32_t needleLen = inner->bgv.keygen.sk->dataSize * (uint32_t)sizeof(uint64_t);
    ASSERT_TRUE(needleLen > 0u);
    needle = (uint8_t *)malloc(needleLen);
    ASSERT_TRUE(needle != NULL);
    memcpy(needle, inner->bgv.keygen.sk->data, needleLen);

    ASSERT_EQ(SecAllocHookInstall(), 0);
    installed = 1;
    g_secNeedle = needle;
    g_secNeedleLen = needleLen;
    g_secArmed = 1;
    uint64_t elt = 1u;
    BSL_Param p[] = {{HIFHE_PARAM_BGV_GALOIS_ELTS, BSL_PARAM_TYPE_OCTETS, &elt, (uint32_t)sizeof(elt), 0},
                     BSL_PARAM_END};
    int32_t r = CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, p, 0u);
    int seen = g_secNeedleSeen;
    int overflow = g_secOverflow;
    g_secArmed = 0;
    g_secNeedle = NULL;
    SecAllocHookRemove();
    installed = 0;

    ASSERT_EQ(r, HIFHE_SUCCESS);
    ASSERT_EQ(overflow, 0);
    ASSERT_EQ(seen, 0);

    /* Wiping owned copies must not have reached the key through a view. */
    msg = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    back = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(msg && pt && ct && back);
    for (uint32_t i = 0; i < d.n; ++i) {
        msg[i] = (i * 11u + 2u) % d.t;
    }
    uint32_t ptLen = 0u;
    ASSERT_EQ(SecEncode(ctx, msg, d.msgLen, pt, d.ptLen, &ptLen), 0);
    uint32_t ctLen = d.ctLen;
    ASSERT_EQ(CRYPT_BGV_Encrypt(ctx, pt, ptLen, ct, &ctLen), HIFHE_SUCCESS);
    uint32_t backLen = d.ptLen;
    ASSERT_EQ(CRYPT_BGV_Decrypt(ctx, ct, ctLen, back, &backLen), HIFHE_SUCCESS);
    ASSERT_EQ(backLen, ptLen);
    ASSERT_EQ(memcmp(back, pt, ptLen), 0);

EXIT:
    if (installed) {
        SecAllocHookRemove();
    }
    free(needle);
    BSL_SAL_Free(msg);
    BSL_SAL_Free(pt);
    BSL_SAL_Free(ct);
    BSL_SAL_Free(back);
    CRYPT_BGV_FreeCtx(ctx);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_REDUCTION_FIXED_CORRECTION_TC001
* @title  The modular reductions on the decryption path agree with the reference over their whole input range.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_REDUCTION_FIXED_CORRECTION_TC001(void)
{
    /* The reductions correct a quotient estimate a fixed number of times
     * instead of looping until the residue is in range. The bound only holds
     * if every reachable input still lands on the reference result. */
    static const uint32_t bits[] = {20u, 24u, 32u, 44u, 48u, 52u, 59u};
    uint64_t state = 0x243f6a8885a308d3ull;
    uint32_t checked = 0u;

    TestMemInit();
    for (uint32_t b = 0; b < sizeof(bits) / sizeof(bits[0]); ++b) {
        for (uint32_t rep = 0; rep < 24u; ++rep) {
            /* xorshift64: the same moduli and inputs on every run. */
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            uint64_t q = (state & ((1ull << bits[b]) - 1u)) | (1ull << (bits[b] - 1u)) | 1u;
            if (rep == 0u) {
                q = (1ull << bits[b]) - 1u;
            }
            if (rep == 1u) {
                q = (1ull << (bits[b] - 1u)) + 1u;
            }

            BarrettConst bc;
            ASSERT_EQ(Kernel_BarrettConst_Init(&bc, q), HIFHE_SUCCESS);

            /* 64-bit reduction: the boundaries first, then random words. */
            uint64_t edge[] = {
                0u, 1u, q - 1u, q, q + 1u, 2u * q, 3u * q, UINT64_MAX, UINT64_MAX - q, UINT64_MAX / q * q};
            for (uint32_t i = 0; i < sizeof(edge) / sizeof(edge[0]); ++i) {
                ASSERT_EQ(Kernel_BarrettReduce64Inl(edge[i], &bc), edge[i] % q);
                checked++;
            }
            for (uint32_t i = 0; i < 128u; ++i) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                ASSERT_EQ(Kernel_BarrettReduce64Inl(state, &bc), state % q);
                checked++;
            }

            /* 128-bit reduction and the Shoup multiplier, over products of
             * reduced operands, which is all either one is given. */
            uint64_t pair[] = {0u, 1u, 2u, q / 2u, q - 2u, q - 1u};
            for (uint32_t i = 0; i < sizeof(pair) / sizeof(pair[0]); ++i) {
                for (uint32_t j = 0; j < sizeof(pair) / sizeof(pair[0]); ++j) {
                    Uint128 prod = Kernel_U128Mul(pair[i], pair[j]);
                    uint64_t want = Kernel_U128ModU64(prod, q);
                    ASSERT_EQ(Kernel_BarrettReduce128Inl(prod.hi, prod.lo, &bc), want);
                    ASSERT_EQ(Kernel_BarrettMulModInl(pair[i], pair[j], &bc), want);
                    ShoupConst sc;
                    ASSERT_EQ(Kernel_ShoupConst_Init(&sc, pair[j], q), HIFHE_SUCCESS);
                    ASSERT_EQ(Kernel_ShoupMulModInl(pair[i], &sc), want);
                    checked += 3u;
                }
            }
            for (uint32_t i = 0; i < 128u; ++i) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                uint64_t a = state % q;
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                uint64_t m = state % q;
                uint64_t want = Kernel_U128ModU64(Kernel_U128Mul(a, m), q);
                ASSERT_EQ(Kernel_BarrettMulModInl(a, m, &bc), want);
                ShoupConst sc;
                ASSERT_EQ(Kernel_ShoupConst_Init(&sc, m, q), HIFHE_SUCCESS);
                ASSERT_EQ(Kernel_ShoupMulModInl(a, &sc), want);
                checked += 2u;
            }
        }
    }
    ASSERT_TRUE(checked > 50000u);

EXIT:
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_ENCODE_MSG_COPY_WIPED_TC001
* @title  The realigned copy of a caller message is wiped before it is released.
* @brief  HIFHE_PARAM_BGV_MSG carries OCTETS, which promise no alignment, so a
*         message that is not 8-byte aligned is copied inside the encode. The
*         copy holds the caller's cleartext. The recording allocator compares
*         every released block against the message bytes.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_ENCODE_MSG_COPY_WIPED_TC001(void)
{
#ifndef HITLS_PROVIDER
    SKIP_TEST();
#else
    CRYPT_BGV_Ctx *ctx = NULL;
    uint8_t *slab = NULL, *needle = NULL, *pt = NULL;
    SecDims d;
    int installed = 0;

    TestMemInit();
    TestRandInit();
    ctx = SecNewCtx(HIFHE_BGV_2048_48_17BIT, SEC_SEED_A, 0);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(SecDimsGet(ctx, &d), 0);

    /* One odd byte in, so the message never starts on a word boundary. */
    slab = (uint8_t *)BSL_SAL_Malloc(d.msgLen + sizeof(uint64_t));
    needle = (uint8_t *)malloc(d.msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(slab != NULL && needle != NULL && pt != NULL);
    uint8_t *mis = slab + 1u;
    ASSERT_TRUE(((uintptr_t)mis % sizeof(uint64_t)) != 0u);
    uint64_t v;
    for (uint32_t i = 0; i < d.n; ++i) {
        v = (uint64_t)((i * 7919u + 13u) % d.t);
        memcpy(mis + (size_t)i * sizeof(uint64_t), &v, sizeof(v));
    }
    memcpy(needle, mis, d.msgLen);

    ASSERT_EQ(SecAllocHookInstall(), 0);
    installed = 1;
    g_secNeedle = needle;
    g_secNeedleLen = d.msgLen;
    g_secArmed = 1;
    uint32_t ptLen = 0u;
    int rc = SecEncode(ctx, (const uint64_t *)mis, d.msgLen, pt, d.ptLen, &ptLen);
    int seen = g_secNeedleSeen;
    int overflow = g_secOverflow;
    g_secArmed = 0;
    g_secNeedle = NULL;
    SecAllocHookRemove();
    installed = 0;

    ASSERT_EQ(rc, 0);
    ASSERT_EQ(overflow, 0);
    ASSERT_EQ(seen, 0);
    /* The caller's own buffer is untouched. */
    ASSERT_EQ(memcmp(mis, needle, d.msgLen), 0);

EXIT:
    if (installed) {
        SecAllocHookRemove();
    }
    free(needle);
    BSL_SAL_Free(slab);
    BSL_SAL_Free(pt);
    CRYPT_BGV_FreeCtx(ctx);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_DECODE_MSG_COPY_WIPED_TC001
* @title  The working copies of a decoded message are wiped before they are released.
* @brief  Decoding into a buffer that is not 8-byte aligned goes through an
*         aligned copy, and decoding a slot-mapped plaintext gathers the slots
*         from a copy in transform order. Both copies hold the caller's
*         cleartext. The recording allocator compares every released block
*         against the message bytes in the layout that copy holds.
*         layout 0: unaligned output; layout 1: slot-mapped plaintext.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_DECODE_MSG_COPY_WIPED_TC001(int layout)
{
#ifndef HITLS_PROVIDER
    (void)layout;
    SKIP_TEST();
#else
#ifndef HIFHE_CUSTOM_PARAM
    if (layout == 1) {
        SKIP_TEST();
    }
#endif
    CRYPT_BGV_Ctx *ctx = NULL;
    uint8_t *slab = NULL, *needle = NULL, *pt = NULL;
    uint64_t *m = NULL;
    SecDims d;
    int installed = 0;

    TestMemInit();
    TestRandInit();
    ctx = SecNewCtx(HIFHE_BGV_2048_48_17BIT, SEC_SEED_A, 0);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(SecDimsGet(ctx, &d), 0);
    if (layout == 1) {
#ifdef HIFHE_CUSTOM_PARAM
        uint32_t flag = 1u;
        ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_SET_SLOT_MAP, &flag, sizeof(flag)), HIFHE_SUCCESS);
#endif
    }

    m = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    slab = (uint8_t *)BSL_SAL_Malloc(d.msgLen + sizeof(uint64_t));
    needle = (uint8_t *)malloc(d.msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(m != NULL && slab != NULL && needle != NULL && pt != NULL);
    for (uint32_t i = 0; i < d.n; ++i) {
        m[i] = (uint64_t)((i * 7919u + 13u) % d.t);
    }
    uint32_t ptLen = 0u;
    ASSERT_EQ(SecEncode(ctx, m, d.msgLen, pt, d.ptLen, &ptLen), 0);

    /* Layout 0 decodes one odd byte in, so the output never starts on a word
     * boundary. Layout 1 decodes into an aligned buffer, and its copy holds
     * slot j at map[j]. */
    uint8_t *dst = slab;
    if (layout == 0) {
        dst = slab + 1u;
        ASSERT_TRUE(((uintptr_t)dst % sizeof(uint64_t)) != 0u);
        memcpy(needle, m, d.msgLen);
    } else {
        CRYPT_BGV_Ctx *inner = NULL;
        ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_INNER_CTX, &inner, sizeof(inner)), HIFHE_SUCCESS);
        ASSERT_TRUE(inner != NULL && inner->bgv.context.slotMap.data != NULL);
        ASSERT_EQ(inner->bgv.context.slotMap.size, d.n);
        const uint32_t *map = inner->bgv.context.slotMap.data;
        for (uint32_t j = 0; j < d.n; ++j) {
            memcpy(needle + (size_t)map[j] * sizeof(uint64_t), &m[j], sizeof(uint64_t));
        }
    }

    ASSERT_EQ(SecAllocHookInstall(), 0);
    installed = 1;
    g_secNeedle = needle;
    g_secNeedleLen = d.msgLen;
    g_secArmed = 1;
    int rc = SecDecode(ctx, pt, ptLen, (uint64_t *)dst, d.msgLen);
    int seen = g_secNeedleSeen;
    int overflow = g_secOverflow;
    g_secArmed = 0;
    g_secNeedle = NULL;
    SecAllocHookRemove();
    installed = 0;

    ASSERT_EQ(rc, 0);
    ASSERT_EQ(overflow, 0);
    ASSERT_EQ(seen, 0);
    /* And the caller still gets the message. */
    ASSERT_EQ(memcmp(dst, m, d.msgLen), 0);

EXIT:
    if (installed) {
        SecAllocHookRemove();
    }
    free(needle);
    BSL_SAL_Free(m);
    BSL_SAL_Free(slab);
    BSL_SAL_Free(pt);
    CRYPT_BGV_FreeCtx(ctx);
#endif
}
/* END_CASE */

/* What one native context derives from a seed: the exported keys, the seed
 * SET_SEED actually installed, and the key origin KeyGen assigned. The seed
 * and the origin are read from the context, so this checks the native control
 * path end to end rather than BGV_BGVContext_SetKeySeed on its own. `pub` and
 * `prv` are caller-owned and replaced on success. */
#ifdef HITLS_PROVIDER
typedef struct {
    uint8_t *pub;
    uint8_t *prv;
    uint32_t pubLen;
    uint32_t prvLen;
    uint8_t bound[HIFHE_CTX_SEED_LEN];
    uint8_t origin[16];
} SecSeeded;

static int SecSeededKeys(int32_t preset, const uint8_t *seed, SecSeeded *s)
{
    uint8_t **pub = &s->pub, **prv = &s->prv;
    uint32_t *pubLen = &s->pubLen, *prvLen = &s->prvLen;
    HIFHE_Ctx *ctx = HIFHE_New(HIFHE_BGV);
    int rc = -1;
    if (ctx == NULL) {
        return -1;
    }
    *pub = NULL;
    *prv = NULL;
    if (HIFHE_SetParaById(ctx, preset) != HIFHE_SUCCESS ||
        HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_SET_SEED, NULL, (void *)(uintptr_t)seed, HIFHE_BGV_SEED_LEN) != HIFHE_SUCCESS) {
        goto EXIT;
    }
    const CRYPT_BGV_Ctx *runtime = ctx->data;
    const uint8_t *stored = BgvContext_GetSeed(&runtime->bgv.context.rlweContext.seedCtx);
    if (stored == NULL) {
        goto EXIT;
    }
    memcpy(s->bound, stored, sizeof(s->bound));
    if (HIFHE_KeyGen(ctx) != HIFHE_SUCCESS) {
        goto EXIT;
    }
    runtime = ctx->data;
    const BgvContext *seedCtx = &runtime->bgv.context.rlweContext.seedCtx;
    uint8_t zero[HIFHE_CTX_SEED_LEN] = {0};
    if (BgvContext_GetSeed(seedCtx) != NULL || memcmp(seedCtx->seed, zero, sizeof(zero)) != 0) {
        goto EXIT;
    }
    memcpy(s->origin, ctx->keysetId, sizeof(s->origin));
    *pubLen = 0u;
    *prvLen = 0u;
    if (HIFHE_ExportPubKey(ctx, NULL, pubLen) != HIFHE_BUFFER_TOO_SMALL ||
        HIFHE_ExportPrvKey(ctx, NULL, prvLen) != HIFHE_BUFFER_TOO_SMALL) {
        goto EXIT;
    }
    *pub = malloc(*pubLen);
    *prv = malloc(*prvLen);
    if (*pub == NULL || *prv == NULL) {
        goto EXIT;
    }
    if (HIFHE_ExportPubKey(ctx, *pub, pubLen) != HIFHE_SUCCESS ||
        HIFHE_ExportPrvKey(ctx, *prv, prvLen) != HIFHE_SUCCESS) {
        goto EXIT;
    }
    rc = 0;
EXIT:
    if (rc != 0) {
        free(*pub);
        free(*prv);
        *pub = NULL;
        *prv = NULL;
    }
    HIFHE_Free(ctx);
    return rc;
}
#endif

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_SEED_PARAM_BOUND_TC001
* @title  One seed under two presets derives unrelated keys, and the same preset repeats them.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_SEED_PARAM_BOUND_TC001(int presetA, int presetB, int same)
{
#ifndef HITLS_PROVIDER
    (void)presetA;
    (void)presetB;
    (void)same;
    SKIP_TEST();
#else
    SecSeeded a = {0}, b = {0};

    TestMemInit();
    TestRandInit();
    ASSERT_EQ(SecSeededKeys((int32_t)presetA, SEC_SEED_A, &a), 0);
    ASSERT_EQ(SecSeededKeys((int32_t)presetB, SEC_SEED_A, &b), 0);
    uint8_t *pubA = a.pub, *prvA = a.prv, *pubB = b.pub;
    uint8_t *prvB = b.prv;
    uint32_t pubALen = a.pubLen, prvALen = a.prvLen, pubBLen = b.pubLen, prvBLen = b.prvLen;

    /* Every pair, whatever its rings: the seed SET_SEED installed and the
     * origin KeyGen assigned agree exactly when the presets do. An unbound
     * seed, or one bound to only some of the parameters, installs the same
     * value under two presets; an origin taken from anything but the bound
     * seed lets one preset's ciphertexts pass for the other's. */
    ASSERT_TRUE((same != 0) == (memcmp(a.bound, b.bound, sizeof(a.bound)) == 0));
    ASSERT_TRUE((same != 0) == (memcmp(a.origin, b.origin, sizeof(a.origin)) == 0));

    /* Exports of different lengths come from different rings and have no
     * bytes to compare; the seed and origin checks above are what separate
     * them. A pair that shares a ring is also compared byte by byte. */
    if (pubALen != pubBLen || prvALen != prvBLen) {
        ASSERT_EQ(same, 0);
        goto EXIT;
    }

    /* The secret is what the two public keys would otherwise share. */
    if (same != 0) {
        ASSERT_EQ(memcmp(prvA, prvB, prvALen), 0);
        ASSERT_EQ(memcmp(pubA, pubB, pubALen), 0);
    } else {
        ASSERT_TRUE(memcmp(prvA, prvB, prvALen) != 0);
        /* The whole public key, then the uniform component on its own: b
         * differs with t alone, so b alone proves nothing. The two
         * components split the ciphertext body in half, b first. */
        ASSERT_TRUE(memcmp(pubA, pubB, pubALen) != 0);
        const uint8_t *aPolyA = SecCtData(pubA);
        const uint8_t *aPolyB = SecCtData(pubB);
        uint32_t bodyLen = pubALen - (uint32_t)(aPolyA - pubA);
        ASSERT_EQ(SecRdU32(pubA + WIRE_CT_SZ_OFF), 2u);
        ASSERT_TRUE(memcmp(aPolyA + bodyLen / 2u, aPolyB + bodyLen / 2u, bodyLen / 2u) != 0);
    }
EXIT:
    free(a.pub);
    free(a.prv);
    free(b.pub);
    free(b.prv);
#endif
}
/* END_CASE */

#define SEC_PARAM_DEGREE     0
#define SEC_PARAM_PLAIN_MOD  1
#define SEC_PARAM_CORRECTION 2
#define SEC_PARAM_CHAIN_LEN  3
#define SEC_PARAM_CHAIN_PRIME 4

/* The seed SetKeySeed derives from SEC_SEED_A under the context's current
 * parameters, copied into `out`. */
#ifdef HITLS_PROVIDER
static int SecBoundSeed(BGVContext *bc, uint8_t out[HIFHE_CTX_SEED_LEN])
{
    if (BGV_BGVContext_SetKeySeed(bc, SEC_SEED_A, HIFHE_BGV_SEED_LEN) != HIFHE_SUCCESS) {
        return -1;
    }
    const uint8_t *seed = BgvContext_GetSeed(&bc->rlweContext.seedCtx);
    if (seed == NULL) {
        return -1;
    }
    memcpy(out, seed, HIFHE_CTX_SEED_LEN);
    return 0;
}
#endif

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_SEED_PARAM_WORD_TC001
* @title  Changing any one parameter that defines a key changes the seed it is bound to.
* @brief  The presets only pair rings that differ in the plaintext modulus, and a
*         custom parameter set cannot change the degree without changing the
*         chain primes, so the binding is checked on one context: each input of
*         the bound seed is changed on its own, the same caller seed installed
*         again, and the bound value compared with the original. Each change is
*         undone before the context is used or freed.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_SEED_PARAM_WORD_TC001(int word)
{
#ifndef HITLS_PROVIDER
    (void)word;
    SKIP_TEST();
#else
    CRYPT_BGV_Ctx *ctx = NULL;
    CRYPT_BGV_Ctx *inner = NULL;
    uint8_t ref[HIFHE_CTX_SEED_LEN], got[HIFHE_CTX_SEED_LEN], again[HIFHE_CTX_SEED_LEN];

    TestMemInit();
    TestRandInit();
    /* Two limbs, so the chain can shrink and still be a chain. */
    ctx = SecNewCtx(HIFHE_BGV_4096_44x2_17BIT, SEC_SEED_A, 1);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_INNER_CTX, &inner, (uint32_t)sizeof(inner)), HIFHE_SUCCESS);
    ASSERT_TRUE(inner != NULL && inner->bgv.haveContext);
    BGVContext *bc = &inner->bgv.context;
    BGVParameter *p = bc->bgvParameter;
    ASSERT_TRUE(p != NULL && p->rlweParameter.cipherMod.size == 2u);
    ASSERT_EQ(SecBoundSeed(bc, ref), 0);

    RlweParameter *rp = &p->rlweParameter;
    const uint32_t degree = rp->polyDegree;
    const Modulus plainMod = p->plainMod;
    const uint64_t correction = p->correctionFactor;
    const uint32_t chainLen = (uint32_t)rp->cipherMod.size;
    const uint64_t prime = rp->cipherMod.data[1];
    switch (word) {
        case SEC_PARAM_DEGREE: rp->polyDegree = degree * 2u; break;
        case SEC_PARAM_PLAIN_MOD: p->plainMod = plainMod + 2u; break;
        case SEC_PARAM_CORRECTION: p->correctionFactor = correction + 1u; break;
        case SEC_PARAM_CHAIN_LEN: rp->cipherMod.size = chainLen - 1u; break;
        case SEC_PARAM_CHAIN_PRIME: rp->cipherMod.data[1] = prime + 2u; break;
        default: break;
    }
    int rc = SecBoundSeed(bc, got);
    rp->polyDegree = degree;
    p->plainMod = plainMod;
    p->correctionFactor = correction;
    rp->cipherMod.size = chainLen;
    rp->cipherMod.data[1] = prime;
    ASSERT_TRUE(word >= SEC_PARAM_DEGREE && word <= SEC_PARAM_CHAIN_PRIME);
    ASSERT_EQ(rc, 0);
    ASSERT_TRUE(memcmp(ref, got, sizeof(ref)) != 0);

    /* Back on the original parameters, the binding repeats. */
    ASSERT_EQ(SecBoundSeed(bc, again), 0);
    ASSERT_EQ(memcmp(ref, again, sizeof(ref)), 0);
EXIT:
    CRYPT_BGV_FreeCtx(ctx);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_PRESET_MODULI_TC001
* @title  A preset's stored moduli are the ones the parameter search finds for it.
* @brief  Presets carry their moduli so that building them searches and
*         validates nothing. This rebuilds the preset through the custom
*         parameter path, which validates the request and runs the Proth
*         search, and requires the same chain and plaintext modulus. The
*         default preset pins its modulus on purpose, so for it only the
*         plaintext modulus is searched and the pinned chain is validated.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_PRESET_MODULI_TC001(int preset)
{
#ifndef HIFHE_CUSTOM_PARAM
    (void)preset;
    SKIP_TEST();
#else
    CRYPT_BGV_Ctx *stored = NULL, *searched = NULL;

    TestMemInit();
    TestRandInit();
    stored = CRYPT_BGV_NewCtx(HIFHE_BGV);
    searched = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(stored != NULL && searched != NULL);
    ASSERT_EQ(BgvUserPara_LoadPreset(&stored->para, (int32_t)preset), HIFHE_SUCCESS);
    ASSERT_EQ(BgvUserPara_LoadPreset(&searched->para, (int32_t)preset), HIFHE_SUCCESS);
    ASSERT_TRUE(stored->para.vetted != 0);

    searched->para.vetted = 0u;
    if (preset != HIFHE_BGV_DEFAULT) {
        Uint64Vector_Destroy(&searched->para.cipherMod);
    }
    if (searched->para.plainMod != 65537u) {
        searched->para.plainMod = 0u;
    }
    ASSERT_EQ(Bgv_BuildContext(stored), HIFHE_SUCCESS);
    ASSERT_EQ(Bgv_BuildContext(searched), HIFHE_SUCCESS);

    const RlweParameter *a = &stored->bgv.params.rlweParameter;
    const RlweParameter *b = &searched->bgv.params.rlweParameter;
    ASSERT_EQ(stored->bgv.params.plainMod, searched->bgv.params.plainMod);
    ASSERT_EQ(a->polyDegree, b->polyDegree);
    ASSERT_EQ(a->cipherMod.size, b->cipherMod.size);
    ASSERT_EQ(memcmp(a->cipherMod.data, b->cipherMod.data, a->cipherMod.size * sizeof(uint64_t)), 0);
EXIT:
    CRYPT_BGV_FreeCtx(stored);
    CRYPT_BGV_FreeCtx(searched);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_FEATURE_GATES_TC001
* @title  Custom-feature gates match the build.
* @brief  Check valid unvetted presets and colliding moduli independently.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_FEATURE_GATES_TC001(void)
{
    HIFHE_Ctx *ctx = NULL;
    CRYPT_BGV_Ctx *bgv = NULL;
    uint32_t format = HIFHE_WIRE_INTERCHANGE;

    TestMemInit();
    TestRandInit();
    ctx = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);
#ifdef HIFHE_CUSTOM_PARAM
    ASSERT_EQ(HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_SET_WIRE_FORMAT, NULL, &format, sizeof(format)), HIFHE_SUCCESS);
    ASSERT_EQ(Bgv_GenRelinKey(NULL), HIFHE_NULL_INPUT);
    ASSERT_EQ(Bgv_GenGaloisKeys(NULL, NULL, 0u), HIFHE_NULL_INPUT);
    ASSERT_EQ(BGV_BGVContext_EnsureSlotMap(NULL), HIFHE_NULL_INPUT);
#else
    ASSERT_EQ(HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_SET_WIRE_FORMAT, NULL, &format, sizeof(format)), HIFHE_NOT_SUPPORTED);
    ASSERT_EQ(Bgv_GenRelinKey(NULL), HIFHE_NOT_SUPPORTED);
    ASSERT_EQ(Bgv_GenGaloisKeys(NULL, NULL, 0u), HIFHE_NOT_SUPPORTED);
    ASSERT_EQ(BGV_BGVContext_EnsureSlotMap(NULL), HIFHE_NOT_SUPPORTED);
#endif
    HIFHE_Free(ctx);
    ctx = NULL;

#if defined(HITLS_PROVIDER) && !defined(HIFHE_CUSTOM_PARAM)
    bgv = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(bgv != NULL);
    BSL_Param params[] = {BSL_PARAM_END};
    uint32_t value = 0u;
    ASSERT_EQ(CRYPT_BGV_SetParaEx(bgv, params), HIFHE_PARAM_INVALID);
    ASSERT_EQ(CRYPT_BGV_Ctrl(bgv, HIFHE_CTRL_BGV_GEN_RELIN_KEY, &value, sizeof(value)), HIFHE_NOT_SUPPORTED);
    ASSERT_EQ(CRYPT_BGV_Ctrl(bgv, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, &value, sizeof(value)), HIFHE_NOT_SUPPORTED);
    ASSERT_EQ(CRYPT_BGV_Ctrl(bgv, HIFHE_CTRL_BGV_SET_SLOT_MAP, &value, sizeof(value)), HIFHE_NOT_SUPPORTED);
    ASSERT_EQ(CRYPT_BGV_Ctrl(bgv, HIFHE_CTRL_BGV_GET_RELIN_KEY_LEN, &value, sizeof(value)), HIFHE_NOT_SUPPORTED);
    CRYPT_BGV_FreeCtx(bgv);
    bgv = NULL;
#endif

    bgv = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(bgv != NULL);
    ASSERT_EQ(BgvUserPara_LoadPreset(&bgv->para, HIFHE_BGV_2048_48_17BIT), HIFHE_SUCCESS);
    bgv->para.vetted = 0u;
#ifdef HIFHE_CUSTOM_PARAM
    ASSERT_EQ(Bgv_BuildContext(bgv), HIFHE_SUCCESS);
    ASSERT_TRUE(bgv->bgv.haveContext);
#else
    ASSERT_EQ(Bgv_BuildContext(bgv), HIFHE_PARAM_INVALID);
    ASSERT_TRUE(!bgv->bgv.haveContext);
#endif
    CRYPT_BGV_FreeCtx(bgv);

    bgv = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(bgv != NULL);
    ASSERT_EQ(BgvUserPara_LoadPreset(&bgv->para, HIFHE_BGV_2048_48_17BIT), HIFHE_SUCCESS);
    ASSERT_TRUE(bgv->para.cipherMod.data != NULL && bgv->para.cipherMod.size > 0u);
    bgv->para.vetted = 0u;
    bgv->para.plainMod = bgv->para.cipherMod.data[0];
    ASSERT_EQ(Bgv_BuildContext(bgv), HIFHE_PARAM_INVALID);
    ASSERT_TRUE(!bgv->bgv.haveContext);
EXIT:
#ifdef HIFHE_ERR
    HIFHE_ErrClearError();
#endif
    HIFHE_Free(ctx);
    CRYPT_BGV_FreeCtx(bgv);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_PLAIN_MOD_BELOW_CHAIN_TC001
* @title  Custom parameters whose moduli cannot be kept apart are refused.
* @brief  N = 32768 with two 20-bit limbs leaves room for a single 20-bit Proth
*         prime, so the search for the second limb has to fail rather than
*         return a narrower prime (which could equal the 17-bit plaintext
*         modulus 65537). The same ring with a pinned chain is then checked
*         on its own: a plaintext search that may only land on a chain prime
*         fails, and a pinned plaintext modulus that is not below every chain
*         modulus is refused.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_PLAIN_MOD_BELOW_CHAIN_TC001(void)
{
#if !defined(HITLS_PROVIDER) || !defined(HIFHE_CUSTOM_PARAM)
    SKIP_TEST();
#else
    CRYPT_BGV_Ctx *ctx = NULL;
    CRYPT_BGV_Ctx *pinned = NULL;

    TestMemInit();
    TestRandInit();
    ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);
    uint32_t degree = 32768u;
    uint32_t plainBit = 17u;
    uint32_t bits[2] = {20u, 20u};
    BSL_Param params[] = {{HIFHE_PARAM_BGV_POLY_DEGREE, BSL_PARAM_TYPE_UINT32, &degree, sizeof(degree), 0},
                          {HIFHE_PARAM_BGV_PLAIN_MOD_BIT, BSL_PARAM_TYPE_UINT32, &plainBit, sizeof(plainBit), 0},
                          {HIFHE_PARAM_BGV_CIPHER_MOD_BITS, BSL_PARAM_TYPE_OCTETS, bits, sizeof(bits), 0},
                          BSL_PARAM_END};
    ASSERT_EQ(CRYPT_BGV_SetParaEx(ctx, params), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Gen(ctx), HIFHE_PARAM_INVALID);
    ASSERT_TRUE(!ctx->bgv.haveContext);

    /* The chain the old walk produced, pinned: 786433 (20 bits) and 65537. */
    static const uint64_t chain[2] = {786433u, 65537u};
    pinned = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(pinned != NULL);
    ASSERT_EQ(BgvUserPara_LoadPreset(&pinned->para, HIFHE_BGV_2048_48_17BIT), HIFHE_SUCCESS);
    pinned->para.vetted = 0u;
    pinned->para.polyDegree = degree;
    Uint32Vector_Destroy(&pinned->para.cipherModBit);
    ASSERT_EQ(Uint32Vector_Create(&pinned->para.cipherModBit, bits, 2u), HIFHE_SUCCESS);
    Uint64Vector_Destroy(&pinned->para.cipherMod);
    ASSERT_EQ(Uint64Vector_Create(&pinned->para.cipherMod, chain, 2u), HIFHE_SUCCESS);
    /* Searched: the only 17-bit candidate for this ring is a chain prime. */
    pinned->para.plainMod = 0u;
    ASSERT_EQ(Bgv_BuildContext(pinned), HIFHE_PARAM_INVALID);
    ASSERT_TRUE(!pinned->bgv.haveContext);
    /* Pinned: equal to a chain modulus. */
    pinned->para.plainMod = 65537u;
    ASSERT_EQ(Bgv_BuildContext(pinned), HIFHE_PARAM_INVALID);
    ASSERT_TRUE(!pinned->bgv.haveContext);
EXIT:
    CRYPT_BGV_FreeCtx(ctx);
    CRYPT_BGV_FreeCtx(pinned);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_KEY_PARSE_TC001
* @title  Reject trailing bytes and reduced zero public keys without replacing keys.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_KEY_PARSE_TC001(void)
{
    HIFHE_Ctx *src = NULL, *dst = NULL;
    uint8_t *pk = NULL, *sk = NULL, *after = NULL;
    uint32_t pkLen = 0u, skLen = 0u, n = 0u;
    TestMemInit();
    TestRandInit();
    src = HIFHE_New(HIFHE_BGV);
    dst = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(src != NULL && dst != NULL);
    ASSERT_EQ(HIFHE_SetParaById(src, HIFHE_BGV_2048_48_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_SetParaById(dst, HIFHE_BGV_2048_48_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(src), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_ExportPubKey(src, NULL, &pkLen), HIFHE_BUFFER_TOO_SMALL);
    ASSERT_EQ(HIFHE_ExportPrvKey(src, NULL, &skLen), HIFHE_BUFFER_TOO_SMALL);
    pk = malloc(pkLen + 1u);
    sk = malloc(skLen + 1u);
    after = malloc(pkLen);
    ASSERT_TRUE(pk != NULL && sk != NULL && after != NULL);
    ASSERT_EQ(HIFHE_ExportPubKey(src, pk, &pkLen), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_ExportPrvKey(src, sk, &skLen), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_ImportPrvKey(dst, sk, skLen), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_ImportPubKey(dst, pk, pkLen), HIFHE_SUCCESS);
    pk[pkLen] = 0x5au;
    sk[skLen] = 0x5au;
    ASSERT_EQ(HIFHE_ImportPubKey(dst, pk, pkLen + 1u), HIFHE_SERDES_FAIL);
    ASSERT_EQ(HIFHE_ImportPrvKey(dst, sk, skLen + 1u), HIFHE_SERDES_FAIL);
    ASSERT_EQ(HIFHE_ImportPubKey(dst, pk, pkLen - 1u), HIFHE_SERDES_FAIL);
    n = pkLen;
    ASSERT_EQ(HIFHE_ExportPubKey(dst, after, &n), HIFHE_SUCCESS);
    ASSERT_EQ(memcmp(pk, after, pkLen), 0);
    n = skLen;
    /* The rejected private key must also remain untouched. */
    uint8_t *skAfter = malloc(skLen);
    ASSERT_TRUE(skAfter != NULL);
    int32_t ret = HIFHE_ExportPrvKey(dst, skAfter, &n);
    int same = ret == HIFHE_SUCCESS && n == skLen && memcmp(sk, skAfter, skLen) == 0;
    free(skAfter);
    ASSERT_TRUE(same);

    /* One 48-bit limb: accept neither literal zero nor q-valued words,
     * in either coefficient or Montgomery NTT representation. */
    uint64_t q;
    memcpy(&q, pk + WIRE_HDR + WIRE_CT_FIXED, sizeof(q));
    uint32_t dataOff = WIRE_HDR + WIRE_CT_FIXED + 8u;
    for (uint32_t form = 0; form < 2u; ++form) {
        for (uint32_t equivalent = 0; equivalent < 2u; ++equivalent) {
            memcpy(pk + WIRE_HDR + 52u, &form, sizeof(form));
            uint64_t v = equivalent ? q : 0u;
            for (uint32_t off = dataOff; off < pkLen; off += 8u) {
                memcpy(pk + off, &v, sizeof(v));
            }
            ASSERT_EQ(HIFHE_ImportPubKey(dst, pk, pkLen), HIFHE_SERDES_FAIL);
            n = pkLen;
            ASSERT_EQ(HIFHE_ExportPubKey(dst, pk, &n), HIFHE_SUCCESS);
            ASSERT_EQ(memcmp(pk, after, pkLen), 0);
        }
    }
EXIT:
    free(pk);
    free(sk);
    free(after);
    HIFHE_Free(src);
    HIFHE_Free(dst);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_CENTERED_SCALE_TC001
* @title  A scale ratio of minus one negates coefficients without multiplying noise by t-1.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_CENTERED_SCALE_TC001(void)
{
    CRYPT_BGV_Ctx *ctx = NULL;
    Ciphertext a = {0}, b = {0}, out = {0};
    Evaluator ev;
    TestMemInit();
    ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(Bgv_SetPreset(ctx, HIFHE_BGV_2048_48_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(Bgv_BuildContext(ctx), HIFHE_SUCCESS);
    BGVContext *bc = &ctx->bgv.context;
    ASSERT_EQ(BGV_Ciphertext_CreateSize2Ntt(&a, 1u, &bc->rlweContext.cipherRnsBase, bc), HIFHE_SUCCESS);
    ASSERT_EQ(BGV_Ciphertext_CreateSize2Ntt(&b, 65536u, &bc->rlweContext.cipherRnsBase, bc), HIFHE_SUCCESS);
    ASSERT_EQ(BGV_Evaluator_Create(&ev, bc, NULL, NULL), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < a.dataSize; ++i) {
        a.data[i] = 7u;
        b.data[i] = 11u;
    }
    ASSERT_EQ(BGV_Evaluator_AddCtCt(&out, &a, &b, &ev), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < out.dataSize; ++i) {
        ASSERT_EQ(out.data[i], bc->rlweContext.cipherRnsBase.data[0] - 4u);
    }
    ASSERT_EQ(out.config.correctionFactor, 1u);
    /* Exercise both output aliases, including the temporary-output path. */
    ASSERT_EQ(BGV_Evaluator_AddCtCt(&a, &a, &b, &ev), HIFHE_SUCCESS);
    ASSERT_EQ(memcmp(a.data, out.data, out.dataSize * sizeof(uint64_t)), 0);
    for (uint32_t i = 0; i < a.dataSize; ++i) {
        a.data[i] = 7u;
    }
    ASSERT_EQ(BGV_Evaluator_AddCtCt(&b, &a, &b, &ev), HIFHE_SUCCESS);
    ASSERT_EQ(memcmp(b.data, out.data, out.dataSize * sizeof(uint64_t)), 0);
EXIT:
    BGV_Ciphertext_Destroy(&a);
    BGV_Ciphertext_Destroy(&b);
    BGV_Ciphertext_Destroy(&out);
    CRYPT_BGV_FreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_PINNED_BOUNDS_TC001
* @title  Pinned parameter widths, duplicate moduli and NTT bounds are checked before building.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_PINNED_BOUNDS_TC001(void)
{
#ifndef HIFHE_CUSTOM_PARAM
    SKIP_TEST();
#else
    CRYPT_BGV_Ctx *ctx = NULL;
    uint64_t table[HIFHE_NTT_TABLE_WORDS(2u)] = {0};
    NttTables tbl;
    BarrettConst barrett;
    ShoupConst shoup;
    TestMemInit();
    ASSERT_EQ(Kernel_BarrettConst_Init(&barrett, UINT64_C(1) << 63), HIFHE_PARAM_INVALID);
    ASSERT_EQ(Kernel_ShoupConst_Init(&shoup, 1u, UINT64_C(1) << 63), HIFHE_PARAM_INVALID);
    ASSERT_EQ(Kernel_Ntt_AttachTables(&tbl, table, (UINT64_C(1) << 62) + 1u, 2u), HIFHE_PARAM_INVALID);
    ASSERT_EQ(Kernel_Ntt_BuildTables(&tbl, table, (UINT64_C(1) << 62) + 1u, 2u), HIFHE_PARAM_INVALID);
    ASSERT_EQ(Kernel_Ntt_AttachTables(&tbl, table, 19u, 2u), HIFHE_PARAM_INVALID);
    ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(Bgv_SetPreset(ctx, HIFHE_BGV_2048_48_17BIT), HIFHE_SUCCESS);
    ctx->para.vetted = 0u;
    ctx->para.plainModBit = 18u;
    ASSERT_EQ(Bgv_BuildContext(ctx), HIFHE_PARAM_INVALID);
    ctx->para.plainModBit = 17u;
    ctx->para.cipherModBit.data[0] = 47u;
    ASSERT_EQ(Bgv_BuildContext(ctx), HIFHE_PARAM_INVALID);
    ctx->para.cipherModBit.data[0] = 48u;
    ASSERT_EQ(Bgv_BuildContext(ctx), HIFHE_SUCCESS);
    CRYPT_BGV_FreeCtx(ctx);
    ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(Bgv_SetPreset(ctx, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    ctx->para.vetted = 0u;
    ctx->para.cipherMod.data[1] = ctx->para.cipherMod.data[0];
    ASSERT_EQ(Bgv_BuildContext(ctx), HIFHE_PARAM_INVALID);
EXIT:
    CRYPT_BGV_FreeCtx(ctx);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_CLEAR_SEED_TC001
* @title  Explicit seed retirement preserves keys and removes seed material from duplicates.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_CLEAR_SEED_TC001(void)
{
#ifndef HITLS_PROVIDER
    SKIP_TEST();
#else
    CRYPT_BGV_Ctx *ctx = NULL, *dup = NULL;
    uint8_t zero[HIFHE_CTX_SEED_LEN] = {0};
    TestMemInit();
    TestRandInit();
    ctx = SecNewCtx(HIFHE_BGV_2048_48_17BIT, SEC_SEED_A, 1);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(ctx->bgv.context.rlweContext.seedCtx.hasSeed);
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_CLEAR_SEED, zero, 0u), HIFHE_PARAM_INVALID);
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_CLEAR_SEED, NULL, 0u), HIFHE_SUCCESS);
    ASSERT_EQ(memcmp(ctx->bgv.context.rlweContext.seedCtx.seed, zero, sizeof(zero)), 0);
    ASSERT_TRUE(!ctx->bgv.context.rlweContext.seedCtx.hasSeed);
    dup = CRYPT_BGV_DupCtx(ctx);
    ASSERT_TRUE(dup != NULL);
    ASSERT_TRUE(!dup->bgv.context.rlweContext.seedCtx.hasSeed);
    ASSERT_EQ(memcmp(dup->bgv.pk.data, ctx->bgv.pk.data, ctx->bgv.pk.dataSize * sizeof(uint64_t)), 0);
    ASSERT_EQ(memcmp(dup->bgv.keygen.sk->data, ctx->bgv.keygen.sk->data,
        ctx->bgv.keygen.sk->dataSize * sizeof(uint64_t)), 0);
#ifdef HIFHE_CUSTOM_PARAM
    ASSERT_EQ(Bgv_GenRelinKey(dup), HIFHE_SUCCESS);
#endif
EXIT:
    CRYPT_BGV_FreeCtx(ctx);
    CRYPT_BGV_FreeCtx(dup);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_CT_SCRATCH_WIPED_TC001
* @title  Ciphertext destruction erases owned data and leaves borrowed buffers untouched.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_CT_SCRATCH_WIPED_TC001(void)
{
    CRYPT_BGV_Ctx *ctx = NULL;
    Ciphertext ct = {0}, borrowed = {0};
    int hooked = 0;
    uint32_t block = SEC_ALLOC_SLOTS;
    TestMemInit();
    ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(Bgv_SetPreset(ctx, HIFHE_BGV_2048_48_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(Bgv_BuildContext(ctx), HIFHE_SUCCESS);
    ASSERT_EQ(SecAllocHookInstall(), 0);
    hooked = 1;
    g_secArmed = 1;
    ASSERT_EQ(BGV_Ciphertext_CreateSize2Ntt(&ct, 1u, &ctx->bgv.context.rlweContext.cipherRnsBase,
        &ctx->bgv.context), HIFHE_SUCCESS);
    memset(ct.data, 0xa5, ct.dataSize * sizeof(uint64_t));
    borrowed.data = ct.data;
    borrowed.dataSize = ct.dataSize;
    ASSERT_EQ(BGV_Ciphertext_Destroy(&borrowed), HIFHE_SUCCESS);
    ASSERT_EQ(ct.data[0], UINT64_C(0xa5a5a5a5a5a5a5a5));
    for (uint32_t i = 0; i < SEC_ALLOC_SLOTS; ++i) {
        if (g_secBlocks[i].ptr == ct.data) {
            block = i;
            break;
        }
    }
    ASSERT_TRUE(block < SEC_ALLOC_SLOTS);
    ASSERT_EQ(BGV_Ciphertext_Destroy(&ct), HIFHE_SUCCESS);
    ASSERT_TRUE(g_secBlocks[block].ptr == NULL && g_secBlocks[block].zeroed);
    ASSERT_EQ(g_secLive, 0u);
EXIT:
    if (hooked) {
        SecAllocHookRemove();
    }
    BGV_Ciphertext_Destroy(&ct);
    CRYPT_BGV_FreeCtx(ctx);
}
/* END_CASE */
/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_TRAILING_ADAPTER_TC001
* @title  Adapter loads reject trailing bytes without retaining allocations.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_TRAILING_ADAPTER_TC001(int operation)
{
#ifndef HITLS_PROVIDER
    (void)operation;
    SKIP_TEST();
#else
#ifndef HIFHE_CUSTOM_PARAM
    if (operation == 6) {
        SKIP_TEST();
    }
#endif
    CRYPT_BGV_Ctx *ctx = NULL;
    uint64_t *msg = NULL;
    uint8_t *pt = NULL, *ct = NULL, *key = NULL, *out = NULL;
    uint32_t ptLen = 0u, ctLen = 0u, keyLen = 0u;
    SecDims d;
    int installed = 0;
    TestMemInit();
    TestRandInit();
    ctx = SecNewCtx(HIFHE_BGV_2048_48_17BIT, SEC_SEED_A, 1);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(SecDimsGet(ctx, &d), 0);
    msg = calloc(1u, d.msgLen);
    pt = malloc(d.ptLen + 1u);
    ct = malloc(d.ctLen + 1u);
    out = malloc(d.ctLen + d.msgLen);
    ASSERT_TRUE(msg != NULL && pt != NULL && ct != NULL && out != NULL);
    ASSERT_EQ(SecEncode(ctx, msg, d.msgLen, pt, d.ptLen, &ptLen), 0);
    ctLen = d.ctLen;
    ASSERT_EQ(CRYPT_BGV_Encrypt(ctx, pt, ptLen, ct, &ctLen), HIFHE_SUCCESS);
    pt[ptLen] = ct[ctLen] = 0x5au;
    if (operation >= 9) {
        ASSERT_EQ(operation == 9 ? Bgv_DumpPub(ctx, NULL, &keyLen) : Bgv_DumpPrv(ctx, NULL, &keyLen),
            HIFHE_BUFFER_TOO_SMALL);
        key = malloc(keyLen + 1u);
        ASSERT_TRUE(key != NULL);
        ASSERT_EQ(operation == 9 ? Bgv_DumpPub(ctx, key, &keyLen) : Bgv_DumpPrv(ctx, key, &keyLen),
            HIFHE_SUCCESS);
        key[keyLen] = 0x5au;
    }
    BSL_Param operands[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct, ctLen, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ct, ctLen, 0}, BSL_PARAM_END};
    BSL_Param plain[] = {
        {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, pt, ptLen + 1u, 0}, BSL_PARAM_END};
    BSL_Param keys[] = {
        {operation == 9 ? HIFHE_PARAM_BGV_PUBKEY : HIFHE_PARAM_BGV_PRVKEY,
            BSL_PARAM_TYPE_OCTETS, key, keyLen + 1u, 0}, BSL_PARAM_END};
    if (operation == 2 || operation == 5) {
        operands[0].valueLen++;
    } else if (operation == 3 || operation == 6) {
        operands[1].valueLen++;
    } else if (operation == 4 || operation == 7) {
        operands[1] = plain[0];
    }
    ASSERT_EQ(SecAllocHookInstall(), 0);
    installed = 1;
    g_secArmed = 1;
    uint32_t outLen = d.ctLen + d.msgLen;
    int32_t ret;
    switch (operation) {
        case 0: ret = CRYPT_BGV_Encrypt(ctx, pt, ptLen + 1u, out, &outLen); break;
        case 1: ret = CRYPT_BGV_Decrypt(ctx, ct, ctLen + 1u, out, &outLen); break;
        case 2:
        case 3:
        case 4: ret = CRYPT_BGV_HEAdd(ctx, operands, out, &outLen); break;
        case 5:
        case 6:
        case 7: ret = CRYPT_BGV_HEMul(ctx, operands, out, &outLen); break;
        case 8: ret = CRYPT_BGV_HEMsgDecode(ctx, plain, out, &outLen); break;
        case 9: ret = CRYPT_BGV_SetPubKeyEx(ctx, keys); break;
        default: ret = CRYPT_BGV_SetPrvKeyEx(ctx, keys); break;
    }
    g_secArmed = 0;
    ASSERT_EQ(ret, HIFHE_SERDES_FAIL);
    ASSERT_EQ(g_secOverflow, 0);
    ASSERT_EQ(g_secLive, 0u);
EXIT:
    if (installed) {
        SecAllocHookRemove();
    }
    free(msg);
    free(pt);
    free(ct);
    free(key);
    free(out);
    CRYPT_BGV_FreeCtx(ctx);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEC_TRAILING_BODY_TC001
* @title  Body loads reject trailing bytes before allocating and destroy prior output state.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEC_TRAILING_BODY_TC001(int kind)
{
#if !defined(HIFHE_CUSTOM_PARAM) && !defined(HITLS_PROVIDER)
    if (kind == 2 || kind == 3) {
        SKIP_TEST();
    }
#endif
    int cipher = kind % 2;
    CRYPT_BGV_Ctx *ctx = NULL;
    Plaintext pt = {0};
    Ciphertext ct = {0};
    PlaintextConfig cfg = {0};
    uint8_t *wire = NULL;
    int installed = 0;
    TestMemInit();
    ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(Bgv_SetPreset(ctx, HIFHE_BGV_2048_48_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(Bgv_BuildContext(ctx), HIFHE_SUCCESS);
    BGVContext *bc = &ctx->bgv.context;
    ASSERT_EQ(BGV_BGVContext_GetDefaultPlaintextConfig(&cfg, bc), HIFHE_SUCCESS);
    ASSERT_EQ(BGV_Plaintext_Create(&pt, &cfg, bc), HIFHE_SUCCESS);
    ASSERT_EQ(BGV_Ciphertext_CreateSize2Ntt(&ct, 1u, &bc->rlweContext.cipherRnsBase, bc), HIFHE_SUCCESS);
    void *obj = cipher ? (void *)&ct : (void *)&pt;
    uint32_t len = BgvSerDes_BodySize(cipher != 0, obj) + (kind >= 2 ? WIRE_HDR : 0u);
    wire = malloc(len + 1u);
    ASSERT_TRUE(wire != NULL);
    int32_t ret;
    switch (kind) {
#if defined(HIFHE_CUSTOM_PARAM) || defined(HITLS_PROVIDER)
        case 2: ret = BgvSerDes_DumpPlaintext(&pt, wire, &len, HIFHE_BGV); break;
        case 3: ret = BgvSerDes_DumpCiphertext(&ct, wire, &len, HIFHE_BGV); break;
#endif
        case 4: ret = BgvSerDes_DumpPrvKey(&pt, wire, &len, HIFHE_BGV); break;
        case 5: ret = BgvSerDes_DumpPubKey(&ct, wire, &len, HIFHE_BGV); break;
        default: ret = BgvSerDes_WriteBody(cipher != 0, obj, wire, len); break;
    }
    ASSERT_EQ(ret, HIFHE_SUCCESS);
    wire[len] = 0x5au;
    ASSERT_EQ(SecAllocHookInstall(), 0);
    installed = 1;
    g_secArmed = 1;
    switch (kind) {
#if defined(HIFHE_CUSTOM_PARAM) || defined(HITLS_PROVIDER)
        case 2: ret = BgvSerDes_LoadPlaintext(&pt, wire, len + 1u, bc); break;
        case 3: ret = BgvSerDes_LoadCiphertext(&ct, wire, len + 1u, bc); break;
#endif
        case 4: ret = BgvSerDes_LoadPrvKey(&pt, wire, len + 1u, bc); break;
        case 5: ret = BgvSerDes_LoadPubKey(&ct, wire, len + 1u, bc); break;
        default: ret = BgvSerDes_ReadBody(cipher != 0, obj, wire, len + 1u, bc); break;
    }
    ASSERT_EQ(ret, HIFHE_SERDES_FAIL);
    ASSERT_EQ(g_secSeen, 0u);
    ASSERT_EQ(g_secLive, 0u);
    ASSERT_TRUE(cipher ? ct.data == NULL && ct.config.crtConfig.rnsbase.data == NULL :
        pt.data == NULL && pt.config.crtConfig.rnsbase.data == NULL);
EXIT:
    BGV_Plaintext_Destroy(&pt);
    BGV_Ciphertext_Destroy(&ct);
    BGV_PlaintextConfig_Destroy(&cfg);
    if (installed) {
        SecAllocHookRemove();
    }
    free(wire);
    CRYPT_BGV_FreeCtx(ctx);
}
/* END_CASE */
