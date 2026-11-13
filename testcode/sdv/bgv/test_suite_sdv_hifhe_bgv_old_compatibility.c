/*
 * Copyright (c) 2026 openHiTLS. All Rights Reserved.
 * HiFHE is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/* BEGIN_HEADER */
#include "hifhe_config.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hifhe.h"
#include "crypt_eal_init.h"
#include "test.h"
/* END_HEADER */

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
 * without it skips the suite.
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
