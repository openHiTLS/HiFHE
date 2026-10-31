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
#include <complex.h>
#include <float.h>
#include <math.h>
#include <stdlib.h>
#include "hifhe_local.h"
#include "crypt_ckks.h"
#include "ckks_local.h"
#include "hifhe_err.h"
#include "hifhe_err_internal.h"
#include "crypto_test_util.h"
#include "test.h"
/* END_HEADER */

static int32_t ConfigureCkks(HIFHE_Ctx *ctx, uint32_t n)
{
    HifheParamConfig config = {.slots = 2, .ckks = {n, 50, 20, 3200, 2}, .isCkks = true};
    return Hifhe_SetParam(ctx, &config);
}

static int32_t EncodeCkks(HIFHE_Ctx *ctx, const double complex *input, HIFHE_HEText **out)
{
    void *data = NULL;
    int32_t ret = ctx->method->encode(ctx, input, 2, &data);
    if (ret == HIFHE_SUCCESS) {
        ret = Hifhe_HETextNew(ctx, data, out);
    }
    return ret;
}

static uint32_t g_allocCount;
static uint32_t g_allocFailAt;

static void *FailMalloc(uint32_t size)
{
    g_allocCount++;
    if (g_allocFailAt != 0 && g_allocCount == g_allocFailAt) {
        return NULL;
    }
    return malloc(size);
}

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_ROUNDTRIP_API_TC001(void)
{
    HIFHE_Ctx *ctx = HIFHE_New(HIFHE_CKKS), *copy = NULL;
    HIFHE_HEText *plaintext = NULL, *ciphertext = NULL, *decrypted = NULL, *restored = NULL;
    uint8_t *wire = NULL, *roundtrip = NULL;
    double complex input[] = {1.25 + 0.5 * I, -2.0 + 0.75 * I};
    double complex output[2] = {0};
    uint32_t count = 2;
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(TestRandInit(), HIFHE_SUCCESS);
    ASSERT_EQ(ConfigureCkks(ctx, 4096), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(ctx), HIFHE_SUCCESS);
    ASSERT_EQ(EncodeCkks(ctx, input, &plaintext), HIFHE_SUCCESS);
    ASSERT_EQ(atomic_load(&ctx->params->references), 1);
    uint32_t len = 0;
    ASSERT_EQ(HIFHE_Serialize(ctx, plaintext, NULL, &len), HIFHE_BUFFER_TOO_SMALL);
    wire = malloc(len);
    ASSERT_TRUE(wire != NULL);
    ASSERT_EQ(HIFHE_Serialize(ctx, plaintext, wire, &len), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Deserialize(ctx, wire, len, &restored), HIFHE_SUCCESS);
    HIFHE_HETextFree(plaintext);
    plaintext = restored;
    restored = NULL;
    free(wire);
    wire = NULL;
    ASSERT_EQ(HIFHE_Encrypt(ctx, plaintext, &ciphertext), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Serialize(ctx, ciphertext, NULL, &len), HIFHE_BUFFER_TOO_SMALL);
    wire = malloc(len);
    roundtrip = malloc(len);
    ASSERT_TRUE(wire != NULL && roundtrip != NULL);
    ASSERT_EQ(HIFHE_Serialize(ctx, ciphertext, wire, &len), HIFHE_SUCCESS);
    copy = Hifhe_CtxDup(ctx);
    ASSERT_TRUE(copy != NULL);
    wire[60] ^= 1;
    ASSERT_EQ(HIFHE_Deserialize(copy, wire, len, &restored), HIFHE_KEY_MISMATCH);
    ASSERT_TRUE(restored == NULL);
    wire[60] ^= 1;
    ASSERT_EQ(HIFHE_Deserialize(copy, wire, len, &restored), HIFHE_SUCCESS);
    uint32_t roundtripLen = len;
    ASSERT_EQ(HIFHE_Serialize(copy, restored, roundtrip, &roundtripLen), HIFHE_SUCCESS);
    ASSERT_EQ(roundtripLen, len);
    ASSERT_EQ(memcmp(wire, roundtrip, len), 0);
    HIFHE_HETextFree(ciphertext);
    ciphertext = restored;
    restored = NULL;
    HIFHE_Free(ctx);
    ctx = copy;
    copy = NULL;
    ASSERT_EQ(HIFHE_Decrypt(ctx, ciphertext, &decrypted), HIFHE_SUCCESS);
    ASSERT_EQ(ctx->method->decode(ctx, decrypted->data, output, &count), HIFHE_SUCCESS);
    ASSERT_EQ(count, 2);
    ASSERT_TRUE(cabs(input[0] - output[0]) < 0.05);
    ASSERT_TRUE(cabs(input[1] - output[1]) < 0.05);
    HIFHE_Free(ctx);
    ctx = HIFHE_New(HIFHE_CKKS);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(ConfigureCkks(ctx, 4096), HIFHE_SUCCESS);
    count = 2;
    ASSERT_EQ(ctx->method->decode(ctx, decrypted->data, output, &count), HIFHE_SUCCESS);
    ASSERT_TRUE(cabs(input[0] - output[0]) < 0.05);
    ASSERT_TRUE(cabs(input[1] - output[1]) < 0.05);
    roundtripLen = len;
    ASSERT_EQ(HIFHE_Serialize(ctx, ciphertext, roundtrip, &roundtripLen), HIFHE_SUCCESS);
    ASSERT_EQ(roundtripLen, len);
    ASSERT_EQ(memcmp(wire, roundtrip, len), 0);
    HIFHE_Free(ctx);
    ctx = NULL;
EXIT:
    HIFHE_HETextFree(plaintext);
    HIFHE_HETextFree(ciphertext);
    HIFHE_HETextFree(decrypted);
    HIFHE_HETextFree(restored);
    HIFHE_Free(ctx);
    HIFHE_Free(copy);
    free(wire);
    free(roundtrip);
}

/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_WEAK_PARAMS_TC001(void)
{
    CRYPT_CKKS_Ctx *ctx = CRYPT_CKKS_NewCtx();
    CRYPT_CkksPara para = {4096, 50, 20, 3.2, 2};
    const uint32_t smallN[] = {8, 16, 1024, 2048};
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_CKKS_SetPara(ctx, &para), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < sizeof(smallN) / sizeof(smallN[0]); i++) {
        para.N = smallN[i];
        ASSERT_EQ(CRYPT_CKKS_SetPara(ctx, &para), HIFHE_INVALID_ARGUMENT);
        ASSERT_EQ(ctx->para->N, 4096);
    }
    para.N = 4096;
    para.sigma = 0.001;
    ASSERT_EQ(CRYPT_CKKS_SetPara(ctx, &para), HIFHE_INVALID_ARGUMENT);
EXIT:
    CRYPT_CKKS_FreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_INVALID_SIGMA_TC001(void)
{
    CRYPT_CKKS_Ctx *ctx = CRYPT_CKKS_NewCtx();
    CRYPT_CkksPara para = {4096, 50, 20, 3.2, 2};
    const double invalid[] = {NAN, INFINITY, -INFINITY, DBL_MAX, 0.0, -1.0, 0.001};
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_CKKS_SetPara(ctx, &para), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        para.sigma = invalid[i];
        ASSERT_EQ(CRYPT_CKKS_SetPara(ctx, &para), HIFHE_INVALID_ARGUMENT);
        ASSERT_TRUE(ctx->para->sigma == CKKS_DEFAULT_SIGMA);
    }
EXIT:
    CRYPT_CKKS_FreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_SAMPLER_SIGMA_TC001(void)
{
    CRYPT_CKKS_Poly *poly = CKKS_NewPoly(2);
    BN_BigNum *q = BN_Create(64);
    BN_Optimizer *opt = BN_OptimizerCreate();
    const double invalid[] = {0.001, NAN, INFINITY, -INFINITY, DBL_MAX, 0.0, -1.0};
    ASSERT_TRUE(poly != NULL && q != NULL && opt != NULL);
    ASSERT_EQ(BN_SetBit(q, 50), HIFHE_SUCCESS);
    ASSERT_EQ(TestRandInit(), HIFHE_SUCCESS);
    ASSERT_EQ(CKKS_SampleGauss(NULL, poly->coeffs, 2, CKKS_DEFAULT_SIGMA, q, opt), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        ASSERT_EQ(CKKS_SampleGauss(NULL, poly->coeffs, 2, invalid[i], q, opt), HIFHE_INVALID_ARGUMENT);
    }
EXIT:
    CKKS_FreePoly(poly);
    BN_Destroy(q);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_COEFFICIENT_BOUNDS_TC001(void)
{
    CRYPT_CKKS_Poly *poly = CKKS_NewPoly(1);
    const uint8_t negativeOne[] = {1, 0, 0, 0x80, 1};
    const uint8_t oversized[] = {9, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    const uint8_t truncated[] = {0xff, 0xff, 0xff, 0x7f};
    const uint8_t padded[] = {2, 0, 0, 0, 0, 1};
    const uint8_t negativeZero[] = {0, 0, 0, 0x80};
    const uint8_t aboveModulus[] = {7, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0};
    ASSERT_TRUE(poly != NULL);
    ASSERT_EQ(CKKS_BytesToPoly(negativeOne, sizeof(negativeOne), poly->coeffs, 1, 50, true), HIFHE_SUCCESS);
    ASSERT_TRUE(BN_IsNegative(poly->coeffs[0]));
    ASSERT_EQ(CKKS_BytesToPoly(oversized, sizeof(oversized), poly->coeffs, 1, 50, true), HIFHE_DECODE_ERROR);
    ASSERT_EQ(CKKS_BytesToPoly(truncated, sizeof(truncated), poly->coeffs, 1, 50, true), HIFHE_DECODE_ERROR);
    ASSERT_EQ(CKKS_BytesToPoly(padded, sizeof(padded), poly->coeffs, 1, 50, true), HIFHE_DECODE_ERROR);
    ASSERT_EQ(CKKS_BytesToPoly(negativeZero, sizeof(negativeZero), poly->coeffs, 1, 50, true), HIFHE_DECODE_ERROR);
    ASSERT_EQ(CKKS_BytesToPoly(aboveModulus, sizeof(aboveModulus), poly->coeffs, 1, 50, false), HIFHE_DECODE_ERROR);
    ASSERT_EQ(CKKS_BytesToPoly(negativeOne, sizeof(negativeOne), poly->coeffs, 1, 50, false), HIFHE_DECODE_ERROR);
EXIT:
    CKKS_FreePoly(poly);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_REJECT_BEFORE_ALLOC_TC001(void)
{
    CRYPT_CKKS_Ctx *ctx = CRYPT_CKKS_NewCtx();
    CRYPT_CkksPara para = {4096, 50, 20, 3.2, 2};
    double complex out[2] = {0};
    uint32_t slots = 2;
    bool hooked = false;
    const uint8_t invalid[] = {0};
    uint8_t header[12] = {0};
    uint8_t *badCoeff = NULL;
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_CKKS_SetPara(ctx, &para), HIFHE_SUCCESS);
    ctx->prvKey = CKKS_NewPrvKey(para.N);
    ASSERT_TRUE(ctx->prvKey != NULL);
    uint32_t polyLen = para.N * 4;
    uint32_t wireLen = 12 + 2 * polyLen;
    badCoeff = calloc(1, wireLen);
    ASSERT_TRUE(badCoeff != NULL);
    memcpy(badCoeff, &polyLen, 4);
    memcpy(badCoeff + 4, &polyLen, 4);
    memcpy(badCoeff + 8, "CKKS", 4);
    memset(badCoeff + 12, 0xff, 4);
    g_allocCount = 0;
    g_allocFailAt = 0;
    ASSERT_EQ(HIFHE_SetMemFuncs(FailMalloc, free), HIFHE_SUCCESS);
    hooked = true;
    ASSERT_EQ(CRYPT_CKKS_DecryptEx(ctx, invalid, sizeof(invalid), out, &slots), HIFHE_DECODE_ERROR);
    ASSERT_EQ(CRYPT_CKKS_DecryptEx(ctx, header, sizeof(header), out, &slots), HIFHE_DECODE_ERROR);
    memcpy(header + 8, "CKKS", 4);
    header[0] = 1;
    ASSERT_EQ(CRYPT_CKKS_DecryptEx(ctx, header, sizeof(header), out, &slots), HIFHE_DECODE_ERROR);
    ASSERT_EQ(CRYPT_CKKS_DecryptEx(ctx, badCoeff, wireLen, out, &slots), HIFHE_DECODE_ERROR);
    ASSERT_EQ(g_allocCount, 0);
EXIT:
    if (hooked) {
        (void)HIFHE_SetMemFuncs(NULL, NULL);
    }
    CRYPT_CKKS_FreeCtx(ctx);
    free(badCoeff);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_INVALID_PARAM_API_TC001(void)
{
    HIFHE_Ctx *ctx = HIFHE_New(HIFHE_CKKS);
    ASSERT_TRUE(ctx != NULL);
    HIFHE_ErrClearError();
    ASSERT_EQ(ConfigureCkks(ctx, 15), HIFHE_INVALID_ARGUMENT);
    ASSERT_EQ(HIFHE_ErrPeekLastError(NULL, NULL), HIFHE_INVALID_ARGUMENT);
    ASSERT_EQ(ConfigureCkks(ctx, 4096), HIFHE_SUCCESS);
EXIT:
    HIFHE_Free(ctx);
}

/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_LEGACY_ROUNDTRIP_TC001(void)
{
    CRYPT_CKKS_Ctx *ctx = CRYPT_CKKS_NewCtx();
    CRYPT_CkksPara para = {4096, 50, 20, 3.2, 2};
    uint8_t *wire = NULL;
    double complex input[] = {1.25 + 0.5 * I, -2.0 + 0.75 * I};
    double complex output[2] = {0};
    uint32_t len = 0, slots = 2;
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(TestRandInit(), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_CKKS_SetPara(ctx, &para), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_CKKS_Gen(ctx), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_CKKS_EncryptEx(ctx, input, 2, NULL, &len), HIFHE_BUFFER_TOO_SMALL);
    wire = malloc(len);
    ASSERT_TRUE(wire != NULL);
    ASSERT_EQ(CRYPT_CKKS_EncryptEx(ctx, input, 2, wire, &len), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_CKKS_DecryptEx(ctx, wire, len, output, &slots), HIFHE_SUCCESS);
    ASSERT_EQ(slots, 2);
    ASSERT_TRUE(cabs(input[0] - output[0]) < 0.05);
    ASSERT_TRUE(cabs(input[1] - output[1]) < 0.05);
EXIT:
    free(wire);
    CRYPT_CKKS_FreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_WIRE_BOUNDS_TC001(void)
{
    HIFHE_Ctx *ctx = HIFHE_New(HIFHE_CKKS);
    HIFHE_HEText *plaintext = NULL, *restored = NULL;
    const double complex input[] = {1.25, -2.0};
    uint8_t *wire = NULL;
    uint32_t len = 0;
    bool hooked = false;
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(ConfigureCkks(ctx, 4096), HIFHE_SUCCESS);
    ASSERT_EQ(EncodeCkks(ctx, input, &plaintext), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Serialize(ctx, plaintext, NULL, &len), HIFHE_BUFFER_TOO_SMALL);
    wire = malloc(len);
    ASSERT_TRUE(wire != NULL);
    ASSERT_EQ(HIFHE_Serialize(ctx, plaintext, wire, &len), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Deserialize(ctx, wire, len, &restored), HIFHE_SUCCESS);
    HIFHE_HETextFree(restored);
    restored = NULL;
    g_allocCount = 0;
    g_allocFailAt = 0;
    ASSERT_EQ(HIFHE_SetMemFuncs(FailMalloc, free), HIFHE_SUCCESS);
    hooked = true;
    ASSERT_EQ(HIFHE_Deserialize(ctx, wire, 1, &restored), HIFHE_INVALID_LENGTH);
    ASSERT_EQ(HIFHE_Deserialize(ctx, wire, len - 1, &restored), HIFHE_INVALID_LENGTH);
    wire[0] ^= 1;
    ASSERT_EQ(HIFHE_Deserialize(ctx, wire, len, &restored), HIFHE_SERDES_FAIL);
    wire[0] ^= 1;
    wire[HIFHE_WIRE_HEADER] ^= 1;
    ASSERT_EQ(HIFHE_Deserialize(ctx, wire, len, &restored), HIFHE_SERDES_FAIL);
    wire[HIFHE_WIRE_HEADER] ^= 1;
    ASSERT_EQ(g_allocCount, 0);
    wire[HIFHE_WIRE_HEADER + 8] = 2;
    ASSERT_EQ(HIFHE_Deserialize(ctx, wire, len, &restored), HIFHE_SERDES_FAIL);
    wire[HIFHE_WIRE_HEADER + 8] = 0;
    wire[HIFHE_WIRE_HEADER + 9] = 0xff;
    ASSERT_EQ(HIFHE_Deserialize(ctx, wire, len, &restored), HIFHE_SERDES_FAIL);
    ASSERT_TRUE(restored == NULL);
EXIT:
    if (hooked) {
        (void)HIFHE_SetMemFuncs(NULL, NULL);
    }
    HIFHE_HETextFree(restored);
    HIFHE_HETextFree(plaintext);
    HIFHE_Free(ctx);
    free(wire);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_LEGACY_KEYS_TC001(void)
{
#ifdef HITLS_PROVIDER
    CRYPT_CKKS_Ctx *ctx = CRYPT_CKKS_NewCtx(), *copy = CRYPT_CKKS_NewCtx();
    CRYPT_CkksPara para = {4096, 50, 20, 3.2, 2};
    uint8_t *pub = NULL, *prv = NULL;
    bool hooked = false;
    BSL_Param pubParam[] = {{HIFHE_PARAM_CKKS_PUBKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0}, BSL_PARAM_END};
    BSL_Param prvParam[] = {{HIFHE_PARAM_CKKS_PRVKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0}, BSL_PARAM_END};
    ASSERT_TRUE(ctx != NULL && copy != NULL);
    ASSERT_EQ(TestRandInit(), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_CKKS_SetPara(ctx, &para), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_CKKS_SetPara(copy, &para), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_CKKS_Gen(ctx), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_CKKS_GetPubKeyEx(ctx, pubParam), HIFHE_BUFFER_TOO_SMALL);
    ASSERT_EQ(CRYPT_CKKS_GetPrvKeyEx(ctx, prvParam), HIFHE_BUFFER_TOO_SMALL);
    pub = malloc(pubParam[0].useLen);
    prv = malloc(prvParam[0].useLen);
    ASSERT_TRUE(pub != NULL && prv != NULL);
    pubParam[0].value = pub;
    pubParam[0].valueLen = pubParam[0].useLen;
    prvParam[0].value = prv;
    prvParam[0].valueLen = prvParam[0].useLen;
    ASSERT_EQ(CRYPT_CKKS_GetPubKeyEx(ctx, pubParam), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_CKKS_GetPrvKeyEx(ctx, prvParam), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_CKKS_SetPubKeyEx(copy, pubParam), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_CKKS_SetPrvKeyEx(copy, prvParam), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < para.N; i++) {
        ASSERT_EQ(BN_Cmp(ctx->pubKey->ax[i], copy->pubKey->ax[i]), 0);
        ASSERT_EQ(BN_Cmp(ctx->pubKey->bx[i], copy->pubKey->bx[i]), 0);
        ASSERT_EQ(BN_Cmp(ctx->prvKey->sx[i], copy->prvKey->sx[i]), 0);
    }
    CRYPT_CKKS_PrvKey *savedPrv = copy->prvKey;
    CRYPT_CKKS_PubKey *savedPub = copy->pubKey;
    g_allocCount = 0;
    g_allocFailAt = 0;
    ASSERT_EQ(HIFHE_SetMemFuncs(FailMalloc, free), HIFHE_SUCCESS);
    hooked = true;
    memset(prv, 0xff, 4);
    memset(pub + 4, 0xff, 4);
    ASSERT_EQ(CRYPT_CKKS_SetPrvKeyEx(copy, prvParam), HIFHE_DECODE_ERROR);
    ASSERT_EQ(CRYPT_CKKS_SetPubKeyEx(copy, pubParam), HIFHE_DECODE_ERROR);
    ASSERT_EQ(g_allocCount, 0);
    ASSERT_TRUE(copy->prvKey == savedPrv && copy->pubKey == savedPub);
EXIT:
    if (hooked) {
        (void)HIFHE_SetMemFuncs(NULL, NULL);
    }
    free(pub);
    free(prv);
    CRYPT_CKKS_FreeCtx(ctx);
    CRYPT_CKKS_FreeCtx(copy);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_ERROR_CODES_ARE_HIFHE_TC001(void)
{
    CRYPT_CKKS_Ctx *math = NULL;
    bool hooked = false;
    /* Reached below Error() in ckks_object.c, which would otherwise fold any
     * stray code into HIFHE_INTERNAL and hide it. */
    CRYPT_CkksPara para = {4096, 50, 20, 3.2, 2};

    ASSERT_EQ(CRYPT_CKKS_SetPara(NULL, &para), HIFHE_NULL_INPUT);

    math = CRYPT_CKKS_NewCtx();
    ASSERT_TRUE(math != NULL);
    ASSERT_EQ(CRYPT_CKKS_SetPara(math, NULL), HIFHE_NULL_INPUT);
    ASSERT_EQ(CRYPT_CKKS_SetPara(math, &para), HIFHE_SUCCESS);

    /* Every allocation along SetPara, one at a time. Whatever comes back is
     * either success or a HiFHE code, never an openhitls one. */
    g_allocCount = 0;
    g_allocFailAt = 0;
    ASSERT_EQ(HIFHE_SetMemFuncs(FailMalloc, free), HIFHE_SUCCESS);
    hooked = true;
    CRYPT_CKKS_FreeCtx(math);
    math = CRYPT_CKKS_NewCtx();
    ASSERT_TRUE(math != NULL);
    ASSERT_EQ(CRYPT_CKKS_SetPara(math, &para), HIFHE_SUCCESS);
    uint32_t allocations = g_allocCount;
    ASSERT_TRUE(allocations > 0);

    for (uint32_t i = 1; i <= allocations; i++) {
        CRYPT_CKKS_FreeCtx(math);
        g_allocCount = 0;
        g_allocFailAt = 0;
        math = CRYPT_CKKS_NewCtx();
        ASSERT_TRUE(math != NULL);
        g_allocCount = 0;
        g_allocFailAt = i;
        int32_t ret = CRYPT_CKKS_SetPara(math, &para);
        g_allocFailAt = 0;
        if (ret == HIFHE_SUCCESS) {
            continue;
        }
        ASSERT_TRUE((uint32_t)ret >= 0x39000001u && (uint32_t)ret <= 0x390001ffu);
    }

EXIT:
    g_allocFailAt = 0;
    if (hooked) {
        (void)HIFHE_SetMemFuncs(NULL, NULL);
    }
    CRYPT_CKKS_FreeCtx(math);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_ENCODE_ALLOC_FAILURE_TC001(void)
{
    HIFHE_Ctx *ctx = HIFHE_New(HIFHE_CKKS);
    HIFHE_HEText *plaintext = NULL;
    double complex input[] = {1.25 + 0.5 * I, -2.0 + 0.75 * I};
    bool hooked = false;

    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(ConfigureCkks(ctx, 4096), HIFHE_SUCCESS);
    g_allocCount = 0;
    g_allocFailAt = 0;
    ASSERT_EQ(HIFHE_SetMemFuncs(FailMalloc, free), HIFHE_SUCCESS);
    hooked = true;
    ASSERT_EQ(EncodeCkks(ctx, input, &plaintext), HIFHE_SUCCESS);
    uint32_t allocations = g_allocCount;
    HIFHE_HETextFree(plaintext);
    plaintext = NULL;
    ASSERT_TRUE(allocations > 0);

    for (uint32_t i = 1; i <= allocations; i++) {
        g_allocCount = 0;
        g_allocFailAt = i;
        HIFHE_ErrClearError();
        int32_t ret = EncodeCkks(ctx, input, &plaintext);
        g_allocFailAt = 0;
        ASSERT_TRUE(g_allocCount >= i);
        ASSERT_EQ(ret, HIFHE_MEMORY_ERROR);
        ASSERT_EQ(HIFHE_ErrPeekLastError(NULL, NULL), ret);
        ASSERT_TRUE(plaintext == NULL);
    }
    ASSERT_EQ(EncodeCkks(ctx, input, &plaintext), HIFHE_SUCCESS);
EXIT:
    g_allocFailAt = 0;
    if (hooked) {
        (void)HIFHE_SetMemFuncs(NULL, NULL);
    }
    HIFHE_HETextFree(plaintext);
    HIFHE_Free(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_CONFIG_ALLOC_FAILURE_TC001(void)
{
    HIFHE_Ctx *ctx = HIFHE_New(HIFHE_CKKS);
    bool hooked = false;

    ASSERT_TRUE(ctx != NULL);
    g_allocCount = 0;
    g_allocFailAt = 0;
    ASSERT_EQ(HIFHE_SetMemFuncs(FailMalloc, free), HIFHE_SUCCESS);
    hooked = true;
    ASSERT_EQ(ConfigureCkks(ctx, 4096), HIFHE_SUCCESS);
    uint32_t allocations = g_allocCount;
    ASSERT_TRUE(allocations > 0);

    for (uint32_t i = 1; i <= allocations; i++) {
        HIFHE_Free(ctx);
        ctx = HIFHE_New(HIFHE_CKKS);
        ASSERT_TRUE(ctx != NULL);
        g_allocCount = 0;
        g_allocFailAt = i;
        HIFHE_ErrClearError();
        int32_t ret = ConfigureCkks(ctx, 4096);
        g_allocFailAt = 0;
        ASSERT_TRUE(g_allocCount >= i);
        ASSERT_TRUE(ret == HIFHE_MEMORY_ERROR || ret == HIFHE_HASH_ERROR);
        ASSERT_EQ(HIFHE_ErrPeekLastError(NULL, NULL), ret);
        ASSERT_TRUE(ctx->params == NULL && ctx->data == NULL);
        ASSERT_EQ(ConfigureCkks(ctx, 4096), HIFHE_SUCCESS);
    }
EXIT:
    g_allocFailAt = 0;
    if (hooked) {
        (void)HIFHE_SetMemFuncs(NULL, NULL);
    }
    HIFHE_Free(ctx);
}
/* END_CASE */
