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
#include <stdlib.h>
#include "hifhe_local.h"
#include "crypt_ckks.h"
#include "hifhe_err.h"
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
    ASSERT_EQ(ConfigureCkks(ctx, 16), HIFHE_SUCCESS);
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
    ASSERT_EQ(HIFHE_Deserialize(copy, wire, len, &restored), HIFHE_CONTEXT_MISMATCH);
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
    ASSERT_EQ(ConfigureCkks(ctx, 16), HIFHE_SUCCESS);
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
void SDV_CRYPTO_HIFHE_CKKS_INVALID_PARAM_API_TC001(void)
{
    HIFHE_Ctx *ctx = HIFHE_New(HIFHE_CKKS);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(ConfigureCkks(ctx, 15), HIFHE_PARAM_INVALID);
    ASSERT_EQ(ConfigureCkks(ctx, 16), HIFHE_SUCCESS);
EXIT:
    HIFHE_Free(ctx);
}

/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_ERROR_CODES_ARE_HIFHE_TC001(void)
{
    CRYPT_CKKS_Ctx *math = NULL;
    bool hooked = false;
    /* Reached below Error() in ckks_object.c, which would otherwise fold any
     * stray code into HIFHE_INTERNAL and hide it. */
    CRYPT_CkksPara para = {16, 50, 20, 3.2, 2};

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
    ASSERT_EQ(ConfigureCkks(ctx, 16), HIFHE_SUCCESS);
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
        int32_t ret = EncodeCkks(ctx, input, &plaintext);
        g_allocFailAt = 0;
        ASSERT_TRUE(g_allocCount >= i);
        ASSERT_EQ(ret, HIFHE_MEMORY_ERROR);
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
    ASSERT_EQ(ConfigureCkks(ctx, 16), HIFHE_SUCCESS);
    uint32_t allocations = g_allocCount;
    ASSERT_TRUE(allocations > 0);

    for (uint32_t i = 1; i <= allocations; i++) {
        HIFHE_Free(ctx);
        ctx = HIFHE_New(HIFHE_CKKS);
        ASSERT_TRUE(ctx != NULL);
        g_allocCount = 0;
        g_allocFailAt = i;
        int32_t ret = ConfigureCkks(ctx, 16);
        g_allocFailAt = 0;
        ASSERT_TRUE(g_allocCount >= i);
        ASSERT_TRUE(ret == HIFHE_MEMORY_ERROR || ret == HIFHE_HASH_ERROR);
        ASSERT_TRUE(ctx->params == NULL && ctx->data == NULL);
        ASSERT_EQ(ConfigureCkks(ctx, 16), HIFHE_SUCCESS);
    }
EXIT:
    g_allocFailAt = 0;
    if (hooked) {
        (void)HIFHE_SetMemFuncs(NULL, NULL);
    }
    HIFHE_Free(ctx);
}
/* END_CASE */
