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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hifhe.h"
#include "crypt_eal_init.h"
#include "test.h"
/* END_HEADER */

static HIFHE_Ctx *Configured(void)
{
    HIFHE_Ctx *ctx = HIFHE_New(HIFHE_BGV);
    if (ctx == NULL) {
        return NULL;
    }
    if (HIFHE_SetParaById(ctx, HIFHE_BGV_4096_44x2_17BIT) != HIFHE_SUCCESS) {
        HIFHE_Free(ctx);
        return NULL;
    }
    return ctx;
}

static uint8_t *Serialized(const HIFHE_Ctx *ctx, const HIFHE_HEText *text, uint32_t *len)
{
    *len = 0;
    if (HIFHE_Serialize(ctx, text, NULL, len) != HIFHE_BUFFER_TOO_SMALL) {
        return NULL;
    }
    uint8_t *bytes = malloc(*len);
    if (bytes == NULL) {
        return NULL;
    }
    if (HIFHE_Serialize(ctx, text, bytes, len) != HIFHE_SUCCESS) {
        free(bytes);
        return NULL;
    }
    return bytes;
}

static void Put32(uint8_t *out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; i++) {
        out[i] = (uint8_t)(value >> (8 * i));
    }
}

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_CONTEXT_CTRL_API_TC001(int cmd)
{
    HIFHE_Ctx *ctx = NULL, *other = NULL;
    HIFHE_HEText *pt = NULL, *ct = NULL, *decoded = NULL;
    uint8_t seed[32] = {1};
    uint32_t value = 1, count = 4096;
    uint64_t output[4096];
    void *arg = cmd == HIFHE_CTRL_BGV_SET_SEED ? (void *)seed : (void *)&value;
    uint32_t argLen = cmd == HIFHE_CTRL_BGV_SET_SEED ? sizeof(seed) : sizeof(value);

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    ctx = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);
    if (cmd != HIFHE_CTRL_BGV_SET_LUT_CACHE) {
        ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_PARAM_NOT_SET);
        ASSERT_EQ(HIFHE_SetParaById(ctx, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    }
    ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(NULL, cmd, NULL, arg, argLen), HIFHE_NULL_INPUT);
    ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, NULL, argLen), HIFHE_NULL_INPUT);
    ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen - 1), HIFHE_PARAM_INVALID);
    ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen + 1), HIFHE_PARAM_INVALID);
    if (cmd == HIFHE_CTRL_BGV_SET_LUT_CACHE) {
        value = 2;
        ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_PARAM_INVALID);
        value = 0;
        ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_SUCCESS);
        value = 1;
        ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_SUCCESS);
        ASSERT_EQ(HIFHE_SetParaById(ctx, -1), HIFHE_PARAM_INVALID);
        ASSERT_EQ(HIFHE_SetParaById(ctx, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
        ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_BAD_STATE);
    }
    other = HIFHE_New(HIFHE_CKKS);
    if (other != NULL) {
        ASSERT_EQ(HIFHE_Ctrl(other, cmd, NULL, arg, argLen), HIFHE_NOT_SUPPORTED);
    }
    ASSERT_EQ(HIFHE_KeyGen(ctx), HIFHE_SUCCESS);
    if (cmd == HIFHE_CTRL_BGV_SET_SEED) {
        ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_BAD_STATE);
    }
    uint64_t message = 7;
    uint32_t actual = 0;
    ASSERT_EQ(HIFHE_Encode(ctx, &message, 1, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(ctx, pt, &ct), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, pt, arg, argLen), HIFHE_PARAM_INVALID);
    if (cmd == HIFHE_CTRL_BGV_GET_POLY_DEGREE) {
        ASSERT_EQ(value, 4096);
    } else if (cmd == HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN) {
        ASSERT_EQ(HIFHE_Serialize(ctx, pt, NULL, &actual), HIFHE_BUFFER_TOO_SMALL);
        ASSERT_EQ(value, actual);
    } else if (cmd == HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN) {
        ASSERT_EQ(HIFHE_Serialize(ctx, ct, NULL, &actual), HIFHE_BUFFER_TOO_SMALL);
        ASSERT_EQ(value, actual);
    }
    ASSERT_EQ(HIFHE_Decrypt(ctx, ct, &decoded), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decode(ctx, decoded, output, &count), HIFHE_SUCCESS);
    ASSERT_EQ(count, 4096);
    for (uint32_t i = 0; i < count; i++) {
        ASSERT_EQ(output[i], i == 0 ? message : 0);
    }
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(decoded);
    HIFHE_Free(ctx);
    HIFHE_Free(other);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_WORKFLOW_API_TC001(void)
{
    HIFHE_Ctx *a = NULL, *b = NULL;
    HIFHE_HEText *p = NULL, *c = NULL, *q = NULL, *bp = NULL, *d = NULL, *mp = NULL, *m = NULL;
    HIFHE_HEText *noised = NULL, *reply = NULL, *decoded = NULL;
    uint8_t *wire = NULL;
    uint64_t *values = NULL;
    uint32_t len = 0;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    a = Configured();
    b = Configured();
    ASSERT_TRUE(a != NULL && b != NULL);
    ASSERT_TRUE(HIFHE_SetParaById(a, HIFHE_BGV_4096_44x2_17BIT) == HIFHE_BAD_STATE);
    ASSERT_EQ(HIFHE_KeyGen(a), HIFHE_SUCCESS);
    uint64_t query[] = {1, 2, 3, 4}, bucket[] = {1, 4, 2, 6}, mask[] = {2, 3, 4, 5};
    ASSERT_EQ(HIFHE_Encode(a, query, 4, &p), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(a, p, &c), HIFHE_SUCCESS);
    wire = Serialized(a, c, &len);
    ASSERT_TRUE(wire != NULL);
    ASSERT_TRUE(len > 76 && memcmp(wire, "HFHE", 4) == 0);
    ASSERT_EQ(HIFHE_Deserialize(b, wire, len, &q), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, q, NULL, 0), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encode(b, bucket, 4, &bp), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Add(b, q, bp, &d), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encode(b, mask, 4, &mp), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Mul(b, d, mp, &m), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, m, &noised, sizeof(noised)), HIFHE_SUCCESS);
    free(wire);
    wire = Serialized(b, noised, &len);
    ASSERT_TRUE(wire != NULL);
    ASSERT_EQ(HIFHE_Deserialize(a, wire, len, &reply), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(a, reply, &decoded), HIFHE_SUCCESS);
    uint32_t count = 0;
    ASSERT_TRUE(HIFHE_Decode(a, decoded, NULL, &count) == HIFHE_BUFFER_TOO_SMALL);
    values = calloc(count, sizeof(*values));
    ASSERT_TRUE(values != NULL);
    ASSERT_EQ(HIFHE_Decode(a, decoded, values, &count), HIFHE_SUCCESS);
    ASSERT_TRUE(values[0] == 0 && values[1] == 6 && values[2] == 65533 && values[3] == 10);
    HIFHE_Free(b);
    b = NULL;
    free(wire);
    wire = Serialized(a, noised, &len);
    ASSERT_TRUE(wire != NULL);
EXIT:
    HIFHE_HETextFree(p);
    HIFHE_HETextFree(c);
    HIFHE_HETextFree(q);
    HIFHE_HETextFree(bp);
    HIFHE_HETextFree(d);
    HIFHE_HETextFree(mp);
    HIFHE_HETextFree(m);
    HIFHE_HETextFree(noised);
    HIFHE_HETextFree(reply);
    HIFHE_HETextFree(decoded);
    HIFHE_Free(a);
    HIFHE_Free(b);
    free(values);
    free(wire);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_TRAILING_BYTES_API_TC001(void)
{
    HIFHE_Ctx *ctx = NULL;
    uint8_t *bytes = NULL;
    HIFHE_HEText *p = NULL, *copy = NULL;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    ctx = Configured();
    ASSERT_TRUE(ctx != NULL);
    uint64_t value = 7;
    uint32_t len = 0;
    ASSERT_EQ(HIFHE_Encode(ctx, &value, 1, &p), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_Serialize(ctx, p, NULL, &len) == HIFHE_BUFFER_TOO_SMALL);
    bytes = calloc(len + 1, 1);
    ASSERT_TRUE(bytes != NULL);
    ASSERT_EQ(HIFHE_Serialize(ctx, p, bytes, &len), HIFHE_SUCCESS);
    len++;
    for (uint32_t i = 0; i < 4; i++) {
        bytes[12 + i] = (uint8_t)(len >> (i * 8));
    }
    ASSERT_TRUE(HIFHE_Deserialize(ctx, bytes, len, &copy) == HIFHE_SERDES_FAIL);
    ASSERT_TRUE(copy == NULL);
EXIT:
    HIFHE_HETextFree(copy);
    HIFHE_HETextFree(p);
    HIFHE_Free(ctx);
    free(bytes);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_OUTPUT_OVERLAP_API_TC001(void)
{
    HIFHE_Ctx *ctx = NULL;
    uint8_t *bytes = NULL;
    uint64_t *values = NULL;
    HIFHE_HEText *pt = NULL;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    ctx = Configured();
    ASSERT_TRUE(ctx != NULL);
    uint64_t value = 7;
    uint32_t len = 0;
    ASSERT_EQ(HIFHE_Encode(ctx, &value, 1, &pt), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_Serialize(ctx, pt, NULL, &len) == HIFHE_BUFFER_TOO_SMALL);
    bytes = malloc(len);
    ASSERT_TRUE(bytes != NULL);
    uint32_t *outLen = (uint32_t *)bytes;
    *outLen = len;
    ASSERT_TRUE(HIFHE_Serialize(ctx, pt, bytes, outLen) == HIFHE_PARAM_INVALID);
    values = calloc(4096, sizeof(*values));
    ASSERT_TRUE(values != NULL);
    uint32_t *count = (uint32_t *)(values + 4095);
    *count = 4096;
    ASSERT_EQ(HIFHE_Decode(ctx, pt, values, count), HIFHE_PARAM_INVALID);
    ASSERT_EQ(*count, 4096);
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_Free(ctx);
    free(bytes);
    free(values);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_UINT64_API_TC001(void)
{
    HIFHE_Ctx *ctx = NULL;
    HIFHE_HEText *pt = NULL;
    uint64_t values[] = {0, 1, 65536, 7};
    uint64_t invalid[] = {65537, (UINT64_C(1) << 32) + 1, UINT64_MAX};
    uint64_t *decoded = NULL;
    uint32_t count = 0;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    ctx = Configured();
    ASSERT_TRUE(ctx != NULL);
    for (uint32_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        ASSERT_EQ(HIFHE_Encode(ctx, &invalid[i], 1, &pt), HIFHE_PARAM_INVALID);
        ASSERT_TRUE(pt == NULL);
    }
    ASSERT_EQ(HIFHE_Encode(ctx, values, 4, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decode(ctx, pt, NULL, &count), HIFHE_BUFFER_TOO_SMALL);
    ASSERT_EQ(count, 4096);
    decoded = malloc((count + 1) * sizeof(*decoded));
    ASSERT_TRUE(decoded != NULL);
    memset(decoded, 0xff, (count + 1) * sizeof(*decoded));
    count--;
    ASSERT_EQ(HIFHE_Decode(ctx, pt, decoded, &count), HIFHE_BUFFER_TOO_SMALL);
    ASSERT_EQ(count, 4096);
    for (uint32_t i = 0; i <= count; i++) {
        ASSERT_TRUE(decoded[i] == UINT64_MAX);
    }
    count++;
    ASSERT_EQ(HIFHE_Decode(ctx, pt, decoded, &count), HIFHE_SUCCESS);
    ASSERT_EQ(count, 4096);
    for (uint32_t i = 0; i < count; i++) {
        ASSERT_EQ(decoded[i], i < 4 ? values[i] : 0);
    }
    ASSERT_TRUE(decoded[count] == UINT64_MAX);
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_Free(ctx);
    free(decoded);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_PRESET_API_TC001(void)
{
    HIFHE_Ctx *a = NULL, *b = NULL;
    HIFHE_HEText *pt = NULL;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_New(0) == NULL);
    a = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(a != NULL);
    ASSERT_TRUE(HIFHE_SetParaById(a, -1) == HIFHE_PARAM_INVALID);
    ASSERT_EQ(HIFHE_SetParaById(a, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_SetParaById(a, HIFHE_BGV_8192_44x4_17BIT) == HIFHE_BAD_STATE);
    b = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(b != NULL);
    ASSERT_EQ(HIFHE_SetParaById(b, HIFHE_BGV_8192_44x4_17BIT), HIFHE_SUCCESS);
    uint64_t input = 8;
    ASSERT_EQ(HIFHE_Encode(a, &input, 1, &pt), HIFHE_SUCCESS);
    uint32_t len = 0;
    ASSERT_TRUE(HIFHE_Serialize(b, pt, NULL, &len) == HIFHE_CONTEXT_MISMATCH);
EXIT:
    HIFHE_Free(a);
    HIFHE_Free(b);
    HIFHE_HETextFree(pt);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_CTRL_API_TC001(void)
{
    HIFHE_Ctx *a = NULL, *b = NULL;
    uint8_t *before = NULL, *after = NULL;
    HIFHE_HEText *pt = NULL, *ct = NULL, *result = NULL, *copy = NULL, *noise = NULL;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    a = Configured();
    b = Configured();
    ASSERT_TRUE(a != NULL && b != NULL);
    ASSERT_EQ(HIFHE_KeyGen(a), HIFHE_SUCCESS);
    uint64_t value = 7;
    uint32_t len = 0, control = 0;
    ASSERT_EQ(HIFHE_Encode(a, &value, 1, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(a, pt, &ct), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_Serialize(a, ct, NULL, &len) == HIFHE_BUFFER_TOO_SMALL);
    before = malloc(len);
    after = malloc(len);
    ASSERT_TRUE(before != NULL && after != NULL);
    ASSERT_EQ(HIFHE_Serialize(a, ct, before, &len), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_Ctrl(a, (int32_t)0x6A02, ct, NULL, 0) == HIFHE_NOT_SUPPORTED);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, ct, &control, sizeof(control)) == HIFHE_PARAM_INVALID);
    ASSERT_TRUE(HIFHE_Ctrl(NULL, HIFHE_CTRL_BGV_SET_NEGATE, ct, NULL, 0) == HIFHE_NULL_INPUT);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, NULL, NULL, 0) == HIFHE_NULL_INPUT);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, ct, NULL, 1) == HIFHE_PARAM_INVALID);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, pt, NULL, 0) == HIFHE_PARAM_INVALID);
    ASSERT_EQ(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, ct, NULL, 0), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, ct, NULL, 0), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Add(b, ct, pt, &result), HIFHE_SUCCESS);
    uint32_t untouched = len;
    ASSERT_TRUE(HIFHE_Serialize(a, ct, after, &untouched) == HIFHE_BAD_STATE);
    ASSERT_TRUE(untouched == len);
    ASSERT_TRUE(HIFHE_Add(b, ct, pt, &result) == HIFHE_BAD_STATE);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, ct, &noise, sizeof(noise)) == HIFHE_BAD_STATE);
    ASSERT_TRUE(noise == NULL);
    ASSERT_EQ(HIFHE_Deserialize(a, before, len, &copy), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, copy, NULL, sizeof(noise)) == HIFHE_NULL_INPUT);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, copy, &noise, 0) == HIFHE_PARAM_INVALID);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, pt, &noise, sizeof(noise)) == HIFHE_PARAM_INVALID);
    ASSERT_TRUE(noise == NULL);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, copy, &result, sizeof(result)) == HIFHE_BAD_STATE);
    ASSERT_EQ(HIFHE_Serialize(a, copy, after, &len), HIFHE_SUCCESS);
    ASSERT_TRUE(memcmp(before, after, len) == 0);
EXIT:
    HIFHE_HETextFree(noise);
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(copy);
    HIFHE_HETextFree(result);
    HIFHE_Free(a);
    HIFHE_Free(b);
    free(before);
    free(after);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_COEFFICIENT_API_TC001(void)
{
    HIFHE_Ctx *ctx = NULL;
    uint8_t *wire = NULL;
    uint64_t *values = NULL;
    HIFHE_HEText *pt = NULL, *coeff = NULL, *ct = NULL, *decoded = NULL;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    ctx = Configured();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HIFHE_KeyGen(ctx), HIFHE_SUCCESS);
    uint64_t one = 1;
    uint32_t len = 0;
    ASSERT_EQ(HIFHE_Encode(ctx, &one, 1, &pt), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_Serialize(ctx, pt, NULL, &len) == HIFHE_BUFFER_TOO_SMALL);
    wire = malloc(len);
    ASSERT_TRUE(wire != NULL);
    ASSERT_EQ(HIFHE_Serialize(ctx, pt, wire, &len), HIFHE_SUCCESS);
    Put32(wire + 76 + 8 + 16, 0);
    uint32_t dataOffset = 76 + 8 + 20 + 16;
    memset(wire + dataOffset, 0, len - dataOffset);
    wire[dataOffset] = 1;
    wire[dataOffset + 4096 * 8] = 1;
    ASSERT_EQ(HIFHE_Deserialize(ctx, wire, len, &coeff), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(ctx, coeff, &ct), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(ctx, ct, &decoded), HIFHE_SUCCESS);
    uint32_t count = 4096;
    values = calloc(count, sizeof(*values));
    ASSERT_TRUE(values != NULL);
    ASSERT_EQ(HIFHE_Decode(ctx, decoded, values, &count), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < count; i++) {
        ASSERT_TRUE(values[i] == 1);
    }
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(coeff);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(decoded);
    HIFHE_Free(ctx);
    free(wire);
    free(values);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */
