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

#include <math.h>
#include "hifhe_local.h"
#include "hifhe_err_internal.h"
#include "crypt_errno.h"
#include "ckks_local.h"
#include "crypt_ckks.h"

static int32_t Error(int32_t ret)
{
    if (ret == HIFHE_SUCCESS || ((uint32_t)ret >= 0x39000001u && (uint32_t)ret <= 0x390001ffu)) {
        return ret;
    }
    if (ret == CRYPT_MEM_ALLOC_FAIL) {
        ret = HIFHE_MEMORY_ERROR;
    } else if (ret == CRYPT_NULL_INPUT) {
        ret = HIFHE_NULL_INPUT;
    } else {
        ret = HIFHE_INTERNAL;
    }
    HIFHE_ERR_PUSH_ERROR(ret);
    return ret;
}

typedef struct {
    HifheTextMeta meta;
    uint32_t scaleBits;
    uint32_t slotCount;

    union {
        CRYPT_CKKS_Poly *plaintext;

        struct {
            CRYPT_CKKS_Poly *c0;
            CRYPT_CKKS_Poly *c1;
        } ciphertext;
    } value;
} HifheCkksText;

static void CkksTextFree(void *data)
{
    HifheCkksText *t = data;
    if (t == NULL) {
        return;
    }
    if (t->meta.kind == HIFHE_TEXT_PLAIN) {
        if (t->value.plaintext != NULL) {
            for (uint32_t i = 0; i < t->value.plaintext->N; i++) {
                BN_Zeroize(t->value.plaintext->coeffs[i]);
            }
            CKKS_FreePoly(t->value.plaintext);
        }
    } else {
        CKKS_FreePoly(t->value.ciphertext.c0);
        CKKS_FreePoly(t->value.ciphertext.c1);
    }
    HifheFree(t);
}

static void CkksCtxFree(void *data)
{
    CRYPT_CKKS_FreeCtx(data);
}

static void *CkksCtxDup(void *data, void *libCtx)
{
    CRYPT_CKKS_Ctx *ctx = CRYPT_CKKS_DupCtx(data);
    if (ctx != NULL) {
        ctx->libCtx = libCtx;
    }
    return ctx;
}

static int32_t CkksCtxNew(HifheParamSnapshot *p, void *libCtx, void **out)
{
    if (!p->config.isCkks) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
        return HIFHE_NOT_SUPPORTED;
    }
    const uint32_t *v = p->config.ckks;
    CRYPT_CkksPara config = {v[0], v[1], v[2], (double)v[3] / 1000.0, v[4]};
    CRYPT_CKKS_Ctx *math = CRYPT_CKKS_NewCtx();
    if (math == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    p->math = math;
    int32_t ret = CRYPT_CKKS_SetPara(math, &config);
    if (ret != HIFHE_SUCCESS) {
        return Error(ret);
    }
    uint8_t canonical[24] = {0};
    Hifhe_Put32(canonical, HIFHE_CKKS);
    for (uint32_t i = 0; i < 5; i++) {
        Hifhe_Put32(canonical + 4 + i * 4, v[i]);
    }
    ret = Hifhe_ParamSetFingerprint(p, canonical, sizeof(canonical));
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    *out = CkksCtxDup(p->math, libCtx);
    if (*out == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    return HIFHE_SUCCESS;
}

static int32_t CkksKeyGen(void *data)
{
    return Error(CRYPT_CKKS_Gen(data));
}

static int32_t WriteCoeffs(BN_BigNum **coeffs, uint32_t n, uint32_t width, uint8_t *out)
{
    for (uint32_t i = 0; i < n; i++) {
        out[0] = BN_IsNegative(coeffs[i]) != 0 ? 1 : 0;
        if (BN_Bn2BinFixZero(coeffs[i], out + 1, width) != 0) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
            return HIFHE_PARAM_INVALID;
        }
        out += width + 1;
    }
    return 0;
}

static int32_t ReadCoeffs(BN_BigNum **coeffs, uint32_t n, uint32_t bits, const uint8_t *in)
{
    uint32_t width = (bits + 7) / 8;
    for (uint32_t i = 0; i < n; i++) {
        if (in[0] > 1 || BN_Bin2Bn(coeffs[i], in + 1, width) != 0 || BN_Bits(coeffs[i]) > bits) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_SERDES_FAIL);
            return HIFHE_SERDES_FAIL;
        }
        if (in[0] != 0 && BN_IsZero(coeffs[i]) != 0) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_SERDES_FAIL);
            return HIFHE_SERDES_FAIL;
        }
        if (BN_SetSign(coeffs[i], in[0] != 0) != 0) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_SERDES_FAIL);
            return HIFHE_SERDES_FAIL;
        }
        in += width + 1;
    }
    return 0;
}

static int32_t CkksEncode(const HIFHE_Ctx *ctx, const void *values, uint32_t count, void **out)
{
    CRYPT_CKKS_Ctx *math = ctx->params->math;
    uint32_t slots = math->para->slots;
    if (count == 0 || count > slots) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_INVALID_LENGTH);
        return HIFHE_INVALID_LENGTH;
    }
    for (uint32_t i = 0; i < count; i++) {
        double complex value = ((const double complex *)values)[i];
        double re = ldexp(creal(value), (int)math->para->pBits);
        double im = ldexp(cimag(value), (int)math->para->pBits);
        double limit = ldexp(1.0, (int)math->para->qBits - 1);
        if (isfinite(re) == 0 || isfinite(im) == 0 || fabs(re) >= limit || fabs(im) >= limit) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_VALUE_OUT_OF_RANGE);
            return HIFHE_VALUE_OUT_OF_RANGE;
        }
    }
    if (out == NULL) {
        return 0;
    }
    double complex *padded = HifheCalloc(slots, sizeof(*padded));
    HifheCkksText *t = HifheCalloc(1, sizeof(*t));
    if (padded == NULL || t == NULL) {
        HifheFree(padded);
        HifheFree(t);
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    t->meta.kind = HIFHE_TEXT_PLAIN;
    t->scaleBits = math->para->pBits;
    t->slotCount = slots;
    t->value.plaintext = CKKS_NewPoly(math->para->N);
    int32_t ret = HIFHE_MEMORY_ERROR;
    if (t->value.plaintext != NULL) {
        memcpy(padded, values, (size_t)count * sizeof(*padded));
        ret = CKKS_Encode(math, padded, slots, t->value.plaintext);
    }
    HifheCleanse(padded, slots * sizeof(*padded));
    HifheFree(padded);
    if (ret != HIFHE_SUCCESS) {
        CkksTextFree(t);
        return Error(ret);
    }
    *out = t;
    return 0;
}

static int32_t CkksDecode(const HIFHE_Ctx *ctx, const void *data, void *out, uint32_t *count)
{
    const HifheCkksText *t = data;
    return Error(CKKS_Decode(ctx->params->math, t->value.plaintext, out, count));
}

static int32_t CkksEncrypt(const HIFHE_Ctx *ctx, const void *data, void **out)
{
    const HifheCkksText *input = data;
    CRYPT_CKKS_Ctx *runtime = ctx->data;
    HifheCkksText *text = HifheCalloc(1, sizeof(*text));
    if (text == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    text->meta.kind = HIFHE_TEXT_CIPHER;
    text->scaleBits = input->scaleBits;
    text->slotCount = input->slotCount;
    memcpy(text->meta.keysetId, ctx->keysetId, 16);
    int32_t ret = HIFHE_MEMORY_ERROR;
    text->value.ciphertext.c0 = CKKS_NewPoly(runtime->para->N);
    text->value.ciphertext.c1 = CKKS_NewPoly(runtime->para->N);
    if (text->value.ciphertext.c0 != NULL && text->value.ciphertext.c1 != NULL) {
        ret = CKKS_PubEnc(runtime, input->value.plaintext, text->value.ciphertext.c0, text->value.ciphertext.c1);
    }
    if (ret != HIFHE_SUCCESS) {
        CkksTextFree(text);
        return Error(ret);
    }
    *out = text;
    return HIFHE_SUCCESS;
}

static int32_t CkksDecrypt(const HIFHE_Ctx *ctx, const void *data, void **out)
{
    const HifheCkksText *input = data;
    CRYPT_CKKS_Ctx *runtime = ctx->data;
    HifheCkksText *text = HifheCalloc(1, sizeof(*text));
    if (text == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    text->meta.kind = HIFHE_TEXT_PLAIN;
    text->scaleBits = input->scaleBits;
    text->slotCount = input->slotCount;
    int32_t ret = HIFHE_MEMORY_ERROR;
    text->value.plaintext = CKKS_NewPoly(runtime->para->N);
    if (text->value.plaintext != NULL) {
        ret = CKKS_PrvDec(runtime, input->value.ciphertext.c0, input->value.ciphertext.c1, text->value.plaintext);
    }
    if (ret != HIFHE_SUCCESS) {
        CkksTextFree(text);
        return Error(ret);
    }
    *out = text;
    return HIFHE_SUCCESS;
}

static int32_t CkksSerialize(const HIFHE_Ctx *ctx, const void *data, uint8_t *out, uint32_t *len)
{
    const HifheCkksText *t = data;
    CRYPT_CKKS_Ctx *math = ctx->params->math;
    uint32_t n = math->para->N, width = (math->para->qBits + 7) / 8;
    uint32_t one = n * (width + 1), need = 8 + one * (t->meta.kind == HIFHE_TEXT_CIPHER ? 2 : 1);
    if (out == NULL || *len < need) {
        *len = need;
        if (out != NULL) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_BUFFER_TOO_SMALL);
        }
        return HIFHE_BUFFER_TOO_SMALL;
    }
    Hifhe_Put32(out, t->scaleBits);
    Hifhe_Put32(out + 4, t->slotCount);
    int32_t ret = WriteCoeffs(t->meta.kind == HIFHE_TEXT_PLAIN ? t->value.plaintext->coeffs :
        t->value.ciphertext.c0->coeffs, n, width, out + 8);
    if (ret == HIFHE_SUCCESS && t->meta.kind == HIFHE_TEXT_CIPHER) {
        ret = WriteCoeffs(t->value.ciphertext.c1->coeffs, n, width, out + 8 + one);
    }
    if (ret == HIFHE_SUCCESS) {
        *len = need;
    }
    return ret;
}

static int32_t CkksDeserialize(const HIFHE_Ctx *ctx, uint32_t kind, const uint8_t *in, uint32_t len, void **out)
{
    CRYPT_CKKS_Ctx *math = ctx->params->math;
    uint32_t n = math->para->N, bits = math->para->qBits;
    uint32_t one = n * ((bits + 7) / 8 + 1), need = 8 + one * (kind == HIFHE_TEXT_CIPHER ? 2 : 1);
    if (len != need || Hifhe_Get32(in) != math->para->pBits || Hifhe_Get32(in + 4) != math->para->slots) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_SERDES_FAIL);
        return HIFHE_SERDES_FAIL;
    }
    HifheCkksText *t = HifheCalloc(1, sizeof(*t));
    if (t == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    t->meta.kind = kind;
    t->scaleBits = math->para->pBits;
    t->slotCount = math->para->slots;
    CRYPT_CKKS_Poly *p0 = CKKS_NewPoly(n), *p1 = kind == HIFHE_TEXT_CIPHER ? CKKS_NewPoly(n) : NULL;
    if (kind == HIFHE_TEXT_CIPHER) {
        t->value.ciphertext.c0 = p0;
        t->value.ciphertext.c1 = p1;
    } else {
        t->value.plaintext = p0;
    }
    int32_t ret = (p0 == NULL || (kind == HIFHE_TEXT_CIPHER && p1 == NULL)) ? HIFHE_MEMORY_ERROR :
                                                                              ReadCoeffs(p0->coeffs, n, bits, in + 8);
    if (ret == HIFHE_SUCCESS && p1 != NULL) {
        ret = ReadCoeffs(p1->coeffs, n, bits, in + 8 + one);
    }
    if (ret != HIFHE_SUCCESS) {
        CkksTextFree(t);
        return ret;
    }
    *out = t;
    return 0;
}

static int32_t CkksCtrl(HIFHE_Ctx *ctx, int32_t cmd, const HIFHE_HEText *text, void *value, uint32_t valueLen)
{
    (void)text;
    if (cmd != HIFHE_CTRL_GET_OUTPUT_LEN) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
        return HIFHE_NOT_SUPPORTED;
    }
    if (value == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (valueLen != sizeof(HifheOutputLen)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_INVALID_LENGTH);
        return HIFHE_INVALID_LENGTH;
    }
    if (ctx->params == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_NOT_SET);
        return HIFHE_PARAM_NOT_SET;
    }
    HifheOutputLen *query = value;
    if (query->op > HIFHE_OP_NOISE) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    CRYPT_CKKS_Ctx *math = ctx->params->math;
    uint32_t one = math->para->N * ((math->para->qBits + 7) / 8 + 1);
    query->len = HIFHE_WIRE_HEADER + 8 + one * (query->op == HIFHE_OP_ENCRYPT ? 2 : 1);
    return HIFHE_SUCCESS;
}

const HifheAlgMethod g_hifheCkksMethod = {.algId = HIFHE_CKKS,
                                          .ctxNew = CkksCtxNew,
                                          .ctxDup = CkksCtxDup,
                                          .ctxFree = CkksCtxFree,
                                          .keyGen = CkksKeyGen,
                                          .ctrl = CkksCtrl,
                                          .encode = CkksEncode,
                                          .decode = CkksDecode,
                                          .encrypt = CkksEncrypt,
                                          .decrypt = CkksDecrypt,
                                          .serialize = CkksSerialize,
                                          .deserialize = CkksDeserialize,
                                          .textFree = CkksTextFree};
