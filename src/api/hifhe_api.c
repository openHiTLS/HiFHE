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

#include <limits.h>
#include <stdint.h>
#include "hifhe_local.h"
#include "crypt_eal_md.h"
#include "crypt_eal_rand.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "hifhe_err_internal.h"

void Hifhe_Put32(uint8_t *p, uint32_t v)
{
    for (uint32_t i = 0; i < 4; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

uint32_t Hifhe_Get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

void Hifhe_Put64(uint8_t *p, uint64_t v)
{
    for (uint32_t i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static const HifheAlgMethod *FindMethod(int32_t id)
{
#ifdef HIFHE_ENABLE_BGV
    if (id == HIFHE_BGV) {
        return &g_hifheBgvMethod;
    }
#endif
#ifdef HIFHE_ENABLE_CKKS
    if (id == HIFHE_CKKS) {
        return &g_hifheCkksMethod;
    }
#endif
    (void)id;
    return NULL;
}

HIFHE_Ctx *Hifhe_CtxNew(int32_t id, void *libCtx)
{
    const HifheAlgMethod *method = FindMethod(id);
    if (method == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
        return NULL;
    }
    HIFHE_Ctx *ctx = HifheCalloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return NULL;
    }
    ctx->method = method;
    ctx->libCtx = libCtx;
    return ctx;
}

HIFHE_Ctx *HIFHE_New(int32_t id)
{
    return Hifhe_CtxNew(id, NULL);
}

void Hifhe_ParamRetain(HifheParamSnapshot *p)
{
    atomic_fetch_add_explicit(&p->references, 1, memory_order_relaxed);
}

void Hifhe_ParamRelease(HifheParamSnapshot *p)
{
    if (p != NULL && atomic_fetch_sub_explicit(&p->references, 1, memory_order_acq_rel) == 1) {
        p->method->ctxFree(p->math);
        HifheFree(p);
    }
}

void HIFHE_Free(HIFHE_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->method->ctxFree(ctx->data);
    Hifhe_ParamRelease(ctx->params);
    HifheCleanse(ctx, sizeof(*ctx));
    HifheFree(ctx);
}

int32_t Hifhe_ParamSetFingerprint(HifheParamSnapshot *params, const uint8_t *canonical, uint32_t len)
{
    uint32_t hashLen = sizeof(params->fingerprint);
    int32_t ret = CRYPT_EAL_Md(CRYPT_MD_SHA256, canonical, len, params->fingerprint, &hashLen);
    if (ret != HIFHE_SUCCESS || hashLen != sizeof(params->fingerprint)) {
        ret = ret == CRYPT_MEM_ALLOC_FAIL ? HIFHE_MEMORY_ERROR : HIFHE_HASH_ERROR;
        HIFHE_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HIFHE_SUCCESS;
}

int32_t Hifhe_SetParam(HIFHE_Ctx *ctx, const HifheParamConfig *p)
{
    if (ctx == NULL || p == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (ctx->params != NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_REPEATED_SET);
        return HIFHE_PARAM_REPEATED_SET;
    }
    HifheParamSnapshot *fresh = HifheCalloc(1, sizeof(*fresh));
    if (fresh == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    atomic_init(&fresh->references, 1);
    fresh->method = ctx->method;
    fresh->config = *p;
    fresh->config.useLutCache = ctx->useLutCache;
    void *data = NULL;
    int32_t ret = ctx->method->ctxNew(fresh, ctx->libCtx, &data);
    if (ret != HIFHE_SUCCESS) {
        ctx->method->ctxFree(data);
        Hifhe_ParamRelease(fresh);
        return ret;
    }
    ctx->params = fresh;
    ctx->data = data;
    return 0;
}

int32_t HIFHE_SetParaById(HIFHE_Ctx *ctx, int32_t id)
{
    HifheParamConfig p = {.paramId = id};
    return Hifhe_SetParam(ctx, &p);
}

HIFHE_Ctx *Hifhe_CtxDup(const HIFHE_Ctx *src)
{
    if (src == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return NULL;
    }
    HIFHE_Ctx *dst = Hifhe_CtxNew(src->method->algId, src->libCtx);
    if (dst == NULL) {
        return NULL;
    }
    if (src->params != NULL) {
        dst->data = src->method->ctxDup(src->data, dst->libCtx);
        if (dst->data == NULL) {
            goto fail;
        }
        dst->params = src->params;
        Hifhe_ParamRetain(dst->params);
    }
    memcpy(dst->keysetId, src->keysetId, 16);
    dst->keyMask = src->keyMask;
    dst->useLutCache = src->useLutCache;
    return dst;
fail:
    HIFHE_Free(dst);
    return NULL;
}

int32_t HIFHE_KeyGen(HIFHE_Ctx *ctx)
{
    if (ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (ctx->params == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_NOT_SET);
        return HIFHE_PARAM_NOT_SET;
    }
    if (ctx->keyMask != 0) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_KEY_REPEATED_SET);
        return HIFHE_KEY_REPEATED_SET;
    }
    void *fresh = ctx->method->ctxDup(ctx->data, ctx->libCtx);
    if (fresh == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    uint8_t id[16];
    int32_t ret = ctx->method->keyGen(fresh);
    if (ret == HIFHE_SUCCESS) {
        ret = ctx->libCtx != NULL ? CRYPT_EAL_RandbytesEx(ctx->libCtx, id, sizeof(id)) :
                                    CRYPT_EAL_Randbytes(id, sizeof(id));
        if (ret != HIFHE_SUCCESS) {
            HifheCleanse(id, sizeof(id));
            ret = HIFHE_RANDOM_ERROR;
            HIFHE_ERR_PUSH_ERROR(ret);
        }
    }
    if (ret != HIFHE_SUCCESS) {
        ctx->method->ctxFree(fresh);
        return ret;
    }
    ctx->method->ctxFree(ctx->data);
    ctx->data = fresh;
    memcpy(ctx->keysetId, id, 16);
    ctx->keyMask = HIFHE_KEY_PUBLIC | HIFHE_KEY_PRIVATE;
    return 0;
}

int32_t Hifhe_HETextNew(const HIFHE_Ctx *ctx, void *data, HIFHE_HEText **out)
{
    HIFHE_HEText *text = HifheCalloc(1, sizeof(*text));
    if (text == NULL) {
        ctx->method->textFree(data);
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    memcpy(text->fingerprint, ctx->params->fingerprint, sizeof(text->fingerprint));
    text->method = ctx->method;
    text->data = data;
    *out = text;
    return 0;
}

void HIFHE_HETextFree(HIFHE_HEText *text)
{
    if (text == NULL) {
        return;
    }
    text->method->textFree(text->data);
    HifheFree(text);
}

static int32_t CheckCtx(const HIFHE_Ctx *ctx)
{
    if (ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (ctx->params == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_NOT_SET);
        return HIFHE_PARAM_NOT_SET;
    }
    return HIFHE_SUCCESS;
}

int32_t Hifhe_CheckText(const HIFHE_Ctx *ctx, const HIFHE_HEText *text, bool flags)
{
    int32_t ret = CheckCtx(ctx);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    if (text == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (text->method != ctx->method) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_ALG_MISMATCH);
        return HIFHE_ALG_MISMATCH;
    }
    if (memcmp(text->fingerprint, ctx->params->fingerprint, 32) != 0) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_MISMATCH);
        return HIFHE_PARAM_MISMATCH;
    }
    HifheTextMeta m = *text->data;
    if (!flags && m.flags != 0) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_BAD_STATE);
        return HIFHE_BAD_STATE;
    }
    if (m.kind == HIFHE_TEXT_CIPHER && ctx->keyMask != 0 && memcmp(m.keysetId, ctx->keysetId, 16) != 0) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_KEY_MISMATCH);
        return HIFHE_KEY_MISMATCH;
    }
    return 0;
}

static bool Overlap(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return a != NULL && b != NULL && (x <= y ? y - x < an : x - y < bn);
}

static int32_t CheckOut(HIFHE_HEText **out)
{
    if (out == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (*out != NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_OUTPUT_NOT_EMPTY);
        return HIFHE_OUTPUT_NOT_EMPTY;
    }
    return HIFHE_SUCCESS;
}

int32_t HIFHE_Encode(const HIFHE_Ctx *ctx, const uint64_t *values, uint32_t count, HIFHE_HEText **out)
{
    int32_t ret = CheckOut(out);
    if (ret == HIFHE_SUCCESS) {
        ret = CheckCtx(ctx);
    }
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    if (values == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (ctx->method->algId != HIFHE_BGV) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
        return HIFHE_NOT_SUPPORTED;
    }
    if (count == 0 || count > ctx->params->config.slots) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_INVALID_LENGTH);
        return HIFHE_INVALID_LENGTH;
    }
    void *data = NULL;
    ret = ctx->method->encode(ctx, values, count, &data);
    return ret != HIFHE_SUCCESS ? ret : Hifhe_HETextNew(ctx, data, out);
}

int32_t HIFHE_Decode(const HIFHE_Ctx *ctx, const HIFHE_HEText *text, uint64_t *values, uint32_t *count)
{
    if (count == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t ret = Hifhe_CheckText(ctx, text, false);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    if (ctx->method->algId != HIFHE_BGV) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
        return HIFHE_NOT_SUPPORTED;
    }
    HifheTextMeta m = *text->data;
    if (m.kind != HIFHE_TEXT_PLAIN) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_TEXT_TYPE_MISMATCH);
        return HIFHE_TEXT_TYPE_MISMATCH;
    }
    uint32_t need = ctx->params->config.slots;
    if (values == NULL || *count < need) {
        *count = need;
        if (values != NULL) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_BUFFER_TOO_SMALL);
        }
        return HIFHE_BUFFER_TOO_SMALL;
    }
    if (Overlap(values, (size_t)need * sizeof(*values), count, sizeof(*count))) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_BUFFER_OVERLAP);
        return HIFHE_BUFFER_OVERLAP;
    }
    uint64_t *fresh = HifheCalloc(need, sizeof(*fresh));
    if (fresh == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    ret = ctx->method->decode(ctx, text->data, fresh, &need);
    if (ret == HIFHE_SUCCESS) {
        memcpy(values, fresh, (size_t)need * sizeof(*values));
        *count = need;
    }
    HifheCleanse(fresh, need * sizeof(*fresh));
    HifheFree(fresh);
    return ret;
}

int32_t Hifhe_CheckCompute(const HIFHE_Ctx *ctx, uint32_t op, const HIFHE_HEText *a, const HIFHE_HEText *b)
{
    int32_t ret = Hifhe_CheckText(ctx, a, op == HIFHE_OP_ADD);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    HifheTextMeta ma = *a->data, mb = {0};
    uint32_t kind = op == HIFHE_OP_ENCRYPT ? HIFHE_TEXT_PLAIN : HIFHE_TEXT_CIPHER;
    if (ma.kind != kind) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_TEXT_TYPE_MISMATCH);
        return HIFHE_TEXT_TYPE_MISMATCH;
    }
    if ((op == HIFHE_OP_ENCRYPT && (ctx->keyMask & HIFHE_KEY_PUBLIC) == 0) ||
        (op == HIFHE_OP_DECRYPT && (ctx->keyMask & HIFHE_KEY_PRIVATE) == 0)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_KEY_NOT_SET);
        return HIFHE_KEY_NOT_SET;
    }
    if (b != NULL) {
        ret = Hifhe_CheckText(ctx, b, false);
        if (ret != HIFHE_SUCCESS) {
            return ret;
        }
        mb = *b->data;
        if (mb.kind == HIFHE_TEXT_CIPHER && memcmp(ma.keysetId, mb.keysetId, 16) != 0) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_KEY_MISMATCH);
            return HIFHE_KEY_MISMATCH;
        }
    } else if (op == HIFHE_OP_MUL || (op == HIFHE_OP_ADD && (ma.flags & HIFHE_TEXT_NEGATE) == 0)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (op == HIFHE_OP_MUL && mb.kind == HIFHE_TEXT_CIPHER) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
        return HIFHE_NOT_SUPPORTED;
    }
    return 0;
}

int32_t HIFHE_Encrypt(HIFHE_Ctx *ctx, const HIFHE_HEText *plaintext, HIFHE_HEText **out)
{
    int32_t ret = CheckOut(out);
    if (ret == HIFHE_SUCCESS) {
        ret = Hifhe_CheckCompute(ctx, HIFHE_OP_ENCRYPT, plaintext, NULL);
    }
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    void *data = NULL;
    ret = ctx->method->encrypt(ctx, plaintext->data, &data);
    return ret != HIFHE_SUCCESS ? ret : Hifhe_HETextNew(ctx, data, out);
}

int32_t HIFHE_Decrypt(HIFHE_Ctx *ctx, const HIFHE_HEText *ciphertext, HIFHE_HEText **out)
{
    int32_t ret = CheckOut(out);
    if (ret == HIFHE_SUCCESS) {
        ret = Hifhe_CheckCompute(ctx, HIFHE_OP_DECRYPT, ciphertext, NULL);
    }
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    void *data = NULL;
    ret = ctx->method->decrypt(ctx, ciphertext->data, &data);
    return ret != HIFHE_SUCCESS ? ret : Hifhe_HETextNew(ctx, data, out);
}

int32_t HIFHE_Add(const HIFHE_Ctx *ctx, const HIFHE_HEText *para1, const HIFHE_HEText *para2, HIFHE_HEText **out)
{
    int32_t ret = CheckOut(out);
    if (ret == HIFHE_SUCCESS) {
        ret = Hifhe_CheckCompute(ctx, HIFHE_OP_ADD, para1, para2);
    }
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    if (ctx->method->add == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
        return HIFHE_NOT_SUPPORTED;
    }
    void *data = NULL;
    ret = ctx->method->add(ctx, para1->data, para2 != NULL ? para2->data : NULL, &data);
    return ret != HIFHE_SUCCESS ? ret : Hifhe_HETextNew(ctx, data, out);
}

int32_t HIFHE_Mul(const HIFHE_Ctx *ctx, const HIFHE_HEText *para1, const HIFHE_HEText *para2, HIFHE_HEText **out)
{
    int32_t ret = CheckOut(out);
    if (ret == HIFHE_SUCCESS) {
        ret = Hifhe_CheckCompute(ctx, HIFHE_OP_MUL, para1, para2);
    }
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    if (ctx->method->mul == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
        return HIFHE_NOT_SUPPORTED;
    }
    void *data = NULL;
    ret = ctx->method->mul(ctx, para1->data, para2->data, &data);
    return ret != HIFHE_SUCCESS ? ret : Hifhe_HETextNew(ctx, data, out);
}

int32_t HIFHE_Ctrl(HIFHE_Ctx *ctx, int32_t cmd, HIFHE_HEText *text, void *value, uint32_t valueLen)
{
    if (ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (ctx->method->algId != HIFHE_BGV) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
        return HIFHE_NOT_SUPPORTED;
    }
    if (cmd != HIFHE_CTRL_BGV_SET_NEGATE && cmd != HIFHE_CTRL_BGV_RERANDOMIZE) {
        if (cmd == HIFHE_CTRL_GET_OUTPUT_LEN) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
            return HIFHE_NOT_SUPPORTED;
        }
        return ctx->method->ctrl(ctx, cmd, text, value, valueLen);
    }
    if (text == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (cmd == HIFHE_CTRL_BGV_SET_NEGATE) {
        if (value != NULL) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_INVALID_ARGUMENT);
            return HIFHE_INVALID_ARGUMENT;
        }
        if (valueLen != 0) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_INVALID_LENGTH);
            return HIFHE_INVALID_LENGTH;
        }
        int32_t ret = Hifhe_CheckText(ctx, text, true);
        if (ret != HIFHE_SUCCESS) {
            return ret;
        }
        if (text->data->kind != HIFHE_TEXT_CIPHER) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_TEXT_TYPE_MISMATCH);
            return HIFHE_TEXT_TYPE_MISMATCH;
        }
        text->data->flags = HIFHE_TEXT_NEGATE;
        return HIFHE_SUCCESS;
    }
    if (value == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (valueLen != sizeof(HIFHE_HEText *)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_INVALID_LENGTH);
        return HIFHE_INVALID_LENGTH;
    }
    HIFHE_HEText **out = value;
    int32_t ret = CheckOut(out);
    if (ret == HIFHE_SUCCESS) {
        ret = Hifhe_CheckCompute(ctx, HIFHE_OP_NOISE, text, NULL);
    }
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    void *data = NULL;
    ret = ctx->method->ctrl(ctx, cmd, text, &data, sizeof(data));
    return ret != HIFHE_SUCCESS ? ret : Hifhe_HETextNew(ctx, data, out);
}

static void WriteHeader(const HIFHE_Ctx *ctx, uint32_t kind, uint32_t len, const uint8_t *id, uint8_t *p)
{
    memcpy(p, "HFHE", 4);
    Hifhe_Put32(p + 4, 1u | kind << 16);
    Hifhe_Put32(p + 8, (uint32_t)ctx->method->algId);
    Hifhe_Put32(p + 12, len);
    Hifhe_Put32(p + 16, (uint32_t)ctx->params->config.paramId);
    Hifhe_Put32(p + 20, ctx->params->config.slots);
    Hifhe_Put32(p + 24, ctx->params->config.mulDepth);
    memcpy(p + 28, ctx->params->fingerprint, 32);
    memcpy(p + 60, id, 16);
}

static int32_t ReadHeader(const HIFHE_Ctx *ctx, const uint8_t *p, uint32_t len, uint32_t *kind)
{
    int32_t ret = CheckCtx(ctx);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    if (p == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (len > HIFHE_MAX_WIRE) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_LIMIT_EXCEEDED);
        return HIFHE_LIMIT_EXCEEDED;
    }
    if (len < HIFHE_WIRE_HEADER || Hifhe_Get32(p + 12) != len) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_INVALID_LENGTH);
        return HIFHE_INVALID_LENGTH;
    }
    if (memcmp(p, "HFHE", 4) != 0) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_SERDES_FAIL);
        return HIFHE_SERDES_FAIL;
    }
    if ((Hifhe_Get32(p + 4) & 0xffff) != 1) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_VERSION_NOT_SUPPORTED);
        return HIFHE_VERSION_NOT_SUPPORTED;
    }
    *kind = Hifhe_Get32(p + 4) >> 16;
    if (*kind != HIFHE_TEXT_PLAIN && *kind != HIFHE_TEXT_CIPHER) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_TEXT_TYPE_MISMATCH);
        return HIFHE_TEXT_TYPE_MISMATCH;
    }
    if (Hifhe_Get32(p + 8) != (uint32_t)ctx->method->algId) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_ALG_MISMATCH);
        return HIFHE_ALG_MISMATCH;
    }
    if (Hifhe_Get32(p + 16) != (uint32_t)ctx->params->config.paramId ||
        Hifhe_Get32(p + 20) != ctx->params->config.slots || Hifhe_Get32(p + 24) != ctx->params->config.mulDepth ||
        memcmp(p + 28, ctx->params->fingerprint, 32) != 0) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_MISMATCH);
        return HIFHE_PARAM_MISMATCH;
    }
    if (*kind != HIFHE_TEXT_PLAIN && ctx->keyMask != 0 && memcmp(p + 60, ctx->keysetId, 16) != 0) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_KEY_MISMATCH);
        return HIFHE_KEY_MISMATCH;
    }
    if (*kind == HIFHE_TEXT_PLAIN) {
        uint8_t zero[16] = {0};
        if (memcmp(p + 60, zero, 16) != 0) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_SERDES_FAIL);
            return HIFHE_SERDES_FAIL;
        }
    }
    return 0;
}

int32_t HIFHE_Serialize(const HIFHE_Ctx *ctx, const HIFHE_HEText *text, uint8_t *out, uint32_t *outLen)
{
    if (outLen == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t ret = Hifhe_CheckText(ctx, text, false);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    if (Overlap(out, *outLen, outLen, sizeof(*outLen))) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_BUFFER_OVERLAP);
        return HIFHE_BUFFER_OVERLAP;
    }
    uint32_t n = 0;
    ret = ctx->method->serialize(ctx, text->data, NULL, &n);
    if (ret != HIFHE_SUCCESS && ret != HIFHE_BUFFER_TOO_SMALL) {
        return ret;
    }
    if (n > HIFHE_MAX_WIRE - HIFHE_WIRE_HEADER) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_LIMIT_EXCEEDED);
        return HIFHE_LIMIT_EXCEEDED;
    }
    uint32_t total = n + HIFHE_WIRE_HEADER;
    if (out == NULL || *outLen < total) {
        *outLen = total;
        if (out != NULL) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_BUFFER_TOO_SMALL);
        }
        return HIFHE_BUFFER_TOO_SMALL;
    }
    uint8_t *fresh = HifheCalloc(1, total);
    if (fresh == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    WriteHeader(ctx, text->data->kind, total, text->data->keysetId, fresh);
    ret = ctx->method->serialize(ctx, text->data, fresh + HIFHE_WIRE_HEADER, &n);
    if (ret == HIFHE_SUCCESS) {
        memcpy(out, fresh, total);
        *outLen = total;
    }
    HifheCleanse(fresh, total);
    HifheFree(fresh);
    return ret;
}

int32_t HIFHE_Deserialize(const HIFHE_Ctx *ctx, const uint8_t *in, uint32_t len, HIFHE_HEText **out)
{
    int32_t ret = CheckOut(out);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    uint32_t kind;
    ret = ReadHeader(ctx, in, len, &kind);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    void *data = NULL;
    ret = ctx->method->deserialize(ctx, kind, in + HIFHE_WIRE_HEADER, len - HIFHE_WIRE_HEADER, &data);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    HifheTextMeta *meta = data;
    memcpy(meta->keysetId, in + 60, 16);
    meta->flags = 0;
    return Hifhe_HETextNew(ctx, data, out);
}
