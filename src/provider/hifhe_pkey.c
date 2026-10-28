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

#include <complex.h>
#include <math.h>
#include "hifhe_local.h"
#include "hifhe_provider_impl.h"
#include "crypt_eal_implprovider.h"
#include "crypt_params_key.h"
#include "crypt_types.h"

static int32_t ParseParams(const BSL_Param *p, uint32_t max, const BSL_Param **out, const int32_t *keys,
                           const uint32_t *types, uint32_t count)
{
    if (p == NULL) {
        return HIFHE_NULL_INPUT;
    }
    memset(out, 0, count * sizeof(*out));
    for (uint32_t i = 0; i < max; i++) {
        if (p[i].key == 0) {
            return 0;
        }
        uint32_t k = 0;
        while (k < count && p[i].key != keys[k]) {
            k++;
        }
        if (k == count || out[k] != NULL || p[i].value == NULL || p[i].valueType != types[k]) {
            return HIFHE_PARAM_INVALID;
        }
        if (types[k] == BSL_PARAM_TYPE_UINT32 && p[i].valueLen != sizeof(uint32_t)) {
            return HIFHE_PARAM_INVALID;
        }
        out[k] = &p[i];
    }
    return HIFHE_PARAM_INVALID;
}

static void *CtxNew(void *prov, int32_t algId)
{
    return Hifhe_CtxNew(algId, prov != NULL ? ((HIFHE_ProvCtx *)prov)->libCtx : NULL);
}

static void CtxFree(void *ctx)
{
    HIFHE_Free(ctx);
}

static void *CtxDup(const void *ctx)
{
    return Hifhe_CtxDup(ctx);
}

#ifdef HIFHE_ENABLE_CKKS
static int32_t SetParam(void *data, const BSL_Param *values)
{
    HIFHE_Ctx *ctx = data;
    if (ctx == NULL || values == NULL) {
        return HIFHE_NULL_INPUT;
    }
    const int32_t keys[] = {HIFHE_PARAM_CKKS_N, HIFHE_PARAM_CKKS_Q_BITS, HIFHE_PARAM_CKKS_P_BITS,
                            HIFHE_PARAM_CKKS_SIGMA_MILLI, HIFHE_PARAM_CKKS_SLOTS};
    const uint32_t types[] = {BSL_PARAM_TYPE_UINT32, BSL_PARAM_TYPE_UINT32, BSL_PARAM_TYPE_UINT32,
                              BSL_PARAM_TYPE_UINT32, BSL_PARAM_TYPE_UINT32};
    const BSL_Param *found[5];
    int32_t ret = ParseParams(values, 6, found, keys, types, 5);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    HifheParamConfig config = {.isCkks = true};
    for (uint32_t i = 0; i < 5; i++) {
        if (found[i] == NULL) {
            return HIFHE_PARAM_INVALID;
        }
        memcpy(&config.ckks[i], found[i]->value, sizeof(uint32_t));
    }
    config.slots = config.ckks[4];
    return Hifhe_SetParam(ctx, &config);
}
#endif

static int32_t Gen(void *ctx)
{
    return HIFHE_KeyGen(ctx);
}

static int32_t OutputSize(const HIFHE_Ctx *ctx, uint32_t op, const HIFHE_HEText *text, uint8_t *out, uint32_t *len)
{
    if (ctx == NULL || len == NULL) {
        return HIFHE_NULL_INPUT;
    }
    if (ctx->params == NULL) {
        return HIFHE_PARAM_NOT_SET;
    }
    if (ctx->method->ctrl == NULL) {
        return HIFHE_NOT_SUPPORTED;
    }
    HifheOutputLen query = {.op = op};
    int32_t ret = ctx->method->ctrl((HIFHE_Ctx *)ctx, HIFHE_CTRL_GET_OUTPUT_LEN, text, &query, sizeof(query));
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    uint32_t n = query.len;
    if (out == NULL || *len < n) {
        *len = n;
        return HIFHE_BUFFER_TOO_SMALL;
    }
    return 0;
}

static int32_t Encode(const void *data, const BSL_Param *input, uint8_t *out, uint32_t *len)
{
    const HIFHE_Ctx *ctx = data;
    if (ctx == NULL || ctx->params == NULL) {
        return HIFHE_PARAM_NOT_SET;
    }
    int32_t key = HIFHE_PARAM_BGV_MSG;
    uint32_t type = BSL_PARAM_TYPE_OCTETS;
    const BSL_Param *p[1];
    int32_t ret = ParseParams(input, 2, p, &key, &type, 1);
    if (ret != HIFHE_SUCCESS || p[0] == NULL || p[0]->valueLen == 0 || (p[0]->valueLen % 8) != 0) {
        return HIFHE_PARAM_INVALID;
    }
    uint32_t count = p[0]->valueLen / 8;
    if (count > ctx->params->config.slots) {
        return HIFHE_PARAM_INVALID;
    }
    uint64_t *values = HifheCalloc(count, sizeof(*values));
    if (values == NULL) {
        return HIFHE_MEMORY_ERROR;
    }
    memcpy(values, p[0]->value, (size_t)count * sizeof(*values));
    ret = ctx->method->encode(ctx, values, count, NULL);
    if (ret == HIFHE_SUCCESS) {
        ret = OutputSize(ctx, 0, NULL, out, len);
    }
    HIFHE_HEText *text = NULL;
    if (ret == HIFHE_SUCCESS) {
        ret = HIFHE_Encode(ctx, values, count, &text);
    }
    if (ret == HIFHE_SUCCESS) {
        ret = HIFHE_Serialize(ctx, text, out, len);
    }
    HIFHE_HETextFree(text);
    HifheCleanse(values, count * sizeof(*values));
    HifheFree(values);
    return ret;
}

static int32_t Decode(const void *data, const BSL_Param *input, uint8_t *out, uint32_t *len)
{
    const HIFHE_Ctx *ctx = data;
    if (len == NULL) {
        return HIFHE_NULL_INPUT;
    }
    int32_t key = HIFHE_PARAM_BGV_PLAINTEXT;
    uint32_t type = BSL_PARAM_TYPE_OCTETS;
    const BSL_Param *p[1];
    int32_t ret = ParseParams(input, 2, p, &key, &type, 1);
    if (ret != HIFHE_SUCCESS || p[0] == NULL) {
        return HIFHE_PARAM_INVALID;
    }
    HIFHE_HEText *text = NULL;
    ret = HIFHE_Deserialize(ctx, p[0]->value, p[0]->valueLen, &text);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    uint32_t count = ctx->params->config.slots, need = count * 8;
    if (text->data->kind != HIFHE_TEXT_PLAIN) {
        ret = HIFHE_PARAM_INVALID;
    } else if (out == NULL || *len < need) {
        *len = need;
        ret = HIFHE_BUFFER_TOO_SMALL;
    }
    uint64_t *values = NULL;
    if (ret == HIFHE_SUCCESS) {
        values = HifheCalloc(count, sizeof(*values));
        if (values == NULL) {
            ret = HIFHE_MEMORY_ERROR;
        }
    }
    if (ret == HIFHE_SUCCESS) {
        ret = HIFHE_Decode(ctx, text, values, &count);
    }
    if (ret == HIFHE_SUCCESS) {
        memcpy(out, values, need);
        *len = need;
    }
    if (values != NULL) {
        HifheCleanse(values, count * sizeof(*values));
    }
    HifheFree(values);
    HIFHE_HETextFree(text);
    return ret;
}

static int32_t Binary(const void *data, const BSL_Param *input, uint8_t *out, uint32_t *len, bool mul)
{
    HIFHE_Ctx *ctx = (HIFHE_Ctx *)data;
    const int32_t keys[] = {CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, CRYPT_PARAM_PKEY_HE_CIPHERTEXT2, HIFHE_PARAM_BGV_PLAINTEXT,
                            HIFHE_PARAM_BGV_NEGATE};
    const uint32_t types[] = {BSL_PARAM_TYPE_OCTETS, BSL_PARAM_TYPE_OCTETS, BSL_PARAM_TYPE_OCTETS,
                              BSL_PARAM_TYPE_OCTETS};
    const BSL_Param *p[4];
    int32_t ret = ParseParams(input, mul ? 3 : 4, p, keys, types, 4);
    if (ret != HIFHE_SUCCESS || p[0] == NULL || (p[1] != NULL && p[2] != NULL) || (mul && p[3] != NULL) ||
        (p[1] == NULL && p[2] == NULL && p[3] == NULL)) {
        return HIFHE_PARAM_INVALID;
    }
    if (p[3] != NULL && (p[3]->valueLen != 1 || *(uint8_t *)p[3]->value != 1)) {
        return HIFHE_PARAM_INVALID;
    }
    HIFHE_HEText *a = NULL, *b = NULL, *result = NULL;
    ret = HIFHE_Deserialize(ctx, p[0]->value, p[0]->valueLen, &a);
    const BSL_Param *second = p[1] != NULL ? p[1] : p[2];
    if (ret == HIFHE_SUCCESS && second != NULL) {
        ret = HIFHE_Deserialize(ctx, second->value, second->valueLen, &b);
    }
    if (ret == HIFHE_SUCCESS && p[3] != NULL) {
        ret = HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_SET_NEGATE, a, NULL, 0);
    }
    if (ret == HIFHE_SUCCESS && b != NULL) {
        if (b->data->kind != (p[1] != NULL ? HIFHE_TEXT_CIPHER : HIFHE_TEXT_PLAIN)) {
            ret = HIFHE_PARAM_INVALID;
        }
    }
    if (ret == HIFHE_SUCCESS) {
        ret = Hifhe_CheckCompute(ctx, mul ? HIFHE_OP_MUL : HIFHE_OP_ADD, a, b);
    }
    if (ret == HIFHE_SUCCESS) {
        ret = OutputSize(ctx, mul ? HIFHE_OP_MUL : HIFHE_OP_ADD, a, out, len);
    }
    if (ret == HIFHE_SUCCESS) {
        ret = mul ? HIFHE_Mul(ctx, a, b, &result) : HIFHE_Add(ctx, a, b, &result);
    }
    if (ret == HIFHE_SUCCESS) {
        ret = HIFHE_Serialize(ctx, result, out, len);
    }
    HIFHE_HETextFree(a);
    HIFHE_HETextFree(b);
    HIFHE_HETextFree(result);
    return ret;
}

static int32_t Add(const void *c, const BSL_Param *p, uint8_t *out, uint32_t *len)
{
    return Binary(c, p, out, len, false);
}

static int32_t Mul(const void *c, const BSL_Param *p, uint8_t *out, uint32_t *len)
{
    return Binary(c, p, out, len, true);
}

static int32_t Crypt(void *data, const uint8_t *input, uint32_t n, uint8_t *out, uint32_t *len, bool enc)
{
    HIFHE_Ctx *ctx = data;
    if (ctx == NULL || input == NULL || len == NULL) {
        return HIFHE_NULL_INPUT;
    }
    if (ctx->params == NULL) {
        return HIFHE_PARAM_NOT_SET;
    }
    if ((ctx->keyMask & (enc ? HIFHE_KEY_PUBLIC : HIFHE_KEY_PRIVATE)) == 0) {
        return HIFHE_KEY_NOT_SET;
    }
    bool ckks = ctx->method->algId == HIFHE_CKKS;
    HIFHE_HEText *text = NULL, *result = NULL;
    int32_t ret = 0;
    if (enc && ckks) {
        if (n == 0 || (n % sizeof(double complex)) != 0 || n / sizeof(double complex) > ctx->params->config.slots) {
            return HIFHE_PARAM_INVALID;
        }
        double complex *values = HifheMalloc(n);
        if (values == NULL) {
            return HIFHE_MEMORY_ERROR;
        }
        memcpy(values, input, n);
        ret = ctx->method->encode(ctx, values, n / sizeof(double complex), NULL);
        HifheCleanse(values, n);
        HifheFree(values);
    } else {
        ret = HIFHE_Deserialize(ctx, input, n, &text);
        if (ret == HIFHE_SUCCESS) {
            ret = Hifhe_CheckCompute(ctx, enc ? HIFHE_OP_ENCRYPT : HIFHE_OP_DECRYPT, text, NULL);
        }
    }
    if (ret == HIFHE_SUCCESS && ckks && !enc) {
        uint32_t need = ctx->params->config.slots * sizeof(double complex);
        if (out == NULL || *len < need) {
            *len = need;
            ret = HIFHE_BUFFER_TOO_SMALL;
        }
    } else if (ret == HIFHE_SUCCESS) {
        ret = OutputSize(ctx, enc ? HIFHE_OP_ENCRYPT : HIFHE_OP_DECRYPT, text, out, len);
    }
    if (ret == HIFHE_SUCCESS && enc && ckks) {
        double complex *aligned = HifheMalloc(n);
        void *plain = NULL;
        if (aligned == NULL) {
            ret = HIFHE_MEMORY_ERROR;
        } else {
            memcpy(aligned, input, n);
            ret = ctx->method->encode(ctx, aligned, n / sizeof(double complex), &plain);
            if (ret == HIFHE_SUCCESS) {
                ret = Hifhe_HETextNew(ctx, plain, &text);
            }
            HifheCleanse(aligned, n);
            HifheFree(aligned);
        }
    }
    if (ret == HIFHE_SUCCESS) {
        ret = enc ? HIFHE_Encrypt(ctx, text, &result) : HIFHE_Decrypt(ctx, text, &result);
    }
    if (ret == HIFHE_SUCCESS && ckks && !enc) {
        uint32_t count = ctx->params->config.slots;
        double complex *values = HifheCalloc(count, sizeof(*values));
        if (values == NULL) {
            ret = HIFHE_MEMORY_ERROR;
        } else {
            ret = ctx->method->decode(ctx, result->data, values, &count);
            if (ret == HIFHE_SUCCESS) {
                *len = count * sizeof(*values);
                memcpy(out, values, *len);
            }
            HifheCleanse(values, count * sizeof(*values));
            HifheFree(values);
        }
    } else if (ret == HIFHE_SUCCESS) {
        ret = HIFHE_Serialize(ctx, result, out, len);
    }
    HIFHE_HETextFree(text);
    HIFHE_HETextFree(result);
    return ret;
}

static int32_t Encrypt(void *c, const uint8_t *p, uint32_t n, uint8_t *o, uint32_t *l)
{
    return Crypt(c, p, n, o, l, true);
}

static int32_t Decrypt(void *c, const uint8_t *p, uint32_t n, uint8_t *o, uint32_t *l)
{
    return Crypt(c, p, n, o, l, false);
}

static int32_t Ctrl(void *data, int32_t cmd, void *args, uint32_t len)
{
    HIFHE_Ctx *ctx = data;
    if (ctx == NULL || args == NULL) {
        return HIFHE_NULL_INPUT;
    }
    switch (cmd) {
        case HIFHE_CTRL_BGV_SET_LUT_CACHE:
        case HIFHE_CTRL_BGV_SET_SEED:
        case HIFHE_CTRL_BGV_GET_POLY_DEGREE:
        case HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN:
        case HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN:
            return HIFHE_Ctrl(ctx, cmd, NULL, args, len);
        default:
            break;
    }
    if (cmd == CRYPT_CTRL_SET_PARA_BY_ID) {
        if (len != 4) {
            return HIFHE_PARAM_INVALID;
        }
        int32_t id;
        memcpy(&id, args, 4);
        return HIFHE_SetParaById(ctx, id);
    }
    if (cmd == HIFHE_CTRL_BGV_RERANDOMIZE) {
        BSL_Param *p = args;
        int32_t keys[] = {CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, CRYPT_PARAM_PKEY_HE_CIPHERTEXT2};
        uint32_t types[] = {BSL_PARAM_TYPE_OCTETS, BSL_PARAM_TYPE_OCTETS};
        const BSL_Param *found[2];
        int32_t ret = ParseParams(p, 3, found, keys, types, 2);
        if (ret != HIFHE_SUCCESS || found[0] == NULL || found[1] == NULL) {
            return HIFHE_PARAM_INVALID;
        }
        HIFHE_HEText *in = NULL, *result = NULL;
        ret = HIFHE_Deserialize(ctx, found[0]->value, found[0]->valueLen, &in);
        uint32_t n = found[1]->valueLen;
        if (ret == HIFHE_SUCCESS) {
            ret = OutputSize(ctx, HIFHE_OP_NOISE, in, found[1]->value, &n);
        }
        if (ret == HIFHE_SUCCESS) {
            ret = HIFHE_Ctrl(ctx, cmd, in, &result, sizeof(result));
        }
        if (ret == HIFHE_SUCCESS) {
            ret = HIFHE_Serialize(ctx, result, found[1]->value, &n);
        }
        if (ret == HIFHE_SUCCESS || ret == HIFHE_BUFFER_TOO_SMALL) {
            ((BSL_Param *)found[1])->useLen = n;
        }
        HIFHE_HETextFree(in);
        HIFHE_HETextFree(result);
        return ret;
    }
    return HIFHE_NOT_SUPPORTED;
}

#ifdef HIFHE_ENABLE_BGV
const CRYPT_EAL_Func g_hifheKeyMgmtBgv[] = {{CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CtxNew},
                                            {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)Gen},
                                            {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CtxDup},
                                            {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)Ctrl},
                                            {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CtxFree},
                                            CRYPT_EAL_FUNC_END};
#endif

#ifdef HIFHE_ENABLE_CKKS
const CRYPT_EAL_Func g_hifheKeyMgmtCkks[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CtxNew},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CtxDup},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CtxFree},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)SetParam},
    CRYPT_EAL_FUNC_END};
#endif

const CRYPT_EAL_Func g_hifheCipherBgv[] = {{CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT, (CRYPT_EAL_ImplPkeyEncrypt)Encrypt},
                                           {CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT, (CRYPT_EAL_ImplPkeyDecrypt)Decrypt},
                                           {CRYPT_EAL_IMPLPKEYCIPHER_HEADD, (CRYPT_EAL_ImplPkeyHEAdd)Add},
                                           {CRYPT_EAL_IMPLPKEYCIPHER_HEMUL, (CRYPT_EAL_ImplPkeyHEMul)Mul},
                                           {CRYPT_EAL_IMPLPKEYCIPHER_MSG_ENCODE, (CRYPT_EAL_ImplPkeyHEMsgEncode)Encode},
                                           {CRYPT_EAL_IMPLPKEYCIPHER_MSG_DECODE, (CRYPT_EAL_ImplPkeyHEMsgDecode)Decode},
                                           CRYPT_EAL_FUNC_END};
const CRYPT_EAL_Func g_hifheCipherCkks[] = {{CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT, (CRYPT_EAL_ImplPkeyEncrypt)Encrypt},
                                            {CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT, (CRYPT_EAL_ImplPkeyDecrypt)Decrypt},
                                            CRYPT_EAL_FUNC_END};
