/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/* Parameter cache consumed by Bgv_BuildContext. */

#include <stdbool.h>
#include <string.h>
#include "hifhe_mem.h"
#include "hifhe_err_internal.h"
#include "kernel/ntt.h"

#include "bgv_local.h"
#include "bgv/params_preset.h"

void BgvUserPara_Init(BgvUserPara *p)
{
    if (p == NULL) {
        return;
    }
    memset(p, 0, sizeof(*p));
    p->correctionFactor = HIFHE_BGV_DEFAULT_CORRECTION_FACTOR;
    p->relinDnum = HIFHE_BGV_DEFAULT_RELIN_DNUM;
}

void BgvUserPara_Clear(BgvUserPara *p)
{
    if (p == NULL) {
        return;
    }
    Uint32Vector_Destroy(&p->cipherModBit);
    Uint64Vector_Destroy(&p->cipherMod);
    /* Frees the tables. Every context must be destroyed.
     * Run Bgv_FreeState(*ctx) first. */
    if (p->lutBlob != NULL) {
        HifheFree(p->lutBlob);
    }
    memset(p, 0, sizeof(*p));
}

static bool BgvUserPara_IsEmpty(const BgvUserPara *p)
{
    return p->set == 0u && p->cipherModBit.data == NULL && p->cipherMod.data == NULL && p->lutBlob == NULL;
}

static void BgvUserPara_Commit(CRYPT_BGV_Ctx *ctx, const BgvUserPara *next)
{
    Bgv_FreeState(&ctx->bgv);
    BgvUserPara_Clear(&ctx->para);
    ctx->para = *next;
    ctx->role = HIFHE_ROLE_PARA;
}

/* True when the tables held match what `param` needs. */
static bool LutMatches(const BgvUserPara *p, const BGVParameter *param)
{
    const ModulusVector *cipherMod = &param->rlweParameter.cipherMod;
    if (p->lutBlob == NULL) {
        return false;
    }
    if (p->lutPolyDegree != param->rlweParameter.polyDegree || p->lutLimbs != cipherMod->size ||
        p->lutPlainMod != param->plainMod) {
        return false;
    }
    for (uint32_t i = 0; i < p->lutLimbs; ++i) {
        if (p->lutCipherMod[i] != cipherMod->data[i]) {
            return false;
        }
    }
    return true;
}

static HIFHE_ERROR BuildLutInto(BgvUserPara *p, const BGVParameter *param)
{
    const ModulusVector *cipherMod = &param->rlweParameter.cipherMod;
    uint32_t L = cipherMod->size;
    uint32_t N = param->rlweParameter.polyDegree;
    if (L == 0u || L > HIFHE_BGV_MAX_CHAIN_LEN || N == 0u || param->plainMod == 0u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    size_t stride = HIFHE_NTT_TABLE_WORDS(N);
    uint64_t *blob = (uint64_t *)HifheMalloc((uint32_t)(((size_t)L + 1u) * stride * sizeof(uint64_t)));
    if (blob == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }

    NttTables scratch;
    for (uint32_t i = 0; i < L; ++i) {
        int32_t r = Kernel_Ntt_BuildTables(&scratch, blob + (size_t)i * stride, cipherMod->data[i], N);
        if (r != HIFHE_SUCCESS) {
            HifheFree(blob);
            return r;
        }
        p->lutCipherMod[i] = cipherMod->data[i];
    }
    int32_t r = Kernel_Ntt_BuildTables(&scratch, blob + (size_t)L * stride, param->plainMod, N);
    if (r != HIFHE_SUCCESS) {
        HifheFree(blob);
        return r;
    }

    p->lutBlob = blob;
    p->lutPolyDegree = N;
    p->lutLimbs = L;
    p->lutPlainMod = param->plainMod;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BgvUserPara_EnsureLut(BgvUserPara *p, const BGVParameter *param)
{
    if (p == NULL || param == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (LutMatches(p, param)) {
        return HIFHE_SUCCESS;
    }
    if (p->lutBlob != NULL) {
        HifheFree(p->lutBlob);
        p->lutBlob = NULL;
        p->lutPolyDegree = 0u;
        p->lutLimbs = 0u;
        p->lutPlainMod = 0u;
    }
    int32_t r = BuildLutInto(p, param);
    return r;
}

uint64_t *BgvUserPara_CipherLut(const BgvUserPara *p, uint32_t index)
{
    if (p == NULL || p->lutBlob == NULL || index >= p->lutLimbs) {
        return NULL;
    }
    return p->lutBlob + (size_t)index * HIFHE_NTT_TABLE_WORDS(p->lutPolyDegree);
}

uint64_t *BgvUserPara_PlainLut(const BgvUserPara *p)
{
    if (p == NULL || p->lutBlob == NULL) {
        return NULL;
    }
    return p->lutBlob + (size_t)p->lutLimbs * HIFHE_NTT_TABLE_WORDS(p->lutPolyDegree);
}

HIFHE_ERROR BgvUserPara_Copy(BgvUserPara *dst, const BgvUserPara *src)
{
    if (dst == NULL || src == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    BgvUserPara_Clear(dst);
    *dst = *src;
    memset(&dst->cipherModBit, 0, sizeof(dst->cipherModBit));
    memset(&dst->cipherMod, 0, sizeof(dst->cipherMod));
    dst->lutBlob = NULL;
    int32_t r = Uint32Vector_Create(&dst->cipherModBit, src->cipherModBit.data, src->cipherModBit.size);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    if (src->cipherMod.size != 0u) {
        r = Uint64Vector_Create(&dst->cipherMod, src->cipherMod.data, src->cipherMod.size);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
    }
    if (src->lutBlob == NULL) {
        dst->lutPolyDegree = 0u;
        dst->lutLimbs = 0u;
        dst->lutPlainMod = 0u;
        memset(dst->lutCipherMod, 0, sizeof(dst->lutCipherMod));
        return HIFHE_SUCCESS;
    }
    if (src->lutPolyDegree == 0u || src->lutLimbs == 0u || src->lutLimbs > HIFHE_BGV_MAX_CHAIN_LEN) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    size_t wordsPerTable = HIFHE_NTT_TABLE_WORDS(src->lutPolyDegree);
    size_t tableCount = (size_t)src->lutLimbs + 1u;
    if (wordsPerTable > UINT32_MAX / sizeof(uint64_t) / tableCount) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    uint32_t bytes = (uint32_t)(wordsPerTable * tableCount * sizeof(uint64_t));
    dst->lutBlob = HifheMalloc(bytes);
    if (dst->lutBlob == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    memcpy(dst->lutBlob, src->lutBlob, bytes);
    return HIFHE_SUCCESS;
}

#ifdef HITLS_PROVIDER
static HIFHE_ERROR BgvUserPara_ParseFromBSL(BgvUserPara *p, const BSL_Param *param)
{
#ifndef HIFHE_CUSTOM_PARAM
    (void)p;
    (void)param;
    HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
    return HIFHE_PARAM_INVALID;
#else
    for (const BSL_Param *cur = param; cur->key != 0; ++cur) {
        switch (cur->key) {
            case HIFHE_PARAM_BGV_POLY_DEGREE:
                if (cur->valueLen != sizeof(uint32_t) || cur->value == NULL) {
                    HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                    return HIFHE_PARAM_INVALID;
                }
                p->polyDegree = *(const uint32_t *)cur->value;
                break;
            case HIFHE_PARAM_BGV_PLAIN_MOD_BIT:
                if (cur->valueLen != sizeof(uint32_t) || cur->value == NULL) {
                    HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                    return HIFHE_PARAM_INVALID;
                }
                p->plainModBit = *(const uint32_t *)cur->value;
                break;
            case HIFHE_PARAM_BGV_CORRECTION_FACTOR:
                if (cur->valueLen != sizeof(uint64_t) || cur->value == NULL) {
                    HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                    return HIFHE_PARAM_INVALID;
                }
                p->correctionFactor = *(const uint64_t *)cur->value;
                break;
            case HIFHE_PARAM_BGV_RELIN_DNUM:
                if (cur->valueLen != sizeof(uint32_t) || cur->value == NULL) {
                    HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                    return HIFHE_PARAM_INVALID;
                }
                p->relinDnum = *(const uint32_t *)cur->value;
                break;
            case HIFHE_PARAM_BGV_CIPHER_MOD_BITS: {
                if (cur->value == NULL || cur->valueLen == 0 || cur->valueLen % sizeof(uint32_t) != 0) {
                    HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                    return HIFHE_PARAM_INVALID;
                }
                uint32_t n = cur->valueLen / (uint32_t)sizeof(uint32_t);
                Uint32Vector_Destroy(&p->cipherModBit);
                int32_t vr = Uint32Vector_Create(&p->cipherModBit, (const uint32_t *)cur->value, n);
                if (vr != HIFHE_SUCCESS) {
                    return vr;
                }
                break;
            }
            default:
                /* Unknown keys are ignored; SetPara is best-effort. */
                break;
        }
    }

    /* The whole set is checked here. An incomplete or inadmissible set is
     * rejected by this call, not by key generation. */
    if (p->cipherModBit.data == NULL || p->cipherModBit.size == 0u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    if (p->correctionFactor == 0u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    int32_t vr = BGV_Params_Validate(p->polyDegree, p->plainModBit, p->cipherModBit.data, p->cipherModBit.size,
                                     HIFHE_BGV_DEFAULT_SECURITY_LEVEL);
    if (vr != HIFHE_SUCCESS) {
        return vr;
    }
    p->set = 1u;
    return HIFHE_SUCCESS;
#endif
}

HIFHE_ERROR Bgv_SetParaFromBSL(CRYPT_BGV_Ctx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    BgvUserPara next;
    BgvUserPara_Init(&next);
    int32_t ret = BgvUserPara_ParseFromBSL(&next, param);
    if (ret != HIFHE_SUCCESS) {
        BgvUserPara_Clear(&next);
        return ret;
    }
    BgvUserPara_Commit(ctx, &next);
    return HIFHE_SUCCESS;
}

#endif

static HIFHE_ERROR BgvUserPara_LoadPresetInto(BgvUserPara *p, int32_t presetId)
{
    BgvPresetPara preset;
    int32_t ret = BGV_Preset_Load(&preset, presetId);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }

    p->polyDegree = preset.polyDegree;
    p->plainModBit = preset.plainModBit;
    p->plainMod = preset.plainMod;
    p->correctionFactor = preset.correctionFactor;
    p->relinDnum = preset.relinDnum;
    p->vetted = preset.vetted;

    if (preset.cipherModBit != NULL && preset.cipherModBitSize > 0) {
        ret = Uint32Vector_Create(&p->cipherModBit, preset.cipherModBit, preset.cipherModBitSize);
        if (ret != HIFHE_SUCCESS) {
            return ret;
        }
    }
    if (preset.cipherMod != NULL && preset.cipherModSize > 0) {
        ret = Uint64Vector_Create(&p->cipherMod, preset.cipherMod, preset.cipherModSize);
        if (ret != HIFHE_SUCCESS) {
            return ret;
        }
    }
    p->set = 1u;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BgvUserPara_LoadPreset(BgvUserPara *p, int32_t presetId)
{
    if (p == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!BgvUserPara_IsEmpty(p)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_BAD_STATE);
        return HIFHE_BAD_STATE;
    }
    int32_t ret = BgvUserPara_LoadPresetInto(p, presetId);
    if (ret != HIFHE_SUCCESS) {
        BgvUserPara_Clear(p);
        BgvUserPara_Init(p);
        return ret;
    }
    return HIFHE_SUCCESS;
}

HIFHE_ERROR Bgv_SetPreset(CRYPT_BGV_Ctx *ctx, int32_t presetId)
{
    if (ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    BgvUserPara next;
    BgvUserPara_Init(&next);
    int32_t ret = BgvUserPara_LoadPreset(&next, presetId);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    BgvUserPara_Commit(ctx, &next);
    return HIFHE_SUCCESS;
}
