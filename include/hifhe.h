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

#ifndef HIFHE_H
#define HIFHE_H
#include <stdint.h>
#ifdef HITLS_PROVIDER
#include "crypt_eal_provider.h"
#endif
#include "hifhe_err.h"
#include "hifhe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

HIFHE_Ctx *HIFHE_New(int32_t algId);
void HIFHE_Free(HIFHE_Ctx *ctx);
int32_t HIFHE_SetParaById(HIFHE_Ctx *ctx, int32_t paramId);
int32_t HIFHE_Ctrl(HIFHE_Ctx *ctx, int32_t cmd, HIFHE_HEText *text, void *value, uint32_t valueLen);
int32_t HIFHE_KeyGen(HIFHE_Ctx *ctx);
void HIFHE_HETextFree(HIFHE_HEText *object);

int32_t HIFHE_Encode(const HIFHE_Ctx *ctx, const uint32_t *values, uint32_t count, HIFHE_HEText **out);
int32_t HIFHE_Encrypt(HIFHE_Ctx *ctx, const HIFHE_HEText *plaintext, HIFHE_HEText **ciphertext);
int32_t HIFHE_Add(const HIFHE_Ctx *ctx, const HIFHE_HEText *para1, const HIFHE_HEText *para2, HIFHE_HEText **out);
int32_t HIFHE_Mul(const HIFHE_Ctx *ctx, const HIFHE_HEText *para1, const HIFHE_HEText *para2, HIFHE_HEText **out);
int32_t HIFHE_Decrypt(HIFHE_Ctx *ctx, const HIFHE_HEText *ciphertext, HIFHE_HEText **plaintext);
int32_t HIFHE_Decode(const HIFHE_Ctx *ctx, const HIFHE_HEText *plaintext, uint32_t *values, uint32_t *count);

int32_t HIFHE_Serialize(const HIFHE_Ctx *ctx, const HIFHE_HEText *object, uint8_t *out, uint32_t *outLen);
int32_t HIFHE_Deserialize(const HIFHE_Ctx *ctx, const uint8_t *data, uint32_t dataLen, HIFHE_HEText **object);

#ifdef HITLS_PROVIDER
int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param, CRYPT_EAL_Func *capFuncs,
                               CRYPT_EAL_Func **outFuncs, void **provCtx);
#endif

#ifdef __cplusplus
}
#endif
#endif
