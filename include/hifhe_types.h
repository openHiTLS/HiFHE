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

#ifndef HIFHE_TYPES_H
#define HIFHE_TYPES_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HIFHE_Ctx HIFHE_Ctx;
typedef struct HIFHE_HEText HIFHE_HEText;

typedef enum {
    HIFHE_BGV = (int32_t)0x89000002u,
    HIFHE_CKKS = (int32_t)0x89000001u,
} HIFHE_ALG_ID;

#ifdef HITLS_PROVIDER
/* Provider attribute, passed to CRYPT_EAL_ProviderPkeyNewCtx. */
#define HIFHE_PROVIDER_ATTR "provider=hifhe"

#define HIFHE_PARAM_BASE             100000
#define HIFHE_PARAM_CKKS_N           (HIFHE_PARAM_BASE + 1)
#define HIFHE_PARAM_CKKS_Q_BITS      (HIFHE_PARAM_BASE + 2)
#define HIFHE_PARAM_CKKS_P_BITS      (HIFHE_PARAM_BASE + 3)
#define HIFHE_PARAM_CKKS_SIGMA_MILLI (HIFHE_PARAM_BASE + 4)
#define HIFHE_PARAM_CKKS_SLOTS       (HIFHE_PARAM_BASE + 5)

#define HIFHE_PARAM_BGV_BASE      (HIFHE_PARAM_BASE + 100)
#define HIFHE_PARAM_BGV_MSG       (HIFHE_PARAM_BGV_BASE + 8)
#define HIFHE_PARAM_BGV_NEGATE    (HIFHE_PARAM_BGV_BASE + 9)
#define HIFHE_PARAM_BGV_PLAINTEXT (HIFHE_PARAM_BGV_BASE + 11)
#endif

#define HIFHE_PRESET_BGV_BASE 100000

typedef enum {
    HIFHE_BGV_DEFAULT = HIFHE_PRESET_BGV_BASE + 0, /* = HIFHE_BGV_2048_48 */
    HIFHE_BGV_2048_48 = HIFHE_PRESET_BGV_BASE + 1,
    HIFHE_BGV_8192_44x4 = HIFHE_PRESET_BGV_BASE + 2,
    /* 2048, 48-bit cipher, plainMod 65537. */
    HIFHE_BGV_2048_48_17BIT = HIFHE_PRESET_BGV_BASE + 3,
    /* 4096, 2 x 44-bit, plainMod 65537. */
    HIFHE_BGV_4096_44x2_17BIT = HIFHE_PRESET_BGV_BASE + 4,
    /* 8192, 4 x 44-bit, plainMod 65537. */
    HIFHE_BGV_8192_44x4_17BIT = HIFHE_PRESET_BGV_BASE + 5,
} HIFHE_BGV_PRESET;

typedef enum {
    HIFHE_CTRL_BGV_RERANDOMIZE = 100001,
    HIFHE_CTRL_BGV_SET_NEGATE = 100002,
    HIFHE_CTRL_BGV_SET_LUT_CACHE = 100003,
    HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN = 100004,
    HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN = 100005,
    HIFHE_CTRL_BGV_GET_POLY_DEGREE = 100006,
    HIFHE_CTRL_BGV_SET_SEED = 100007,
} HIFHE_CMD;

#ifdef __cplusplus
}
#endif
#endif
