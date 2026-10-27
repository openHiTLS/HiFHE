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
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include "hifhe.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
#include "crypt_params_key.h"
#include "crypt_errno.h"
#include "test.h"
/* END_HEADER */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_PROVIDER_TC001(void)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *cipher = NULL;
    bool loaded = false;
    const char *path = getenv("HIFHE_PROVIDER_PATH");

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL), HIFHE_SUCCESS);
    ASSERT_TRUE(path != NULL);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(NULL, path), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe", NULL, NULL), HIFHE_SUCCESS);
    loaded = true;
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_CKKS, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    ASSERT_TRUE(ctx != NULL);
    uint32_t n = 16, q = 50, p = 20, sigma = 3200, slots = 4;
    BSL_Param values[] = {{HIFHE_PARAM_CKKS_N, BSL_PARAM_TYPE_UINT32, &n, 4, 0},
                          {HIFHE_PARAM_CKKS_Q_BITS, BSL_PARAM_TYPE_UINT32, &q, 4, 0},
                          {HIFHE_PARAM_CKKS_P_BITS, BSL_PARAM_TYPE_UINT32, &p, 4, 0},
                          {HIFHE_PARAM_CKKS_SIGMA_MILLI, BSL_PARAM_TYPE_UINT32, &sigma, 4, 0},
                          {HIFHE_PARAM_CKKS_SLOTS, BSL_PARAM_TYPE_UINT32, &slots, 4, 0},
                          BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(ctx, values), HIFHE_SUCCESS);
    uint32_t bits = UINT32_MAX;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_BITS, &bits, sizeof(bits)), HIFHE_NOT_SUPPORTED);
    ASSERT_EQ(bits, UINT32_MAX);
    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyBits(ctx), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyLen(ctx), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);
    double complex input[] = {1.25 + 2.5 * I, -3.0 + 0.5 * I};
    uint32_t len = 0;
    double complex invalid = NAN + 0.0 * I;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, (const uint8_t *)&invalid, sizeof(invalid), NULL, &len), HIFHE_PARAM_INVALID);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, (const uint8_t *)input, sizeof(input), NULL, &len), HIFHE_BUFFER_TOO_SMALL);
    cipher = malloc(len);
    ASSERT_TRUE(cipher != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, (const uint8_t *)input, sizeof(input), cipher, &len), HIFHE_SUCCESS);
    double complex output[4];
    uint32_t outLen = sizeof(output);
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, cipher, len, (uint8_t *)output, &outLen), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < 4; i++) {
        ASSERT_TRUE(cabs(output[i] - (i < 2 ? input[i] : 0)) < 0.005);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    free(cipher);
    if (loaded) {
        if (CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe") != HIFHE_SUCCESS) {
            RecordFailure("CRYPT_EAL_ProviderUnload", __FILE__);
        }
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
}
/* END_CASE */
