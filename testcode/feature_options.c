/*
 * Copyright (c) 2026 openHiTLS. All Rights Reserved.
 * HiFHE is licensed under Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 */

#include "hifhe_config.h"
#include "hifhe.h"
#include "bgv_local.h"

int main(void)
{
    HIFHE_Ctx *ctx = HIFHE_New(HIFHE_BGV);
    if (ctx == NULL) {
        return 1;
    }
    uint32_t format = HIFHE_WIRE_INTERCHANGE;
    int32_t ret = HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_SET_WIRE_FORMAT, NULL, &format, sizeof(format));
    HIFHE_Free(ctx);
    if (ret != HIFHE_NOT_SUPPORTED || Bgv_GenRelinKey(NULL) != HIFHE_NOT_SUPPORTED ||
        Bgv_GenGaloisKeys(NULL, NULL, 0) != HIFHE_NOT_SUPPORTED ||
        BGV_BGVContext_EnsureSlotMap(NULL) != HIFHE_NOT_SUPPORTED) {
        return 1;
    }
    CRYPT_BGV_Ctx *bgv = CRYPT_BGV_NewCtx(HIFHE_BGV);
    if (bgv == NULL) {
        return 1;
    }
#ifdef HITLS_PROVIDER
    BSL_Param params[] = {BSL_PARAM_END};
    uint32_t value = 0u;
    if (CRYPT_BGV_SetParaEx(bgv, params) != HIFHE_PARAM_INVALID ||
        CRYPT_BGV_Ctrl(bgv, HIFHE_CTRL_BGV_GEN_RELIN_KEY, &value, sizeof(value)) != HIFHE_NOT_SUPPORTED ||
        CRYPT_BGV_Ctrl(bgv, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, &value, sizeof(value)) != HIFHE_NOT_SUPPORTED ||
        CRYPT_BGV_Ctrl(bgv, HIFHE_CTRL_BGV_SET_SLOT_MAP, &value, sizeof(value)) != HIFHE_NOT_SUPPORTED ||
        CRYPT_BGV_Ctrl(bgv, HIFHE_CTRL_BGV_GET_RELIN_KEY_LEN, &value, sizeof(value)) != HIFHE_NOT_SUPPORTED) {
        CRYPT_BGV_FreeCtx(bgv);
        return 1;
    }
#endif
    ret = BgvUserPara_LoadPreset(&bgv->para, HIFHE_BGV_2048_48_17BIT);
    /* An unvetted parameter bag takes the custom-parameter build path. */
    bgv->para.vetted = 0u;
    int ok = ret == HIFHE_SUCCESS && Bgv_BuildContext(bgv) == HIFHE_PARAM_INVALID &&
        !bgv->bgv.haveContext;
    CRYPT_BGV_FreeCtx(bgv);
    return ok ? 0 : 1;
}
