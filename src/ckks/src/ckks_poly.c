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

#include "crypt_ckks.h"
#include "ckks_local.h"
#include "hifhe_mem.h"
#include "hifhe_err_internal.h"
#include "crypt_bn.h"
#include "hifhe_err.h"
#include <math.h>

CRYPT_CKKS_Poly *CKKS_NewPoly(uint32_t N)
{
    CRYPT_CKKS_Poly *poly = (CRYPT_CKKS_Poly *)HifheMalloc(sizeof(CRYPT_CKKS_Poly));
    if (poly == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return NULL;
    }

    poly->N = N;
    poly->coeffs = (BN_BigNum **)HifheCalloc(N, sizeof(BN_BigNum *));
    if (poly->coeffs == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        HifheFree(poly);
        return NULL;
    }

    for (uint32_t i = 0; i < N; i++) {
        poly->coeffs[i] = BN_Create(CKKS_BN_WORK_BITS);
        if (poly->coeffs[i] == NULL) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
            CKKS_FreePoly(poly);
            return NULL;
        }
    }

    return poly;
}

void CKKS_FreePoly(CRYPT_CKKS_Poly *poly)
{
    if (poly == NULL) {
        return;
    }
    if (poly->coeffs != NULL) {
        for (uint32_t i = 0; i < poly->N; i++) {
            BN_Destroy(poly->coeffs[i]);
        }
        HifheFree(poly->coeffs);
    }
    HifheFree(poly);
}

void CKKS_CoeffsDestroy(BN_BigNum **coeffs, uint32_t N)
{
    if (coeffs == NULL) {
        return;
    }
    for (uint32_t i = 0; i < N; i++) {
        BN_Destroy(coeffs[i]);
    }
    HifheFree(coeffs);
}

int32_t CKKS_RandDouble(void *libCtx, double *r)
{
    BN_BigNum *rand = BN_Create(64);
    if (rand == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    int32_t ret = BN_RandEx(libCtx, rand, 53, BN_RAND_TOP_NOBIT, BN_RAND_BOTTOM_ONEBIT);
    if (ret != HIFHE_SUCCESS) {
        BN_Destroy(rand);
        HIFHE_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *r = (double)BN_GetLimb(rand) / 9007199254740992.0;

    BN_Destroy(rand);
    return ret;
}

int32_t CKKS_SampleGauss(void *libCtx, BN_BigNum **coeffs, uint32_t N, double sigma, const BN_BigNum *Q,
                         BN_Optimizer *optimizer)
{
    if (coeffs == NULL || Q == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    /* With sigma 3.2 and r2 >= 2^-53, rounded samples fit even a 32-bit long. */
    if (sigma != CKKS_DEFAULT_SIGMA) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_INVALID_ARGUMENT);
        return HIFHE_INVALID_ARGUMENT;
    }

    int32_t ret = HIFHE_SUCCESS;
    double r1;
    double r2;
    double theta;
    double rr;
    long x1;
    long x2;

    for (uint32_t i = 0; i < N; i += 2) {
        ret = CKKS_RandDouble(libCtx, &r1);
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ret = CKKS_RandDouble(libCtx, &r2);
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }

        if (r1 <= 0.0) {
            r1 = 1e-12; // Prevent log(0)
        }
        if (r2 <= 0.0) {
            r2 = 1e-12;
        }

        theta = 2.0 * CKKS_PI * r1;
        rr = sqrt(-2.0 * log(r2)) * sigma;

        x1 = (long)floor(rr * cos(theta) + 0.5);
        x2 = (long)floor(rr * sin(theta) + 0.5);

        ret = BN_SetLimb(coeffs[i], (BN_UINT)labs(x1));
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }

        ret = BN_SetSign(coeffs[i], (x1 < 0));
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }

        if (i + 1 < N) {
            ret = BN_SetLimb(coeffs[i + 1], (BN_UINT)labs(x2));
            if (ret != HIFHE_SUCCESS) {
                HIFHE_ERR_PUSH_ERROR(ret);
                return ret;
            }

            ret = BN_SetSign(coeffs[i + 1], (x2 < 0));
            if (ret != HIFHE_SUCCESS) {
                HIFHE_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }

        for (uint32_t j = i; j < i + 2 && j < N; j++) {
            if (!BN_IsZero(coeffs[j])) {
                ret = BN_Mod(coeffs[j], coeffs[j], Q, optimizer);
                if (ret != HIFHE_SUCCESS) {
                    HIFHE_ERR_PUSH_ERROR(ret);
                    return ret;
                }
            }
        }
    }

    return ret;
}

int32_t CKKS_SampleUniform(void *libCtx, BN_BigNum **coeffs, uint32_t N, const BN_BigNum *Q)
{
    if (coeffs == NULL || Q == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t ret = HIFHE_SUCCESS;
    uint32_t qBits = BN_Bits(Q);

    for (uint32_t i = 0; i < N; i++) {
        ret = BN_RandEx(libCtx, coeffs[i], qBits, 0, 0);
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return HIFHE_SUCCESS;
}

int32_t CKKS_SampleTernary(void *libCtx, BN_BigNum **coeffs, uint32_t N)
{
    if (coeffs == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }

    int32_t ret = HIFHE_SUCCESS;
    uint32_t randVal;

    BN_BigNum *rand = BN_Create(8);
    if (rand == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }

    for (uint32_t i = 0; i < N; i++) {
        ret = BN_RandEx(libCtx, rand, 2, 0, 0); // 2 bits random
        if (ret != HIFHE_SUCCESS) {
            BN_Destroy(rand);
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }

        randVal = (uint32_t)BN_GetLimb(rand) & 0x3; // Get 2 bits
        if ((randVal & 1) == 0) { // 00,01 ?? 0
            ret = BN_SetLimb(coeffs[i], 0);
            if (ret != HIFHE_SUCCESS) {
                HIFHE_ERR_PUSH_ERROR(ret);
                return ret;
            }
        } else if ((randVal & 2) == 0) { // 10 ?? +1
            ret = BN_SetLimb(coeffs[i], 1);
            if (ret != HIFHE_SUCCESS) {
                HIFHE_ERR_PUSH_ERROR(ret);
                return ret;
            }
            ret = BN_SetSign(coeffs[i], false);
            if (ret != HIFHE_SUCCESS) {
                HIFHE_ERR_PUSH_ERROR(ret);
                return ret;
            }
        } else { // 11 ?? -1
            ret = BN_SetLimb(coeffs[i], 1);
            if (ret != HIFHE_SUCCESS) {
                HIFHE_ERR_PUSH_ERROR(ret);
                return ret;
            }
            ret = BN_SetSign(coeffs[i], true);
            if (ret != HIFHE_SUCCESS) {
                HIFHE_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
    }
    BN_Destroy(rand);
    return HIFHE_SUCCESS;
}

int32_t CKKS_PolyAdd(BN_BigNum **result, BN_BigNum **a, BN_BigNum **b, uint32_t N, const BN_BigNum *Q,
                     BN_Optimizer *optimizer)
{
    if (result == NULL || a == NULL || b == NULL || Q == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t ret = HIFHE_SUCCESS;

    for (uint32_t i = 0; i < N; i++) {
        ret = BN_Add(result[i], a[i], b[i]);
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }

        ret = BN_Mod(result[i], result[i], Q, optimizer);
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return HIFHE_SUCCESS;
}

int32_t CKKS_PolySub(BN_BigNum **result, BN_BigNum **a, BN_BigNum **b, uint32_t N, const BN_BigNum *Q,
                     BN_Optimizer *optimizer)
{
    if (result == NULL || a == NULL || b == NULL || Q == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t ret = HIFHE_SUCCESS;

    for (uint32_t i = 0; i < N; i++) {
        ret = BN_Sub(result[i], a[i], b[i]);
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }

        ret = BN_Mod(result[i], result[i], Q, optimizer);
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return HIFHE_SUCCESS;
}

int32_t CKKS_PolyMult(BN_BigNum **result, BN_BigNum **a, BN_BigNum **b, uint32_t N, const BN_BigNum *Q,
                      BN_Optimizer *optimizer)
{
    if (result == NULL || a == NULL || b == NULL || Q == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }

    int32_t ret = HIFHE_SUCCESS;
    uint32_t idx;

    for (uint32_t i = 0; i < N; i++) {
        ret = BN_SetLimb(result[i], 0);
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    BN_BigNum *temp = BN_Create(CKKS_BN_WORK_BITS);
    if (temp == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }

    for (uint32_t i = 0; i < N; i++) {
        for (uint32_t j = 0; j < N; j++) {
            ret = BN_Mul(temp, a[i], b[j], optimizer);
            if (ret != HIFHE_SUCCESS) {
                BN_Destroy(temp);
                HIFHE_ERR_PUSH_ERROR(ret);
                return ret;
            }

            idx = (i + j) % N;
            if (i + j >= N) {
                // X^N = -1, so X^(N+k) = -X^k
                ret = BN_Sub(result[idx], result[idx], temp);
                if (ret != HIFHE_SUCCESS) {
                    BN_Destroy(temp);
                    HIFHE_ERR_PUSH_ERROR(ret);
                    return ret;
                }
            } else {
                ret = BN_Add(result[idx], result[idx], temp);
                if (ret != HIFHE_SUCCESS) {
                    BN_Destroy(temp);
                    HIFHE_ERR_PUSH_ERROR(ret);
                    return ret;
                }
            }
        }
    }
    BN_Destroy(temp);

    for (uint32_t i = 0; i < N; i++) {
        ret = BN_Mod(result[i], result[i], Q, optimizer);
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return HIFHE_SUCCESS;
}

int32_t CKKS_PolyMultByConst(BN_BigNum **result, BN_BigNum **a, const BN_BigNum *c, uint32_t N, const BN_BigNum *Q,
                             BN_Optimizer *optimizer)
{
    if (result == NULL || a == NULL || c == NULL || Q == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t ret = HIFHE_SUCCESS;

    for (uint32_t i = 0; i < N; i++) {
        ret = BN_Mul(result[i], a[i], c, optimizer);
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ret = BN_Mod(result[i], result[i], Q, optimizer);
        if (ret != HIFHE_SUCCESS) {
            HIFHE_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return HIFHE_SUCCESS;
}

int32_t CKKS_PolyToBytes(BN_BigNum **coeffs, uint32_t N, uint8_t *out, uint32_t *outLen)
{
    if (coeffs == NULL || outLen == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }

    int32_t ret = HIFHE_SUCCESS;
    uint32_t totalLen = 0;
    uint32_t maxLen = *outLen;
    uint32_t coeffLen = 0;

    for (uint32_t i = 0; i < N; i++) {
        coeffLen = BN_Bytes(coeffs[i]);
        totalLen += coeffLen + 4; // 4 bytes for length prefix
    }

    if (out == NULL || totalLen > maxLen) {
        *outLen = totalLen;
        return HIFHE_BUFFER_TOO_SMALL;
    }

    uint32_t offset = 0;
    uint32_t actualLen = 0;
    for (uint32_t i = 0; i < N; i++) {
        coeffLen = BN_Bytes(coeffs[i]);

        // Write length (4 bytes, little-endian)
        uint32_t encodedLen = coeffLen | (BN_IsNegative(coeffs[i]) ? 0x80000000u : 0);
        out[offset] = (uint8_t)(encodedLen & 0xFF);
        out[offset + 1] = (uint8_t)((encodedLen >> 8) & 0xFF);
        out[offset + 2] = (uint8_t)((encodedLen >> 16) & 0xFF);
        out[offset + 3] = (uint8_t)((encodedLen >> 24) & 0xFF);
        offset += 4;

        if (coeffLen > 0) {
            actualLen = coeffLen;
            ret = BN_Bn2Bin(coeffs[i], out + offset, &actualLen);
            if (ret != HIFHE_SUCCESS) {
                HIFHE_ERR_PUSH_ERROR(ret);
                return ret;
            }
            offset += actualLen;
        }
    }

    *outLen = offset;
    return HIFHE_SUCCESS;
}

int32_t CKKS_CheckPolyBytes(const uint8_t *data, uint32_t dataLen, uint32_t N, uint32_t bits, bool allowNegative)
{
    if (data == NULL) {
        return HIFHE_NULL_INPUT;
    }
    if (N == 0 || N > CKKS_MAX_N || bits == 0 || bits > CKKS_MAX_LOGQ + 1) {
        return HIFHE_INVALID_ARGUMENT;
    }
    uint32_t width = (bits + 7) / 8;
    if (dataLen < N * 4 || dataLen > N * (4 + width)) {
        return HIFHE_DECODE_ERROR;
    }
    uint32_t offset = 0;
    for (uint32_t i = 0; i < N; i++) {
        if (dataLen - offset < 4) {
            return HIFHE_DECODE_ERROR;
        }
        uint32_t size = (uint32_t)data[offset] | ((uint32_t)data[offset + 1] << 8) |
            ((uint32_t)data[offset + 2] << 16) | ((uint32_t)data[offset + 3] << 24);
        offset += 4;
        bool negative = (size & 0x80000000u) != 0;
        size &= 0x7fffffffu;
        if (size > width || size > dataLen - offset || (negative && (!allowNegative || size == 0))) {
            return HIFHE_DECODE_ERROR;
        }
        if (size != 0 && (data[offset] == 0 ||
            (size == width && bits % 8 != 0 && data[offset] >= (1u << (bits % 8))))) {
            return HIFHE_DECODE_ERROR;
        }
        offset += size;
    }
    return offset == dataLen ? HIFHE_SUCCESS : HIFHE_DECODE_ERROR;
}

int32_t CKKS_BytesToPoly(const uint8_t *data, uint32_t dataLen, BN_BigNum **coeffs, uint32_t N, uint32_t bits,
    bool allowNegative)
{
    if (data == NULL || coeffs == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }

    int32_t ret = CKKS_CheckPolyBytes(data, dataLen, N, bits, allowNegative);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    uint32_t offset = 0;
    uint32_t coeffLen = 0;
    uint32_t i = 0;

    for (i = 0; i < N; i++) {
        coeffLen = (uint32_t)data[offset] | ((uint32_t)data[offset + 1] << 8) | ((uint32_t)data[offset + 2] << 16) |
                   ((uint32_t)data[offset + 3] << 24);
        offset += 4;
        bool negative = (coeffLen & 0x80000000u) != 0;
        coeffLen &= 0x7fffffffu;

        if (coeffLen > 0) {
            ret = BN_Bin2Bn(coeffs[i], data + offset, coeffLen);
            if (ret != HIFHE_SUCCESS) {
                HIFHE_ERR_PUSH_ERROR(ret);
                return ret;
            }
            ret = BN_SetSign(coeffs[i], negative);
            if (ret != HIFHE_SUCCESS) {
                return ret;
            }
            offset += coeffLen;
        } else {
            ret = BN_SetLimb(coeffs[i], 0);
            if (ret != HIFHE_SUCCESS) {
                HIFHE_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
    }

    return ret;
}
