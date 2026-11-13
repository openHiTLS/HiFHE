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

/* Preset tables. Cipher-mod bit slices are static const; BGV_Preset_Load
 * returns pointers into them (loader-owned, do not free). */

#include <stddef.h>
#include "hifhe_err_internal.h"
#include "hifhe_types.h"
#include "hifhe_err.h"
#include "bgv/params_preset.h"
#include "bgv/bgv.h"

/* ---- 2048 / 48-bit single-slice presets ---- */
static const uint32_t kCipherBits_2048_48[] = {48u};
/* The default preset names its modulus rather than taking whatever the Proth
 * walk reaches first, so the ring is fixed by the header and not by the
 * search's starting point. 48 bits, 1 mod 4096, inside the 54-bit budget
 * that N=2048 has at the 128-bit level. */
static const uint64_t kCipherMod_default[] = {140786965118977ull};
/* The moduli every other preset resolves to. They are the primes the Proth
 * search returns for the bit widths beside them, written out so that a
 * context built from a preset searches and validates nothing; the custom
 * parameter path still searches, and the preset SDV case checks that the
 * search and these tables agree. */
static const uint64_t kCipherMod_2048_48[] = {281474976694273ull};
/* ---- 4096 / 2 x 44-bit chain ---- */
static const uint32_t kCipherBits_4096_44x2[] = {44u, 44u};
static const uint64_t kCipherMod_4096_44x2[] = {17592186028033ull, 17592185659393ull};
/* ---- 8192 / 4-limb chain. Widths are 43,43,44,44 rather than a flat 44:
 * this is the chain the "44x4" preset has always carried, and the name is
 * kept so an existing caller's preset id still means the same ring. ---- */
static const uint32_t kCipherBits_8192_44x4[] = {43u, 43u, 44u, 44u};
static const uint64_t kCipherMod_8192_44x4[] = {8796092858369ull, 8796092792833ull, 17592186028033ull,
                                                17592185438209ull};
/* Proth primes of 17 and 20 bits for N = 2048 and 8192, as the search finds them. */
#define PLAIN_MOD_17BIT_2048 114689ull
#define PLAIN_MOD_20BIT_8192 1032193ull

#define PRESET_CHAIN(o, bits, mods)                                          \
    do {                                                                     \
        (o)->cipherModBit = (bits);                                          \
        (o)->cipherModBitSize = (uint32_t)(sizeof(bits) / sizeof((bits)[0])); \
        (o)->cipherMod = (mods);                                             \
        (o)->cipherModSize = (uint32_t)(sizeof(mods) / sizeof((mods)[0]));   \
    } while (0)

HIFHE_ERROR BGV_Preset_Load(BgvPresetPara *out, int32_t presetId)
{
    if (out == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    /* Zero the struct so callers reading un-set fields see 0. */
    out->polyDegree = 0u;
    out->plainModBit = 0u;
    out->plainMod = 0ull;
    out->correctionFactor = HIFHE_BGV_DEFAULT_CORRECTION_FACTOR;
    out->relinDnum = HIFHE_BGV_DEFAULT_RELIN_DNUM;
    out->cipherModBit = NULL;
    out->cipherModBitSize = 0u;
    out->cipherMod = NULL;
    out->cipherModSize = 0u;
    out->vetted = 1u;

    switch (presetId) {
        case HIFHE_BGV_DEFAULT:
            out->polyDegree = 2048u;
            out->plainModBit = 17u;
            out->plainMod = PLAIN_MOD_17BIT_2048;
            PRESET_CHAIN(out, kCipherBits_2048_48, kCipherMod_default);
            return HIFHE_SUCCESS;

        case HIFHE_BGV_2048_48:
            out->polyDegree = 2048u;
            out->plainModBit = 17u;
            out->plainMod = PLAIN_MOD_17BIT_2048;
            PRESET_CHAIN(out, kCipherBits_2048_48, kCipherMod_2048_48);
            return HIFHE_SUCCESS;

        case HIFHE_BGV_8192_44x4:
            out->polyDegree = 8192u;
            out->plainModBit = 20u;
            out->plainMod = PLAIN_MOD_20BIT_8192;
            PRESET_CHAIN(out, kCipherBits_8192_44x4, kCipherMod_8192_44x4);
            return HIFHE_SUCCESS;

        case HIFHE_BGV_2048_48_17BIT:
            /* F4 = 65537 bypasses the Proth search. NTT-friendly for
         * polyDegree <= 32768, since 65536 = 2^16. */
            out->polyDegree = 2048u;
            out->plainModBit = 17u;
            out->plainMod = 65537ull;
            PRESET_CHAIN(out, kCipherBits_2048_48, kCipherMod_2048_48);
            return HIFHE_SUCCESS;

        case HIFHE_BGV_4096_44x2_17BIT:
            out->polyDegree = 4096u;
            out->plainModBit = 17u;
            out->plainMod = 65537ull;
            PRESET_CHAIN(out, kCipherBits_4096_44x2, kCipherMod_4096_44x2);
            return HIFHE_SUCCESS;

        case HIFHE_BGV_8192_44x4_17BIT:
            /* Same ring as HIFHE_BGV_8192_44x4, with the plaintext modulus
         * pinned to 65537 instead of Proth-searched. */
            out->polyDegree = 8192u;
            out->plainModBit = 17u;
            out->plainMod = 65537ull;
            PRESET_CHAIN(out, kCipherBits_8192_44x4, kCipherMod_8192_44x4);
            return HIFHE_SUCCESS;

        default:
            HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_ID_INVALID);
            return HIFHE_PARAM_ID_INVALID;
    }
}
