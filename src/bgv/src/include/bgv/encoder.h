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

/* Message slots <-> plaintext polynomial. */

#ifndef HIFHE_BGV_ENCODER_H
#define HIFHE_BGV_ENCODER_H

#include <stdint.h>
#include "hifhe_err.h"
#include "bgv/bgv.h"
#include "bgv/plaintext.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    BGVContext *context; /* not owned */
} Encoder;

HIFHE_ERROR BGV_Encoder_Create(Encoder *out, BGVContext *ctx);
HIFHE_ERROR BGV_Encoder_Destroy(Encoder *self);

/* msg[0..slotCount), each < plainMod. slotCount == polyDegree. The plaintext
 * holds every coefficient as its centred representative in (-t/2, t/2]. */
HIFHE_ERROR BGV_Encoder_Encode(Plaintext *out, const uint64_t *msg, uint32_t slotCount, const Encoder *self);

HIFHE_ERROR BGV_Encoder_Decode(uint64_t *msg, uint32_t slotCount, const Plaintext *pt, const Encoder *self);

/* Write coefficients coeff[0..N), each in [0, t), to every limb of `out` as
 * the residues of their centred representative: c for c <= t/2, else c - t,
 * i.e. q_i - (t - c). Requires t < q_i. `coeff` may be limb 0 of `out`. */
void BGV_Encoder_LiftCentred(uint64_t *out, const uint64_t *coeff, const RnsBase *base, uint32_t N, Modulus t);

/* out[j] = centred CRT reconstruction of data[.. j] over `base`, mod t.
 * `data` holds base->size coefficient-form limbs of N words each. */
HIFHE_ERROR BGV_Encoder_CrtCenteredModT(uint64_t *out, const uint64_t *data, const RnsBase *base, uint32_t N,
                                        Modulus t);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_ENCODER_H */
