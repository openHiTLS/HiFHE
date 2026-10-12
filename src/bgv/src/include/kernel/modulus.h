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

/* Modulus type and modular arithmetic primitives. */

#ifndef HIFHE_KERNEL_MODULUS_H
#define HIFHE_KERNEL_MODULUS_H

#include <stdint.h>
#include <stddef.h>
#include "hifhe_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t Modulus;

/* Wide multiplication carrier. */
#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 ModulusWide;
#else
#  error "requires a compiler with __int128 support (GCC/Clang)."
#endif

/* Barrett constant: ratio = floor(2^128 / q), kept as two words.
 * Populated at BGVContext build time. */
typedef struct {
    Modulus  q;
    uint64_t ratioLo;   /* low  64 bits of floor(2^128 / q) */
    uint64_t ratioHi;   /* high 64 bits */
    uint32_t qBits;     /* ceil(log2(q)); useful for lazy-reduction bounds */
} BarrettConst;

/* Shoup constant: quotient = floor((m << 64) / q). Turns mul-mod into one
 * 128-bit mul plus a conditional subtraction. Populated lazily per (m, q). */
typedef struct {
    Modulus  q;
    uint64_t operand;
    uint64_t quotient;
} ShoupConst;

HIFHE_ERROR Kernel_BarrettConst_Init(BarrettConst *out, Modulus q);
uint64_t   Kernel_BarrettReduce64  (uint64_t x, const BarrettConst *bc);
uint64_t   Kernel_BarrettReduce128 (uint64_t xHi, uint64_t xLo, const BarrettConst *bc);

HIFHE_ERROR Kernel_ShoupConst_Init  (ShoupConst *out, uint64_t operand, Modulus q);
uint64_t   Kernel_ShoupMulMod      (uint64_t x, const ShoupConst *sc);

/* Straightforward mul-mod, no precomputation. Uses ModulusWide internally. */
uint64_t   Kernel_MulMod           (uint64_t a, uint64_t b, Modulus q);

/* a^e mod q via square-and-multiply. */
uint64_t   Kernel_PowMod           (uint64_t a, uint64_t e, Modulus q);

/* Extended Euclid. Returns 0 when gcd(a, q) != 1. For the moduli shipped
 * here (primes, or t coprime to q) 0 always means failure. */
uint64_t   Kernel_ModInv           (uint64_t a, Modulus q);

/* ceil(log2(x)), the bit count of x - 1. 0 for x <= 1. */
uint32_t   Kernel_Log2Ceil         (uint64_t x);


/* Inline bodies of the reductions above, for hot loops. The exported
 * functions wrap these; without LTO a cross-file call per coefficient costs
 * more than the arithmetic. */
static inline uint64_t Kernel_BarrettReduce64Inl(uint64_t x, const BarrettConst *bc)
{
    ModulusWide acc = (ModulusWide)x * (ModulusWide)bc->ratioHi;
    acc += ((ModulusWide)x * (ModulusWide)bc->ratioLo) >> 64;
    uint64_t qhat = (uint64_t)(acc >> 64);
    uint64_t r = x - qhat * bc->q;
    while (r >= bc->q) r -= bc->q;
    return r;
}

static inline uint64_t Kernel_BarrettReduce128Inl(uint64_t xHi, uint64_t xLo,
                                                  const BarrettConst *bc)
{
    ModulusWide acc = (ModulusWide)xHi * (ModulusWide)bc->ratioHi;
    acc += ((ModulusWide)xHi * (ModulusWide)bc->ratioLo) >> 64;
    acc += ((ModulusWide)xLo * (ModulusWide)bc->ratioHi) >> 64;
    uint64_t qhat = (uint64_t)acc;
    uint64_t r = xLo - qhat * bc->q;
    while (r >= bc->q) r -= bc->q;
    return r;
}

/* a * b mod q through the Barrett constant; a, b < q. */
static inline uint64_t Kernel_BarrettMulModInl(uint64_t a, uint64_t b, const BarrettConst *bc)
{
    ModulusWide p = (ModulusWide)a * (ModulusWide)b;
    return Kernel_BarrettReduce128Inl((uint64_t)(p >> 64), (uint64_t)p, bc);
}

static inline uint64_t Kernel_ShoupMulModInl(uint64_t x, const ShoupConst *sc)
{
    uint64_t qHat = (uint64_t)(((ModulusWide)x * (ModulusWide)sc->quotient) >> 64);
    uint64_t r = x * sc->operand - qHat * sc->q;
    if (r >= sc->q) r -= sc->q;
    return r;
}

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_KERNEL_MODULUS_H */
