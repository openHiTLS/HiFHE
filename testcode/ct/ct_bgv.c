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

/* Focused data-dependency probes. This is regression evidence, not a proof
 * of constant time for the library or its cryptographic dependencies. */
#define _POSIX_C_SOURCE 200809L
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef HIFHE_CT_VALGRIND
#include <valgrind/memcheck.h>
#define SECRET(p, n) ((void)VALGRIND_MAKE_MEM_UNDEFINED((p), (n)))
#define PUBLIC(p, n) ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))
#else
#define SECRET(p, n) ((void)0)
#define PUBLIC(p, n) ((void)0)
#endif
#include "crypt_eal_init.h"
#include "bgv_local.h"
#include "bgv/encoder.h"
#include "bgv/encryptor.h"
#include "kernel/sampler.h"
#include "rlwe/crt_ops.h"

#define CHECK(expr) do { if ((expr) != HIFHE_SUCCESS) { \
    fprintf(stderr, "failed at line %d\n", __LINE__); exit(1); } } while (0)

static void Probe(void)
{
    CRYPT_BGV_Ctx *ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    if (ctx == NULL) {
        exit(1);
    }
    CHECK(Bgv_SetPreset(ctx, HIFHE_BGV_4096_44x2_17BIT));
    CHECK(Bgv_Gen(ctx));
    BGVContext *bc = &ctx->bgv.context;
    uint32_t n = bc->rlweContext.parameter->polyDegree;
    uint32_t words = n * bc->rlweContext.cipherRnsBase.size;
    uint64_t *v = calloc(words, sizeof(*v));
    uint64_t *z = calloc(words, sizeof(*z));
    int64_t *small = calloc(n, sizeof(*small));
    if (v == NULL || z == NULL || small == NULL) {
        exit(1);
    }
    for (uint32_t i = 0; i < words; ++i) {
        v[i] = i * 7919u;
    }
    SECRET(v, words * sizeof(*v));
    CHECK(Kernel_Ntt_Forward(v, &bc->rlweContext.nttTables[0]));
    CHECK(Kernel_Ntt_Inverse(v, &bc->rlweContext.nttTables[0]));
    CHECK(BGV_Encoder_CrtCenteredModT(z, v, &bc->rlweContext.cipherRnsBase, n, 65537u));
    BGV_Encoder_LiftCentred(v, z, &bc->rlweContext.cipherRnsBase, n, 65537u);
    PUBLIC(v, words * sizeof(*v));
    PUBLIC(z, words * sizeof(*z));

    uint8_t seed[HIFHE_CTX_SEED_LEN] = {1, 3, 7};
    BgvEntropy entropy = BgvEntropy_Seeded(seed, sizeof(seed), "ct-regression");
    SECRET(seed, sizeof(seed));
    CHECK(Kernel_Sampler_Ternary(small, 64u, &entropy));
    CHECK(Kernel_Sampler_TernaryFixedWeight(small, 64u, 31u, &entropy));
    CHECK(Kernel_Sampler_CBD(small, 64u, 2u, &entropy));
    PUBLIC(seed, sizeof(seed));
    PUBLIC(small, n * sizeof(*small));

    Plaintext pt = {0}, decoded = {0};
    Ciphertext ct = {0};
    Encoder encoder;
    Encryptor encryptor;
    CHECK(BGV_Encoder_Create(&encoder, bc));
    CHECK(BGV_Encoder_Encode(&pt, z, n, &encoder));
    CrtPoly view;
    CHECK(RLWE_CrtPoly_CreateFromExist(&view, pt.data, pt.dataSize, &pt.config.crtConfig, &bc->rlweContext));
    for (uint32_t i = 0; i < n; ++i) {
        small[i] = (int64_t)(i % 3u) - 1;
    }
    SECRET(small, n * sizeof(*small));
    CHECK(RLWE_CrtPoly_SetSigned(&view, small));
    PUBLIC(small, n * sizeof(*small));
    PUBLIC(pt.data, pt.dataSize * sizeof(uint64_t));
    RLWE_CrtPoly_Destroy(&view);
    CHECK(BGV_Encryptor_CreateFromPublic(&encryptor, &ctx->bgv.pk, ctx->bgv.keygen.sk, bc));
    CHECK(BGV_Encryptor_EncryptAsymmetric(&ct, &pt, &encryptor));
    SECRET(ctx->bgv.keygen.sk->data, words * sizeof(uint64_t));
    CHECK(BGV_Encryptor_Decrypt(&decoded, &ct, &encryptor));
    PUBLIC(ctx->bgv.keygen.sk->data, words * sizeof(uint64_t));
    PUBLIC(decoded.data, decoded.dataSize * sizeof(uint64_t));
    BGV_Plaintext_Destroy(&decoded);
    BGV_Plaintext_Destroy(&pt);
    BGV_Ciphertext_Destroy(&ct);
    free(v);
    free(z);
    free(small);
    CRYPT_BGV_FreeCtx(ctx);
}

typedef struct { double mean, m2; unsigned count; } Stats;
static void Add(Stats *s, double x)
{
    double delta = x - s->mean;
    s->count++;
    s->mean += delta / s->count;
    s->m2 += delta * (x - s->mean);
}

/* Fixed-vs-random NTT inputs, with random class order and all preparation
 * outside the measured interval. Welch's t is diagnostic, not a certificate. */
static int Timing(void)
{
    const unsigned samples = 40000u;
    const unsigned n = 2048u;
    uint64_t *table = calloc(HIFHE_NTT_TABLE_WORDS(n), sizeof(uint64_t));
    uint64_t *poly = calloc(n, sizeof(uint64_t));
    if (table == NULL || poly == NULL) {
        exit(1);
    }
    NttTables tbl;
    CHECK(Kernel_Ntt_BuildTables(&tbl, table, UINT64_C(281474976694273), n));
    Stats s[2] = {{0}};
    uint64_t state = UINT64_C(0x6a09e667f3bcc909);
    for (unsigned i = 0; i < samples + 1000u; ++i) {
        state ^= state << 13; state ^= state >> 7; state ^= state << 17;
        unsigned cls = state & 1u;
        for (unsigned j = 0; j < n; ++j) {
            state ^= state << 13; state ^= state >> 7; state ^= state << 17;
            poly[j] = cls ? state % tbl.q : 0u;
        }
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);
        CHECK(Kernel_Ntt_Forward(poly, &tbl));
        CHECK(Kernel_Ntt_Inverse(poly, &tbl));
        clock_gettime(CLOCK_MONOTONIC_RAW, &end);
        if (i >= 1000u) {
            double ns = (end.tv_sec - start.tv_sec) * 1e9 + end.tv_nsec - start.tv_nsec;
            Add(&s[cls], ns);
        }
    }
    double t = (s[0].mean - s[1].mean) /
        sqrt(s[0].m2 / (s[0].count - 1u) / s[0].count + s[1].m2 / (s[1].count - 1u) / s[1].count);
    printf("NTT fixed-vs-random: n0=%u n1=%u Welch t=%.3f\n", s[0].count, s[1].count, t);
    free(poly);
    free(table);
    /* A large statistic requires investigation; passing does not establish CT. */
    return !isfinite(t) || fabs(t) > 10.0;
}

int main(int argc, char **argv)
{
    CHECK(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND));
    int ret = 0;
    if (argc == 2 && strcmp(argv[1], "--timing") == 0) {
        ret = Timing();
    } else {
        Probe();
        puts("secret-data dependency probes completed");
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
    return ret;
}
