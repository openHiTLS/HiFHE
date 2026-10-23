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

/* Leaked-string detection between a client and a server.
 *
 * The client asks whether its secret is in the server's leak bucket. The
 * server sees a ciphertext and a bucket id. The client learns one index.
 *
 * One query, t = plainMod, 4 slots per entry:
 *   client  h   = SHA3-256(secret)[0..7]
 *           q   = the four 16-bit fields of h, repeated over every entry slot
 *           ctQ = Encrypt(Encode(q)), sent with BUCKET_ID
 *   server  pt  = Encode(bucket entry fields, 4 slots per entry)
 *           r   = Encode(one random value in [1, t) per slot)
 *           ct  = Rerandomize(r * (pt - ctQ)), sent back
 *   client  m   = Decode(Decrypt(ct))
 *           entry i matched when m[4i .. 4i+3] are all 0
 *
 * t is prime and both operands are below t, so a slot is 0 exactly when the
 * two fields were equal.
 *
 * The two parties hold unrelated seeds. The server runs HEAdd, HEMul and
 * Rerandomize, none of which take a key, so it never generates one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>

#include "bsl_params.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "crypt_types.h"

#include "hifhe_err.h"
#include "hifhe_provider.h"
#include "hifhe_types.h"

#define PRESET          HIFHE_BGV_2048_48_17BIT
#define SLOTS_PER_ENTRY 4u
#define DIGEST_LEN      32u

/* Hardcoded exchange: this bucket, this id, the secret at this index. */
#define BUCKET_ID   36u
#define MATCH_INDEX 7u
#define NO_MATCH    UINT32_MAX

static const char *g_bucket[] = {
    "123456",   "password", "qwerty",  "letmein", "dragon",   "monkey",   "football", "hunter2",
    "iloveyou", "admin",    "welcome", "login",   "starwars", "trustno1", "whatever", "shadow",
};
#define BUCKET_COUNT (uint32_t)(sizeof(g_bucket) / sizeof(g_bucket[0]))

static const uint8_t g_clientSeed[HIFHE_BGV_SEED_LEN] = {
    0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x2D, 0x73, 0x65, 0x65, 0x64, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B,
};

static const uint8_t g_serverSeed[HIFHE_BGV_SEED_LEN] = {
    0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2D, 0x73, 0x65, 0x65, 0x64, 0xA0, 0xB1, 0xC2, 0xD3, 0xE4,
    0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F, 0xB0, 0xC1, 0xD2, 0xE3, 0xF4,
};

/* One party. Buffers are allocated once and reused by every query.
 * ct2 is the server's second ciphertext buffer, NULL on the client. */
typedef struct {
    CRYPT_EAL_PkeyCtx *ctx;
    uint32_t n; /* polyDegree, one slot each */
    uint32_t ptLen; /* plaintext wire bytes */
    uint32_t ctLen; /* ciphertext wire bytes */
    uint32_t msgLen; /* message vector bytes */
    uint64_t t; /* plaintext modulus */
    uint64_t *msg;
    uint8_t *pt;
    uint8_t *ct;
    uint8_t *ct2;
} Party;

/* ---------------- helpers ---------------- */

/* First 8 bytes of SHA3-256(s) as a big-endian integer. */
static int Digest8(const char *s, uint64_t *out)
{
    CRYPT_EAL_MdCtx *md = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA3_256);
    if (md == NULL) {
        return -1;
    }
    uint8_t d[DIGEST_LEN];
    uint32_t dLen = DIGEST_LEN;
    int rc = -1;
    if (CRYPT_EAL_MdInit(md) == CRYPT_SUCCESS &&
        CRYPT_EAL_MdUpdate(md, (const uint8_t *)s, (uint32_t)strlen(s)) == CRYPT_SUCCESS &&
        CRYPT_EAL_MdFinal(md, d, &dLen) == CRYPT_SUCCESS && dLen == DIGEST_LEN) {
        uint64_t v = 0u;
        for (uint32_t i = 0; i < 8u; ++i) {
            v = (v << 8) | (uint64_t)d[i];
        }
        *out = v;
        rc = 0;
    }
    CRYPT_EAL_MdFreeCtx(md);
    return rc;
}

/* The four 16-bit fields of h, most significant first. */
static void SplitFields(uint64_t h, uint64_t f[SLOTS_PER_ENTRY])
{
    f[0] = (h >> 48) & 0xFFFFu;
    f[1] = (h >> 32) & 0xFFFFu;
    f[2] = (h >> 16) & 0xFFFFu;
    f[3] = h & 0xFFFFu;
}

/* ---------------- party ---------------- */

static void PartyFree(Party *p)
{
    BSL_SAL_Free(p->msg);
    BSL_SAL_Free(p->pt);
    BSL_SAL_Free(p->ct);
    BSL_SAL_Free(p->ct2);
    CRYPT_EAL_PkeyFreeCtx(p->ctx);
    memset(p, 0, sizeof(*p));
}

/* keygen gives the party a secret key, twoCt a second ciphertext buffer.
 * Call order is fixed: preset, then seed, then Gen. */
static int PartyInit(Party *p, const uint8_t *seed, bool keygen, bool twoCt)
{
    memset(p, 0, sizeof(*p));
    p->ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_PKEY_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    if (p->ctx == NULL) {
        fprintf(stderr, "ProviderPkeyNewCtx failed\n");
        return -1;
    }
    int32_t preset = PRESET;
    int32_t r = CRYPT_EAL_PkeyCtrl(p->ctx, CRYPT_CTRL_SET_PARA_BY_ID, &preset, sizeof(preset));
    if (r == HIFHE_SUCCESS) {
        r = CRYPT_EAL_PkeyCtrl(p->ctx, HIFHE_CTRL_BGV_SET_SEED, (void *)(uintptr_t)seed, HIFHE_BGV_SEED_LEN);
    }
    if (r == HIFHE_SUCCESS && keygen) {
        r = CRYPT_EAL_PkeyGen(p->ctx);
    }
    if (r == HIFHE_SUCCESS) {
        r = CRYPT_EAL_PkeyCtrl(p->ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &p->n, sizeof(p->n));
    }
    if (r == HIFHE_SUCCESS) {
        r = CRYPT_EAL_PkeyCtrl(p->ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &p->ptLen, sizeof(p->ptLen));
    }
    if (r == HIFHE_SUCCESS) {
        r = CRYPT_EAL_PkeyCtrl(p->ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &p->ctLen, sizeof(p->ctLen));
    }
    if (r == HIFHE_SUCCESS) {
        r = CRYPT_EAL_PkeyCtrl(p->ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &p->msgLen, sizeof(p->msgLen));
    }
    if (r == HIFHE_SUCCESS) {
        r = CRYPT_EAL_PkeyCtrl(p->ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &p->t, sizeof(p->t));
    }
    if (r != HIFHE_SUCCESS) {
        fprintf(stderr, "context setup failed: 0x%08x\n", (unsigned)r);
        PartyFree(p);
        return -1;
    }

    p->msg = (uint64_t *)BSL_SAL_Malloc(p->msgLen);
    p->pt = (uint8_t *)BSL_SAL_Malloc(p->ptLen);
    p->ct = (uint8_t *)BSL_SAL_Malloc(p->ctLen);
    p->ct2 = twoCt ? (uint8_t *)BSL_SAL_Malloc(p->ctLen) : NULL;
    if (p->msg == NULL || p->pt == NULL || p->ct == NULL || (twoCt && p->ct2 == NULL)) {
        fprintf(stderr, "out of memory\n");
        PartyFree(p);
        return -1;
    }
    return 0;
}

/* True when the context holds no secret key, as the getter reports it. */
static bool NoPrivateKey(CRYPT_EAL_PkeyCtx *ctx)
{
    uint8_t stub = 0u;
    BSL_Param get[] = {{HIFHE_PARAM_BGV_PRVKEY, BSL_PARAM_TYPE_OCTETS, &stub, 0u, 0}, BSL_PARAM_END};
    return CRYPT_EAL_PkeyGetPrvEx(ctx, get) == HIFHE_KEY_NOT_SET;
}

/* p->msg into p->pt. */
static int Encode(Party *p, uint32_t *ptLen)
{
    BSL_Param in[] = {{HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, p->msg, p->msgLen, 0}, BSL_PARAM_END};
    uint32_t out = p->ptLen;
    int32_t r = CRYPT_EAL_PkeyHEMsgEncode(p->ctx, in, p->pt, &out);
    if (r != HIFHE_SUCCESS) {
        fprintf(stderr, "HEMsgEncode failed: 0x%08x\n", (unsigned)r);
        return -1;
    }
    *ptLen = out;
    return 0;
}

/* p->pt of ptLen into p->msg. */
static int Decode(Party *p, uint32_t ptLen)
{
    BSL_Param in[] = {{HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, p->pt, ptLen, 0}, BSL_PARAM_END};
    uint32_t out = p->msgLen;
    int32_t r = CRYPT_EAL_PkeyHEMsgDecode(p->ctx, in, (uint8_t *)p->msg, &out);
    if (r != HIFHE_SUCCESS) {
        fprintf(stderr, "HEMsgDecode failed: 0x%08x\n", (unsigned)r);
        return -1;
    }
    return 0;
}

/* ---------------- client ---------------- */

/* Encrypt the secret's fields into client->ct. */
static int ClientQuery(Party *client, const char *secret, uint32_t *ctLen)
{
    uint64_t h = 0u;
    if (Digest8(secret, &h) != 0) {
        return -1;
    }
    uint64_t f[SLOTS_PER_ENTRY];
    SplitFields(h, f);
    for (uint32_t i = 0; i < client->n; ++i) {
        client->msg[i] = f[i % SLOTS_PER_ENTRY];
    }

    uint32_t ptLen = 0u;
    if (Encode(client, &ptLen) != 0) {
        return -1;
    }
    uint32_t out = client->ctLen;
    int32_t r = CRYPT_EAL_PkeyEncrypt(client->ctx, client->pt, ptLen, client->ct, &out);
    if (r != HIFHE_SUCCESS) {
        fprintf(stderr, "Encrypt failed: 0x%08x\n", (unsigned)r);
        return -1;
    }
    *ctLen = out;
    return 0;
}

/* Index of the first entry whose four slots are 0, NO_MATCH if none. */
static int ClientFind(Party *client, const uint8_t *resp, uint32_t respLen, uint32_t count, uint32_t *index)
{
    uint32_t out = client->ptLen;
    int32_t r = CRYPT_EAL_PkeyDecrypt(client->ctx, resp, respLen, client->pt, &out);
    if (r != HIFHE_SUCCESS) {
        fprintf(stderr, "Decrypt failed: 0x%08x\n", (unsigned)r);
        return -1;
    }
    if (Decode(client, out) != 0) {
        return -1;
    }

    *index = NO_MATCH;
    for (uint32_t i = 0; i < count; ++i) {
        bool zero = true;
        for (uint32_t j = 0; j < SLOTS_PER_ENTRY; ++j) {
            if (client->msg[i * SLOTS_PER_ENTRY + j] != 0u) {
                zero = false;
                break;
            }
        }
        if (zero && *index == NO_MATCH) {
            *index = i;
        }
    }
    return 0;
}

/* ---------------- server ---------------- */

/* One random value in [1, t) per slot, encoded into server->pt.
 * A zero mask slot would hand the client the raw difference. */
static int ServerMask(Party *server, uint32_t *ptLen)
{
    if (CRYPT_EAL_Randbytes((uint8_t *)server->msg, server->msgLen) != CRYPT_SUCCESS) {
        fprintf(stderr, "Randbytes failed\n");
        return -1;
    }
    for (uint32_t i = 0; i < server->n; ++i) {
        server->msg[i] = (server->msg[i] % (server->t - 1u)) + 1u;
    }
    return Encode(server, ptLen);
}

/* Encode the bucket entry fields into server->pt. */
static int ServerBucket(Party *server, uint32_t *ptLen)
{
    memset(server->msg, 0, server->msgLen);
    for (uint32_t i = 0; i < BUCKET_COUNT; ++i) {
        uint64_t h = 0u;
        if (Digest8(g_bucket[i], &h) != 0) {
            return -1;
        }
        SplitFields(h, &server->msg[i * SLOTS_PER_ENTRY]);
    }
    return Encode(server, ptLen);
}

/* Answer one query: Rerandomize(mask * (bucket - ctQ)), left in server->ct2.
 * bucketId is the client's routing tag, already resolved to g_bucket here. */
static int ServerAnswer(Party *server, uint32_t bucketId, const uint8_t *ctQ, uint32_t ctQLen, uint32_t *respLen)
{
    (void)bucketId;

    uint32_t ptLen = 0u;
    if (ServerBucket(server, &ptLen) != 0) {
        return -1;
    }

    /* NEGATE and PLAINTEXT in one HEAdd drop the plaintext, so negate first. */
    uint8_t negate = 1u;
    BSL_Param neg[] = {{HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, (void *)(uintptr_t)ctQ, ctQLen, 0},
                       {HIFHE_PARAM_BGV_NEGATE, BSL_PARAM_TYPE_OCTETS, &negate, 1u, 0},
                       BSL_PARAM_END};
    uint32_t negLen = server->ctLen;
    int32_t r = CRYPT_EAL_PkeyHEAdd(server->ctx, neg, server->ct, &negLen);
    if (r != HIFHE_SUCCESS) {
        fprintf(stderr, "HEAdd negate failed: 0x%08x\n", (unsigned)r);
        return -1;
    }

    BSL_Param diff[] = {{HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, server->ct, negLen, 0},
                        {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, server->pt, ptLen, 0},
                        BSL_PARAM_END};
    uint32_t diffLen = server->ctLen;
    r = CRYPT_EAL_PkeyHEAdd(server->ctx, diff, server->ct2, &diffLen);
    if (r != HIFHE_SUCCESS) {
        fprintf(stderr, "HEAdd plaintext failed: 0x%08x\n", (unsigned)r);
        return -1;
    }

    /* The bucket plaintext is consumed, so the mask reuses the same buffer. */
    uint32_t maskLen = 0u;
    if (ServerMask(server, &maskLen) != 0) {
        return -1;
    }
    BSL_Param blind[] = {{HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, server->ct2, diffLen, 0},
                         {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, server->pt, maskLen, 0},
                         BSL_PARAM_END};
    uint32_t blindLen = server->ctLen;
    r = CRYPT_EAL_PkeyHEMul(server->ctx, blind, server->ct, &blindLen);
    if (r != HIFHE_SUCCESS) {
        fprintf(stderr, "HEMul failed: 0x%08x\n", (unsigned)r);
        return -1;
    }

    BSL_Param rerand[] = {{HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, server->ct, blindLen, 0},
                          {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, server->ct2, server->ctLen, 0},
                          BSL_PARAM_END};
    r = CRYPT_EAL_PkeyCtrl(server->ctx, HIFHE_CTRL_BGV_HE_RERANDOMIZE, rerand, 0u);
    if (r != HIFHE_SUCCESS) {
        fprintf(stderr, "Rerandomize failed: 0x%08x\n", (unsigned)r);
        return -1;
    }
    *respLen = rerand[1].useLen;
    return 0;
}

/* ---------------- query ---------------- */

/* Index of secret in g_bucket, NO_MATCH if absent. */
static uint32_t BucketIndexOf(const char *secret)
{
    for (uint32_t i = 0; i < BUCKET_COUNT; ++i) {
        if (strcmp(g_bucket[i], secret) == 0) {
            return i;
        }
    }
    return NO_MATCH;
}

static void PrintIndex(const char *label, uint32_t index)
{
    if (index == NO_MATCH) {
        printf("%s at [none]\n", label);
    } else {
        printf("%s at [%u]\n", label, index);
    }
}

/* Client queries, server answers, client reads the index back out. */
static int RunQuery(Party *client, Party *server, const char *secret)
{
    printf("\nquery \"%s\"\n", secret);
    PrintIndex("  set match", BucketIndexOf(secret));

    uint32_t ctQLen = 0u;
    if (ClientQuery(client, secret, &ctQLen) != 0) {
        return -1;
    }
    printf("  client -> server : bucket %u, %u byte ciphertext\n", BUCKET_ID, ctQLen);

    uint32_t respLen = 0u;
    if (ServerAnswer(server, BUCKET_ID, client->ct, ctQLen, &respLen) != 0) {
        return -1;
    }
    printf("  server -> client : %u byte ciphertext\n", respLen);

    uint32_t found = NO_MATCH;
    if (ClientFind(client, server->ct2, respLen, BUCKET_COUNT, &found) != 0) {
        return -1;
    }
    PrintIndex("  find match", found);
    printf("  result : %s\n", found == NO_MATCH ? "NOT_FOUND" : "LEAK_DETECTED");

    if (found != BucketIndexOf(secret)) {
        printf("  MISMATCH : expected [%u]\n", BucketIndexOf(secret));
        return -1;
    }
    return 0;
}

/* ---------------- provider ---------------- */

static int ProviderLoad(void)
{
    char path[PATH_MAX] = {0};
    const char *env = getenv("HIFHE_PROVIDER_PATH");
    if (env != NULL) {
        snprintf(path, sizeof(path), "%s", env);
    } else {
        char self[PATH_MAX] = {0};
        ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1u);
        if (n < 0) {
            fprintf(stderr, "readlink /proc/self/exe failed\n");
            return -1;
        }
        self[n] = '\0';
        /* testcode/output/demo/<binary> to build */
        snprintf(path, sizeof(path), "%s/../../../build", dirname(self));
    }
    int32_t r = CRYPT_EAL_ProviderSetLoadPath(NULL, path);
    if (r == CRYPT_SUCCESS) {
        r = CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe_provider", NULL, NULL);
    }
    if (r != CRYPT_SUCCESS) {
        fprintf(stderr, "hifhe_provider load from %s failed: 0x%08x\n", path, (unsigned)r);
        return -1;
    }
    return 0;
}

/* ---------------- main ---------------- */

int main(void)
{
    /* CRYPT_EAL_Init resets the library context, so it precedes the load. */
    if (CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL) != CRYPT_SUCCESS) {
        fprintf(stderr, "CRYPT_EAL_Init failed\n");
        return 1;
    }
    if (ProviderLoad() != 0) {
        return 1;
    }

    Party client;
    Party server;
    int rc = 1;

    /* The client holds the key. The server runs key-free operations and gets
     * a second ciphertext buffer to ping-pong the four of them across. */
    if (PartyInit(&client, g_clientSeed, true, false) != 0) {
        return 1;
    }
    if (PartyInit(&server, g_serverSeed, false, true) != 0) {
        PartyFree(&client);
        return 1;
    }

    printf("=== HiFHE leaked-string detection, client and server ===\n");
    printf("ring   : N=%u t=%" PRIu64 " slots/entry=%u\n", client.n, client.t, SLOTS_PER_ENTRY);
    printf("bucket : id %u, %u entries\n", BUCKET_ID, BUCKET_COUNT);
    printf("client : %s\n", NoPrivateKey(client.ctx) ? "no key" : "secret key from its own seed");
    printf("server : %s\n", NoPrivateKey(server.ctx) ? "no key, GetPrv reports KEY_NOT_SET" : "secret key present");

    if (RunQuery(&client, &server, g_bucket[MATCH_INDEX]) != 0) {
        goto out;
    }
    if (RunQuery(&client, &server, "a-string-not-in-the-bucket") != 0) {
        goto out;
    }
    rc = 0;

out:
    PartyFree(&server);
    PartyFree(&client);
    (void)CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe_provider");
    return rc;
}
