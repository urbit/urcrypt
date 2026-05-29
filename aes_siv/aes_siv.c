/* Copyright (c) 2017-2019 Akamai Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Retargeted from OpenSSL's libcrypto onto GNU Nettle for urcrypt: the
 * RFC 5297 S2V/CTR construction is unchanged; only the AES, CMAC and CTR
 * primitives now come from Nettle (aes, cmac128, ctr) instead of EVP/CMAC.
 */

#define _POSIX_C_SOURCE 200112L
#define _ISOC99_SOURCE 1

#include "config.h"
#include "aes_siv.h"

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#ifdef ENABLE_DEBUG_OUTPUT
#include <stdio.h>
#endif
#ifdef _MSC_VER
/* For _byteswap_uint64 */
#include <stdlib.h>
#endif
#include <string.h>

#include <nettle/aes.h>
#include <nettle/cmac.h>
#include <nettle/ctr.h>

#ifdef ENABLE_CTGRIND
#include <ctgrind.h>
#endif

#if CHAR_BIT != 8
#error "libaes_siv requires an 8-bit char type"
#endif

#if -1 != ~0
#error "libaes_siv requires a two's-complement architecture"
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901
#undef inline
#elif defined(__GNUC__) || defined(__clang__)
#define inline __inline__
#elif defined(_MSC_VER)
#define inline __inline
#else
#define inline
#endif

#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(cond) __builtin_expect(cond, 1)
#define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#define LIKELY(cond) cond
#define UNLIKELY(cond) cond
#endif

#ifndef ENABLE_CTGRIND
static inline void ct_poison(const void *data, size_t len) {
        (void)data;
        (void)len;
}
static inline void ct_unpoison(const void *data, size_t len) {
        (void)data;
        (void)len;
}
#endif

/* Securely zero memory without being optimized away. Nettle provides no
   equivalent of OPENSSL_cleanse(). */
static void cleanse(void *p, size_t len) {
        volatile unsigned char *v = (volatile unsigned char *)p;
        while (len--) {
                *v++ = 0;
        }
}

static void debug(const char *label, const unsigned char *hex, size_t len) {
/* ENABLE_CTGRIND has to override ENABLE_DEBUG_OUTPUT since sensitive data
   gets printed.
*/
#if defined(ENABLE_DEBUG_OUTPUT) && !defined(ENABLE_CTGRIND)
        size_t i;
        printf("%16s: ", label);
        for (i = 0; i < len; i++) {
                if (i > 0 && i % 16 == 0) {
                        printf("\n                  ");
                }
                printf("%.2x", (int)hex[i]);
                if (i > 0 && i % 4 == 3) {
                        printf(" ");
                }
        }
        printf("\n");
#else
        (void)label;
        (void)hex;
        (void)len;
#endif
}

typedef union block_un {
        uint64_t word[2];
        unsigned char byte[16];
} block;

const union {
        uint64_t word;
        char byte[8];
} endian = {0x0102030405060708};

#define I_AM_BIG_ENDIAN (endian.byte[0] == 1 && \
                         endian.byte[1] == 2 && \
                         endian.byte[2] == 3 && \
                         endian.byte[3] == 4 && \
                         endian.byte[4] == 5 && \
                         endian.byte[5] == 6 && \
                         endian.byte[6] == 7 && \
                         endian.byte[7] == 8)

#define I_AM_LITTLE_ENDIAN (endian.byte[0] == 8 && \
                            endian.byte[1] == 7 && \
                            endian.byte[2] == 6 && \
                            endian.byte[3] == 5 && \
                            endian.byte[4] == 4 && \
                            endian.byte[5] == 3 && \
                            endian.byte[6] == 2 && \
                            endian.byte[7] == 1)

#if defined(__GNUC__) || defined(__clang__)
static inline uint64_t bswap64(uint64_t x) { return __builtin_bswap64(x); }
#elif defined(_MSC_VER)
static inline uint64_t bswap64(uint64_t x) { return _byteswap_uint64(x); }
#else

static inline uint32_t rotl(uint32_t x) { return (x << 8) | (x >> 24); }
static inline uint32_t rotr(uint32_t x) { return (x >> 8) | (x << 24); }

static inline uint64_t bswap64(uint64_t x) {
        uint32_t high = (uint32_t)(x >> 32);
        uint32_t low = (uint32_t)x;

        high = (rotl(high) & 0x00ff00ff) | (rotr(high) & 0xff00ff00);
        low = (rotl(low) & 0x00ff00ff) | (rotr(low) & 0xff00ff00);
        return ((uint64_t)low) << 32 | (uint64_t)high;
}
#endif

static inline uint64_t getword(block const *block, size_t i) {
#ifndef ENABLE_DEBUG_WEIRD_ENDIAN
        if (I_AM_BIG_ENDIAN) {
                return block->word[i];
        } else if (I_AM_LITTLE_ENDIAN) {
                return bswap64(block->word[i]);
        } else {
#endif
                i <<= 3;
                return ((uint64_t)block->byte[i + 7]) |
                       ((uint64_t)block->byte[i + 6] << 8) |
                       ((uint64_t)block->byte[i + 5] << 16) |
                       ((uint64_t)block->byte[i + 4] << 24) |
                       ((uint64_t)block->byte[i + 3] << 32) |
                       ((uint64_t)block->byte[i + 2] << 40) |
                       ((uint64_t)block->byte[i + 1] << 48) |
                       ((uint64_t)block->byte[i] << 56);
#ifndef ENABLE_DEBUG_WEIRD_ENDIAN
        }
#endif
}

static inline void putword(block *block, size_t i, uint64_t x) {
#ifndef ENABLE_DEBUG_WEIRD_ENDIAN
        if (I_AM_BIG_ENDIAN) {
                block->word[i] = x;
        } else if (I_AM_LITTLE_ENDIAN) {
                block->word[i] = bswap64(x);
        } else {
#endif
                i <<= 3;
                block->byte[i] = (unsigned char)(x >> 56);
                block->byte[i + 1] = (unsigned char)((x >> 48) & 0xff);
                block->byte[i + 2] = (unsigned char)((x >> 40) & 0xff);
                block->byte[i + 3] = (unsigned char)((x >> 32) & 0xff);
                block->byte[i + 4] = (unsigned char)((x >> 24) & 0xff);
                block->byte[i + 5] = (unsigned char)((x >> 16) & 0xff);
                block->byte[i + 6] = (unsigned char)((x >> 8) & 0xff);
                block->byte[i + 7] = (unsigned char)(x & 0xff);
#ifndef ENABLE_DEBUG_WEIRD_ENDIAN
        }
#endif
}

static inline void xorblock(block *x, block const *y) {
        x->word[0] ^= y->word[0];
        x->word[1] ^= y->word[1];
}

/* Doubles `block`, which is 16 bytes representing an element
   of GF(2**128) modulo the irreducible polynomial
   x**128 + x**7 + x**2 + x + 1. */
static inline void dbl(block *block) {
        uint64_t high = getword(block, 0);
        uint64_t low = getword(block, 1);
        uint64_t high_carry = high & (((uint64_t)1) << 63);
        uint64_t low_carry = low & (((uint64_t)1) << 63);
        /* Assumes two's-complement arithmetic */
        int64_t low_mask = -((int64_t)(high_carry >> 63)) & 0x87;
        uint64_t high_mask = low_carry >> 63;
        high = (high << 1) | high_mask;
        low = (low << 1) ^ (uint64_t)low_mask;
        putword(block, 0, high);
        putword(block, 1, low);
}

/* AES key schedule for whichever variant is in use. The same union type backs
   both the CMAC half and the CTR half of the SIV key. */
union aes_ctx {
        struct aes128_ctx a128;
        struct aes192_ctx a192;
        struct aes256_ctx a256;
};

struct AES_SIV_CTX_st {
        /* d stores intermediate results of S2V; it corresponds to D from the
           pseudocode in section 2.4 of RFC 5297. */
        block d;
        /* cmac_cipher and ctr_cipher hold the AES key schedules for the S2V
           (CMAC) and CTR halves of the SIV key; encrypt is the matching Nettle
           block-cipher function. cmac_key holds the CMAC subkeys derived from
           cmac_cipher, and cmac_ctx is a scratchpad used by
           AES_SIV_AssociateData() and AES_SIV_(En|De)cryptFinal. */
        union aes_ctx cmac_cipher, ctr_cipher;
        nettle_cipher_func *encrypt;
        struct cmac128_key cmac_key;
        struct cmac128_ctx cmac_ctx;
};

void AES_SIV_CTX_cleanup(AES_SIV_CTX *ctx) {
        cleanse(ctx, sizeof *ctx);
}

void AES_SIV_CTX_free(AES_SIV_CTX *ctx) {
        if (ctx) {
                cleanse(ctx, sizeof *ctx);
                free(ctx);
        }
}

AES_SIV_CTX *AES_SIV_CTX_new(void) {
        return malloc(sizeof(struct AES_SIV_CTX_st));
}

int AES_SIV_CTX_copy(AES_SIV_CTX *dst, AES_SIV_CTX const *src) {
        /* The context is self-contained (no external pointers), so a flat copy
           reproduces the key schedules, subkeys and S2V state. */
        memcpy(dst, src, sizeof *dst);
        return 1;
}

int AES_SIV_Init(AES_SIV_CTX *ctx, unsigned char const *key, size_t key_len) {
        static const unsigned char zero[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 0};
        int ret = 0;

        ct_poison(key, key_len);

        switch (key_len) {
        case 32:
                aes128_set_encrypt_key(&ctx->cmac_cipher.a128, key);
                aes128_set_encrypt_key(&ctx->ctr_cipher.a128, key + 16);
                ctx->encrypt = (nettle_cipher_func *)aes128_encrypt;
                break;
        case 48:
                aes192_set_encrypt_key(&ctx->cmac_cipher.a192, key);
                aes192_set_encrypt_key(&ctx->ctr_cipher.a192, key + 24);
                ctx->encrypt = (nettle_cipher_func *)aes192_encrypt;
                break;
        case 64:
                aes256_set_encrypt_key(&ctx->cmac_cipher.a256, key);
                aes256_set_encrypt_key(&ctx->ctr_cipher.a256, key + 32);
                ctx->encrypt = (nettle_cipher_func *)aes256_encrypt;
                break;
        default:
                goto done;
        }

        cmac128_set_key(&ctx->cmac_key, &ctx->cmac_cipher, ctx->encrypt);
        cmac128_init(&ctx->cmac_ctx);
        cmac128_update(&ctx->cmac_ctx, &ctx->cmac_cipher, ctx->encrypt,
                       sizeof zero, zero);
        cmac128_digest(&ctx->cmac_ctx, &ctx->cmac_key, &ctx->cmac_cipher,
                       ctx->encrypt, ctx->d.byte);
        debug("CMAC(zero)", ctx->d.byte, 16);
        ret = 1;

 done:
        ct_unpoison(key, key_len);
        return ret;
}

int AES_SIV_AssociateData(AES_SIV_CTX *ctx, unsigned char const *data,
                          size_t len) {
        block cmac_out;

        ct_poison(data, len);

        dbl(&ctx->d);
        debug("double()", ctx->d.byte, 16);

        cmac128_init(&ctx->cmac_ctx);
        cmac128_update(&ctx->cmac_ctx, &ctx->cmac_cipher, ctx->encrypt, len,
                       data);
        cmac128_digest(&ctx->cmac_ctx, &ctx->cmac_key, &ctx->cmac_cipher,
                       ctx->encrypt, cmac_out.byte);
        debug("CMAC(ad)", cmac_out.byte, 16);

        xorblock(&ctx->d, &cmac_out);
        debug("xor", ctx->d.byte, 16);

        ct_unpoison(data, len);
        return 1;
}

static inline int do_s2v_p(AES_SIV_CTX *ctx, block *out,
                           unsigned char const* in, size_t len) {
        block t;

        cmac128_init(&ctx->cmac_ctx);

        if(len >= 16) {
                cmac128_update(&ctx->cmac_ctx, &ctx->cmac_cipher, ctx->encrypt,
                               len - 16, in);
                debug("xorend part 1", in, len - 16);
                memcpy(&t, in + (len-16), 16);
                xorblock(&t, &ctx->d);
                debug("xorend part 2", t.byte, 16);
                cmac128_update(&ctx->cmac_ctx, &ctx->cmac_cipher, ctx->encrypt,
                               16, t.byte);
        } else {
                size_t i;
                memcpy(&t, in, len);
                t.byte[len] = 0x80;
                for(i = len + 1; i < 16; i++) {
                        t.byte[i] = 0;
                }
                debug("pad", t.byte, 16);
                dbl(&ctx->d);
                xorblock(&t, &ctx->d);
                debug("xor", t.byte, 16);
                cmac128_update(&ctx->cmac_ctx, &ctx->cmac_cipher, ctx->encrypt,
                               16, t.byte);
        }
        cmac128_digest(&ctx->cmac_ctx, &ctx->cmac_key, &ctx->cmac_cipher,
                       ctx->encrypt, out->byte);
        debug("CMAC(final)", out->byte, 16);
        return 1;
}

static inline int do_encrypt(AES_SIV_CTX *ctx, unsigned char *out,
                             unsigned char const *in, size_t len, block *icv) {
        /* Nettle's ctr_crypt() takes a size_t length and mutates the counter in
           place, so the OpenSSL int-length chunking loop is unnecessary. icv is
           the caller's scratch copy of the synthetic IV. */
        ctr_crypt(&ctx->ctr_cipher, ctx->encrypt, 16, icv->byte, len, out, in);
        return 1;
}

int AES_SIV_EncryptFinal(AES_SIV_CTX *ctx, unsigned char *v_out,
                         unsigned char *c_out, unsigned char const *plaintext,
                         size_t len) {
        block q;
        int ret = 0;

        ct_poison(plaintext, len);

        if(UNLIKELY(do_s2v_p(ctx, &q, plaintext, len) != 1)) {
                goto done;
        }

        ct_unpoison(&q, sizeof q);
        memcpy(v_out, &q, 16);
        q.byte[8] &= 0x7f;
        q.byte[12] &= 0x7f;

        if(UNLIKELY(do_encrypt(ctx, c_out, plaintext, len, &q) != 1)) {
                goto done;
        }

        ret = 1;
        debug("ciphertext", c_out, len);

done:
        ct_unpoison(plaintext, len);
        ct_unpoison(c_out, len);
        ct_unpoison(v_out, 16);
        return ret;
}

int AES_SIV_DecryptFinal(AES_SIV_CTX *ctx, unsigned char *out,
                         unsigned char const *v, unsigned char const *c,
                         size_t len) {
        block t, q;
        size_t i;
        uint64_t result;
        int ret = 0;

        ct_poison(c, len);

        memcpy(&q, v, 16);
        q.byte[8] &= 0x7f;
        q.byte[12] &= 0x7f;

        if(UNLIKELY(do_encrypt(ctx, out, c, len, &q) != 1)) {
                goto done;
        }
        debug("plaintext", out, len);

        if(UNLIKELY(do_s2v_p(ctx, &t, out, len) != 1)) {
                goto done;
        }

        for (i = 0; i < 16; i++) {
                t.byte[i] ^= v[i];
        }

        result = t.word[0] | t.word[1];
        ct_unpoison(&result, sizeof result);
        ret = !result;

        if(ret) {
                ct_unpoison(out, len);
        } else {
                cleanse(out, len);
        }

done:
        ct_unpoison(c, len);
        return ret;
}

int AES_SIV_Encrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
                    unsigned char const *key, size_t key_len,
                    unsigned char const *nonce, size_t nonce_len,
                    unsigned char const *plaintext, size_t plaintext_len,
                    unsigned char const *ad, size_t ad_len) {
        if (UNLIKELY(*out_len < plaintext_len + 16)) {
                return 0;
        }
        *out_len = plaintext_len + 16;

        if (UNLIKELY(AES_SIV_Init(ctx, key, key_len) != 1)) {
                return 0;
        }
        if (UNLIKELY(AES_SIV_AssociateData(ctx, ad, ad_len) != 1)) {
                return 0;
        }
        if (nonce != NULL &&
            UNLIKELY(AES_SIV_AssociateData(ctx, nonce, nonce_len) != 1)) {
                return 0;
        }
        if (UNLIKELY(AES_SIV_EncryptFinal(ctx, out, out + 16, plaintext,
                                          plaintext_len) != 1)) {
                return 0;
        }

        debug("IV || C", out, *out_len);
        return 1;
}

int AES_SIV_Decrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
                    unsigned char const *key, size_t key_len,
                    unsigned char const *nonce, size_t nonce_len,
                    unsigned char const *ciphertext, size_t ciphertext_len,
                    unsigned char const *ad, size_t ad_len) {
        if (UNLIKELY(ciphertext_len < 16)) {
                return 0;
        }
        if (UNLIKELY(*out_len < ciphertext_len - 16)) {
                return 0;
        }
        *out_len = ciphertext_len - 16;

        if (UNLIKELY(AES_SIV_Init(ctx, key, key_len) != 1)) {
                return 0;
        }
        if (UNLIKELY(AES_SIV_AssociateData(ctx, ad, ad_len) != 1)) {
                return 0;
        }
        if (nonce != NULL &&
            UNLIKELY(AES_SIV_AssociateData(ctx, nonce, nonce_len) != 1)) {
                return 0;
        }
        if (UNLIKELY(AES_SIV_DecryptFinal(ctx, out, ciphertext, ciphertext + 16,
                                          ciphertext_len - 16) != 1)) {
                return 0;
        }
        debug("plaintext", out, *out_len);
        return 1;
}
