/* Copyright (c) 2017-2019 Akamai Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Retargeted onto GNU Nettle for urcrypt. The AES_SIV_CTX is caller-allocated
 * (it has no internal pointers, so it can live on the stack), and the library
 * never calls malloc; there is no AES_SIV_CTX_new()/AES_SIV_CTX_free(). Wipe a
 * finished context with AES_SIV_CTX_cleanup().
 */

#ifndef AES_SIV_H_
#define AES_SIV_H_

#include <stddef.h>
#include <stdint.h>

#include <nettle/aes.h>
#include <nettle/cmac.h>

#define LIBAES_SIV_VERSION_MAJOR 1
#define LIBAES_SIV_VERSION_MINOR 0
#define LIBAES_SIV_VERSION_PATCH 1

#define LIBAES_SIV_VERSION ((LIBAES_SIV_VERSION_MAJOR << 16) + \
                            (LIBAES_SIV_VERSION_MINOR << 8) +  \
                            LIBAES_SIV_VERSION_PATCH)


#ifdef __cplusplus
extern "C" {
#endif

/* 16-byte block, accessible as two 64-bit words or as bytes. */
typedef union block_un {
        uint64_t word[2];
        unsigned char byte[16];
} block;

/* AES key schedule for whichever variant is in use. The same union type backs
   both the CMAC half and the CTR half of the SIV key. */
union aes_ctx {
        struct aes128_ctx a128;
        struct aes192_ctx a192;
        struct aes256_ctx a256;
};

/* The context is caller-allocated and fully self-contained (no external
   pointers), so it can live on the stack. */
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

typedef struct AES_SIV_CTX_st AES_SIV_CTX;

int AES_SIV_CTX_copy(AES_SIV_CTX *dst, AES_SIV_CTX const *src);
void AES_SIV_CTX_cleanup(AES_SIV_CTX *ctx);

int AES_SIV_Init(AES_SIV_CTX *ctx, unsigned char const *key, size_t key_len);
int AES_SIV_AssociateData(AES_SIV_CTX *ctx, unsigned char const *data,
                          size_t len);
int AES_SIV_EncryptFinal(AES_SIV_CTX *ctx, unsigned char *v_out,
                         unsigned char *c_out, unsigned char const *plaintext,
                         size_t len);
int AES_SIV_DecryptFinal(AES_SIV_CTX *ctx, unsigned char *out,
                         unsigned char const *v, unsigned char const *c,
                         size_t len);

int AES_SIV_Encrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
                    unsigned char const *key, size_t key_len,
                    unsigned char const *nonce, size_t nonce_len,
                    unsigned char const *plaintext, size_t plaintext_len,
                    unsigned char const *ad, size_t ad_len);

int AES_SIV_Decrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
                    unsigned char const *key, size_t key_len,
                    unsigned char const *nonce, size_t nonce_len,
                    unsigned char const *ciphertext, size_t ciphertext_len,
                    unsigned char const *ad, size_t ad_len);


#ifdef __cplusplus
}
#endif

#endif
