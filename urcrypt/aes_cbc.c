#include "urcrypt.h"
#include "util.h"
#include <string.h>
#include <nettle/aes.h>
#include <nettle/cbc.h>

static int
urcrypt__cbc_pad(uint8_t **message_ptr,
                 size_t *length_ptr,
                 urcrypt_realloc_t realloc_ptr)
{
  size_t length = *length_ptr,
         remain = length % 16;

  if ( 0 == remain ) {
    // no padding needed
    return 0;
  }
  else {
    size_t padding = 16 - remain,
           padded  = length + padding;

    if ( padded < length ) {
      // size_t overflow
      return -1;
    }
    else {
      uint8_t *out = (*realloc_ptr)(*message_ptr, padded);
      if ( NULL == out ) {
        return -2;
      }
      else {
        memset(out + length, 0, padding);
        *message_ptr = out;
        *length_ptr  = padded;
        return 0;
      }
    }
  }
}

static int
urcrypt__cbc_help(uint8_t **message_ptr,
                  size_t *length_ptr,
                  const void *ctx,
                  nettle_cipher_func *f,
                  uint8_t ivec[16],
                  const int enc,
                  urcrypt_realloc_t realloc_ptr)
{
  if ( 0 != urcrypt__cbc_pad(message_ptr, length_ptr, realloc_ptr) ) {
    return -1;
  }
  else {
    uint8_t *out = *message_ptr;
    size_t length = *length_ptr;
    urcrypt__reverse(16, ivec);
    urcrypt__reverse(length, out);
    if ( enc ) {
      cbc_encrypt(ctx, f, 16, ivec, length, out, out);
    }
    else {
      cbc_decrypt(ctx, f, 16, ivec, length, out, out);
    }
    urcrypt__reverse(length, out);
    return 0;
  }
}

int
urcrypt_aes_cbca_en(uint8_t **message_ptr,
                    size_t *length_ptr,
                    uint8_t key[16],
                    uint8_t ivec[16],
                    urcrypt_realloc_t realloc_ptr)
{
  struct aes128_ctx ctx;

  urcrypt__reverse(16, key);
  aes128_set_encrypt_key(&ctx, key);
  return urcrypt__cbc_help(message_ptr, length_ptr, &ctx,
      (nettle_cipher_func *)aes128_encrypt, ivec, 1, realloc_ptr);
}

int
urcrypt_aes_cbca_de(uint8_t **message_ptr,
                    size_t *length_ptr,
                    uint8_t key[16],
                    uint8_t ivec[16],
                    urcrypt_realloc_t realloc_ptr)
{
  struct aes128_ctx ctx;

  urcrypt__reverse(16, key);
  aes128_set_decrypt_key(&ctx, key);
  return urcrypt__cbc_help(message_ptr, length_ptr, &ctx,
      (nettle_cipher_func *)aes128_decrypt, ivec, 0, realloc_ptr);
}

int
urcrypt_aes_cbcb_en(uint8_t **message_ptr,
                    size_t *length_ptr,
                    uint8_t key[24],
                    uint8_t ivec[16],
                    urcrypt_realloc_t realloc_ptr)
{
  struct aes192_ctx ctx;

  urcrypt__reverse(24, key);
  aes192_set_encrypt_key(&ctx, key);
  return urcrypt__cbc_help(message_ptr, length_ptr, &ctx,
      (nettle_cipher_func *)aes192_encrypt, ivec, 1, realloc_ptr);
}

int
urcrypt_aes_cbcb_de(uint8_t **message_ptr,
                    size_t *length_ptr,
                    uint8_t key[24],
                    uint8_t ivec[16],
                    urcrypt_realloc_t realloc_ptr)
{
  struct aes192_ctx ctx;

  urcrypt__reverse(24, key);
  aes192_set_decrypt_key(&ctx, key);
  return urcrypt__cbc_help(message_ptr, length_ptr, &ctx,
      (nettle_cipher_func *)aes192_decrypt, ivec, 0, realloc_ptr);
}

int
urcrypt_aes_cbcc_en(uint8_t **message_ptr,
                    size_t *length_ptr,
                    uint8_t key[32],
                    uint8_t ivec[16],
                    urcrypt_realloc_t realloc_ptr)
{
  struct aes256_ctx ctx;

  urcrypt__reverse(32, key);
  aes256_set_encrypt_key(&ctx, key);
  return urcrypt__cbc_help(message_ptr, length_ptr, &ctx,
      (nettle_cipher_func *)aes256_encrypt, ivec, 1, realloc_ptr);
}

int
urcrypt_aes_cbcc_de(uint8_t **message_ptr,
                    size_t *length_ptr,
                    uint8_t key[32],
                    uint8_t ivec[16],
                    urcrypt_realloc_t realloc_ptr)
{
  struct aes256_ctx ctx;

  urcrypt__reverse(32, key);
  aes256_set_decrypt_key(&ctx, key);
  return urcrypt__cbc_help(message_ptr, length_ptr, &ctx,
      (nettle_cipher_func *)aes256_decrypt, ivec, 0, realloc_ptr);
}
