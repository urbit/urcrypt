#include "urcrypt.h"
#include "util.h"
#include <nettle/aes.h>

int
urcrypt_aes_ecba_en(uint8_t key[16], uint8_t block[16], uint8_t out[16])
{
  struct aes128_ctx ctx;

  urcrypt__reverse(16, key);
  urcrypt__reverse(16, block);

  aes128_set_encrypt_key(&ctx, key);
  aes128_encrypt(&ctx, 16, out, block);
  urcrypt__reverse(16, out);
  return 0;
}

int
urcrypt_aes_ecba_de(uint8_t key[16], uint8_t block[16], uint8_t out[16])
{
  struct aes128_ctx ctx;

  urcrypt__reverse(16, key);
  urcrypt__reverse(16, block);

  aes128_set_decrypt_key(&ctx, key);
  aes128_decrypt(&ctx, 16, out, block);
  urcrypt__reverse(16, out);
  return 0;
}

int
urcrypt_aes_ecbb_en(uint8_t key[24], uint8_t block[16], uint8_t out[16])
{
  struct aes192_ctx ctx;

  urcrypt__reverse(24, key);
  urcrypt__reverse(16, block);

  aes192_set_encrypt_key(&ctx, key);
  aes192_encrypt(&ctx, 16, out, block);
  urcrypt__reverse(16, out);
  return 0;
}

int
urcrypt_aes_ecbb_de(uint8_t key[24], uint8_t block[16], uint8_t out[16])
{
  struct aes192_ctx ctx;

  urcrypt__reverse(24, key);
  urcrypt__reverse(16, block);

  aes192_set_decrypt_key(&ctx, key);
  aes192_decrypt(&ctx, 16, out, block);
  urcrypt__reverse(16, out);
  return 0;
}

int
urcrypt_aes_ecbc_en(uint8_t key[32], uint8_t block[16], uint8_t out[16])
{
  struct aes256_ctx ctx;

  urcrypt__reverse(32, key);
  urcrypt__reverse(16, block);

  aes256_set_encrypt_key(&ctx, key);
  aes256_encrypt(&ctx, 16, out, block);
  urcrypt__reverse(16, out);
  return 0;
}

int
urcrypt_aes_ecbc_de(uint8_t key[32], uint8_t block[16], uint8_t out[16])
{
  struct aes256_ctx ctx;

  urcrypt__reverse(32, key);
  urcrypt__reverse(16, block);

  aes256_set_decrypt_key(&ctx, key);
  aes256_decrypt(&ctx, 16, out, block);
  urcrypt__reverse(16, out);
  return 0;
}
