#include "urcrypt.h"
#include "util.h"
#include <aes_siv.h>

/* the caller stack-allocates the context (see aes_siv.h); urcrypt never calls
 * malloc, and we wipe the finished context with AES_SIV_CTX_cleanup().
 */
static int
urcrypt__aes_siv_init(AES_SIV_CTX *ctx,
                      uint8_t *key,
                      size_t key_length,
                      urcrypt_aes_siv_data *data,
                      size_t data_length)
{
  urcrypt__reverse(key_length, key);
  if ( 0 == AES_SIV_Init(ctx, key, key_length) ) {
    return -1;
  }
  else {
    size_t i, len;
    uint8_t *dat;

    for ( i = 0; i < data_length; ++i ) {
      len = data[i].length;
      dat = data[i].bytes;
      urcrypt__reverse(len, dat);
      if ( 0 == AES_SIV_AssociateData(ctx, dat, len) ) {
        return -1;
      }
    }

    return 0;
  }
}

static int
urcrypt__aes_siv_en(uint8_t *key,
                    size_t key_length,
                    uint8_t *message,
                    size_t message_length,
                    urcrypt_aes_siv_data *data,
                    size_t data_length,
                    uint8_t iv[16],
                    uint8_t *out)
{
  int ret;
  AES_SIV_CTX ctx;

  if ( 0 != urcrypt__aes_siv_init(&ctx, key, key_length, data, data_length) ) {
    ret = -1;
  }
  else {
    urcrypt__reverse(message_length, message);
    if ( 0 == AES_SIV_EncryptFinal(&ctx, iv, out, message, message_length) ) {
      ret = -2;
    }
    else {
      urcrypt__reverse(16, iv);
      urcrypt__reverse(message_length, out);
      ret = 0;
    }
  }

  AES_SIV_CTX_cleanup(&ctx);
  return ret;
}

static int
urcrypt__aes_siv_de(uint8_t *key,
                    size_t key_length,
                    uint8_t *message,
                    size_t message_length,
                    urcrypt_aes_siv_data *data,
                    size_t data_length,
                    uint8_t iv[16],
                    uint8_t *out)
{
  int ret;
  AES_SIV_CTX ctx;

  if ( 0 != urcrypt__aes_siv_init(&ctx, key, key_length, data, data_length) ) {
    ret = -1;
  }
  else {
    urcrypt__reverse(message_length, message);
    urcrypt__reverse(16, iv);
    if ( 0 == AES_SIV_DecryptFinal(&ctx, out, iv, message, message_length) ) {
      ret = -2;
    }
    else {
      urcrypt__reverse(message_length, out);
      ret = 0;
    }
  }

  AES_SIV_CTX_cleanup(&ctx);
  return ret;
}

int
urcrypt_aes_siva_en(uint8_t *message,
                    size_t message_length,
                    urcrypt_aes_siv_data *data,
                    size_t data_length,
                    uint8_t key[32],
                    uint8_t iv[16],
                    uint8_t *out)
{
  return urcrypt__aes_siv_en(key, 32,
      message, message_length, data, data_length, iv, out);
}

int
urcrypt_aes_siva_de(uint8_t *message,
                    size_t message_length,
                    urcrypt_aes_siv_data *data,
                    size_t data_length,
                    uint8_t key[32],
                    uint8_t iv[16],
                    uint8_t *out)
{
  return urcrypt__aes_siv_de(key, 32,
      message, message_length, data, data_length, iv, out);
}

int
urcrypt_aes_sivb_en(uint8_t *message,
                    size_t message_length,
                    urcrypt_aes_siv_data *data,
                    size_t data_length,
                    uint8_t key[48],
                    uint8_t iv[16],
                    uint8_t *out)
{
  return urcrypt__aes_siv_en(key, 48,
      message, message_length, data, data_length, iv, out);
}

int
urcrypt_aes_sivb_de(uint8_t *message,
                    size_t message_length,
                    urcrypt_aes_siv_data *data,
                    size_t data_length,
                    uint8_t key[48],
                    uint8_t iv[16],
                    uint8_t *out)
{
  return urcrypt__aes_siv_de(key, 48,
      message, message_length, data, data_length, iv, out);
}

int
urcrypt_aes_sivc_en(uint8_t *message,
                    size_t message_length,
                    urcrypt_aes_siv_data *data,
                    size_t data_length,
                    uint8_t key[64],
                    uint8_t iv[16],
                    uint8_t *out)
{
  return urcrypt__aes_siv_en(key, 64,
      message, message_length, data, data_length, iv, out);
}

int
urcrypt_aes_sivc_de(uint8_t *message,
                    size_t message_length,
                    urcrypt_aes_siv_data *data,
                    size_t data_length,
                    uint8_t key[64],
                    uint8_t iv[16],
                    uint8_t *out)
{
  return urcrypt__aes_siv_de(key, 64,
      message, message_length, data, data_length, iv, out);
}
