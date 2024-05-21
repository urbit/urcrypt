#include <string.h>
#include <monocypher.h>

void
urcrypt_chacha_crypt(size_t rounds,
                     uint8_t key[32],
                     uint8_t nonce[8],
                     uint64_t counter,
                     size_t message_length,
                     uint8_t *message)
{
  crypto_chacha_djb(message, message, message_length, rounds, key, nonce, counter);
}

void
urcrypt_chacha_xchacha(size_t rounds,
                       uint8_t key[32],
                       uint8_t nonce[24],
                       uint8_t out_key[32],
                       uint8_t out_nonce[8])
{
  crypto_chacha_h(out_key, rounds, key, nonce);
  memcpy(out_nonce, nonce + 16, 8);
}
