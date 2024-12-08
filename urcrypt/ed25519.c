#include "urcrypt.h"
#include <string.h>
#include <ed25519.h>
#include <sc.h>

void
urcrypt_ed_scalar_muladd(uint8_t a[32], uint8_t b[32], uint8_t c[32], uint8_t out[32]) {
  sc_muladd(out, a, b, c);
}

void
urcrypt_ed_scalar_reduce(uint8_t a[64]) {
  sc_reduce(a);
}

void
urcrypt_ed_add_scalar_private(uint8_t private[64],
                              const uint8_t scalar[32])
{
  ed25519_add_scalar((unsigned char *) 0, private, scalar);
}

void
urcrypt_ed_add_scalar_public(uint8_t public[32],
                             const uint8_t scalar[32])
{
  ed25519_add_scalar(public, (unsigned char *) 0, scalar);
}

void
urcrypt_ed_add_scalar_public_private(uint8_t public[32],
                                     uint8_t private[64],
                                     const uint8_t scalar[32])
{
  ed25519_add_scalar(public, private, scalar);
}

void
urcrypt_ed_puck(const uint8_t seed[32],
                uint8_t out[32])
{
  uint8_t secret[64];
  ed25519_create_keypair(out, secret, seed);
}

void
urcrypt_ed_luck(const uint8_t seed[32],
                uint8_t public_out[32],
                uint8_t private_out[64])
{
  ed25519_create_keypair(public_out, private_out, seed);
}

void
urcrypt_ed_shar(const uint8_t public[32],
                const uint8_t seed[32],
                uint8_t out[32])
{
  uint8_t self[32], exp[64];

  ed25519_create_keypair(self, exp, seed);
  ed25519_key_exchange(out, public, exp);
}

void
urcrypt_ed_slar(const uint8_t public[32],
                const uint8_t private[64],
                uint8_t out[32])
{
  ed25519_key_exchange(out, public, private);
}

void
urcrypt_ed_sign(const uint8_t *message,
                size_t length,
                const uint8_t seed[32],
                uint8_t out[64])
{
  uint8_t public[64], secret[64];

  ed25519_create_keypair(public, secret, seed);
  ed25519_sign(out, message, length, public, secret);
}

void
urcrypt_ed_sign_raw(const uint8_t *message,
                size_t length,
                const uint8_t public[32],
                const uint8_t private[32],
                uint8_t out[64]) {
  ed25519_sign(out, message, length, public, private);
}

bool
urcrypt_ed_veri(const uint8_t *message,
                size_t length,
                const uint8_t public[32],
                const uint8_t signature[64])
{
  return ( ed25519_verify(signature, message, length, public) == 1 )
    ? true
    : false;
}
