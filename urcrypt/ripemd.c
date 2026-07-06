#include "urcrypt.h"
#include "util.h"
#include <nettle/ripemd160.h>

int
urcrypt_ripemd160(uint8_t *message, size_t length, uint8_t out[20])
{
  struct ripemd160_ctx ctx;
  urcrypt__reverse(length, message);
  ripemd160_init(&ctx);
  ripemd160_update(&ctx, length, message);
  ripemd160_digest(&ctx, out);
  urcrypt__reverse(20, out);
  return 0;
}

