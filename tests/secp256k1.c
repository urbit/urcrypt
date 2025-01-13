#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include "urcrypt.h"

static uint8_t context_ent[32] = {
  0x95, 0x99, 0x6b, 0x8c, 0x81, 0x59, 0xd3, 0xc6,
  0x4e, 0x6c, 0x20, 0x5a, 0x21, 0xd3, 0x3d, 0xe4,
  0x28, 0x38, 0x0c, 0x38, 0xc1, 0x70, 0xa4, 0x79,
  0x67, 0xf7, 0x0d, 0xb2, 0x6e, 0x1b, 0xf9, 0x15, 
};

static uint8_t scalar_0[32] = {
  0x2c, 0x26, 0xb4, 0x6b, 0x68, 0xff, 0xc6, 0x8f,
  0xf9, 0x9b, 0x45, 0x3c, 0x1d, 0x30, 0x41, 0x34,
  0x13, 0x42, 0x2d, 0x70, 0x64, 0x83, 0xbf, 0xa0,
  0xf9, 0x8a, 0x5e, 0x88, 0x62, 0x66, 0xe7, 0xae, 
};

static uint8_t scalar_1[32] = {
  0xfc, 0xde, 0x2b, 0x2e, 0xdb, 0xa5, 0x6b, 0xf4,
  0x08, 0x60, 0x1f, 0xb7, 0x21, 0xfe, 0x9b, 0x5c,
  0x33, 0x8d, 0x10, 0xee, 0x42, 0x9e, 0xa0, 0x4f,
  0xae, 0x55, 0x11, 0xb6, 0x8f, 0xbf, 0x8f, 0xb9, 
};

static urcrypt_secp_context* sec_u;

/* call at process start */
void
_cs_secp_init()
{
  sec_u = malloc(urcrypt_secp_prealloc_size());

  if ( 0 != urcrypt_secp_init(sec_u, context_ent) ) {
    abort();
  }
}

/* call at process end */
void
_cs_secp_stop()
{
  urcrypt_secp_destroy(sec_u);
  free(sec_u);
  sec_u = NULL;
}

int main(int argc, char** argv) {
  _cs_secp_init();

  uint8_t cmp_point[33];
  urcrypt_secp_cmp_point_from_scalar(sec_u, scalar_0, cmp_point);

  printf("compressed pubkey: ");
  for (unsigned int i = 0; i < 33; i++) {
    printf("%02x", cmp_point[i]);
  }

  // printf("\ny: ");
  // for (unsigned int i = 0; i < 32; i++) {
  //   printf("%02x", point[i + 33]);
  // }
  printf("\n");

  uint8_t secret[32];
  memcpy(secret, scalar_0, 32);
  urcrypt_secp_scalar_tweak_add(sec_u, secret, scalar_1);

  printf("tweaked seckey: ");
  for (unsigned int i = 0; i < 32; i++) {
    printf("%02x", secret[i]);
  }
  printf("\n");

  urcrypt_secp_cmp_point_tweak_add(sec_u, cmp_point, scalar_1);

  printf("tweaked pubkey: ");
  for (unsigned int i = 0; i < 33; i++) {
    printf("%02x", cmp_point[i]);
  }
  printf("\n");

  _cs_secp_stop();
}
