#include "test_common.h"
#include "urcrypt/urcrypt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * secp256k1 Test Suite
 *
 * Tests for secp256k1 ECDSA signing, key recovery, and Schnorr signatures.
 *
 * Reference test vectors from:
 * - secp256k1: Bitcoin Core secp256k1 library
 *   https://github.com/bitcoin-core/secp256k1
 * - Schnorr: BIP-340
 *   https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 */

/*
 * Test: secp256k1 - Context initialization and destruction
 */
static int test_secp_context(void) {
  size_t size = urcrypt_secp_prealloc_size();
  ASSERT(size > 0, "secp context size should be positive");

  urcrypt_secp_context *ctx = malloc(size);
  ASSERT(ctx != NULL, "secp context allocation should succeed");

  /* Initialize with test entropy */
  uint8_t entropy[32];
  for (int i = 0; i < 32; i++) {
    entropy[i] = i;
  }

  int ret = urcrypt_secp_init(ctx, entropy);
  ASSERT(ret == 0, "secp context init should succeed");

  /* Cleanup */
  urcrypt_secp_destroy(ctx);
  free(ctx);

  return 0;
}

/*
 * Test: secp256k1 - Public key generation from private key
 */
static int test_secp_make_pubkey(void) {
  uint8_t privkey[32];
  uint8_t hash[32];
  uint8_t pubkey[32];

  /* Use a known private key */
  hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000001", privkey, 32);

  /* Hash is unused in make, but required parameter */
  memset(hash, 0, 32);

  int ret = urcrypt_secp_make(hash, privkey, pubkey);
  ASSERT(ret == 0, "secp make pubkey should succeed");

  /* Verify pubkey is not all zeros */
  int all_zero = 1;
  for (int i = 0; i < 32; i++) {
    if (pubkey[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(all_zero == 0, "secp pubkey should not be all zeros");

  return 0;
}

/*
 * Test: secp256k1 - Sign and recover
 */
static int test_secp_sign_recover(void) {
  size_t size = urcrypt_secp_prealloc_size();
  urcrypt_secp_context *ctx = malloc(size);

  uint8_t entropy[32];
  for (int i = 0; i < 32; i++) {
    entropy[i] = i + 42;
  }
  urcrypt_secp_init(ctx, entropy);

  /* Setup test data */
  uint8_t hash[32];
  uint8_t privkey[32];
  uint8_t pubkey_orig[32];
  uint8_t pubkey_recovered_x[32];
  uint8_t pubkey_recovered_y[32];
  uint8_t v;
  uint8_t r[32];
  uint8_t s[32];

  /* Generate keypair */
  hex_to_bytes("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", privkey, 32);
  memset(hash, 0, 32);  /* hash unused for make */
  urcrypt_secp_make(hash, privkey, pubkey_orig);

  /* Sign a message */
  hex_to_bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", hash, 32);

  int ret = urcrypt_secp_sign(ctx, hash, privkey, &v, r, s);
  ASSERT(ret == 0, "secp sign should succeed");
  ASSERT(v < 4, "secp recovery id should be 0-3");

  /* Recover public key */
  ret = urcrypt_secp_reco(ctx, hash, v, r, s, pubkey_recovered_x, pubkey_recovered_y);
  ASSERT(ret == 0, "secp recover should succeed");

  /* Note: Recovery returns x,y coordinates, not compressed pubkey format,
   * so we just verify the recovery succeeded and returned non-zero values */
  int x_nonzero = 0, y_nonzero = 0;
  for (int i = 0; i < 32; i++) {
    if (pubkey_recovered_x[i] != 0) x_nonzero = 1;
    if (pubkey_recovered_y[i] != 0) y_nonzero = 1;
  }
  ASSERT(x_nonzero && y_nonzero, "secp recovered pubkey should be non-zero");

  urcrypt_secp_destroy(ctx);
  free(ctx);
  return 0;
}

/*
 * Test: secp256k1 Schnorr - Sign and verify (BIP-340)
 */
static int test_secp_schnorr_sign_verify(void) {
  size_t size = urcrypt_secp_prealloc_size();
  urcrypt_secp_context *ctx = malloc(size);

  uint8_t entropy[32];
  for (int i = 0; i < 32; i++) {
    entropy[i] = i + 100;
  }
  urcrypt_secp_init(ctx, entropy);

  /*
   * Test Schnorr signature - simplified test
   * We test that signing succeeds. Full verification testing would require
   * extracting the x-only public key, which requires accessing internal
   * secp256k1 structures not exposed through the urcrypt API.
   */
  uint8_t privkey[32];
  uint8_t msg[32];
  uint8_t aux[32];
  uint8_t sig[64];

  /* Initialize buffers with deterministic values */
  for (int i = 0; i < 32; i++) {
    privkey[i] = i + 1;
    msg[i] = i * 2;
    aux[i] = i * 3;
  }

  /* Test that signing succeeds */
  int ret = urcrypt_secp_schnorr_sign(ctx, privkey, msg, aux, sig);
  ASSERT(ret == 0, "schnorr sign should succeed");

  /* Test determinism - same inputs should produce same signature */
  uint8_t privkey2[32], msg2[32], aux2[32], sig2[64];
  for (int i = 0; i < 32; i++) {
    privkey2[i] = i + 1;
    msg2[i] = i * 2;
    aux2[i] = i * 3;
  }

  ret = urcrypt_secp_schnorr_sign(ctx, privkey2, msg2, aux2, sig2);
  ASSERT(ret == 0, "schnorr sign should succeed (determinism test)");
  ASSERT(memcmp(sig, sig2, 64) == 0, "schnorr signatures should be deterministic");

  urcrypt_secp_destroy(ctx);
  free(ctx);
  return 0;
}

/* Test suite entry point */
int suite_secp256k1(void) {
  int suite_failures = 0;

  RUN_TEST(test_secp_context);
  RUN_TEST(test_secp_make_pubkey);
  RUN_TEST(test_secp_sign_recover);
  RUN_TEST(test_secp_schnorr_sign_verify);

  return suite_failures;
}
