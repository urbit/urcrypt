#include "test_common.h"
#include "urcrypt/urcrypt.h"
#include <string.h>
#include <stdio.h>

/*
 * Keccak Test Suite
 *
 * Tests for the Keccak cryptographic hash function family wrappers.
 *
 * Reference test vectors from Ethereum's cryptographic library:
 * https://github.com/ethereum/js-ethereum-cryptography/blob/master/test/test-vectors/keccak.ts
 *
 * This implementation uses original Keccak (padding delimiter 0x01), as adopted by Ethereum.
 * NIST SHA-3 uses a different padding (0x06), producing different hash outputs for identical inputs.
 * The Keccak team submitted the original algorithm to the SHA-3 competition; NIST modified the
 * padding scheme when standardizing it as FIPS 202, creating the distinction between
 * "Keccak" (original, 0x01) and "SHA-3" (standardized, 0x06).
 *
 * Note: urcrypt outputs hashes in little-endian byte order per Urbit convention.
 */

/*
 * Test: Keccak-224 - Empty string
 */
static int test_keccak_224_empty(void) {
  uint8_t out[28];
  uint8_t expected[28];

  /* Ethereum test vector for empty string */
  hex_to_bytes("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd", expected, 28);
  reverse_bytes(expected, 28);

  int ret = urcrypt_keccak_224(NULL, 0, out);

  ASSERT(ret == 0, "keccak_224 should succeed");
  ASSERT_MEM_EQ(out, expected, 28, "keccak_224 empty string hash mismatch");

  return 0;
}

/*
 * Test: Keccak-224 - Single byte 0x41 ('A')
 */
static int test_keccak_224_41(void) {
  uint8_t out[28];
  uint8_t expected[28];
  uint8_t input = 0x41;

  /* Ethereum test vector for 0x41 */
  hex_to_bytes("ef40b16ff375c834e91412489889f36538748c5454f4b02ba750b65e", expected, 28);
  reverse_bytes(expected, 28);

  int ret = urcrypt_keccak_224(&input, 1, out);

  ASSERT(ret == 0, "keccak_224 should succeed");
  ASSERT_MEM_EQ(out, expected, 28, "keccak_224 single byte 0x41 hash mismatch");

  return 0;
}

/*
 * Test: Keccak-224 - Short message "asd"
 */
static int test_keccak_224_asd(void) {
  uint8_t out[28];
  uint8_t expected[28];
  const char *message = "asd";

  /* Ethereum test vector for "asd" */
  hex_to_bytes("c8cc732c0fa9004eb33d5d833ca22fbd27f21f1c53ef5670bc6779ca", expected, 28);
  reverse_bytes(expected, 28);

  int ret = urcrypt_keccak_224((const uint8_t*)message, strlen(message), out);

  ASSERT(ret == 0, "keccak_224 should succeed");
  ASSERT_MEM_EQ(out, expected, 28, "keccak_224 'asd' hash mismatch");

  return 0;
}

/*
 * Test: Keccak-256 - Empty string
 */
static int test_keccak_256_empty(void) {
  uint8_t out[32];
  uint8_t expected[32];

  /* Ethereum test vector for empty string */
  hex_to_bytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", expected, 32);
  reverse_bytes(expected, 32);

  int ret = urcrypt_keccak_256(NULL, 0, out);

  ASSERT(ret == 0, "keccak_256 should succeed");
  ASSERT_MEM_EQ(out, expected, 32, "keccak_256 empty string hash mismatch");

  return 0;
}

/*
 * Test: Keccak-256 - Single byte 0x41 ('A')
 */
static int test_keccak_256_41(void) {
  uint8_t out[32];
  uint8_t expected[32];
  uint8_t input = 0x41;

  /* Ethereum test vector for 0x41 */
  hex_to_bytes("03783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760", expected, 32);
  reverse_bytes(expected, 32);

  int ret = urcrypt_keccak_256(&input, 1, out);

  ASSERT(ret == 0, "keccak_256 should succeed");
  ASSERT_MEM_EQ(out, expected, 32, "keccak_256 single byte 0x41 hash mismatch");

  return 0;
}

/*
 * Test: Keccak-256 - Short message "asd"
 */
static int test_keccak_256_asd(void) {
  uint8_t out[32];
  uint8_t expected[32];
  const char *message = "asd";

  /* Ethereum test vector for "asd" */
  hex_to_bytes("87c2d362de99f75a4f2755cdaaad2d11bf6cc65dc71356593c445535ff28f43d", expected, 32);
  reverse_bytes(expected, 32);

  int ret = urcrypt_keccak_256((const uint8_t*)message, strlen(message), out);

  ASSERT(ret == 0, "keccak_256 should succeed");
  ASSERT_MEM_EQ(out, expected, 32, "keccak_256 'asd' hash mismatch");

  return 0;
}

/*
 * Test: Keccak-384 - Empty string
 */
static int test_keccak_384_empty(void) {
  uint8_t out[48];
  uint8_t expected[48];

  /* Ethereum test vector for empty string */
  hex_to_bytes("2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff", expected, 48);
  reverse_bytes(expected, 48);

  int ret = urcrypt_keccak_384(NULL, 0, out);

  ASSERT(ret == 0, "keccak_384 should succeed");
  ASSERT_MEM_EQ(out, expected, 48, "keccak_384 empty string hash mismatch");

  return 0;
}

/*
 * Test: Keccak-384 - Single byte 0x41 ('A')
 */
static int test_keccak_384_41(void) {
  uint8_t out[48];
  uint8_t expected[48];
  uint8_t input = 0x41;

  /* Ethereum test vector for 0x41 */
  hex_to_bytes("5c744cf4b4e3fb8967189e9744261a74f0ef31cdd8850554c737803585ac109039b73c22c50ea866c94debf1061f37a4", expected, 48);
  reverse_bytes(expected, 48);

  int ret = urcrypt_keccak_384(&input, 1, out);

  ASSERT(ret == 0, "keccak_384 should succeed");
  ASSERT_MEM_EQ(out, expected, 48, "keccak_384 single byte 0x41 hash mismatch");

  return 0;
}

/*
 * Test: Keccak-384 - Short message "asd"
 */
static int test_keccak_384_asd(void) {
  uint8_t out[48];
  uint8_t expected[48];
  const char *message = "asd";

  /* Ethereum test vector for "asd" */
  hex_to_bytes("50efbfa7d5aa41e132c3cfba2bc503d0014eb5bf6d214420851bff0f284bc9a5383a49327600e2efc3ad9db3621decaf", expected, 48);
  reverse_bytes(expected, 48);

  int ret = urcrypt_keccak_384((const uint8_t*)message, strlen(message), out);

  ASSERT(ret == 0, "keccak_384 should succeed");
  ASSERT_MEM_EQ(out, expected, 48, "keccak_384 'asd' hash mismatch");

  return 0;
}

/*
 * Test: Keccak-512 - Empty string
 */
static int test_keccak_512_empty(void) {
  uint8_t out[64];
  uint8_t expected[64];

  /* Ethereum test vector for empty string */
  hex_to_bytes("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e", expected, 64);
  reverse_bytes(expected, 64);

  int ret = urcrypt_keccak_512(NULL, 0, out);

  ASSERT(ret == 0, "keccak_512 should succeed");
  ASSERT_MEM_EQ(out, expected, 64, "keccak_512 empty string hash mismatch");

  return 0;
}

/*
 * Test: Keccak-512 - Single byte 0x41 ('A')
 */
static int test_keccak_512_41(void) {
  uint8_t out[64];
  uint8_t expected[64];
  uint8_t input = 0x41;

  /* Ethereum test vector for 0x41 */
  hex_to_bytes("421a35a60054e5f383b6137e43d44e998f496748cc77258240ccfaa8730b51f40cf47c1bc09c728a8cd4f096731298d51463f15af89543fed478053346260c38", expected, 64);
  reverse_bytes(expected, 64);

  int ret = urcrypt_keccak_512(&input, 1, out);

  ASSERT(ret == 0, "keccak_512 should succeed");
  ASSERT_MEM_EQ(out, expected, 64, "keccak_512 single byte 0x41 hash mismatch");

  return 0;
}

/*
 * Test: Keccak-512 - Short message "asd"
 */
static int test_keccak_512_asd(void) {
  uint8_t out[64];
  uint8_t expected[64];
  const char *message = "asd";

  /* Ethereum test vector for "asd" */
  hex_to_bytes("3fb67c8b512d8ce73324db02dda2d19ebfb9d6a923c48fb503be3e0c7c752eb84e4da0818665133a27638dce8e9e8696a51b64b6b247354764609f22b4e65d35", expected, 64);
  reverse_bytes(expected, 64);

  int ret = urcrypt_keccak_512((const uint8_t*)message, strlen(message), out);

  ASSERT(ret == 0, "keccak_512 should succeed");
  ASSERT_MEM_EQ(out, expected, 64, "keccak_512 'asd' hash mismatch");

  return 0;
}

/*
 * Test: Keccak determinism
 *
 * Verify that the same input always produces the same output
 */
static int test_keccak_determinism(void) {
  uint8_t out1[32];
  uint8_t out2[32];
  const char *message = "determinism test";

  urcrypt_keccak_256((const uint8_t*)message, strlen(message), out1);
  urcrypt_keccak_256((const uint8_t*)message, strlen(message), out2);

  ASSERT_MEM_EQ(out1, out2, 32, "keccak_256 is not deterministic");

  return 0;
}

/*
 * Test: Keccak with longer message
 *
 * Tests that Keccak can handle messages longer than a single block
 */
static int test_keccak_longer_message(void) {
  uint8_t out[32];
  /* Message longer than 136 bytes (Keccak-256 block size) */
  const char *message = "The quick brown fox jumps over the lazy dog. "
                        "The quick brown fox jumps over the lazy dog. "
                        "The quick brown fox jumps over the lazy dog. "
                        "The quick brown fox jumps over the lazy dog.";

  int ret = urcrypt_keccak_256((const uint8_t*)message, strlen(message), out);

  ASSERT(ret == 0, "keccak_256 should succeed with longer message");

  /* Verify output is not all zeros */
  int all_zero = 1;
  for (int i = 0; i < 32; i++) {
    if (out[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(all_zero == 0, "keccak_256 should produce non-zero output");

  return 0;
}

/*
 * Test: Different Keccak variants produce different outputs
 *
 * Verify that the same input produces different hashes with different variants
 */
static int test_keccak_variants_differ(void) {
  uint8_t out_224[28];
  uint8_t out_256[32];
  const char *message = "test";

  urcrypt_keccak_224((const uint8_t*)message, strlen(message), out_224);
  urcrypt_keccak_256((const uint8_t*)message, strlen(message), out_256);

  /* First 28 bytes should differ (different algorithms) */
  int all_same = 1;
  for (int i = 0; i < 28; i++) {
    if (out_224[i] != out_256[i]) {
      all_same = 0;
      break;
    }
  }

  ASSERT(all_same == 0, "keccak_224 and keccak_256 should produce different outputs");

  return 0;
}

/* Test suite entry point */
int suite_keccak(void) {
  int suite_failures = 0;

  RUN_TEST(test_keccak_224_empty);
  RUN_TEST(test_keccak_224_41);
  RUN_TEST(test_keccak_224_asd);
  RUN_TEST(test_keccak_256_empty);
  RUN_TEST(test_keccak_256_41);
  RUN_TEST(test_keccak_256_asd);
  RUN_TEST(test_keccak_384_empty);
  RUN_TEST(test_keccak_384_41);
  RUN_TEST(test_keccak_384_asd);
  RUN_TEST(test_keccak_512_empty);
  RUN_TEST(test_keccak_512_41);
  RUN_TEST(test_keccak_512_asd);
  RUN_TEST(test_keccak_determinism);
  RUN_TEST(test_keccak_longer_message);
  RUN_TEST(test_keccak_variants_differ);

  return suite_failures;
}
