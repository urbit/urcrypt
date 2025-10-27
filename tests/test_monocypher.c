#include "test_common.h"
#include "urcrypt/urcrypt.h"
#include <string.h>
#include <stdio.h>

/*
 * Monocypher Test Suite
 *
 * Tests for Monocypher cryptographic operations (ChaCha20 and XChaCha20).
 *
 * Reference test vectors from:
 * - ChaCha20: draft-strombergson-chacha-test-vectors-01 (DJB original with 8-byte nonce)
 *   https://github.com/secworks/chacha_testvectors
 * - HChaCha20/XChaCha20: draft-irtf-cfrg-xchacha-03
 *   https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
 *
 * Note: urcrypt uses DJB's original ChaCha20 with 64-bit nonce and 64-bit counter,
 * not the IETF variant (RFC 8439) which uses 96-bit nonce and 32-bit counter.
 */

/*
 * Test: ChaCha20 - All-zero key and nonce
 *
 * Test vector from draft-strombergson-chacha-test-vectors-01
 * Tests the basic keystream generation with zeros
 */
static int test_chacha20_zeros(void) {
  uint8_t key[32] = {0};
  uint8_t nonce[8] = {0};
  uint8_t message[64] = {0};  /* All zeros as plaintext */
  uint8_t expected[64];

  /* Expected keystream block 0 from test vector */
  hex_to_bytes("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
               "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
               expected, 64);

  /* ChaCha20 encryption of zeros produces the keystream */
  urcrypt_chacha_crypt(20, key, nonce, 0, 64, message);

  ASSERT_MEM_EQ(message, expected, 64, "chacha20 all-zeros keystream mismatch");

  return 0;
}

/*
 * Test: ChaCha20 - Sequence pattern key
 *
 * Test vector from draft-strombergson-chacha-test-vectors-01
 * Tests with a patterned key and nonce
 */
static int test_chacha20_sequence(void) {
  uint8_t key[32];
  uint8_t nonce[8];
  uint8_t message[64] = {0};
  uint8_t expected[64];

  /* Key: 00112233445566778899aabbccddeeff ffeeddccbbaa99887766554433221100 */
  hex_to_bytes("00112233445566778899aabbccddeeff"
               "ffeeddccbbaa99887766554433221100", key, 32);

  /* Nonce: 0f1e2d3c4b5a6978 */
  hex_to_bytes("0f1e2d3c4b5a6978", nonce, 8);

  /* Expected keystream block 0 */
  hex_to_bytes("9fadf409c00811d00431d67efbd88fba59218d5d6708b1d685863fabbb0e961e"
               "ea480fd6fb532bfd494b2151015057423ab60a63fe4f55f7a212e2167ccab931",
               expected, 64);

  urcrypt_chacha_crypt(20, key, nonce, 0, 64, message);

  ASSERT_MEM_EQ(message, expected, 64, "chacha20 sequence keystream mismatch");

  return 0;
}

/*
 * Test: ChaCha20 - Text encryption
 *
 * Tests encrypting actual text and verifying round-trip
 */
static int test_chacha20_text_encrypt(void) {
  uint8_t key[32];
  uint8_t nonce[8];
  const char *plaintext = "Hello, World! This is a ChaCha20 encryption test.";
  size_t len = strlen(plaintext);
  uint8_t encrypted[128];
  uint8_t decrypted[128];

  /* Use test vector key and nonce */
  hex_to_bytes("00112233445566778899aabbccddeeff"
               "ffeeddccbbaa99887766554433221100", key, 32);
  hex_to_bytes("0f1e2d3c4b5a6978", nonce, 8);

  /* Copy plaintext to encrypted buffer */
  memcpy(encrypted, plaintext, len);

  /* Encrypt in place */
  urcrypt_chacha_crypt(20, key, nonce, 0, len, encrypted);

  /* Encrypted should differ from plaintext */
  ASSERT(memcmp(encrypted, plaintext, len) != 0, "chacha20 encryption should modify data");

  /* Copy to decrypted buffer and decrypt */
  memcpy(decrypted, encrypted, len);
  urcrypt_chacha_crypt(20, key, nonce, 0, len, decrypted);

  /* Should match original plaintext */
  ASSERT_MEM_EQ(decrypted, (const uint8_t*)plaintext, len, "chacha20 decryption mismatch");

  return 0;
}

/*
 * Test: ChaCha20 - Determinism
 *
 * Verify that the same inputs always produce the same output
 */
static int test_chacha20_determinism(void) {
  uint8_t key[32] = {1, 2, 3, 4, 5};  /* Partial initialization */
  uint8_t nonce[8] = {9, 8, 7, 6};
  uint8_t msg1[32] = {0};
  uint8_t msg2[32] = {0};

  urcrypt_chacha_crypt(20, key, nonce, 0, 32, msg1);
  urcrypt_chacha_crypt(20, key, nonce, 0, 32, msg2);

  ASSERT_MEM_EQ(msg1, msg2, 32, "chacha20 should be deterministic");

  return 0;
}

/*
 * Test: ChaCha20 - Different counters produce different output
 *
 * Verify that changing the counter changes the keystream
 */
static int test_chacha20_counter(void) {
  uint8_t key[32] = {1, 2, 3};
  uint8_t nonce[8] = {4, 5, 6};
  uint8_t msg1[32] = {0};
  uint8_t msg2[32] = {0};

  urcrypt_chacha_crypt(20, key, nonce, 0, 32, msg1);
  urcrypt_chacha_crypt(20, key, nonce, 1, 32, msg2);

  /* Different counters should produce different keystreams */
  ASSERT(memcmp(msg1, msg2, 32) != 0, "chacha20 different counters should differ");

  return 0;
}

/*
 * Test: HChaCha20 - Key derivation
 *
 * Test vector from draft-irtf-cfrg-xchacha-03
 * HChaCha20 is used to derive a subkey from key+nonce for XChaCha20
 */
static int test_hchacha20_derivation(void) {
  uint8_t key[32];
  uint8_t nonce[24];
  uint8_t out_key[32];
  uint8_t out_nonce[8];
  uint8_t expected_key[32];
  uint8_t expected_nonce[8];

  /* Input key */
  hex_to_bytes("000102030405060708090a0b0c0d0e0f"
               "101112131415161718191a1b1c1d1e1f", key, 32);

  /* Input nonce (24 bytes for XChaCha) */
  hex_to_bytes("000000090000004a00000000314159270000000000000000", nonce, 24);

  /* Expected subkey from HChaCha20 */
  hex_to_bytes("82413b4227b27bfed30e42508a877d73"
               "a0f9e4d58a74a853c12ec41326d3ecdc", expected_key, 32);

  /* Expected output nonce (last 8 bytes of input nonce) */
  hex_to_bytes("0000000000000000", expected_nonce, 8);

  /* Perform HChaCha20 key derivation */
  urcrypt_chacha_xchacha(20, key, nonce, out_key, out_nonce);

  ASSERT_MEM_EQ(out_key, expected_key, 32, "hchacha20 derived key mismatch");
  ASSERT_MEM_EQ(out_nonce, expected_nonce, 8, "hchacha20 output nonce mismatch");

  return 0;
}

/*
 * Test: HChaCha20 - Nonce extraction
 *
 * Verify that the output nonce is correctly extracted from bytes 16-23 of input
 */
static int test_hchacha20_nonce_extraction(void) {
  uint8_t key[32] = {0};
  uint8_t nonce[24];
  uint8_t out_key[32];
  uint8_t out_nonce[8];
  uint8_t expected_nonce[8];

  /* Set nonce with recognizable pattern */
  for (int i = 0; i < 24; i++) {
    nonce[i] = i;
  }

  /* Bytes 16-23 should be copied to output nonce */
  memcpy(expected_nonce, nonce + 16, 8);

  urcrypt_chacha_xchacha(20, key, nonce, out_key, out_nonce);

  ASSERT_MEM_EQ(out_nonce, expected_nonce, 8, "hchacha20 nonce not properly extracted");

  return 0;
}

/*
 * Test: HChaCha20 - Different inputs produce different keys
 *
 * Verify that changing inputs changes the derived key
 */
static int test_hchacha20_uniqueness(void) {
  uint8_t key1[32] = {1, 2, 3};
  uint8_t key2[32] = {1, 2, 4};  /* One byte different */
  uint8_t nonce[24] = {0};
  uint8_t out_key1[32];
  uint8_t out_key2[32];
  uint8_t out_nonce[8];

  urcrypt_chacha_xchacha(20, key1, nonce, out_key1, out_nonce);
  urcrypt_chacha_xchacha(20, key2, nonce, out_key2, out_nonce);

  ASSERT(memcmp(out_key1, out_key2, 32) != 0, "hchacha20 different keys should produce different output");

  return 0;
}

/* Test suite entry point */
int suite_monocypher(void) {
  int suite_failures = 0;

  printf("  Running test_chacha20_zeros...\n");
  if (test_chacha20_zeros() != 0) {
    suite_failures++;
  }

  printf("  Running test_chacha20_sequence...\n");
  if (test_chacha20_sequence() != 0) {
    suite_failures++;
  }

  printf("  Running test_chacha20_text_encrypt...\n");
  if (test_chacha20_text_encrypt() != 0) {
    suite_failures++;
  }

  printf("  Running test_chacha20_determinism...\n");
  if (test_chacha20_determinism() != 0) {
    suite_failures++;
  }

  printf("  Running test_chacha20_counter...\n");
  if (test_chacha20_counter() != 0) {
    suite_failures++;
  }

  printf("  Running test_hchacha20_derivation...\n");
  if (test_hchacha20_derivation() != 0) {
    suite_failures++;
  }

  printf("  Running test_hchacha20_nonce_extraction...\n");
  if (test_hchacha20_nonce_extraction() != 0) {
    suite_failures++;
  }

  printf("  Running test_hchacha20_uniqueness...\n");
  if (test_hchacha20_uniqueness() != 0) {
    suite_failures++;
  }

  return suite_failures;
}
