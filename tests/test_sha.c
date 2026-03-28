#include "test_common.h"
#include "urcrypt/urcrypt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * SHA Test Suite
 *
 * Tests for SHA-1, SHA-256, SHA-512, and SHA-256 with salt functions.
 *
 * Reference test vectors from:
 * - SHA-1/256/512: NIST CAVP Secure Hashing
 *   https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
 */

/*
 * ============================================================================
 * SHA-1 Tests
 * ============================================================================
 */

/*
 * Test: SHA-1 - Empty string
 */
static int test_sha1_empty(void) {
  uint8_t message[1] = {0};  /* Empty message, use array not literal */
  uint8_t out[20];
  uint8_t expected[20];

  /* SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709 (big-endian)
   * urcrypt reverses input and output, so we reverse the expected vector */
  hex_to_bytes("da39a3ee5e6b4b0d3255bfef95601890afd80709", expected, 20);
  urcrypt__reverse(20, expected);

  urcrypt_sha1(message, 0, out);

  ASSERT_MEM_EQ(out, expected, 20, "sha1 empty string mismatch");

  return 0;
}

static int test_sha1_abc(void) {
  uint8_t message[3] = "abc";
  uint8_t out[20];
  uint8_t expected[20];

  urcrypt__reverse(3, message);
  hex_to_bytes("a9993e364706816aba3e25717850c26c9cd0d89d", expected, 20);
  urcrypt__reverse(20, expected);

  urcrypt_sha1(message, 3, out);

  ASSERT_MEM_EQ(out, expected, 20, "sha1 'abc' mismatch");

  return 0;
}

/*
 * Test: SHA-1 - Longer string
 */
static int test_sha1_longer(void) {
  uint8_t message[56] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  uint8_t out[20];
  uint8_t expected[20];

  urcrypt__reverse(56, message);
  hex_to_bytes("84983e441c3bd26ebaae4aa1f95129e5e54670f1", expected, 20);
  urcrypt__reverse(20, expected);

  urcrypt_sha1(message, 56, out);

  ASSERT_MEM_EQ(out, expected, 20, "sha1 longer string mismatch");

  return 0;
}

/*
 * Test: SHA-1 - Even longer string
 */
static int test_sha1_longer2(void) {
  uint8_t message[112] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  uint8_t out[20];
  uint8_t expected[20];

  urcrypt__reverse(112, message);
  hex_to_bytes("a49b2446a02c645bf419f995b67091253a04a259", expected, 20);
  urcrypt__reverse(20, expected);

  urcrypt_sha1(message, 112, out);

  ASSERT_MEM_EQ(out, expected, 20, "sha1 even longer string mismatch");

  return 0;
}

/*
 * Test: SHA-1 - Determinism
 */
static int test_sha1_determinism(void) {
  uint8_t message1[] = "test message for sha1";
  uint8_t message2[] = "test message for sha1";
  uint8_t out1[20];
  uint8_t out2[20];

  urcrypt_sha1(message1, 21, out1);
  urcrypt_sha1(message2, 21, out2);

  ASSERT_MEM_EQ(out1, out2, 20, "sha1 should be deterministic");

  /* Verify output is not all zeros */
  int all_zero = 1;
  for (int i = 0; i < 20; i++) {
    if (out1[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(all_zero == 0, "sha1 should produce non-zero output");

  return 0;
}

/*
 * ============================================================================
 * SHA-256 Tests
 * ============================================================================
 */

/*
 * Test: SHA-256 - Empty string
 */
static int test_sha256_empty(void) {
  uint8_t out[32];
  uint8_t expected[32];

  /* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
  hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", expected, 32);

  urcrypt_shay((uint8_t*)"", 0, out);

  ASSERT_MEM_EQ(out, expected, 32, "sha256 empty string mismatch");

  return 0;
}

/*
 * Test: SHA-256 - "abc"
 */
static int test_sha256_abc(void) {
  const char *message = "abc";
  uint8_t out[32];
  uint8_t expected[32];

  /* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
  hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", expected, 32);

  urcrypt_shay((uint8_t*)message, strlen(message), out);

  ASSERT_MEM_EQ(out, expected, 32, "sha256 'abc' mismatch");

  return 0;
}

/*
 * Test: SHA-256 - Longer message
 */
static int test_sha256_longer(void) {
  const char *message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  uint8_t out[32];
  uint8_t expected[32];

  /* SHA-256 of message above */
  hex_to_bytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", expected, 32);

  urcrypt_shay((uint8_t*)message, strlen(message), out);

  ASSERT_MEM_EQ(out, expected, 32, "sha256 longer message mismatch");

  return 0;
}

/*
 * Test: SHA-256 - Even longer message
 */
static int test_sha256_longer2(void) {
  const char *message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  uint8_t out[32];
  uint8_t expected[32];

  /* SHA-256 of message above */
  hex_to_bytes("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1", expected, 32);

  urcrypt_shay((uint8_t*)message, strlen(message), out);

  ASSERT_MEM_EQ(out, expected, 32, "sha256 longer message mismatch");

  return 0;
}

/*
 * ============================================================================
 * SHA-512 Tests
 * ============================================================================
 */

/*
 * Test: SHA-512 - Empty string
 */
static int test_sha512_empty(void) {
  uint8_t out[64];
  uint8_t expected[64];

  /* SHA-512("") */
  hex_to_bytes("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
               "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
               expected, 64);

  urcrypt_shal((uint8_t*)"", 0, out);

  ASSERT_MEM_EQ(out, expected, 64, "sha512 empty string mismatch");

  return 0;
}

/*
 * Test: SHA-512 - "abc"
 */
static int test_sha512_abc(void) {
  const char *message = "abc";
  uint8_t out[64];
  uint8_t expected[64];

  /* SHA-512("abc") */
  hex_to_bytes("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
               "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
               expected, 64);

  urcrypt_shal((uint8_t*)message, strlen(message), out);

  ASSERT_MEM_EQ(out, expected, 64, "sha512 'abc' mismatch");

  return 0;
}

/*
 * Test: SHA-512 - Longer string
 */
static int test_sha512_longer(void) {
  const char *message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  uint8_t out[64];
  uint8_t expected[64];

  /* SHA-512(message) */
  hex_to_bytes("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
               "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
               expected, 64);

  urcrypt_shal((uint8_t*)message, strlen(message), out);

  ASSERT_MEM_EQ(out, expected, 64, "sha512 longer string mismatch");

  return 0;
}

/*
 * Test: SHA-512 - Even longer string
 */
static int test_sha512_longer2(void) {
  const char *message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  uint8_t out[64];
  uint8_t expected[64];

  /* SHA-512(message) */
  hex_to_bytes("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
               "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
               expected, 64);

  urcrypt_shal((uint8_t*)message, strlen(message), out);

  ASSERT_MEM_EQ(out, expected, 64, "sha512 even longer string mismatch");

  return 0;
}

/*
 * ============================================================================
 * SHA-256 with Salt Tests
 * ============================================================================
 */

/*
 * Test: SHA-256 with salt - Basic test
 *
 * Note: urcrypt_shas computes SHA-256(salt XOR SHA-256(message))
 */
static int test_sha256_salt(void) {
  uint8_t message[] = "test message";
  uint8_t salt[] = "salt";
  uint8_t out[32];

  urcrypt_shas(salt, 4,
               message, 12,
               out);

  /* Verify output is not all zeros */
  int all_zero = 1;
  for (int i = 0; i < 32; i++) {
    if (out[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(all_zero == 0, "sha256 with salt should produce non-zero output");

  /* Test determinism */
  uint8_t out2[32];
  uint8_t salt2[] = "salt";
  uint8_t message2[] = "test message";
  urcrypt_shas(salt2, 4,
               message2, 12,
               out2);

  ASSERT_MEM_EQ(out, out2, 32, "sha256 with salt should be deterministic");

  return 0;
}

/* Test suite entry point */
int suite_sha(void) {
  int suite_failures = 0;

  RUN_TEST(test_sha1_empty);
  RUN_TEST(test_sha1_abc);
  RUN_TEST(test_sha1_longer);
  RUN_TEST(test_sha1_longer2);
  RUN_TEST(test_sha1_determinism);
  RUN_TEST(test_sha256_empty);
  RUN_TEST(test_sha256_abc);
  RUN_TEST(test_sha256_longer);
  RUN_TEST(test_sha256_longer2);
  RUN_TEST(test_sha512_empty);
  RUN_TEST(test_sha512_abc);
  RUN_TEST(test_sha512_longer);
  RUN_TEST(test_sha512_longer2);
  RUN_TEST(test_sha256_salt);

  return suite_failures;
}
