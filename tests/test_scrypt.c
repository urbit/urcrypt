#include "test_common.h"
#include "urcrypt/urcrypt.h"
#include <string.h>
#include <stdio.h>

/*
 * Scrypt Test Suite
 *
 * Tests for the scrypt password-based key derivation function and PBKDF2-SHA256.
 *
 * Reference test vectors from:
 * - Scrypt: RFC 7914 - The scrypt Password-Based Key Derivation Function
 *   https://tools.ietf.org/html/rfc7914
 * - PBKDF2-SHA256: RFC 6070 - PKCS #5: Password-Based Key Derivation Function 2
 *   https://tools.ietf.org/html/rfc6070
 *
 * Scrypt is designed to be memory-hard (requires O(N) memory) to resist
 * hardware brute-force attacks. Parameters:
 * - N: CPU/memory cost parameter (must be power of 2)
 * - r: block size parameter
 * - p: parallelization parameter
 */

/* Helper function to convert hex string to bytes */
static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
  for (size_t i = 0; i < len; i++) {
    sscanf(hex + 2*i, "%2hhx", &bytes[i]);
  }
}

/*
 * Test: Scrypt - RFC 7914 Test Vector 1
 *
 * Simple test with low parameters (N=16, r=1, p=1)
 */
static int test_scrypt_rfc7914_vector1(void) {
  const char *passwd = "";
  const char *salt = "";
  uint8_t out[64];
  uint8_t expected[64];

  /* RFC 7914 test vector 1: empty password and salt, N=16, r=1, p=1 */
  hex_to_bytes("77d6576238657b203b19ca42c18a0497"
               "f16b4844e3074ae8dfdffa3fede21442"
               "fcd0069ded0948f8326a753a0fc81f17"
               "e8d3e0fb2e0d3628cf35e20c38d18906",
               expected, 64);

  int ret = urcrypt_scrypt((const uint8_t*)passwd, strlen(passwd),
                           (const uint8_t*)salt, strlen(salt),
                           16, 1, 1, 64, out);

  ASSERT(ret == 0, "scrypt should succeed");
  ASSERT_MEM_EQ(out, expected, 64, "scrypt RFC 7914 vector 1 mismatch");

  return 0;
}

/*
 * Test: Scrypt - RFC 7914 Test Vector 2
 *
 * Test with simple password and salt, low parameters
 */
static int test_scrypt_rfc7914_vector2(void) {
  const char *passwd = "password";
  const char *salt = "NaCl";
  uint8_t out[64];
  uint8_t expected[64];

  /* RFC 7914 test vector 2: N=1024, r=8, p=16 */
  hex_to_bytes("fdbabe1c9d3472007856e7190d01e9fe"
               "7c6ad7cbc8237830e77376634b373162"
               "2eaf30d92e22a3886ff109279d9830da"
               "c727afb94a83ee6d8360cbdfa2cc0640",
               expected, 64);

  int ret = urcrypt_scrypt((const uint8_t*)passwd, strlen(passwd),
                           (const uint8_t*)salt, strlen(salt),
                           1024, 8, 16, 64, out);

  ASSERT(ret == 0, "scrypt should succeed");
  ASSERT_MEM_EQ(out, expected, 64, "scrypt RFC 7914 vector 2 mismatch");

  return 0;
}

/*
 * Test: Scrypt - RFC 7914 Test Vector 3
 *
 * Test with longer password and salt, moderate parameters
 */
static int test_scrypt_rfc7914_vector3(void) {
  const char *passwd = "pleaseletmein";
  const char *salt = "SodiumChloride";
  uint8_t out[64];
  uint8_t expected[64];

  /* RFC 7914 test vector 3: N=16384, r=8, p=1 */
  hex_to_bytes("7023bdcb3afd7348461c06cd81fd38eb"
               "fda8fbba904f8e3ea9b543f6545da1f2"
               "d5432955613f0fcf62d49705242a9af9"
               "e61e85dc0d651e40dfcf017b45575887",
               expected, 64);

  int ret = urcrypt_scrypt((const uint8_t*)passwd, strlen(passwd),
                           (const uint8_t*)salt, strlen(salt),
                           16384, 8, 1, 64, out);

  ASSERT(ret == 0, "scrypt should succeed");
  ASSERT_MEM_EQ(out, expected, 64, "scrypt RFC 7914 vector 3 mismatch");

  return 0;
}

/*
 * Test: Scrypt - Short output length
 *
 * Verify scrypt can produce shorter outputs (32 bytes)
 */
static int test_scrypt_short_output(void) {
  const char *passwd = "test";
  const char *salt = "salt";
  uint8_t out[32];

  int ret = urcrypt_scrypt((const uint8_t*)passwd, strlen(passwd),
                           (const uint8_t*)salt, strlen(salt),
                           16, 1, 1, 32, out);

  ASSERT(ret == 0, "scrypt should succeed with 32-byte output");

  /* Verify output is not all zeros */
  int all_zero = 1;
  for (int i = 0; i < 32; i++) {
    if (out[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(all_zero == 0, "scrypt should produce non-zero output");

  return 0;
}

/*
 * Test: Scrypt - Determinism
 *
 * Verify that the same inputs always produce the same output
 */
static int test_scrypt_determinism(void) {
  const char *passwd = "determinism";
  const char *salt = "test";
  uint8_t out1[32];
  uint8_t out2[32];

  urcrypt_scrypt((const uint8_t*)passwd, strlen(passwd),
                 (const uint8_t*)salt, strlen(salt),
                 16, 1, 1, 32, out1);

  urcrypt_scrypt((const uint8_t*)passwd, strlen(passwd),
                 (const uint8_t*)salt, strlen(salt),
                 16, 1, 1, 32, out2);

  ASSERT_MEM_EQ(out1, out2, 32, "scrypt should be deterministic");

  return 0;
}

/*
 * Test: Scrypt - Different parameters produce different outputs
 *
 * Verify that changing N parameter changes the output
 */
static int test_scrypt_parameter_variation(void) {
  const char *passwd = "password";
  const char *salt = "salt";
  uint8_t out1[32];
  uint8_t out2[32];

  urcrypt_scrypt((const uint8_t*)passwd, strlen(passwd),
                 (const uint8_t*)salt, strlen(salt),
                 16, 1, 1, 32, out1);

  urcrypt_scrypt((const uint8_t*)passwd, strlen(passwd),
                 (const uint8_t*)salt, strlen(salt),
                 32, 1, 1, 32, out2);

  ASSERT(memcmp(out1, out2, 32) != 0, "scrypt different N should produce different output");

  return 0;
}

/*
 * Test: PBKDF2-SHA256 - RFC 6070 Test Vector 1
 *
 * Basic test with 1 iteration
 */
static int test_pbkdf2_rfc6070_vector1(void) {
  const char *passwd = "password";
  const char *salt = "salt";
  uint8_t out[20];
  uint8_t expected[20];

  /* RFC 6070 test vector 1: 1 iteration */
  hex_to_bytes("120fb6cffcf8b32c43e7225256c4f837a86548c9", expected, 20);

  urcrypt_scrypt_pbkdf_sha256((const uint8_t*)passwd, strlen(passwd),
                              (const uint8_t*)salt, strlen(salt),
                              1, 20, out);

  ASSERT_MEM_EQ(out, expected, 20, "pbkdf2 RFC 6070 vector 1 mismatch");

  return 0;
}

/*
 * Test: PBKDF2-SHA256 - RFC 6070 Test Vector 2
 *
 * Test with 2 iterations
 */
static int test_pbkdf2_rfc6070_vector2(void) {
  const char *passwd = "password";
  const char *salt = "salt";
  uint8_t out[20];
  uint8_t expected[20];

  /* RFC 6070 test vector 2: 2 iterations */
  hex_to_bytes("ae4d0c95af6b46d32d0adff928f06dd02a303f8e", expected, 20);

  urcrypt_scrypt_pbkdf_sha256((const uint8_t*)passwd, strlen(passwd),
                              (const uint8_t*)salt, strlen(salt),
                              2, 20, out);

  ASSERT_MEM_EQ(out, expected, 20, "pbkdf2 RFC 6070 vector 2 mismatch");

  return 0;
}

/*
 * Test: PBKDF2-SHA256 - RFC 6070 Test Vector 3
 *
 * Test with 4096 iterations (more realistic for password hashing)
 */
static int test_pbkdf2_rfc6070_vector3(void) {
  const char *passwd = "password";
  const char *salt = "salt";
  uint8_t out[20];
  uint8_t expected[20];

  /* RFC 6070 test vector 3: 4096 iterations */
  hex_to_bytes("c5e478d59288c841aa530db6845c4c8d962893a0", expected, 20);

  urcrypt_scrypt_pbkdf_sha256((const uint8_t*)passwd, strlen(passwd),
                              (const uint8_t*)salt, strlen(salt),
                              4096, 20, out);

  ASSERT_MEM_EQ(out, expected, 20, "pbkdf2 RFC 6070 vector 3 mismatch");

  return 0;
}

/*
 * Test: PBKDF2-SHA256 - RFC 6070 Test Vector 4
 *
 * Test with longer password (25 characters)
 */
static int test_pbkdf2_rfc6070_vector4(void) {
  const char *passwd = "passwordPASSWORDpassword";
  const char *salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
  uint8_t out[25];
  uint8_t expected[25];

  /* RFC 6070 test vector 4: 4096 iterations, longer inputs */
  hex_to_bytes("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c", expected, 25);

  urcrypt_scrypt_pbkdf_sha256((const uint8_t*)passwd, strlen(passwd),
                              (const uint8_t*)salt, strlen(salt),
                              4096, 25, out);

  ASSERT_MEM_EQ(out, expected, 25, "pbkdf2 RFC 6070 vector 4 mismatch");

  return 0;
}

/*
 * Test: PBKDF2-SHA256 - Determinism
 *
 * Verify that the same inputs always produce the same output
 */
static int test_pbkdf2_determinism(void) {
  const char *passwd = "test";
  const char *salt = "salt";
  uint8_t out1[32];
  uint8_t out2[32];

  urcrypt_scrypt_pbkdf_sha256((const uint8_t*)passwd, strlen(passwd),
                              (const uint8_t*)salt, strlen(salt),
                              100, 32, out1);

  urcrypt_scrypt_pbkdf_sha256((const uint8_t*)passwd, strlen(passwd),
                              (const uint8_t*)salt, strlen(salt),
                              100, 32, out2);

  ASSERT_MEM_EQ(out1, out2, 32, "pbkdf2 should be deterministic");

  return 0;
}

/*
 * Test: PBKDF2-SHA256 - Different iteration counts produce different outputs
 *
 * Verify that changing iteration count changes the output
 */
static int test_pbkdf2_iteration_variation(void) {
  const char *passwd = "password";
  const char *salt = "salt";
  uint8_t out1[32];
  uint8_t out2[32];

  urcrypt_scrypt_pbkdf_sha256((const uint8_t*)passwd, strlen(passwd),
                              (const uint8_t*)salt, strlen(salt),
                              1, 32, out1);

  urcrypt_scrypt_pbkdf_sha256((const uint8_t*)passwd, strlen(passwd),
                              (const uint8_t*)salt, strlen(salt),
                              2, 32, out2);

  ASSERT(memcmp(out1, out2, 32) != 0, "pbkdf2 different iterations should produce different output");

  return 0;
}

/* Test suite entry point */
int suite_scrypt(void) {
  int suite_failures = 0;

  printf("  Running test_scrypt_rfc7914_vector1...\n");
  if (test_scrypt_rfc7914_vector1() != 0) {
    suite_failures++;
  }

  printf("  Running test_scrypt_rfc7914_vector2...\n");
  if (test_scrypt_rfc7914_vector2() != 0) {
    suite_failures++;
  }

  printf("  Running test_scrypt_rfc7914_vector3...\n");
  if (test_scrypt_rfc7914_vector3() != 0) {
    suite_failures++;
  }

  printf("  Running test_scrypt_short_output...\n");
  if (test_scrypt_short_output() != 0) {
    suite_failures++;
  }

  printf("  Running test_scrypt_determinism...\n");
  if (test_scrypt_determinism() != 0) {
    suite_failures++;
  }

  printf("  Running test_scrypt_parameter_variation...\n");
  if (test_scrypt_parameter_variation() != 0) {
    suite_failures++;
  }

  printf("  Running test_pbkdf2_rfc6070_vector1...\n");
  if (test_pbkdf2_rfc6070_vector1() != 0) {
    suite_failures++;
  }

  printf("  Running test_pbkdf2_rfc6070_vector2...\n");
  if (test_pbkdf2_rfc6070_vector2() != 0) {
    suite_failures++;
  }

  printf("  Running test_pbkdf2_rfc6070_vector3...\n");
  if (test_pbkdf2_rfc6070_vector3() != 0) {
    suite_failures++;
  }

  printf("  Running test_pbkdf2_rfc6070_vector4...\n");
  if (test_pbkdf2_rfc6070_vector4() != 0) {
    suite_failures++;
  }

  printf("  Running test_pbkdf2_determinism...\n");
  if (test_pbkdf2_determinism() != 0) {
    suite_failures++;
  }

  printf("  Running test_pbkdf2_iteration_variation...\n");
  if (test_pbkdf2_iteration_variation() != 0) {
    suite_failures++;
  }

  return suite_failures;
}
