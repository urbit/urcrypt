#include "test_common.h"
#include "urcrypt/urcrypt.h"
#include <string.h>

/*
 * Argon2 Test Suite
 *
 * Tests for the Argon2 password hashing functionality using reference vectors.
 * These tests account for urcrypt's little-endian byte order convention.
 */

/*
 * Helper: Reverse a string in place
 */
static void reverse_string(char *str, size_t len) {
  for (size_t i = 0; i < len/2; i++) {
    char tmp = str[i];
    str[i] = str[len - 1 - i];
    str[len - 1 - i] = tmp;
  }
}

/*
 * Test argon2i with reference vector from argon2 test.c
 * password="password", salt="somesalt", t=2, m=65536, p=1, v=0x10
 * Reference output: f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694
 */
static int test_argon2i_reference_vector_1(void) {
  uint8_t out[32];
  const char *error;

  /* Pre-reverse inputs for urcrypt's little-endian convention */
  char pwd[] = "password";
  char slt[] = "somesalt";
  reverse_string(pwd, 8);
  reverse_string(slt, 8);

  /* Expected output (reversed from reference) */
  uint8_t expected[32];
  hex_to_bytes("f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694", expected, 32);
  urcrypt__reverse(32, expected);

  error = urcrypt_argon2(
    urcrypt_argon2_i, 0x10, 1, 65536, 2,
    0, NULL, 0, NULL,
    8, (uint8_t*)pwd, 8, (uint8_t*)slt,
    32, out, NULL, NULL
  );

  ASSERT(error == NULL, "argon2i reference vector 1 should succeed");
  ASSERT_MEM_EQ(out, expected, 32, "argon2i reference vector 1 output mismatch");

  return 0;
}

/*
 * Test argon2i with lower memory cost
 * password="password", salt="somesalt", t=2, m=256, p=1, v=0x10
 * Reference output: fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06
 */
static int test_argon2i_reference_vector_2(void) {
  uint8_t out[32];
  const char *error;

  char pwd[] = "password";
  char slt[] = "somesalt";
  reverse_string(pwd, 8);
  reverse_string(slt, 8);

  uint8_t expected[32];
  hex_to_bytes("fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06", expected, 32);
  urcrypt__reverse(32, expected);

  error = urcrypt_argon2(
    urcrypt_argon2_i, 0x10, 1, 256, 2,
    0, NULL, 0, NULL,
    8, (uint8_t*)pwd, 8, (uint8_t*)slt,
    32, out, NULL, NULL
  );

  ASSERT(error == NULL, "argon2i reference vector 2 should succeed");
  ASSERT_MEM_EQ(out, expected, 32, "argon2i reference vector 2 output mismatch");

  return 0;
}

/*
 * Test argon2i with different parallelism
 * password="password", salt="somesalt", t=2, m=256, p=2, v=0x10
 * Reference output: b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb
 */
static int test_argon2i_reference_vector_3(void) {
  uint8_t out[32];
  const char *error;

  char pwd[] = "password";
  char slt[] = "somesalt";
  reverse_string(pwd, 8);
  reverse_string(slt, 8);

  uint8_t expected[32];
  hex_to_bytes("b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb", expected, 32);
  urcrypt__reverse(32, expected);

  error = urcrypt_argon2(
    urcrypt_argon2_i, 0x10, 2, 256, 2,
    0, NULL, 0, NULL,
    8, (uint8_t*)pwd, 8, (uint8_t*)slt,
    32, out, NULL, NULL
  );

  ASSERT(error == NULL, "argon2i reference vector 3 should succeed");
  ASSERT_MEM_EQ(out, expected, 32, "argon2i reference vector 3 output mismatch");

  return 0;
}

/*
 * Test argon2i with different password
 * password="differentpassword", salt="somesalt", t=2, m=65536, p=1, v=0x10
 * Reference output: e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3
 */
static int test_argon2i_reference_vector_4(void) {
  uint8_t out[32];
  const char *error;

  char pwd[] = "differentpassword";
  char slt[] = "somesalt";
  reverse_string(pwd, 17);
  reverse_string(slt, 8);

  uint8_t expected[32];
  hex_to_bytes("e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3", expected, 32);
  urcrypt__reverse(32, expected);

  error = urcrypt_argon2(
    urcrypt_argon2_i, 0x10, 1, 65536, 2,
    0, NULL, 0, NULL,
    17, (uint8_t*)pwd, 8, (uint8_t*)slt,
    32, out, NULL, NULL
  );

  ASSERT(error == NULL, "argon2i reference vector 4 should succeed");
  ASSERT_MEM_EQ(out, expected, 32, "argon2i reference vector 4 output mismatch");

  return 0;
}

/*
 * Test argon2i with different salt
 * password="password", salt="diffsalt", t=2, m=65536, p=1, v=0x10
 * Reference output: 79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497
 */
static int test_argon2i_reference_vector_5(void) {
  uint8_t out[32];
  const char *error;

  char pwd[] = "password";
  char slt[] = "diffsalt";
  reverse_string(pwd, 8);
  reverse_string(slt, 8);

  uint8_t expected[32];
  hex_to_bytes("79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497", expected, 32);
  urcrypt__reverse(32, expected);

  error = urcrypt_argon2(
    urcrypt_argon2_i, 0x10, 1, 65536, 2,
    0, NULL, 0, NULL,
    8, (uint8_t*)pwd, 8, (uint8_t*)slt,
    32, out, NULL, NULL
  );

  ASSERT(error == NULL, "argon2i reference vector 5 should succeed");
  ASSERT_MEM_EQ(out, expected, 32, "argon2i reference vector 5 output mismatch");

  return 0;
}

/*
 * Test all four argon2 variants produce different outputs
 */
static int test_argon2_variants(void) {
  uint8_t out_d[32], out_i[32], out_id[32], out_u[32];
  const char *error;

  /* Use simple inputs for this test */
  char pwd[] = "testpass";
  char slt[] = "testsalt";
  reverse_string(pwd, 8);
  reverse_string(slt, 8);

  /* Test argon2d */
  char pwd_d[9], slt_d[9];
  memcpy(pwd_d, pwd, 9);
  memcpy(slt_d, slt, 9);
  error = urcrypt_argon2(urcrypt_argon2_d, 0x13, 1, 256, 2,
    0, NULL, 0, NULL, 8, (uint8_t*)pwd_d, 8, (uint8_t*)slt_d, 32, out_d, NULL, NULL);
  ASSERT(error == NULL, "argon2d should succeed");

  /* Test argon2i */
  char pwd_i[9], slt_i[9];
  memcpy(pwd_i, pwd, 9);
  memcpy(slt_i, slt, 9);
  error = urcrypt_argon2(urcrypt_argon2_i, 0x13, 1, 256, 2,
    0, NULL, 0, NULL, 8, (uint8_t*)pwd_i, 8, (uint8_t*)slt_i, 32, out_i, NULL, NULL);
  ASSERT(error == NULL, "argon2i should succeed");

  /* Test argon2id */
  char pwd_id[9], slt_id[9];
  memcpy(pwd_id, pwd, 9);
  memcpy(slt_id, slt, 9);
  error = urcrypt_argon2(urcrypt_argon2_id, 0x13, 1, 256, 2,
    0, NULL, 0, NULL, 8, (uint8_t*)pwd_id, 8, (uint8_t*)slt_id, 32, out_id, NULL, NULL);
  ASSERT(error == NULL, "argon2id should succeed");

  /* Test argon2u */
  char pwd_u[9], slt_u[9];
  memcpy(pwd_u, pwd, 9);
  memcpy(slt_u, slt, 9);
  error = urcrypt_argon2(urcrypt_argon2_u, 0x13, 1, 256, 2,
    0, NULL, 0, NULL, 8, (uint8_t*)pwd_u, 8, (uint8_t*)slt_u, 32, out_u, NULL, NULL);
  ASSERT(error == NULL, "argon2u should succeed");

  /* All variants should produce different outputs */
  ASSERT(memcmp(out_d, out_i, 32) != 0, "argon2d and argon2i should differ");
  ASSERT(memcmp(out_d, out_id, 32) != 0, "argon2d and argon2id should differ");
  ASSERT(memcmp(out_i, out_id, 32) != 0, "argon2i and argon2id should differ");

  return 0;
}

/*
 * Test with optional secret and associated data
 */
static int test_argon2_with_optional_params(void) {
  uint8_t out[32];
  const char *error;

  char pwd[] = "password";
  char slt[] = "somesalt";
  char sec[] = "secret";
  char asc[] = "associated";

  reverse_string(pwd, 8);
  reverse_string(slt, 8);
  reverse_string(sec, 6);
  reverse_string(asc, 10);

  error = urcrypt_argon2(
    urcrypt_argon2_i, 0x13, 1, 256, 2,
    6, (uint8_t*)sec,
    10, (uint8_t*)asc,
    8, (uint8_t*)pwd, 8, (uint8_t*)slt,
    32, out, NULL, NULL
  );

  ASSERT(error == NULL, "argon2 with optional params should succeed");

  return 0;
}

/*
 * Test error handling: invalid type
 */
static int test_argon2_invalid_type(void) {
  uint8_t out[32];
  const char *error;

  char pwd[] = "password";
  char slt[] = "somesalt";
  reverse_string(pwd, 8);
  reverse_string(slt, 8);

  error = urcrypt_argon2(99, 0x13, 1, 256, 2,
    0, NULL, 0, NULL, 8, (uint8_t*)pwd, 8, (uint8_t*)slt, 32, out, NULL, NULL);

  ASSERT(error != NULL, "invalid type should return error");
  ASSERT(strstr(error, "unknown type") != NULL, "error should mention unknown type");

  return 0;
}

/*
 * Test urcrypt_blake2 with reference vector
 * The BLAKE2b reference for empty message with no key:
 * 786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce
 * (for 64-byte output)
 */
static int test_blake2_reference_vector(void) {
  uint8_t out[64];
  int result;

  /* Empty message */
  uint8_t msg[1] = {0};

  /* Expected output (reversed for urcrypt) */
  uint8_t expected[64];
  hex_to_bytes("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
               "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
               expected, 64);
  urcrypt__reverse(64, expected);

  result = urcrypt_blake2(0, msg, 0, NULL, 64, out);

  ASSERT(result == 0, "blake2 reference vector should succeed");
  ASSERT_MEM_EQ(out, expected, 64, "blake2 reference vector output mismatch");

  return 0;
}

/*
 * Test urcrypt_blake2 with key
 */
static int test_blake2_with_key(void) {
  uint8_t out[32];
  int result;

  char msg[] = "hello";
  uint8_t key[16] = {0};
  reverse_string(msg, 5);
  urcrypt__reverse(16, key);

  result = urcrypt_blake2(5, (uint8_t*)msg, 16, key, 32, out);

  ASSERT(result == 0, "blake2 with key should succeed");

  return 0;
}

/*
 * Test urcrypt_blake2 determinism
 */
static int test_blake2_determinism(void) {
  uint8_t out1[64], out2[64];
  int result;

  char msg1[] = "test message";
  char msg2[] = "test message";
  uint8_t key1[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint8_t key2[8] = {1, 2, 3, 4, 5, 6, 7, 8};

  reverse_string(msg1, 12);
  reverse_string(msg2, 12);
  urcrypt__reverse(8, key1);
  urcrypt__reverse(8, key2);

  result = urcrypt_blake2(12, (uint8_t*)msg1, 8, key1, 64, out1);
  ASSERT(result == 0, "first blake2 run should succeed");

  result = urcrypt_blake2(12, (uint8_t*)msg2, 8, key2, 64, out2);
  ASSERT(result == 0, "second blake2 run should succeed");

  ASSERT_MEM_EQ(out1, out2, 64, "same inputs should produce same output");

  return 0;
}

/*
 * Test urcrypt_blake2 error: key too long
 */
static int test_blake2_key_too_long(void) {
  uint8_t out[32];
  int result;

  char msg[] = "hello";
  uint8_t key[65];
  memset(key, 0, 65);

  result = urcrypt_blake2(5, (uint8_t*)msg, 65, key, 32, out);

  ASSERT(result == -1, "blake2 with oversized key should fail");

  return 0;
}

/* Test suite entry point */
int suite_argon2(void) {
  int suite_failures = 0;

  RUN_TEST(test_argon2i_reference_vector_1);
  RUN_TEST(test_argon2i_reference_vector_2);
  RUN_TEST(test_argon2i_reference_vector_3);
  RUN_TEST(test_argon2i_reference_vector_4);
  RUN_TEST(test_argon2i_reference_vector_5);
  RUN_TEST(test_argon2_variants);
  RUN_TEST(test_argon2_with_optional_params);
  RUN_TEST(test_argon2_invalid_type);
  RUN_TEST(test_blake2_reference_vector);
  RUN_TEST(test_blake2_with_key);
  RUN_TEST(test_blake2_determinism);
  RUN_TEST(test_blake2_key_too_long);

  return suite_failures;
}
