#include "test_common.h"
#include "urcrypt/urcrypt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * RIPEMD-160 Test Suite
 *
 * Tests for RIPEMD-160 hash functions.
 *
 * Reference test vectors from:
 * - RIPEMD-160: Official RIPEMD-160 page
 *   https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 */

/*
 * Test: RIPEMD-160 - Empty string
 */
static int test_ripemd160_empty(void) {
  uint8_t message[1] = {0};
  uint8_t out[20];
  uint8_t expected[20];

  /* RIPEMD-160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31 (big-endian)
   * urcrypt reverses input and output, so we reverse the expected vector */
  hex_to_bytes("9c1185a5c5e9fc54612808977ee8f548b2258d31", expected, 20);
  urcrypt__reverse(20, expected);

  int ret = urcrypt_ripemd160(message, 0, out);

  ASSERT(ret == 0, "ripemd160 should succeed");
  ASSERT_MEM_EQ(out, expected, 20, "ripemd160 empty string mismatch");

  return 0;
}

/*
 * Test: RIPEMD-160 - Determinism
 */
static int test_ripemd160_determinism(void) {
  uint8_t message1[] = "test ripemd160";
  uint8_t message2[] = "test ripemd160";
  uint8_t out1[20];
  uint8_t out2[20];

  int ret1 = urcrypt_ripemd160(message1, 14, out1);
  int ret2 = urcrypt_ripemd160(message2, 14, out2);

  ASSERT(ret1 == 0, "ripemd160 should succeed");
  ASSERT(ret2 == 0, "ripemd160 should succeed");
  ASSERT_MEM_EQ(out1, out2, 20, "ripemd160 should be deterministic");

  /* Verify output is not all zeros */
  int all_zero = 1;
  for (int i = 0; i < 20; i++) {
    if (out1[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(all_zero == 0, "ripemd160 should produce non-zero output");

  return 0;
}

/* Test suite entry point */
int suite_ripemd(void) {
  int suite_failures = 0;

  RUN_TEST(test_ripemd160_empty);
  RUN_TEST(test_ripemd160_determinism);

  return suite_failures;
}
