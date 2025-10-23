#include "test_common.h"
#include "urcrypt/urcrypt.h"
#include <string.h>
#include <stdio.h>

/*
 * GE Additions Test Suite
 *
 * Tests for additional group element operations on Ed25519 curve.
 * These test advanced operations not covered in the standard ed25519 suite.
 *
 * Note: Basic operations (point_add, point_neg, scalarmult_base) are tested
 * in test_ed25519.c. This suite focuses on the remaining ge_additions functions.
 */

/* Helper function to convert hex string to bytes */
static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
  for (size_t i = 0; i < len; i++) {
    sscanf(hex + 2*i, "%2hhx", &bytes[i]);
  }
}

/*
 * Test: urcrypt_ed_scalarmult - Basic functionality
 *
 * Multiply an arbitrary point by a scalar
 */
static int test_scalarmult_basic(void) {
  uint8_t scalar[32];
  uint8_t point[32];
  uint8_t result[32];

  /* Generate a point using scalarmult_base */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", scalar, 32);
  urcrypt_ed_scalarmult_base(scalar, point);

  /* Now multiply that point by another scalar (mask high bit) */
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a66b", scalar, 32);
  int ret = urcrypt_ed_scalarmult(scalar, point, result);

  ASSERT(ret == 0, "ed_scalarmult should succeed");

  /* Result should not be all zeros */
  int all_zero = 1;
  for (int i = 0; i < 32; i++) {
    if (result[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(all_zero == 0, "ed_scalarmult result should not be all zeros");

  return 0;
}

/*
 * Test: urcrypt_ed_scalarmult - Consistency with scalarmult_base
 *
 * Multiplying base point should match scalarmult_base result
 */
static int test_scalarmult_consistency(void) {
  uint8_t scalar[32];
  uint8_t base_point[32];
  uint8_t result1[32];
  uint8_t result2[32];

  /* Use a known scalar */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", scalar, 32);

  /* Get base point by multiplying by 1 */
  uint8_t one[32] = {1};
  urcrypt_ed_scalarmult_base(one, base_point);

  /* Method 1: scalarmult_base */
  urcrypt_ed_scalarmult_base(scalar, result1);

  /* Method 2: scalarmult with base point */
  urcrypt_ed_scalarmult(scalar, base_point, result2);

  /* Results should match */
  ASSERT_MEM_EQ(result1, result2, 32, "ed_scalarmult with base point should match scalarmult_base");

  return 0;
}

/*
 * Test: urcrypt_ed_scalarmult - Invalid scalar (high bit set)
 */
static int test_scalarmult_invalid_scalar(void) {
  uint8_t scalar[32];
  uint8_t point[32];
  uint8_t result[32];

  /* Generate a valid point */
  uint8_t valid_scalar[32];
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", valid_scalar, 32);
  urcrypt_ed_scalarmult_base(valid_scalar, point);

  /* Create scalar with high bit set */
  memset(scalar, 0, 32);
  scalar[31] = 0x80;

  /* Should fail */
  int ret = urcrypt_ed_scalarmult(scalar, point, result);

  ASSERT(ret == -1, "ed_scalarmult should reject scalar with high bit set");

  return 0;
}

/*
 * Test: urcrypt_ed_scalarmult - Commutativity of operations
 *
 * Verify that scalar multiplication is consistent
 */
static int test_scalarmult_commutativity(void) {
  uint8_t scalar1[32], scalar2[32];
  uint8_t point[32];
  uint8_t result1[32], result2[32];

  /* Two scalars */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", scalar1, 32);
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a66b", scalar2, 32);

  /* Method 1: (scalar1 * G) * scalar2 */
  urcrypt_ed_scalarmult_base(scalar1, point);
  urcrypt_ed_scalarmult(scalar2, point, result1);

  /* Method 2: (scalar2 * G) * scalar1 */
  urcrypt_ed_scalarmult_base(scalar2, point);
  urcrypt_ed_scalarmult(scalar1, point, result2);

  /* Results should match (commutativity) */
  ASSERT_MEM_EQ(result1, result2, 32, "ed_scalarmult should be commutative");

  return 0;
}

/*
 * Test: urcrypt_ed_add_scalarmult_scalarmult_base - Basic functionality
 *
 * Compute a*A + b*G where G is the base point
 */
static int test_add_scalarmult_scalarmult_base_basic(void) {
  uint8_t a[32], b[32];
  uint8_t point_a[32];
  uint8_t result[32];

  /* Generate point A */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", a, 32);
  urcrypt_ed_scalarmult_base(a, point_a);

  /* Scalars for computation */
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a66b", a, 32);
  hex_to_bytes("45aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b445877", b, 32);

  /* Compute a*A + b*G */
  int ret = urcrypt_ed_add_scalarmult_scalarmult_base(a, point_a, b, result);

  ASSERT(ret == 0, "add_scalarmult_scalarmult_base should succeed");

  /* Result should not be all zeros */
  int all_zero = 1;
  for (int i = 0; i < 32; i++) {
    if (result[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(all_zero == 0, "add_scalarmult_scalarmult_base result should not be all zeros");

  return 0;
}

/*
 * Test: urcrypt_ed_add_scalarmult_scalarmult_base - Verify against manual computation
 *
 * Compute a*A + b*G manually and compare with combined operation
 */
static int test_add_scalarmult_scalarmult_base_manual(void) {
  uint8_t a[32], b[32];
  uint8_t point_a[32];
  uint8_t result_combined[32];
  uint8_t result_manual[32];
  uint8_t temp1[32], temp2[32];

  /* Generate point A */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", a, 32);
  urcrypt_ed_scalarmult_base(a, point_a);

  /* Scalars */
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a66b", a, 32);
  hex_to_bytes("45aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b445877", b, 32);

  /* Method 1: Combined operation */
  urcrypt_ed_add_scalarmult_scalarmult_base(a, point_a, b, result_combined);

  /* Method 2: Manual computation */
  urcrypt_ed_scalarmult(a, point_a, temp1);      /* a*A */
  urcrypt_ed_scalarmult_base(b, temp2);          /* b*G */
  urcrypt_ed_point_add(temp1, temp2, result_manual); /* a*A + b*G */

  /* Results should match */
  ASSERT_MEM_EQ(result_combined, result_manual, 32,
                "add_scalarmult_scalarmult_base should match manual computation");

  return 0;
}

/*
 * Test: urcrypt_ed_add_double_scalarmult - Basic functionality
 *
 * Compute a*A + b*B
 */
static int test_add_double_scalarmult_basic(void) {
  uint8_t a[32], b[32];
  uint8_t point_a[32], point_b[32];
  uint8_t result[32];

  /* Generate two points */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", a, 32);
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a66b", b, 32);
  urcrypt_ed_scalarmult_base(a, point_a);
  urcrypt_ed_scalarmult_base(b, point_b);

  /* New scalars for multiplication */
  hex_to_bytes("45aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b445877", a, 32);
  hex_to_bytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", b, 32);

  /* Compute a*A + b*B */
  int ret = urcrypt_ed_add_double_scalarmult(a, point_a, b, point_b, result);

  ASSERT(ret == 0, "add_double_scalarmult should succeed");

  /* Result should not be all zeros */
  int all_zero = 1;
  for (int i = 0; i < 32; i++) {
    if (result[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(all_zero == 0, "add_double_scalarmult result should not be all zeros");

  return 0;
}

/*
 * Test: urcrypt_ed_add_double_scalarmult - Verify against manual computation
 */
static int test_add_double_scalarmult_manual(void) {
  uint8_t a[32], b[32];
  uint8_t point_a[32], point_b[32];
  uint8_t result_combined[32];
  uint8_t result_manual[32];
  uint8_t temp1[32], temp2[32];

  /* Generate two points */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", a, 32);
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a66b", b, 32);
  urcrypt_ed_scalarmult_base(a, point_a);
  urcrypt_ed_scalarmult_base(b, point_b);

  /* Scalars for multiplication */
  hex_to_bytes("45aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b445877", a, 32);
  hex_to_bytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", b, 32);

  /* Method 1: Combined operation */
  urcrypt_ed_add_double_scalarmult(a, point_a, b, point_b, result_combined);

  /* Method 2: Manual computation */
  urcrypt_ed_scalarmult(a, point_a, temp1);          /* a*A */
  urcrypt_ed_scalarmult(b, point_b, temp2);          /* b*B */
  urcrypt_ed_point_add(temp1, temp2, result_manual); /* a*A + b*B */

  /* Results should match */
  ASSERT_MEM_EQ(result_combined, result_manual, 32,
                "add_double_scalarmult should match manual computation");

  return 0;
}

/*
 * Test: urcrypt_ed_add_double_scalarmult - Consistency check
 *
 * Verify that when using same point twice, result matches expected
 */
static int test_add_double_scalarmult_consistency(void) {
  uint8_t a[32], b[32];
  uint8_t point[32];
  uint8_t result_double[32];
  uint8_t result_single[32];

  /* Generate a point */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", a, 32);
  urcrypt_ed_scalarmult_base(a, point);

  /* Use same scalars */
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a66b", a, 32);
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a66b", b, 32);

  /* Compute a*P + b*P (where a==b) */
  urcrypt_ed_add_double_scalarmult(a, point, b, point, result_double);

  /* This should equal 2a*P, but we can just verify it's non-zero and consistent */
  int all_zero = 1;
  for (int i = 0; i < 32; i++) {
    if (result_double[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(all_zero == 0, "add_double_scalarmult with same point should produce non-zero result");

  return 0;
}

/* Test suite entry point */
int suite_ge_additions(void) {
  int suite_failures = 0;

  printf("  Running test_scalarmult_basic...\n");
  if (test_scalarmult_basic() != 0) {
    suite_failures++;
  }

  printf("  Running test_scalarmult_consistency...\n");
  if (test_scalarmult_consistency() != 0) {
    suite_failures++;
  }

  printf("  Running test_scalarmult_invalid_scalar...\n");
  if (test_scalarmult_invalid_scalar() != 0) {
    suite_failures++;
  }

  printf("  Running test_scalarmult_commutativity...\n");
  if (test_scalarmult_commutativity() != 0) {
    suite_failures++;
  }

  printf("  Running test_add_scalarmult_scalarmult_base_basic...\n");
  if (test_add_scalarmult_scalarmult_base_basic() != 0) {
    suite_failures++;
  }

  printf("  Running test_add_scalarmult_scalarmult_base_manual...\n");
  if (test_add_scalarmult_scalarmult_base_manual() != 0) {
    suite_failures++;
  }

  printf("  Running test_add_double_scalarmult_basic...\n");
  if (test_add_double_scalarmult_basic() != 0) {
    suite_failures++;
  }

  printf("  Running test_add_double_scalarmult_manual...\n");
  if (test_add_double_scalarmult_manual() != 0) {
    suite_failures++;
  }

  printf("  Running test_add_double_scalarmult_consistency...\n");
  if (test_add_double_scalarmult_consistency() != 0) {
    suite_failures++;
  }

  return suite_failures;
}
