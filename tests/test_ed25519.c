#include "test_common.h"
#include "urcrypt/urcrypt.h"
#include <string.h>
#include <stdio.h>

/*
 * Ed25519 Test Suite
 *
 * Tests for Ed25519 digital signature algorithm wrapper functions.
 * Reference test vectors from RFC 8032: https://datatracker.ietf.org/doc/html/rfc8032
 */

/*
 * Test: Sign and verify empty message
 *
 * RFC 8032 TEST 1
 */
static int test_sign_verify_empty(void) {
  uint8_t seed[32];
  uint8_t expected_public[32];
  uint8_t expected_signature[64];
  uint8_t public_key[32];
  uint8_t signature[64];
  const uint8_t *message = NULL;
  size_t message_len = 0;

  /* RFC 8032 TEST 1 vectors */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32);
  hex_to_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", expected_public, 32);
  hex_to_bytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", expected_signature, 64);

  /* Derive public key from seed */
  urcrypt_ed_puck(seed, public_key);
  ASSERT_MEM_EQ(public_key, expected_public, 32, "ed25519 public key derivation mismatch");

  /* Sign empty message */
  urcrypt_ed_sign(message, message_len, seed, signature);
  ASSERT_MEM_EQ(signature, expected_signature, 64, "ed25519 signature mismatch for empty message");

  /* Verify signature */
  bool valid = urcrypt_ed_veri(message, message_len, public_key, signature);
  ASSERT(valid == true, "ed25519 signature verification failed for empty message");

  return 0;
}

/*
 * Test: Sign and verify 1-byte message
 *
 * RFC 8032 TEST 2
 */
static int test_sign_verify_one_byte(void) {
  uint8_t seed[32];
  uint8_t expected_public[32];
  uint8_t expected_signature[64];
  uint8_t public_key[32];
  uint8_t signature[64];
  uint8_t message[1];

  /* RFC 8032 TEST 2 vectors */
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", seed, 32);
  hex_to_bytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", expected_public, 32);
  hex_to_bytes("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00", expected_signature, 64);
  hex_to_bytes("72", message, 1);

  /* Derive public key */
  urcrypt_ed_puck(seed, public_key);
  ASSERT_MEM_EQ(public_key, expected_public, 32, "ed25519 public key mismatch (1-byte test)");

  /* Sign message */
  urcrypt_ed_sign(message, 1, seed, signature);
  ASSERT_MEM_EQ(signature, expected_signature, 64, "ed25519 signature mismatch for 1-byte message");

  /* Verify signature */
  bool valid = urcrypt_ed_veri(message, 1, public_key, signature);
  ASSERT(valid == true, "ed25519 verification failed for 1-byte message");

  return 0;
}

/*
 * Test: Sign and verify 2-byte message
 *
 * RFC 8032 TEST 3
 */
static int test_sign_verify_two_bytes(void) {
  uint8_t seed[32];
  uint8_t expected_public[32];
  uint8_t expected_signature[64];
  uint8_t public_key[32];
  uint8_t signature[64];
  uint8_t message[2];

  /* RFC 8032 TEST 3 vectors */
  hex_to_bytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", seed, 32);
  hex_to_bytes("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", expected_public, 32);
  hex_to_bytes("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a", expected_signature, 64);
  hex_to_bytes("af82", message, 2);

  /* Derive public key */
  urcrypt_ed_puck(seed, public_key);
  ASSERT_MEM_EQ(public_key, expected_public, 32, "ed25519 public key mismatch (2-byte test)");

  /* Sign message */
  urcrypt_ed_sign(message, 2, seed, signature);
  ASSERT_MEM_EQ(signature, expected_signature, 64, "ed25519 signature mismatch for 2-byte message");

  /* Verify signature */
  bool valid = urcrypt_ed_veri(message, 2, public_key, signature);
  ASSERT(valid == true, "ed25519 verification failed for 2-byte message");

  return 0;
}

/*
 * Test: Full keypair generation with urcrypt_ed_luck
 */
static int test_keypair_generation(void) {
  uint8_t seed[32];
  uint8_t public_key[32];
  uint8_t private_key[64];
  uint8_t expected_public[32];

  /* Use TEST 1 seed */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32);
  hex_to_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", expected_public, 32);

  /* Generate keypair */
  urcrypt_ed_luck(seed, public_key, private_key);

  /* Verify public key matches expected */
  ASSERT_MEM_EQ(public_key, expected_public, 32, "ed25519 luck public key mismatch");

  /* Verify private key is not all zeros */
  int all_zero = 1;
  for (int i = 0; i < 64; i++) {
    if (private_key[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(all_zero == 0, "ed25519 luck private key should not be all zeros");

  return 0;
}

/*
 * Test: Sign with seed vs sign_raw with keypair
 *
 * Both methods should produce identical signatures
 */
static int test_sign_vs_sign_raw(void) {
  uint8_t seed[32];
  uint8_t public_key[32];
  uint8_t private_key[64];
  uint8_t signature1[64];
  uint8_t signature2[64];
  const char *message = "Hello, world!";
  size_t message_len = strlen(message);

  /* Generate keypair */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32);
  urcrypt_ed_luck(seed, public_key, private_key);

  /* Sign with seed */
  urcrypt_ed_sign((const uint8_t*)message, message_len, seed, signature1);

  /* Sign with raw keys */
  urcrypt_ed_sign_raw((const uint8_t*)message, message_len, public_key, private_key, signature2);

  /* Both signatures should be identical */
  ASSERT_MEM_EQ(signature1, signature2, 64, "ed25519 sign vs sign_raw should produce same signature");

  /* Both should verify */
  ASSERT(urcrypt_ed_veri((const uint8_t*)message, message_len, public_key, signature1), "sign verification failed");
  ASSERT(urcrypt_ed_veri((const uint8_t*)message, message_len, public_key, signature2), "sign_raw verification failed");

  return 0;
}

/*
 * Test: Invalid signature detection
 */
static int test_invalid_signature(void) {
  uint8_t seed[32];
  uint8_t public_key[32];
  uint8_t signature[64];
  const char *message = "Hello, world!";
  size_t message_len = strlen(message);

  /* Generate keypair and sign */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32);
  urcrypt_ed_puck(seed, public_key);
  urcrypt_ed_sign((const uint8_t*)message, message_len, seed, signature);

  /* Flip a bit in the signature */
  signature[44] ^= 0x10;

  /* Verification should fail */
  bool valid = urcrypt_ed_veri((const uint8_t*)message, message_len, public_key, signature);
  ASSERT(valid == false, "ed25519 should detect invalid signature");

  return 0;
}

/*
 * Test: Key exchange with urcrypt_ed_shar and urcrypt_ed_slar
 *
 * Both parties should derive the same shared secret
 */
static int test_key_exchange(void) {
  uint8_t seed1[32], seed2[32];
  uint8_t public1[32], public2[32];
  uint8_t private1[64], private2[64];
  uint8_t shared1[32], shared2[32];

  /* Generate two keypairs */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed1, 32);
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", seed2, 32);

  urcrypt_ed_luck(seed1, public1, private1);
  urcrypt_ed_luck(seed2, public2, private2);

  /* Perform key exchange from both perspectives using shar (with seed) */
  urcrypt_ed_shar(public2, seed1, shared1);
  urcrypt_ed_shar(public1, seed2, shared2);

  /* Shared secrets should match */
  ASSERT_MEM_EQ(shared1, shared2, 32, "ed25519 shar key exchange mismatch");

  /* Now test with slar (with private key) */
  uint8_t shared3[32], shared4[32];
  urcrypt_ed_slar(public2, private1, shared3);
  urcrypt_ed_slar(public1, private2, shared4);

  /* These should also match */
  ASSERT_MEM_EQ(shared3, shared4, 32, "ed25519 slar key exchange mismatch");

  /* shar and slar should produce same result */
  ASSERT_MEM_EQ(shared1, shared3, 32, "ed25519 shar and slar should match");

  return 0;
}

/*
 * Test: Scalar reduce operation
 */
static int test_scalar_reduce(void) {
  uint8_t scalar64[64];
  uint8_t scalar64_copy[64];

  /* Initialize with known pattern */
  for (int i = 0; i < 64; i++) {
    scalar64[i] = i;
    scalar64_copy[i] = i;
  }

  /* Reduce scalar */
  urcrypt_ed_scalar_reduce(scalar64);

  /* Result should be different from input (unless input was already reduced) */
  int changed = 0;
  for (int i = 0; i < 64; i++) {
    if (scalar64[i] != scalar64_copy[i]) {
      changed = 1;
      break;
    }
  }
  ASSERT(changed == 1, "ed25519 scalar_reduce should modify the input");

  /* Reduced value should have specific properties (high bits cleared) */
  /* After reduction, first 32 bytes contain the reduced scalar, rest are modified */
  return 0;
}

/*
 * Test: Add scalar to public key
 */
static int test_add_scalar_public(void) {
  uint8_t seed[32];
  uint8_t public_key[32];
  uint8_t public_key_orig[32];
  uint8_t scalar[32];
  uint8_t signature[64];
  const char *message = "test message";
  size_t message_len = strlen(message);

  /* Generate keypair */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32);
  urcrypt_ed_puck(seed, public_key);
  memcpy(public_key_orig, public_key, 32);

  /* Create a scalar */
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", scalar, 32);

  /* Add scalar to public key */
  urcrypt_ed_add_scalar_public(public_key, scalar);

  /* Public key should have changed */
  int changed = 0;
  for (int i = 0; i < 32; i++) {
    if (public_key[i] != public_key_orig[i]) {
      changed = 1;
      break;
    }
  }
  ASSERT(changed == 1, "ed25519 add_scalar_public should modify public key");

  return 0;
}

/*
 * Test: Add scalar to both public and private keys, then sign and verify
 */
static int test_add_scalar_sign_verify(void) {
  uint8_t seed[32];
  uint8_t public_key[32];
  uint8_t private_key[64];
  uint8_t scalar[32];
  uint8_t signature[64];
  const char *message = "test after scalar addition";
  size_t message_len = strlen(message);

  /* Generate keypair */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32);
  urcrypt_ed_luck(seed, public_key, private_key);

  /* Create a scalar */
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", scalar, 32);

  /* Add scalar to both keys */
  urcrypt_ed_add_scalar_public_private(public_key, private_key, scalar);

  /* Sign with modified keys */
  urcrypt_ed_sign_raw((const uint8_t*)message, message_len, public_key, private_key, signature);

  /* Verify with modified public key */
  bool valid = urcrypt_ed_veri((const uint8_t*)message, message_len, public_key, signature);
  ASSERT(valid == true, "ed25519 signature should verify after scalar addition");

  return 0;
}

/*
 * Test: Scalar multiplication of base point
 */
static int test_scalarmult_base(void) {
  uint8_t scalar[32];
  uint8_t point[32];

  /* Use a known scalar (from TEST 1 seed) */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", scalar, 32);

  /* Multiply base point by scalar */
  int result = urcrypt_ed_scalarmult_base(scalar, point);

  ASSERT(result == 0, "ed25519 scalarmult_base should succeed");

  /* Point should not be all zeros */
  int all_zero = 1;
  for (int i = 0; i < 32; i++) {
    if (point[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(all_zero == 0, "ed25519 scalarmult_base should produce non-zero point");

  return 0;
}

/*
 * Test: Point addition
 */
static int test_point_add(void) {
  uint8_t scalar1[32], scalar2[32];
  uint8_t point1[32], point2[32], sum[32];

  /* Generate two points */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", scalar1, 32);
  hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", scalar2, 32);

  urcrypt_ed_scalarmult_base(scalar1, point1);
  urcrypt_ed_scalarmult_base(scalar2, point2);

  /* Add the two points */
  int result = urcrypt_ed_point_add(point1, point2, sum);

  ASSERT(result == 0, "ed25519 point_add should succeed");

  /* Sum should be different from both inputs */
  int diff1 = memcmp(sum, point1, 32);
  int diff2 = memcmp(sum, point2, 32);
  ASSERT(diff1 != 0 && diff2 != 0, "ed25519 point_add sum should differ from inputs");

  return 0;
}

/*
 * Test: Scalar with high bit set should fail
 */
static int test_invalid_scalar(void) {
  uint8_t scalar[32];
  uint8_t point[32];

  /* Create scalar with high bit set (bit 255) */
  memset(scalar, 0, 32);
  scalar[31] = 0x80;

  /* This should fail */
  int result = urcrypt_ed_scalarmult_base(scalar, point);

  ASSERT(result != 0, "ed25519 scalarmult_base should reject scalar with high bit set");

  return 0;
}

/*
 * Test: Point negation
 */
static int test_point_neg(void) {
  uint8_t scalar[32];
  uint8_t point[32];
  uint8_t point_orig[32];

  /* Generate a point */
  hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", scalar, 32);
  urcrypt_ed_scalarmult_base(scalar, point);
  memcpy(point_orig, point, 32);

  /* Negate the point */
  int result = urcrypt_ed_point_neg(point);

  ASSERT(result == 0, "ed25519 point_neg should succeed");

  /* Point should have changed */
  int changed = (memcmp(point, point_orig, 32) != 0);
  ASSERT(changed == 1, "ed25519 point_neg should modify the point");

  return 0;
}

/* Test suite entry point */
int suite_ed25519(void) {
  int suite_failures = 0;

  printf("  Running test_sign_verify_empty...\n");
  if (test_sign_verify_empty() != 0) {
    suite_failures++;
  }

  printf("  Running test_sign_verify_one_byte...\n");
  if (test_sign_verify_one_byte() != 0) {
    suite_failures++;
  }

  printf("  Running test_sign_verify_two_bytes...\n");
  if (test_sign_verify_two_bytes() != 0) {
    suite_failures++;
  }

  printf("  Running test_keypair_generation...\n");
  if (test_keypair_generation() != 0) {
    suite_failures++;
  }

  printf("  Running test_sign_vs_sign_raw...\n");
  if (test_sign_vs_sign_raw() != 0) {
    suite_failures++;
  }

  printf("  Running test_invalid_signature...\n");
  if (test_invalid_signature() != 0) {
    suite_failures++;
  }

  printf("  Running test_key_exchange...\n");
  if (test_key_exchange() != 0) {
    suite_failures++;
  }

  printf("  Running test_scalar_reduce...\n");
  if (test_scalar_reduce() != 0) {
    suite_failures++;
  }

  printf("  Running test_add_scalar_public...\n");
  if (test_add_scalar_public() != 0) {
    suite_failures++;
  }

  printf("  Running test_add_scalar_sign_verify...\n");
  if (test_add_scalar_sign_verify() != 0) {
    suite_failures++;
  }

  printf("  Running test_scalarmult_base...\n");
  if (test_scalarmult_base() != 0) {
    suite_failures++;
  }

  printf("  Running test_point_add...\n");
  if (test_point_add() != 0) {
    suite_failures++;
  }

  printf("  Running test_invalid_scalar...\n");
  if (test_invalid_scalar() != 0) {
    suite_failures++;
  }

  printf("  Running test_point_neg...\n");
  if (test_point_neg() != 0) {
    suite_failures++;
  }

  return suite_failures;
}
