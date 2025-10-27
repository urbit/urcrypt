#include "test_common.h"
#include "urcrypt/urcrypt.h"
#include <blake3.h>
#include <string.h>
#include <stdio.h>

/*
 * BLAKE3 Test Suite
 *
 * Tests for the BLAKE3 cryptographic hash function wrapper.
 * Reference test vectors from: https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
 */

/* Helper function to get BLAKE3 IV as bytes */
static void get_blake3_iv(uint8_t iv_bytes[32]) {
  const uint32_t IV[8] = {0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL,
                          0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL,
                          0x1F83D9ABUL, 0x5BE0CD19UL};
  memcpy(iv_bytes, IV, 32);
}

/*
 * Test: BLAKE3 hash of empty input
 *
 * Reference vector from official test_vectors.json
 */
static int test_blake3_empty_input(void) {
  uint8_t out[32];
  uint8_t expected[32];
  uint8_t iv[32];

  /* Official test vector for 0-byte input */
  hex_to_bytes("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", expected, 32);

  get_blake3_iv(iv);
  urcrypt_blake3_hash(0, NULL, iv, 0, 32, out);

  ASSERT_MEM_EQ(out, expected, 32, "blake3 empty input hash mismatch");
  return 0;
}

/*
 * Test: BLAKE3 hash of 1-byte input
 */
static int test_blake3_one_byte(void) {
  uint8_t out[32];
  uint8_t expected[32];
  uint8_t input[1] = {0x00};  /* First byte of the test pattern */
  uint8_t iv[32];

  /* Official test vector for 1-byte input (byte value 0) */
  hex_to_bytes("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", expected, 32);

  get_blake3_iv(iv);
  urcrypt_blake3_hash(1, input, iv, 0, 32, out);

  ASSERT_MEM_EQ(out, expected, 32, "blake3 1-byte input hash mismatch");
  return 0;
}

/*
 * Test: BLAKE3 hash of short ASCII string
 */
static int test_blake3_short_string(void) {
  uint8_t out[32];
  uint8_t expected[32];
  uint8_t input[3] = {0x00, 0x01, 0x02};
  uint8_t iv[32];

  /* Official test vector for 3-byte input [0, 1, 2] */
  hex_to_bytes("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f", expected, 32);

  get_blake3_iv(iv);
  urcrypt_blake3_hash(3, input, iv, 0, 32, out);

  ASSERT_MEM_EQ(out, expected, 32, "blake3 3-byte input hash mismatch");
  return 0;
}

/*
 * Test: BLAKE3 keyed hash mode
 *
 * Tests the KEYED_HASH flag with a 32-byte key
 */
static int test_blake3_keyed_hash(void) {
  uint8_t out[32];
  uint8_t expected[32];

  /* Key: "whats the Elvish word for friend" (32 bytes) */
  uint8_t key[32] = "whats the Elvish word for fri";
  memcpy(key + 29, "end", 3);  /* Complete the 32-byte key */

  /* Official test vector for keyed hash with 0-byte input */
  hex_to_bytes("92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26", expected, 32);

  /* KEYED_HASH flag = 1 << 4 = 16 */
  urcrypt_blake3_hash(0, NULL, key, 16, 32, out);

  ASSERT_MEM_EQ(out, expected, 32, "blake3 keyed hash mismatch");
  return 0;
}

/*
 * Test: BLAKE3 derive key mode
 *
 * Tests the DERIVE_KEY_CONTEXT flag
 */
static int test_blake3_derive_key(void) {
  uint8_t out[32];
  uint8_t expected[32];
  uint8_t iv[32];
  uint8_t context_key[32];

  /* Context string: "BLAKE3 2019-12-27 16:29:52 test vectors context" */
  const char *context = "BLAKE3 2019-12-27 16:29:52 test vectors context";

  /* Official test vector for derive_key with 0-byte input */
  hex_to_bytes("2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d", expected, 32);

  /* First, hash the context with DERIVE_KEY_CONTEXT flag (1 << 5 = 32) to get the key */
  get_blake3_iv(iv);
  urcrypt_blake3_hash(strlen(context), (uint8_t*)context, iv, 32, 32, context_key);

  /* Then use DERIVE_KEY_MATERIAL flag (1 << 6 = 64) to derive key from empty input */
  urcrypt_blake3_hash(0, NULL, context_key, 64, 32, out);

  ASSERT_MEM_EQ(out, expected, 32, "blake3 derive_key hash mismatch");
  return 0;
}

/*
 * Test: BLAKE3 variable output length
 *
 * Tests that BLAKE3 can produce outputs of different lengths
 */
static int test_blake3_variable_output(void) {
  uint8_t out64[64];
  uint8_t expected64[64];
  uint8_t iv[32];

  /* First 64 bytes of extended output for 0-byte input */
  hex_to_bytes(
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    "e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a",
    expected64, 64
  );

  get_blake3_iv(iv);
  urcrypt_blake3_hash(0, NULL, iv, 0, 64, out64);

  ASSERT_MEM_EQ(out64, expected64, 64, "blake3 64-byte output mismatch");
  return 0;
}

/*
 * Test: BLAKE3 determinism
 *
 * Verify that the same input always produces the same output
 */
static int test_blake3_determinism(void) {
  uint8_t out1[32];
  uint8_t out2[32];
  uint8_t input[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  uint8_t iv[32];

  get_blake3_iv(iv);
  urcrypt_blake3_hash(10, input, iv, 0, 32, out1);

  get_blake3_iv(iv);
  urcrypt_blake3_hash(10, input, iv, 0, 32, out2);

  ASSERT_MEM_EQ(out1, out2, 32, "blake3 is not deterministic");
  return 0;
}

/*
 * Test: BLAKE3 chunk_output function
 *
 * Tests the low-level chunk processing function
 */
static int test_blake3_chunk_output(void) {
  uint8_t chunk[1024];
  uint8_t cv[32];
  uint8_t block[64];
  uint8_t block_len;
  uint64_t counter = 0;
  uint8_t flags = 0;

  /* Initialize chunk with test pattern */
  for (size_t i = 0; i < 1024; i++) {
    chunk[i] = i % 251;
  }

  /* Initialize cv with BLAKE3 IV */
  const uint32_t IV[8] = {0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL,
                          0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL,
                          0x1F83D9ABUL, 0x5BE0CD19UL};
  memcpy(cv, IV, 32);

  /* Process the chunk */
  urcrypt_blake3_chunk_output(1024, chunk, cv, block, &block_len, &counter, &flags);

  /* Verify that block_len is 64 (last block remains in buffer) */
  ASSERT(block_len == 64, "blake3 chunk_output block_len should be 64 for 1024 bytes");

  /* Verify that flags has CHUNK_END set */
  ASSERT((flags & 2) != 0, "blake3 chunk_output should set CHUNK_END flag");

  return 0;
}

/*
 * Test: BLAKE3 compress function
 *
 * Tests the low-level compression function
 */
static int test_blake3_compress(void) {
  uint8_t cv[32];
  uint8_t block[64];
  uint8_t out[64];

  /* Initialize cv with BLAKE3 IV */
  const uint32_t IV[8] = {0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL,
                          0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL,
                          0x1F83D9ABUL, 0x5BE0CD19UL};
  memcpy(cv, IV, 32);

  /* Initialize block with zeros */
  memset(block, 0, 64);

  /* Compress with counter=0, block_len=0, flags=0 */
  urcrypt_blake3_compress(cv, block, 0, 0, 0, out);

  /* Just verify it doesn't crash and produces some output */
  /* We can't easily verify correctness without duplicating the algorithm */
  int all_zero = 1;
  for (int i = 0; i < 64; i++) {
    if (out[i] != 0) {
      all_zero = 0;
      break;
    }
  }

  ASSERT(all_zero == 0, "blake3 compress should produce non-zero output");
  return 0;
}

/* Test suite entry point */
int suite_blake3(void) {
  int suite_failures = 0;

  printf("  Running test_blake3_empty_input...\n");
  if (test_blake3_empty_input() != 0) {
    suite_failures++;
  }

  printf("  Running test_blake3_one_byte...\n");
  if (test_blake3_one_byte() != 0) {
    suite_failures++;
  }

  printf("  Running test_blake3_short_string...\n");
  if (test_blake3_short_string() != 0) {
    suite_failures++;
  }

  printf("  Running test_blake3_keyed_hash...\n");
  if (test_blake3_keyed_hash() != 0) {
    suite_failures++;
  }

  printf("  Running test_blake3_derive_key...\n");
  if (test_blake3_derive_key() != 0) {
    suite_failures++;
  }

  printf("  Running test_blake3_variable_output...\n");
  if (test_blake3_variable_output() != 0) {
    suite_failures++;
  }

  printf("  Running test_blake3_determinism...\n");
  if (test_blake3_determinism() != 0) {
    suite_failures++;
  }

  printf("  Running test_blake3_chunk_output...\n");
  if (test_blake3_chunk_output() != 0) {
    suite_failures++;
  }

  printf("  Running test_blake3_compress...\n");
  if (test_blake3_compress() != 0) {
    suite_failures++;
  }

  return suite_failures;
}
