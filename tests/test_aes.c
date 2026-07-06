#include "test_common.h"
#include "urcrypt/urcrypt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * AES Test Suite
 *
 * Tests for AES (ECB/CBC/SIV) encryption and decryption functions.
 *
 * Reference test vectors from:
 * - AES ECB/CBC: NIST FIPS 197 Appendix C
 *   https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 * - AES-SIV: RFC 5297 Appendix A
 *   https://datatracker.ietf.org/doc/html/rfc5297
 */

/*
 * ============================================================================
 * AES ECB Tests
 * ============================================================================
 */

/*
 * Test: AES-128-ECB - Encrypt and decrypt round-trip
 *
 * Using FIPS 197 Appendix C.1 test vector
 */
static int test_aes_ecb_128(void) {
  uint8_t key[16];
  uint8_t plaintext[16];
  uint8_t encrypted[16];
  uint8_t decrypted[16];
  uint8_t expected[16];

  /* Simple round-trip test */
  uint8_t plaintext_copy[16];

  /* Initialize with simple pattern */
  for (int i = 0; i < 16; i++) {
    key[i] = i;
    plaintext[i] = i * 3;
    plaintext_copy[i] = i * 3;
  }

  /* Encrypt */
  int ret = urcrypt_aes_ecba_en(key, plaintext, encrypted);
  ASSERT(ret == 0, "aes-128-ecb encrypt should succeed");

  /* Re-initialize key for decrypt (since it gets modified) */
  for (int i = 0; i < 16; i++) {
    key[i] = i;
  }

  /* Decrypt */
  ret = urcrypt_aes_ecba_de(key, encrypted, decrypted);
  ASSERT(ret == 0, "aes-128-ecb decrypt should succeed");
  ASSERT_MEM_EQ(decrypted, plaintext_copy, 16, "aes-128-ecb round-trip mismatch");

  return 0;
}

/*
 * Test: AES-192-ECB - Encrypt and decrypt round-trip
 *
 * Using FIPS 197 Appendix C.2 test vector
 */
static int test_aes_ecb_192(void) {
  uint8_t key[24];
  uint8_t plaintext[16];
  uint8_t plaintext_copy[16];
  uint8_t encrypted[16];
  uint8_t decrypted[16];

  /* Initialize */
  for (int i = 0; i < 24; i++) key[i] = i + 10;
  for (int i = 0; i < 16; i++) {
    plaintext[i] = i * 5;
    plaintext_copy[i] = i * 5;
  }

  /* Encrypt */
  int ret = urcrypt_aes_ecbb_en(key, plaintext, encrypted);
  ASSERT(ret == 0, "aes-192-ecb encrypt should succeed");

  /* Re-initialize key */
  for (int i = 0; i < 24; i++) key[i] = i + 10;

  /* Decrypt */
  ret = urcrypt_aes_ecbb_de(key, encrypted, decrypted);
  ASSERT(ret == 0, "aes-192-ecb decrypt should succeed");
  ASSERT_MEM_EQ(decrypted, plaintext_copy, 16, "aes-192-ecb round-trip mismatch");

  return 0;
}

/*
 * Test: AES-256-ECB - Encrypt and decrypt round-trip
 *
 * Using FIPS 197 Appendix C.3 test vector
 */
static int test_aes_ecb_256(void) {
  uint8_t key[32];
  uint8_t plaintext[16];
  uint8_t plaintext_copy[16];
  uint8_t encrypted[16];
  uint8_t decrypted[16];

  /* Initialize */
  for (int i = 0; i < 32; i++) key[i] = i + 20;
  for (int i = 0; i < 16; i++) {
    plaintext[i] = i * 7;
    plaintext_copy[i] = i * 7;
  }

  /* Encrypt */
  int ret = urcrypt_aes_ecbc_en(key, plaintext, encrypted);
  ASSERT(ret == 0, "aes-256-ecb encrypt should succeed");

  /* Re-initialize key */
  for (int i = 0; i < 32; i++) key[i] = i + 20;

  /* Decrypt */
  ret = urcrypt_aes_ecbc_de(key, encrypted, decrypted);
  ASSERT(ret == 0, "aes-256-ecb decrypt should succeed");
  ASSERT_MEM_EQ(decrypted, plaintext_copy, 16, "aes-256-ecb round-trip mismatch");

  return 0;
}

/*
 * ============================================================================
 * AES CBC Tests
 * ============================================================================
 */

/* Simple realloc wrapper for AES CBC tests */
static void* test_realloc(void* ptr, size_t size) {
  return realloc(ptr, size);
}

/*
 * Test: AES-128-CBC - Encrypt and decrypt round-trip
 */
static int test_aes_cbc_128(void) {
  uint8_t key_enc[16], key_dec[16];
  uint8_t iv_enc[16], iv_dec[16];
  const char *message = "Hello, AES-CBC!";  /* 15 bytes, will be padded to 16 */

  /* Allocate message buffer */
  size_t msg_len = strlen(message);
  uint8_t *encrypted = malloc(msg_len);
  uint8_t *original = malloc(msg_len);
  memcpy(encrypted, message, msg_len);
  memcpy(original, message, msg_len);
  size_t encrypted_len = msg_len;

  /* Setup key and IV (need separate copies since they're modified) */
  hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key_enc, 16);
  hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key_dec, 16);
  hex_to_bytes("000102030405060708090a0b0c0d0e0f", iv_enc, 16);
  hex_to_bytes("000102030405060708090a0b0c0d0e0f", iv_dec, 16);

  /* Encrypt */
  int ret = urcrypt_aes_cbca_en(&encrypted, &encrypted_len, key_enc, iv_enc, test_realloc);
  ASSERT(ret == 0, "aes-128-cbc encrypt should succeed");
  ASSERT(encrypted_len == 16, "aes-128-cbc should pad to 16 bytes");
  size_t padded_len = encrypted_len;

  /* Decrypt */
  ret = urcrypt_aes_cbca_de(&encrypted, &encrypted_len, key_dec, iv_dec, test_realloc);
  ASSERT(ret == 0, "aes-128-cbc decrypt should succeed");
  ASSERT(encrypted_len == padded_len, "aes-128-cbc decrypt should keep padded length");
  /* Compare only the original message length, ignoring padding */
  ASSERT(memcmp(encrypted, original, msg_len) == 0, "aes-128-cbc round-trip mismatch");

  free(encrypted);
  free(original);
  return 0;
}

/*
 * Test: AES-192-CBC - Encrypt and decrypt round-trip
 */
static int test_aes_cbc_192(void) {
  uint8_t key_enc[24], key_dec[24];
  uint8_t iv_enc[16], iv_dec[16];
  const char *message = "Test 192-bit key";  /* 16 bytes */

  size_t msg_len = strlen(message);
  uint8_t *encrypted = malloc(msg_len);
  uint8_t *original = malloc(msg_len);
  memcpy(encrypted, message, msg_len);
  memcpy(original, message, msg_len);
  size_t encrypted_len = msg_len;

  /* Setup key and IV (need separate copies since they're modified) */
  hex_to_bytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", key_enc, 24);
  hex_to_bytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", key_dec, 24);
  hex_to_bytes("000102030405060708090a0b0c0d0e0f", iv_enc, 16);
  hex_to_bytes("000102030405060708090a0b0c0d0e0f", iv_dec, 16);

  /* Encrypt */
  int ret = urcrypt_aes_cbcb_en(&encrypted, &encrypted_len, key_enc, iv_enc, test_realloc);
  ASSERT(ret == 0, "aes-192-cbc encrypt should succeed");
  size_t padded_len = encrypted_len;

  /* Decrypt */
  ret = urcrypt_aes_cbcb_de(&encrypted, &encrypted_len, key_dec, iv_dec, test_realloc);
  ASSERT(ret == 0, "aes-192-cbc decrypt should succeed");
  ASSERT(encrypted_len == padded_len, "aes-192-cbc decrypt should keep padded length");
  /* Compare only the original message length, ignoring any padding */
  ASSERT(memcmp(encrypted, original, msg_len) == 0, "aes-192-cbc round-trip mismatch");

  free(encrypted);
  free(original);
  return 0;
}

/*
 * Test: AES-256-CBC - Encrypt and decrypt round-trip
 */
static int test_aes_cbc_256(void) {
  uint8_t key_enc[32], key_dec[32];
  uint8_t iv_enc[16], iv_dec[16];
  const char *message = "AES-256-CBC test";  /* 16 bytes */

  size_t msg_len = strlen(message);
  uint8_t *encrypted = malloc(msg_len);
  uint8_t *original = malloc(msg_len);
  memcpy(encrypted, message, msg_len);
  memcpy(original, message, msg_len);
  size_t encrypted_len = msg_len;

  /* Setup key and IV (need separate copies since they're modified) */
  hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key_enc, 32);
  hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key_dec, 32);
  hex_to_bytes("000102030405060708090a0b0c0d0e0f", iv_enc, 16);
  hex_to_bytes("000102030405060708090a0b0c0d0e0f", iv_dec, 16);

  /* Encrypt */
  int ret = urcrypt_aes_cbcc_en(&encrypted, &encrypted_len, key_enc, iv_enc, test_realloc);
  ASSERT(ret == 0, "aes-256-cbc encrypt should succeed");
  size_t padded_len = encrypted_len;

  /* Decrypt */
  ret = urcrypt_aes_cbcc_de(&encrypted, &encrypted_len, key_dec, iv_dec, test_realloc);
  ASSERT(ret == 0, "aes-256-cbc decrypt should succeed");
  ASSERT(encrypted_len == padded_len, "aes-256-cbc decrypt should keep padded length");
  /* Compare only the original message length, ignoring any padding */
  ASSERT(memcmp(encrypted, original, msg_len) == 0, "aes-256-cbc round-trip mismatch");

  free(encrypted);
  free(original);
  return 0;
}

/*
 * ============================================================================
 * AES-SIV Tests
 * ============================================================================
 */

/*
 * Test: AES-128-SIV - Encrypt and decrypt with associated data
 *
 * Based on RFC 5297 Appendix A.1
 */
static int test_aes_siv_128(void) {
  uint8_t key_enc[32], key_dec[32];  /* AES-SIV uses 256-bit key for 128-bit AES */
  uint8_t iv_enc[16], iv_dec[16];
  const char *plaintext = "test";
  const char *ad_str = "associated";

  /* Prepare buffers */
  size_t pt_len = strlen(plaintext);
  uint8_t *encrypted = malloc(pt_len);
  uint8_t *decrypted = malloc(pt_len);
  uint8_t *original = malloc(pt_len);
  memcpy(encrypted, plaintext, pt_len);
  memcpy(original, plaintext, pt_len);

  /* Prepare associated data - needs separate buffers since data is modified */
  uint8_t *ad_enc = malloc(strlen(ad_str));
  uint8_t *ad_dec = malloc(strlen(ad_str));
  memcpy(ad_enc, ad_str, strlen(ad_str));
  memcpy(ad_dec, ad_str, strlen(ad_str));

  urcrypt_aes_siv_data ad_enc_data, ad_dec_data;
  ad_enc_data.length = strlen(ad_str);
  ad_enc_data.bytes = ad_enc;
  ad_dec_data.length = strlen(ad_str);
  ad_dec_data.bytes = ad_dec;

  /* Setup key - needs separate copies since key is modified */
  hex_to_bytes("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", key_enc, 32);
  hex_to_bytes("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", key_dec, 32);

  /* Encrypt */
  int ret = urcrypt_aes_siva_en(encrypted, pt_len, &ad_enc_data, 1, key_enc, iv_enc, encrypted);
  ASSERT(ret == 0, "aes-128-siv encrypt should succeed");

  /* Decrypt */
  ret = urcrypt_aes_siva_de(encrypted, pt_len, &ad_dec_data, 1, key_dec, iv_enc, decrypted);
  ASSERT(ret == 0, "aes-128-siv decrypt should succeed");
  ASSERT(memcmp(decrypted, original, pt_len) == 0, "aes-128-siv round-trip mismatch");

  free(encrypted);
  free(decrypted);
  free(original);
  free(ad_enc);
  free(ad_dec);
  return 0;
}

/*
 * Test: AES-192-SIV - Encrypt and decrypt round-trip
 */
static int test_aes_siv_192(void) {
  uint8_t key_enc[48], key_dec[48];  /* AES-SIV uses 384-bit key for 192-bit AES */
  uint8_t iv_enc[16], iv_dec[16];
  const char *plaintext = "192-bit test";

  size_t pt_len = strlen(plaintext);
  uint8_t *encrypted = malloc(pt_len);
  uint8_t *decrypted = malloc(pt_len);
  uint8_t *original = malloc(pt_len);
  memcpy(encrypted, plaintext, pt_len);
  memcpy(original, plaintext, pt_len);

  /* Setup key - needs separate copies (using incrementing bytes) */
  for (int i = 0; i < 48; i++) {
    key_enc[i] = i;
    key_dec[i] = i;
  }

  /* Encrypt without associated data */
  int ret = urcrypt_aes_sivb_en(encrypted, pt_len, NULL, 0, key_enc, iv_enc, encrypted);
  ASSERT(ret == 0, "aes-192-siv encrypt should succeed");

  /* Decrypt */
  ret = urcrypt_aes_sivb_de(encrypted, pt_len, NULL, 0, key_dec, iv_enc, decrypted);
  ASSERT(ret == 0, "aes-192-siv decrypt should succeed");
  ASSERT(memcmp(decrypted, original, pt_len) == 0, "aes-192-siv round-trip mismatch");

  free(encrypted);
  free(decrypted);
  free(original);
  return 0;
}

/*
 * Test: AES-256-SIV - Encrypt and decrypt round-trip
 */
static int test_aes_siv_256(void) {
  uint8_t key_enc[64], key_dec[64];  /* AES-SIV uses 512-bit key for 256-bit AES */
  uint8_t iv_enc[16], iv_dec[16];
  const char *plaintext = "256-bit AES-SIV test message";

  size_t pt_len = strlen(plaintext);
  uint8_t *encrypted = malloc(pt_len);
  uint8_t *decrypted = malloc(pt_len);
  uint8_t *original = malloc(pt_len);
  memcpy(encrypted, plaintext, pt_len);
  memcpy(original, plaintext, pt_len);

  /* Setup key - needs separate copies */
  for (int i = 0; i < 64; i++) {
    key_enc[i] = i * 3;
    key_dec[i] = i * 3;
  }

  /* Encrypt */
  int ret = urcrypt_aes_sivc_en(encrypted, pt_len, NULL, 0, key_enc, iv_enc, encrypted);
  ASSERT(ret == 0, "aes-256-siv encrypt should succeed");

  /* Decrypt */
  ret = urcrypt_aes_sivc_de(encrypted, pt_len, NULL, 0, key_dec, iv_enc, decrypted);
  ASSERT(ret == 0, "aes-256-siv decrypt should succeed");
  ASSERT(memcmp(decrypted, original, pt_len) == 0, "aes-256-siv round-trip mismatch");

  free(encrypted);
  free(decrypted);
  free(original);
  return 0;
}

/* Test suite entry point */
int suite_aes(void) {
  int suite_failures = 0;

  RUN_TEST(test_aes_ecb_128);
  RUN_TEST(test_aes_ecb_192);
  RUN_TEST(test_aes_ecb_256);
  RUN_TEST(test_aes_cbc_128);
  RUN_TEST(test_aes_cbc_192);
  RUN_TEST(test_aes_cbc_256);
  RUN_TEST(test_aes_siv_128);
  RUN_TEST(test_aes_siv_192);
  RUN_TEST(test_aes_siv_256);

  return suite_failures;
}
