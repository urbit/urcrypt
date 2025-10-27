#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Test result tracking - defined in test_runner.c */
extern int test_failures;
extern int test_passes;

/* Color codes for terminal output */
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_RESET   "\x1b[0m"

/* Test assertion macros */
#define ASSERT(condition, message) \
  do { \
    if (!(condition)) { \
      fprintf(stderr, COLOR_RED "FAIL" COLOR_RESET ": %s:%d: %s\n", \
              __FILE__, __LINE__, message); \
      test_failures++; \
      return 1; \
    } else { \
      test_passes++; \
    } \
  } while (0)

#define ASSERT_EQ(a, b, message) \
  do { \
    if ((a) != (b)) { \
      fprintf(stderr, COLOR_RED "FAIL" COLOR_RESET ": %s:%d: %s (expected %d, got %d)\n", \
              __FILE__, __LINE__, message, (int)(b), (int)(a)); \
      test_failures++; \
      return 1; \
    } else { \
      test_passes++; \
    } \
  } while (0)

#define ASSERT_MEM_EQ(a, b, len, message) \
  do { \
    if (memcmp((a), (b), (len)) != 0) { \
      fprintf(stderr, COLOR_RED "FAIL" COLOR_RESET ": %s:%d: %s\n", \
              __FILE__, __LINE__, message); \
      test_failures++; \
      return 1; \
    } else { \
      test_passes++; \
    } \
  } while (0)

/* Helper function to print hex for debugging */
static void print_hex(const char *label, const uint8_t *data, size_t len) {
  printf("%s: ", label);
  for (size_t i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}

/* Helper function to convert hex string to bytes */
static inline void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
  for (size_t i = 0; i < len; i++) {
    sscanf(hex + 2*i, "%2hhx", &bytes[i]);
  }
}

/* Helper function to reverse bytes in place */
static inline void reverse_bytes(uint8_t *bytes, size_t len) {
  for (size_t i = 0; i < len/2; i++) {
    uint8_t tmp = bytes[i];
    bytes[i] = bytes[len - 1 - i];
    bytes[len - 1 - i] = tmp;
  }
}

#endif /* TEST_COMMON_H */
