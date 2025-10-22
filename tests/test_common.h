#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Test result tracking */
static int test_failures = 0;
static int test_passes = 0;

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

#endif /* TEST_COMMON_H */
