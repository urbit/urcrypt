#include <stdio.h>
#include <stdlib.h>
#include "test_common.h"

/* Test result tracking - shared across all test files */
int test_failures = 0;
int test_passes = 0;

/* Test suite declarations */
int suite_argon2(void);
int suite_blake3(void);
int suite_ed25519(void);
int suite_ge_additions(void);
int suite_keccak(void);
int suite_monocypher(void);
int suite_scrypt(void);
int suite_urcrypt(void);

/* Main test runner */
int main(int argc, char *argv[]) {
  int total_failures = 0;
  int suites_run = 0;
  int suites_failed = 0;

  printf("\n");
  printf("========================================\n");
  printf("  Urcrypt Test Suite\n");
  printf("========================================\n\n");

  /* Run all test suites */
  #define RUN_SUITE(name) \
    do { \
      printf(COLOR_YELLOW "Running " #name " test suite..." COLOR_RESET "\n"); \
      int failures = suite_##name(); \
      suites_run++; \
      if (failures > 0) { \
        printf(COLOR_RED "✗ " #name " suite: %d test(s) failed" COLOR_RESET "\n\n", failures); \
        total_failures += failures; \
        suites_failed++; \
      } else { \
        printf(COLOR_GREEN "✓ " #name " suite: all tests passed" COLOR_RESET "\n\n"); \
      } \
    } while (0)

  RUN_SUITE(argon2);
  RUN_SUITE(blake3);
  RUN_SUITE(ed25519);
  RUN_SUITE(ge_additions);
  RUN_SUITE(keccak);
  RUN_SUITE(monocypher);
  RUN_SUITE(scrypt);
  RUN_SUITE(urcrypt);

  /* Print summary */
  printf("========================================\n");
  printf("  Test Summary\n");
  printf("========================================\n");
  printf("Test suites run:    %d\n", suites_run);
  printf("Test suites passed: %d\n", suites_run - suites_failed);
  printf("Test suites failed: %d\n", suites_failed);
  printf("Total test passes:  %d\n", test_passes);
  printf("Total test failures: %d\n", total_failures);
  printf("========================================\n\n");

  if (total_failures > 0) {
    return EXIT_FAILURE;
  } else {
    return EXIT_SUCCESS;
  }
}
