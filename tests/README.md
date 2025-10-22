# Urcrypt Test Suite

This directory contains the test suite for the urcrypt cryptography library.

## Structure

- `test_common.h` - Common test macros and utilities used by all test files
- `test_runner.c` - Main test runner that executes all test suites
- `test_*.c` - Individual test suite files for each module:
  - `test_argon2.c` - Tests for Argon2 password hashing
  - `test_blake3.c` - Tests for BLAKE3 cryptographic hash function
  - `test_ed25519.c` - Tests for Ed25519 digital signatures
  - `test_ge_additions.c` - Tests for Ed25519 curve group element operations
  - `test_keccak.c` - Tests for Keccak/SHA-3 hash functions
  - `test_monocypher.c` - Tests for ChaCha20 and Poly1305 primitives
  - `test_murmur3.c` - Tests for MurmurHash3 non-cryptographic hash
  - `test_scrypt.c` - Tests for scrypt key derivation function
  - `test_urcrypt.c` - Tests for main library (AES, SHA, RIPEMD, secp256k1)

## Running Tests

### Using the wrapper script (recommended for macOS)

From the repository root:

```bash
./run-tests.sh
```

This script automatically sets the correct library paths for macOS.

### Using make directly

```bash
make check
```

Note: On macOS, if you encounter library loading errors, the wrapper script `run-tests.sh`
handles this automatically. Alternatively, you can set `DYLD_LIBRARY_PATH` manually:

```bash
DYLD_LIBRARY_PATH=/usr/local/lib make check
```

### Running tests directly

After building with `make`, you can run the test executable directly:

```bash
DYLD_LIBRARY_PATH=/usr/local/lib ./.libs/test_runner
```

## Adding New Tests

To add a new test to an existing suite:

1. Open the appropriate `test_*.c` file
2. Define a new static test function with explicit naming:
   ```c
   static int test_my_new_test(void) {
     uint8_t result[32];
     // Test implementation
     ASSERT(condition, "error message");
     return 0;
   }
   ```
3. Add the test to the suite function:
   ```c
   int suite_argon2(void) {
     int suite_failures = 0;

     printf("  Running test_existing...\n");
     if (test_existing() != 0) {
       suite_failures++;
     }

     printf("  Running test_my_new_test...\n");
     if (test_my_new_test() != 0) {
       suite_failures++;
     }

     return suite_failures;
   }
   ```

## Test Macros

The following assertion macros are available in `test_common.h`:

- `ASSERT(condition, message)` - Assert that a condition is true
- `ASSERT_EQ(a, b, message)` - Assert that two values are equal
- `ASSERT_MEM_EQ(a, b, len, message)` - Assert that two memory buffers are equal

Helper functions:
- `print_hex(label, data, len)` - Print byte array in hexadecimal format

## Test Output

The test runner provides colored output:
- 🟡 Yellow: Test suite is running
- 🟢 Green: Tests passed
- 🔴 Red: Tests failed

The summary at the end shows:
- Number of test suites run
- Number of test suites passed/failed
- Total number of individual test passes/failures

## Current Status

The test suite scaffolding is in place with placeholder tests for all modules.
The framework is ready for adding actual test implementations.
