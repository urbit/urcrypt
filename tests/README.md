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
  - `test_scrypt.c` - Tests for scrypt key derivation function
  - `test_urcrypt.c` - Tests for main library (AES, SHA, RIPEMD, secp256k1)

## Running Tests

```bash
make check
```
