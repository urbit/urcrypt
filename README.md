What is urcrypt?
----------------
urcrypt is a library of cryptography routines used by urbit jets.

Why is urcrypt?
---------------
Urbit's C runtime (long the only urbit runtime) has accumulated a collection of
cryptography dependencies, some with custom additions or patches. These
libraries have different conventions and have been managed by u3 in an ad-hoc
manner. Reproducing that arrangement in other runtimes is tricky and
error-prone. The (sometimes inconsistent) logic must be reproduced and suitable
cryptography primitives must be found (or worse, written) for the new
environment.

To ease these burdens, urcrypt isolates the quirks behind a consistent calling
convention. Everything is a little-endian byte array, and each jetted operation
has a corresponding function in the library. Jets simply unpack their nouns,
call urcrypt, and pack the results.

What is a cryptography routine?
-------------------------------
This is more of a subjective question than it might appear. Any of the following
conditions are sufficient, but not necessary, for a function to be included in
urcrypt:

  * The routine is sensitive to side-channel attacks (encryption, etc)
  * Some property of the routine is cryptographically useful (SHA, RIPE, etc)
  * The routine typically lives in a crypto library, for whatever reason.

A word on dependencies
----------------------
Urcrypt depends on [GNU Nettle](https://www.lysator.liu.se/~nisse/nettle/)
(libnettle) for its SHA, RIPEMD, and AES (ECB, CBC, and SIV) primitives.
Unlike OpenSSL's libcrypto, Nettle keeps no global state, so there is no need
to initialize the library, register custom memory functions, or arrange for a
shared object — urcrypt may be built statically or shared without restriction.

AES-SIV (RFC 5297) is provided by a vendored copy of
[libaes_siv](https://github.com/dfoxfranke/libaes_siv) under `aes_siv/`, with
its OpenSSL primitives retargeted onto Nettle's `cmac128`, `ctr`, and `aes`.
It preserves the full RFC 5297 interface (256/384/512-bit keys and a vector of
associated-data blocks) and passes the upstream RFC 5297 test vectors.

Dependencies
------------
Urcrypt requires the following libraries:

- **GNU Nettle (>= 4.0)** - For SHA, RIPEMD, and AES (ECB, CBC) primitives.
- **libsecp256k1** - For secp256k1 elliptic curve operations. It **must** be
  built with the recovery and Schnorr signature modules enabled (i.e. provide
  `secp256k1_recovery.h` and `secp256k1_schnorrsig.h`); `configure` errors out
  otherwise. Most distribution packages omit these modules, so building from
  source is usually required (see below).

AES-SIV is supplied by the vendored `aes_siv/` copy and needs no external
package.

### macOS Installation

Install the build tools and Nettle via Homebrew:

```bash
brew install autoconf automake libtool autoconf-archive pkg-config nettle
```

### Linux Installation

On Debian/Ubuntu:

```bash
sudo apt-get install autoconf automake libtool autoconf-archive pkg-config nettle-dev
```

### Building libsecp256k1 with the required modules

```bash
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
./autogen.sh
./configure --enable-module-recovery --enable-module-schnorrsig --enable-module-ecdh
make
sudo make install   # then `sudo ldconfig` on Linux
```

Installation
------------

Once dependencies are installed:

```bash
./autogen.sh
./configure
make
sudo make install
```

Building and Testing
--------------------
After installing dependencies, build the library:

```bash
./autogen.sh           # Generate configure script
./configure            # Configure the build (add --disable-shared for static linking)
make                   # Build the library
```

To run the test suite:

```bash
make check
```

To clean up build artifacts:

```bash
make clean             # Remove built files
make distclean         # Remove all generated files (including configure artifacts)
```
