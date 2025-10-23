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

A word on OpenSSL
-----------------
Urcrypt depends on OpenSSL's libcrypto, which has global state. In order
to avoid dealing with this state, urcrypt refuses to build with an internal
libcrypto. Either build statically (pass `--disable-shared` to `./configure`)
or provide a shared libcrypto for urcrypt to link against. It is the library
user's responsibility to initialize openssl, set custom memory functions, etc.

Dependencies
------------
Urcrypt requires the following libraries:

- **OpenSSL (libcrypto)** - For cryptographic primitives
- **libsecp256k1** - For secp256k1 elliptic curve operations (must have recovery and Schnorr signature support enabled)
- **libaes_siv** - For AES-SIV authenticated encryption

### macOS Installation

Install the required tools and most dependencies via Homebrew:

```bash
# Install build tools
brew install autoconf automake libtool autoconf-archive pkg-config

# Install crypto libraries
brew install openssl@3 secp256k1
```

**libaes_siv** is not available via Homebrew and must be built from source:

```bash
git clone https://github.com/dfoxfranke/libaes_siv.git
cd libaes_siv
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
make
sudo make install
```

### Linux Installation

On Debian/Ubuntu:

```bash
sudo apt-get install autoconf automake libtool autoconf-archive pkg-config
sudo apt-get install libssl-dev libsecp256k1-dev

# libaes_siv must be built from source (same instructions as macOS)
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
