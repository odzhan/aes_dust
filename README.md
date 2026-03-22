# AES-dust

AES-dust is a compact, size-conscious AES-128 block cipher implementation written in portable C99. It targets resource-constrained environments while still providing modern build tooling and packaging.

## Highlights
- AES-128 with ECB, CBC, CTR, OFB, XTS, CFB, EAX, CCM, GCM, and GCM-SIV modes.
- Portable, warning-clean C99 code tested on 32- and 64-bit little-endian architectures and the Arduino Uno.
- CMake-based build with generated package config files and optional pkg-config integration.
- Self-test executable and vector suites to validate integrations.

## Getting Started

### Prerequisites
- CMake 3.16 or newer
- A C compiler with C99 support
- (Optional) CTest for running the bundled tests

### Configure and build
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Configuration Options
- `AES_DUST_ENABLE_WERROR` (default `OFF`) - treat compiler warnings as errors.
- `BUILD_TESTING` (default `ON`) - enable the test executable and CTest integration.
- `BUILD_SHARED_LIBS` (default `OFF`) - build the library as a shared library.
- Standard CMake controls such as `CMAKE_INSTALL_PREFIX` work as expected.

## Running Tests
Tests build automatically when `BUILD_TESTING` is enabled:

```bash
ctest --test-dir build --output-on-failure
```

On Windows multi-config generators pass `-C Debug` or `-C Release` as appropriate. The helper batch script and Makefile targets supply the correct arguments for you.

## Installation and Consumption
Install headers, the library, and generated metadata:

```bash
cmake --install build --prefix /your/install/prefix
```

Consume from another CMake project:

```cmake
find_package(aes_dust CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE aes_dust::aes128)
```

After installation, pkg-config users can obtain compiler and linker flags with:

```bash
pkg-config --cflags --libs aes_dust
```

## Supported Modes

Ordered roughly by practical security properties (AEAD > confidentiality-only; misuse-resistant first).

| Mode | Security intent / properties | Notes |
|------|------------------------------|-------|
| GCM-SIV | AEAD, nonce-misuse resistant (SIV) | Confidentiality + integrity; best when nonce uniqueness cannot be guaranteed. |
| EAX | AEAD, nonce-based | Confidentiality + integrity; requires unique nonce. |
| CCM | AEAD, nonce-based | Confidentiality + integrity; requires unique nonce and constrained nonce/tag lengths. |
| GCM | AEAD, nonce-based | Confidentiality + integrity; nonce reuse is catastrophic. |
| XTS | Tweakable confidentiality for storage | No integrity; requires unique tweak per sector/block. |
| CTR | Stream cipher mode (confidentiality) | Unique nonce required; no integrity. |
| OFB | Stream cipher mode (confidentiality) | Unique IV required; no integrity. |
| CFB | Stream cipher mode (confidentiality) | Unique IV required; no integrity. |
| CBC | Block mode (confidentiality) | Random/unpredictable IV required; no integrity. |
| ECB | No semantic security | Patterns leak; avoid unless you know why you need it. |

## Test Coverage

Three test executables are built when `BUILD_TESTING` is enabled.

### `aes_dust_vectors_test` — official KAT vectors and negative authentication tests

| Mode | Test vectors | Extra checks |
|------|-------------|--------------|
| ECB | FIPS-197 App. B; NIST SP 800-38A §F.1.1 blocks 1–4 (encrypt + decrypt) | — |
| CBC | NIST SP 800-38A §F.2.1 4-block encrypt + decrypt | Rejects non-block-aligned length |
| CFB-128 | NIST SP 800-38A §F.3.13 4-block encrypt + decrypt | — |
| OFB | NIST SP 800-38A §F.4.1 4-block encrypt + decrypt | — |
| CTR | NIST SP 800-38A §F.5.1 4-block encrypt + decrypt; partial-block (10 bytes) | — |
| XTS | IEEE 1619-2007 TC1 (16 bytes) and TC2 (32 bytes) encrypt + decrypt | Rejects input shorter than one block |
| EAX | Rogaway et al. (2003) TC1 (empty), TC2 (2 bytes), TC3 (5 bytes) encrypt + decrypt | Tampered tag, ciphertext, and AAD each rejected |
| CCM | RFC 3610 TC13 (23-byte msg, 8-byte tag) and TC14 (24-byte msg, 8-byte tag) | Tampered tag and ciphertext rejected; plaintext zeroed on failure |
| GCM | NIST SP 800-38D §B TC1 (empty) and TC2 (16-byte zero PT); custom 80-byte vector | Tampered tag, ciphertext, and AAD each rejected |
| GCM-SIV | RFC 8452 §8.1 TC1 (empty) and TC2 (8-byte PT) encrypt + decrypt | Tampered tag and ciphertext rejected |
| LightMAC | 4 KAT vectors (s=64, t=128): empty, 1, 8, 9 bytes; one-shot and streaming API | Positive and negative `verify`; invalid parameter rejection |

### `aes_dust_test` — cross-mode round-trip and Monte Carlo tests

| Mode | Tests |
|------|-------|
| ECB | FIPS-197 and NIST SP 800-38A §F.1 encrypt + decrypt round-trip (4 vectors each) |
| CBC | Encrypt/decrypt round-trip (2 single-block vectors); NIST AESAVS Monte Carlo test (100 × 1000 iterations) |
| CFB-128 | NIST SP 800-38A §F.3.13 4-block encrypt + decrypt with ciphertext comparison |
| OFB | Encrypt/decrypt round-trip (2 single-block vectors); NIST AESAVS Monte Carlo test (100 × 1000 iterations) |
| CTR | Encrypt/decrypt round-trip (4 blocks, per-block counter reset) |
| XTS | IEEE 1619-2007 TC1 and TC2 encrypt + decrypt with ciphertext comparison |
| EAX | Rogaway et al. TC1–TC3 encrypt + decrypt |
| CCM | RFC 3610 TC13 and TC14 encrypt + decrypt with ciphertext and tag comparison |
| GCM-SIV | RFC 8452 §8.1 TC1 and TC2 encrypt + decrypt |
| GCM | Custom 80-byte vector with AAD; tag comparison + decrypt |

### `aes_dust_lightmac_test` — LightMAC KAT and fuzz

| Sub-test | Description |
|----------|-------------|
| KAT (`kat`) | 7 known-answer vectors (varying s, t, message length); one-shot, streaming, and `verify` API |
| Fuzz (`fuzz 200`) | 200 randomised round-trips: generate tag, verify it matches, verify tampered tag fails, verify tampered message fails |

## Project Layout

| Path | Purpose |
|------|---------|
| `include/` | Public headers for each AES-128 mode |
| `src/` | Library sources and the main CMake target |
| `docs/` | Reference material and design notes |
| `cmake/` | Package configuration templates |
| `pkgconfig/` | Template for the `aes_dust.pc` file |
| `test.c` | Cross-mode round-trip and Monte Carlo test driver |
| `test_vectors.c` | Official KAT vectors and negative authentication tests |
| `test_lightmac.c` | LightMAC KAT and fuzz test driver |

## Portability and Security Notes
The implementation is tuned for minimal size rather than constant-time behaviour. Evaluate side-channel resistance for your threat model before deploying the code in high-assurance environments.

## License
AES-dust is released under the terms of the [Unlicense](UNLICENSE), placing the code in the public domain.

