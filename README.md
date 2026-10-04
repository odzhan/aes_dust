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

On Windows multi-config generators pass `-C Debug` or `-C Release` as appropriate. The Makefile test target supplies the configuration argument for you.

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
| ECB | FIPS-197 AES-128 example; NIST SP 800-38A §F.1.1 blocks 2–4 (encrypt + decrypt) | — |
| CBC | NIST SP 800-38A §F.2.1 4-block encrypt + decrypt | Rejects non-block-aligned length |
| CFB-128 | NIST SP 800-38A §F.3.13 4-block encrypt + decrypt | — |
| OFB | NIST SP 800-38A §F.4.1 4-block encrypt + decrypt | Every two-part split; bytewise decrypt; IV reset |
| CTR | NIST SP 800-38A §F.5.1 4-block encrypt + decrypt; partial-block (10 bytes) | Every two-part split; bytewise decrypt; counter exhaustion; atomic rejection; nonce reset |
| XTS | IEEE 1619-2007 TC1 (16 bytes) and TC2 (32 bytes) encrypt + decrypt | Rejects input shorter than one block |
| EAX | Rogaway et al. (2003) TC1 (empty), TC2 (2 bytes), TC3 (5 bytes) encrypt + decrypt | Tampered tag, ciphertext, and AAD each rejected |
| CCM | RFC 3610 TC13 (23-byte msg, 8-byte tag) and TC14 (24-byte msg, 8-byte tag) | Tampered tag and ciphertext rejected; plaintext zeroed on failure |
| GCM | Zero-key/IV vectors (empty and 16-byte zero PT); custom 80-byte vector in `aes_dust_test` | Tampered tag, ciphertext, and AAD each rejected |
| GCM-SIV | RFC 8452 §8.1 TC1 (empty) and TC2 (8-byte PT) encrypt + decrypt | Tampered tag and ciphertext rejected |
| LightMAC | 4 KAT vectors (s=64, t=128): empty, 1, 8, 9 bytes; one-shot and streaming API | Positive and negative `verify`; invalid parameter rejection |

All four AEAD modes also exercise in-place encryption and decryption at lengths
0, 1, 15, 16, 17, 31, 32, 33, 64, and 65 bytes. Tampered tags, ciphertext,
AAD, and nonces are rejected. GCM leaves output unchanged on authentication
failure; EAX, CCM, and GCM-SIV zero the output. Checks stay active in Release builds.

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
| KAT (`kat`) | 7 known-answer vectors (varying s, t, message length); one-shot and `verify` API |
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

## Buffer and State Contracts

Initialize a context with `aes128_init_ctx()`, set its key, then set the IV or
nonce before starting a message. Each context belongs to one active message.
CTR and OFB accept arbitrary chunk sizes and retain unused keystream bytes, so
splitting a message does not change its ciphertext. Decryption uses the same
initial IV/nonce and a fresh or reset context.

- `aes128_ctr_set()` accepts a unique 12-byte nonce, starts the 32-bit big-endian
  counter at zero, discards buffered bytes, and clears exhaustion. To supply a
  different initial counter, set `ctx.ctr[12..15]` immediately after the setter,
  before processing any data. Do not modify a used context's counter directly.
- CTR returns 1 on success or 0 if the request exceeds remaining counter space.
  Rejection changes neither data nor context. The last block can be consumed
  across calls; subsequent requests fail once its buffered bytes are exhausted.
  Zero-length requests always succeed. A new unique nonce starts another message.
- `aes128_set_iv()` resets OFB buffering for a new message. Changing the key
  discards buffered stream bytes; set a fresh IV/nonce before starting again.
- GCM message input/output may be identical or disjoint. Partial overlap is
  unsupported. Keep tag storage separate from message storage. A bad tag returns
  -1 and leaves the output unchanged; successful encryption/decryption returns 0.
- CBC and CFB-128 accept only whole blocks. XTS supports whole-block data units;
  ciphertext stealing for partial blocks is not implemented.

The streaming fix changes the public `aes128_ctx` layout: rebuild the library
and all consumers together. On the reviewed 64-bit MinGW build, the context is
744 bytes (previously 720), including 512 bytes of per-context S-boxes, 176 bytes
of round keys, and stream state. This is a code-size/RAM tradeoff, not a claim of
minimal RAM usage. The separate `src/compact/` implementation has different
storage and build requirements and is not the CMake library backend.

## Portability and Security Notes
The implementation is tuned for minimal size rather than constant-time behaviour. Evaluate side-channel resistance for your threat model before deploying the code in high-assurance environments.

## License
AES-dust is released under the terms of the [Unlicense](UNLICENSE), placing the code in the public domain.

