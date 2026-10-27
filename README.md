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
cmake --build build --config Release
```

## Configuration Options
- `AES_DUST_ENABLE_WERROR` (default `OFF`) - treat compiler warnings as errors.
- `BUILD_TESTING` (default `ON`) - enable the test executable and CTest integration.
- `BUILD_SHARED_LIBS` (default `OFF`) - build the library as a shared library.
- `AES_DUST_ENABLE_SANITIZERS` (default `OFF`) - enable AddressSanitizer and
  UndefinedBehaviorSanitizer with GCC or Clang; detected errors fail the test.
- `AES_DUST_TEST_DIFFERENTIAL` (default `OFF`) - add independent Python reference
  and offline Wycheproof tests; requires `BUILD_SHARED_LIBS=ON` and the packages
  in `tests/requirements.txt`.
- Standard CMake controls such as `CMAKE_INSTALL_PREFIX` work as expected.

## Running Tests
Tests build automatically when `BUILD_TESTING` is enabled:

```bash
cmake -E chdir build ctest -C Release --output-on-failure
```

Use the same configuration for building, testing, and installation. These examples
select Release explicitly, including with Visual Studio and other multi-config
generators. The Makefile supplies the selected `BUILD_TYPE` for all three steps.
The test command above works with the minimum supported CMake/CTest 3.16.

For memory and undefined-behavior checks, use a separate GCC/Clang build:

```bash
cmake -S . -B build/sanitizers -DCMAKE_BUILD_TYPE=Debug -DAES_DUST_ENABLE_SANITIZERS=ON
cmake --build build/sanitizers --parallel
cmake -E chdir build/sanitizers ctest --output-on-failure
```

To run independent AEAD comparisons, install the pinned test dependencies in
your Python environment and configure a separate shared-library build:

```bash
python -m pip install -r tests/requirements.txt
cmake -S . -B build/reference -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DAES_DUST_TEST_DIFFERENTIAL=ON
cmake --build build/reference --config Release --parallel
cmake -E chdir build/reference ctest -C Release --output-on-failure
```

Assembly regressions require GNU make, GCC, and the GNU assembler. Run:

```bash
make -C src/compact test-asm test-dyn-asm
```

These targets execute static and dynamic S-box backends and keep artifacts in
`build/assembly/`. They test ECB on supported architectures, and CTR plus the
calling convention on x86-64 (CTR also on i386). On Windows, run them in an
MSYS2 UCRT64 shell with its GCC toolchain.

## Installation and Consumption
Install headers, the library, and generated metadata:

```bash
cmake --install build --config Release --prefix /your/install/prefix
```

Use `make clean` to remove compiled artifacts, or `make distclean` to remove the
entire `BUILD_DIR`. Installations outside the build directory are preserved.

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
| CFB | Stream cipher mode (confidentiality) | Fresh unpredictable IV required; no integrity. |
| CBC | Block mode (confidentiality) | Random/unpredictable IV required; no integrity. |
| ECB | No semantic security | Patterns leak; avoid unless you know why you need it. |

## Test Coverage

Fourteen test executables provide 15 CTest entries when `BUILD_TESTING` is enabled:
six core test entries and nine compact C configurations. Enabling
`AES_DUST_TEST_DIFFERENTIAL` adds a sixteenth entry. Assembly tests run through
the separate Makefile targets above.

### `aes_dust_vectors_test` — official KAT vectors and negative authentication tests

| Mode | Test vectors | Extra checks |
|------|-------------|--------------|
| ECB | FIPS-197 AES-128 example; NIST SP 800-38A §F.1.1 blocks 2–4 (encrypt + decrypt) | — |
| CBC | NIST SP 800-38A §F.2.1 4-block encrypt + decrypt | Rejects non-block-aligned length |
| CFB-128 | NIST SP 800-38A §F.3.13 4-block encrypt + decrypt | — |
| OFB | NIST SP 800-38A §F.4.1 4-block encrypt + decrypt | Every two-part split; bytewise decrypt; IV reset |
| CTR | NIST SP 800-38A §F.5.1 4-block encrypt + decrypt; partial-block (10 bytes) | Every two-part split; bytewise decrypt; counter exhaustion; atomic rejection; nonce reset |
| XTS | IEEE 1619-2007 TC1 (16 bytes) and TC2 (32 bytes) encrypt + decrypt | Rejects partial blocks and data units larger than 16 MiB; empty input is a no-op |
| EAX | Rogaway et al. (2003) TC1 (empty), TC2 (2 bytes), TC3 (5 bytes) encrypt + decrypt | Tampered tag, ciphertext, and AAD each rejected; 128-bit counter-wrap regressions |
| CCM | RFC 3610 TC13 (23-byte msg, 8-byte tag) and TC14 (24-byte msg, 8-byte tag) | Tampered tag and ciphertext rejected; plaintext zeroed on failure |
| GCM | Zero-key/IV vectors (empty and 16-byte zero PT); custom 80-byte vector in `aes_dust_test` | Tampered tag, ciphertext, and AAD each rejected |
| GCM-SIV | RFC 8452 §8.1 TC1 (empty) and TC2 (8-byte PT) encrypt + decrypt | Tampered tag and ciphertext rejected |
| LightMAC | 4 KAT vectors (s=64, t=128): empty, 1, 8, 9 bytes; one-shot and streaming API | Positive and negative `verify`; invalid parameter rejection |

All four AEAD modes also exercise in-place encryption and decryption at lengths
0, 1, 15, 16, 17, 31, 32, 33, 64, and 65 bytes. Tampered tags, ciphertext,
AAD, and nonces are rejected. GCM leaves output unchanged on authentication
failure; EAX, CCM, and GCM-SIV zero the output. Checks stay active in Release builds.

The vector suite also checks that GCM rejects empty IVs without changing output,
and that EAX, GCM, and GCM-SIV accept valid messages whose counters wrap.
These regressions cover encryption, decryption, in-place operation, and tag rejection.

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
| KAT (`kat`) | 7 known-answer vectors with every tag bit individually corrupted, plus 48 rate-boundary cases across all counter widths; every two-part split, bytewise updates, tag truncation, counter limits, and finalization/reset checks |
| Fuzz (`fuzz 5000`) | 5000 randomised round-trips: verify generated tags, reject tampered tags, and check modified messages against recomputed tags, including legitimate truncated-tag collisions |

### Independent AEAD and state tests

`aes_dust_aead_test` uses 245 independently generated expected ciphertext/tag
fixtures. It crosses AAD/message lengths 0, 1, 15, 16, 17, 31, 32, and 33 for
EAX, GCM, and GCM-SIV, covers empty/partial/long EAX nonces and nonstandard GCM
IV sizes, and tests every supported CCM nonce/tag-length combination. CCM AAD
lengths 65,279, 65,280, 65,535, and 65,536 exercise its length-prefix transition.
A 65,535-byte CCM message is checked against an independent tag and six
ciphertext windows; oversized messages are rejected before processing.

Every authentication-tag bit is individually corrupted, including each CCM
tag size. Ciphertext, AAD, and nonce bytes are also corrupted. Both disjoint and
in-place output contracts, empty messages, invalid length parameters, unchanged
inputs, and surrounding buffer canaries are checked.

`aes_dust_modes_test` adds 256 independent AES variable-key/variable-plaintext
vectors, CBC/CFB continuation at every block-aligned split, feedback state,
IV resets, rejection without mutation, and independent XTS data units through
512 bytes with unaligned buffers and canaries.

The optional `aes_dust_differential` test runs 1,400 seeded AEAD cases against
PyCryptodome and cryptography plus 474 applicable offline Wycheproof cases.
The Wycheproof subset is pinned to an upstream commit, retains case IDs and
source hashes, and filters out key/tag sizes the API cannot represent; see
`tests/import_wycheproof.py` and `tests/wycheproof/`. Tests never fetch data at
runtime. Python checks remain active under `python -O`.

The checked-in C fixtures need no external test dependencies. Regenerate them
with `tests/generate_aead_vectors.py`, `tests/generate_mode_vectors.py`,
`tests/generate_compact_vectors.py`, and `tests/assembly_generate_vectors.py`
using the pinned Python requirements.
These generators use independent implementations and do not load AES-dust.

Mutation checks confirmed that the added AEAD tests reject three errors missed
by the older suite: omitting GCM tag byte 7, corrupting CCM's extended-AAD prefix,
and encoding the GCM-SIV AAD length in bytes rather than bits. The assembly ABI
probe also rejects an x86-64 backend built for the wrong calling convention.

### Compact C configurations

Nine executables built from `src/compact/test128.c` cover AES-128 with byte and
word implementations and AES-256 with the word implementation, each using the
static, table-free `DYNAMIC`, and per-call `RUNTIME` S-box options. They check
NIST ECB, CTR, and OFB vectors, unaligned key/data buffers, partial stream blocks,
messages longer than 255 bytes, block-aligned continuation, and both CTR/OFB API
naming variants. Each AES-128 configuration also checks 256 independent
variable-key/variable-plaintext vectors; each AES-256 configuration checks 384.
These include every one-bit key/plaintext pattern, varying input alignment,
buffer canaries, and preservation of the caller's key. Failed checks return a
nonzero exit status.

## Project Layout

| Path | Purpose |
|------|---------|
| `include/` | Public headers for each AES-128 mode |
| `src/` | Library sources and the main CMake target |
| `docs/` | Reference material and design notes |
| `cmake/` | Package configuration templates |
| `pkgconfig/` | Template for the `aes_dust.pc` file |
| `tests/` | Library test drivers, independent fixtures, generators, differential checks, and pinned Wycheproof cases |
| `tests/test.c` | Cross-mode round-trip and Monte Carlo test driver |
| `tests/test_vectors.c` | Official KAT vectors, negative authentication tests, and IV/counter-boundary regressions |
| `tests/test_lightmac.c` | LightMAC KAT and fuzz test driver |
| `src/compact/test128.c` | Compact AES-128/256 ECB and stream-mode regression driver |
| `src/compact/test_asm.c` | Assembly ECB/CTR, calling-convention, counter, and buffer regressions |

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
  IVs must contain at least one byte; an empty IV returns -1 without changing
  output or tag storage.
- GCM and GCM-SIV increment their 32-bit counters modulo 2^32. Crossing the
  numeric wrap boundary is valid; the API's `uint32_t` byte lengths are below
  each mode's message-length limit.
- LightMAC requires two independent secret keys, generated independently or
  derived with distinct labels using a suitable KDF. Identical key values return
  `AES128_LIGHTMAC_BAD_PARAM` without changing the context or output tag.
  Keep `s_bits` and `t_bits` fixed for each key pair. Unequal keys alone do not
  guarantee independence. Previously accepted identical-key configurations
  must use a new independent key pair; existing tags from those configurations
  must be regenerated.
- LightMAC processes every complete `16 - s_bits/8` byte block under K1 before
  padding the remaining suffix, including an empty suffix, for finalization.
  A successful `aes128_lightmac_final()` ends the message. Further valid
  `update()` or `final()` calls return `AES128_LIGHTMAC_BAD_STATE` until
  `aes128_lightmac_reset()` starts a new message with the same keys.
- CBC and CFB-128 accept only whole blocks and require fresh unpredictable IVs,
  as specified by [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf).
- XTS supports whole-block data units of at most 16 MiB (2^20 AES blocks), the
  bound in [NIST SP 800-38E](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38e.pdf).
  Empty input succeeds without changes; ciphertext stealing for partial blocks
  is not implemented. Oversized or non-block-aligned requests fail without changes.

The LightMAC boundary correction changes tags for nonempty messages whose
length is an exact multiple of `16 - s_bits/8` bytes. Tags produced by older
versions at those lengths are incompatible with the corrected implementation.

The streaming fix changes the public `aes128_ctx` layout: rebuild the library
and all consumers together. On the reviewed 64-bit MinGW build, the context is
744 bytes (previously 720), including 512 bytes of per-context S-boxes, 176 bytes
of round keys, and stream state. This is a code-size/RAM tradeoff, not a claim of
minimal RAM usage. The separate `src/compact/` implementation has different
storage and build requirements and is not the CMake library backend.

The compact CTR/OFB APIs use `uint32_t` byte lengths independently of
`AES_INT_LEN`. Rebuild compact callers and the implementation together after
this change, especially for the 8-bit configuration. Both modes update their
supplied counter or IV for continuation. Every call except the final call of
a message must contain a whole number of 16-byte blocks; a final partial block
discards unused keystream bytes. Preserve the initial counter or IV and restore
it before decryption. In particular, compact OFB now updates the caller's IV.

## Portability and Security Notes
The implementation is tuned for minimal size rather than constant-time behaviour. Evaluate side-channel resistance for your threat model before deploying the code in high-assurance environments.

## License
AES-dust is released under the terms of the [Unlicense](UNLICENSE), placing the code in the public domain.

