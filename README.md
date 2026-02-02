#![CI](https://github.com/odzhan/aes_dust/actions/workflows/ci.yml/badge.svg)
![Issues](https://img.shields.io/github/issues/odzhan/aes_dust)
![Stars](https://img.shields.io/github/stars/odzhan/aes_dust)
![Forks](https://img.shields.io/github/forks/odzhan/aes_dust)
![License](https://img.shields.io/github/license/odzhan/aes_dust)
![Last Commit](https://img.shields.io/github/last-commit/odzhan/aes_dust)
![Repo Size](https://img.shields.io/github/repo-size/odzhan/aes_dust)

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

### Presets (CMake >= 3.20)
```bash
cmake --preset ninja-release
cmake --build --preset build-release
ctest --preset test-release --output-on-failure
```

### GNU Make wrapper
```bash
make build                # Configure + build (defaults to Release)
make test                 # Run ctest for the current configuration
make install PREFIX=/tmp/install-root
```

Override variables such as `BUILD_TYPE`, `BUILD_DIR`, `GEN`, `WERROR`, `BUILD_TESTING`, `SHARED`, and `PREFIX` as needed.

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

## Project Layout

| Path | Purpose |
|------|---------|
| `include/` | Public headers for each AES-128 mode |
| `src/` | Library sources and the main CMake target |
| `src/compact/` | Experimental ultra-compact build variant |
| `docs/` | Reference material and design notes |
| `cmake/` | Package configuration templates |
| `pkgconfig/` | Template for the `aes_dust.pc` file |
| `test.c` | Cross-mode test driver used by CTest |

## Portability and Security Notes
The implementation is tuned for minimal size rather than constant-time behaviour. Evaluate side-channel resistance for your threat model before deploying the code in high-assurance environments.

## License
AES-dust is released under the terms of the [Unlicense](UNLICENSE), placing the code in the public domain.

## Acknowledgements
Thanks to MarkC for optimisation contributions and to the broader AES community for test vectors and analysis.

