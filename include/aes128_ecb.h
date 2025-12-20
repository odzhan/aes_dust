/**
  This is free and unencumbered software released into the public domain.

  Anyone is free to copy, modify, publish, use, compile, sell, or
  distribute this software, either in source code form or as a compiled
  binary, for any purpose, commercial or non-commercial, and by any
  means.

  In jurisdictions that recognize copyright laws, the author or authors
  of this software dedicate any and all copyright interest in the
  software to the public domain. We make this dedication for the benefit
  of the public at large and to the detriment of our heirs and
  successors. We intend this dedication to be an overt act of
  relinquishment in perpetuity of all present and future rights to this
  software under copyright law.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
  OTHER DEALINGS IN THE SOFTWARE.

  For more information, please refer to <http://unlicense.org/> */

#ifndef AES128_ECB_H
#define AES128_ECB_H

#include <string.h>
#include <stdint.h>

#if defined(_MSC_VER)            /* any flavour of MSVC / clang‑cl */
#   define ALIGN16 __declspec(align(16))

#elif defined(__GNUC__) || defined(__clang__)
        /*  GCC, Clang and their cousins (including ICC when –gcc‑compat)  */
#   define ALIGN16 __attribute__((aligned(16)))

#else
    /*  C11/C++11 provide an intrinsic keyword; fall back to that if the
        compiler is neither MSVC nor GCC/Clang but still understands it.   */
#   if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#       define ALIGN16 _Alignas(16)
#   elif defined(__cplusplus) && (__cplusplus >= 201103L)
#       include <cstddef>         /* alignas */
#       define ALIGN16 alignas(16)
#   else
#       error "ALIGN16: unknown compiler—please add alignment syntax here"
#   endif
#endif

/* Pack 4 bytes (little-endian) into a 32-bit word */
static inline uint32_t pack32(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* Unpack a 32-bit word (little-endian) into 4 bytes */
static inline void unpack32(uint32_t v, uint8_t *p) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#define AES_KEY_LEN 16
#define AES_BLK_LEN 16 
#define AES_IV_LEN  16
#define AES_CTR_LEN 16

typedef union _aes_blk_t {
    uint8_t b[AES_BLK_LEN];
    uint16_t h[AES_BLK_LEN/2];
    uint32_t w[AES_BLK_LEN/4];
    uint64_t q[AES_BLK_LEN/8];
} aes_blk_t;

typedef union _aes_key_t {
    uint8_t b[AES_KEY_LEN];
    uint16_t h[AES_KEY_LEN/2];
    uint32_t w[AES_KEY_LEN/4];
    uint64_t q[AES_KEY_LEN/8];
} aes_key_t;

typedef struct _aes128_ctx {
    uint8_t sbox[256];
    uint8_t sbox_inv[256];
    
    uint8_t ctr[AES_CTR_LEN];
    uint8_t iv[AES_IV_LEN];
    aes_key_t rkeys[11];
} aes128_ctx;


#ifdef __cplusplus
extern "C" {
#endif

void
aes128_init_ctx(aes128_ctx*);

void
aes128_set_iv(aes128_ctx*, void*);

void
aes128_set_key(aes128_ctx*, void*);

void 
aes128_ecb_encrypt(aes128_ctx*, void*);

void 
aes128_ecb_decrypt(aes128_ctx*, void*);

#ifdef __cplusplus
}
#endif

#endif

