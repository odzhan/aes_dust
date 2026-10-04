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

#ifndef AES128_LIGHTMAC_H
#define AES128_LIGHTMAC_H

#include <aes128_ecb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes */
#define AES128_LIGHTMAC_OK         0
#define AES128_LIGHTMAC_BAD_PARAM -1
#define AES128_LIGHTMAC_TOO_LONG  -2
#define AES128_LIGHTMAC_BAD_STATE -3

/**
 * LightMAC context for AES-128.
 *
 * Parameters (stored in the context so callers can control them):
 * - s_bits: counter length in bits (must be multiple of 8, 8..64)
 * - t_bits: tag length in bits (must be multiple of 8, 8..128)
 */
typedef struct _aes128_lightmac_ctx {
    aes128_ctx aes;         /* AES-128 context (sbox + round keys); initialized by aes128_init_ctx(). */
    uint8_t k1[AES_KEY_LEN];/* K1 key bytes (16 bytes); caller provides any 16-byte value. */
    uint8_t k2[AES_KEY_LEN];/* K2 key bytes (16 bytes); caller provides any 16-byte value. */
    uint8_t v[AES_BLK_LEN]; /* Accumulator V (16 bytes); internal state, do not modify directly. */
    uint8_t buf[AES_BLK_LEN];/* Pending message bytes (up to r_bytes); internal buffer. */
    uint8_t buf_len;        /* Bytes currently in buf; valid range 0..r_bytes. */
    uint8_t s_bits;         /* Counter length in bits; must be byte-aligned (8..64). */
    uint8_t t_bits;         /* Tag length in bits; must be byte-aligned (8..128). */
    uint8_t s_bytes;        /* Counter length in bytes; derived from s_bits (1..8). */
    uint8_t t_bytes;        /* Tag length in bytes; derived from t_bits (1..16). */
    uint8_t r_bytes;        /* Rate in bytes per block under K1; derived as 16 - s_bytes. */
    uint8_t key_state;      /* Which key is loaded in aes: 1=K1, 2=K2; internal use. */
    int status;             /* Last error status; AES128_LIGHTMAC_OK on success. */
    uint64_t block_index;   /* Counter i for blocks under K1; starts at 1, increments per block. */
} aes128_lightmac_ctx;

int aes128_lightmac_init(aes128_lightmac_ctx *ctx, const uint8_t *k1, const uint8_t *k2,
                         uint8_t s_bits, uint8_t t_bits);

void aes128_lightmac_reset(aes128_lightmac_ctx *ctx);

int aes128_lightmac_update(aes128_lightmac_ctx *ctx, const uint8_t *data, uint32_t len);

int aes128_lightmac_final(aes128_lightmac_ctx *ctx, uint8_t *tag);

int aes128_lightmac(uint8_t *tag, const uint8_t *k1, const uint8_t *k2,
                    uint8_t s_bits, uint8_t t_bits,
                    const uint8_t *msg, uint32_t msg_len);

/* Returns 1 if tag is valid, 0 if invalid, or a negative error code on failure. */
int aes128_lightmac_verify(const uint8_t *tag, const uint8_t *k1, const uint8_t *k2,
                           uint8_t s_bits, uint8_t t_bits,
                           const uint8_t *msg, uint32_t msg_len);

#ifdef __cplusplus
}
#endif

#endif
