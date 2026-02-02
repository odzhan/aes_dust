/**
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

#include <aes128_gcm.h>

#ifndef BIT
#define BIT(x) (1U << (x))
#endif

/* --- Utility functions for Big-Endian conversions --- */
static inline uint32_t GET_BE32(const uint8_t *a) {
    return ((uint32_t)a[0] << 24) | ((uint32_t)a[1] << 16) | ((uint32_t)a[2] << 8) | ((uint32_t)a[3]);
}

static inline void PUT_BE32(uint8_t *a, uint32_t val) {
    a[0] = (uint8_t)((val >> 24) & 0xff);
    a[1] = (uint8_t)((val >> 16) & 0xff);
    a[2] = (uint8_t)((val >> 8) & 0xff);
    a[3] = (uint8_t)(val & 0xff);
}

static inline uint64_t GET_BE64(const uint8_t *a) {
    return (((uint64_t)a[0]) << 56) | (((uint64_t)a[1]) << 48) |
           (((uint64_t)a[2]) << 40) | (((uint64_t)a[3]) << 32) |
           (((uint64_t)a[4]) << 24) | (((uint64_t)a[5]) << 16) |
           (((uint64_t)a[6]) << 8)  | ((uint64_t)a[7]);
}

static inline void PUT_BE64(uint8_t *a, uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        a[i] = (uint8_t)(val & 0xff);
        val >>= 8;
    }
}

static int ct_eq16(const uint8_t a[16], const uint8_t b[16]) {
    uint32_t d = 0;
    for (int i = 0; i < 16; i++) d |= (uint32_t)(a[i] ^ b[i]);
    /* reduce to 0/1 without branches */
    d = (d | -d) >> 31;
    return 1 ^ (int)d; // 1 if equal, 0 if not
}

/* Increment the last 32 bits (big-endian) of a 16-byte block. */
static void inc32(uint8_t *block) {
    uint32_t val = GET_BE32(block + 12);
    val++;
    PUT_BE32(block + 12, val);
}

/* Check if a 32-bit counter can cover len bytes without wrapping. */
static int gcm_ctr_ok(uint32_t len, const uint8_t *J0) {
    if (len == 0) {
        return 1;
    }
    uint64_t blocks = ((uint64_t)len + AES_BLK_LEN - 1) / AES_BLK_LEN;
    uint32_t ctr = GET_BE32(J0 + 12);
    uint64_t remaining = 0xFFFFFFFFu - ctr;
    return blocks <= remaining;
}

/* XOR two 16-byte blocks (dst ^= src). */
static void xor_block(uint8_t *dst, const uint8_t *src) {
    for (int i = 0; i < AES_BLK_LEN; i++) {
        dst[i] ^= src[i];
    }
}

/* Shift a 16-byte block right by one bit.
 * This function treats the block as four 32-bit big-endian words.
 */
static void shift_right_block(uint8_t *v) {
    uint32_t val;
    for (int i = 12; i >= 0; i -= 4) {
        val = GET_BE32(v + i);
        val >>= 1;
        if (i > 0 && (v[i - 1] & 0x01))
            val |= 0x80000000;
        PUT_BE32(v + i, val);
    }
}

/* Multiply two 128-bit values (x and y) in GF(2^128) as used in GCM.
 * z = x * y.
 */
static void gf_mult(const uint8_t *x, const uint8_t *y, uint8_t *z) {
    uint8_t v[16];
    int i, j;
    memset(z, 0, AES_BLK_LEN);
    memcpy(v, y, AES_BLK_LEN);

    for (i = 0; i < AES_BLK_LEN; i++) {
        for (j = 0; j < 8; j++) {
            if (x[i] & BIT(7 - j)) {
                xor_block(z, v);
            }
            if (v[15] & 0x01) {
                shift_right_block(v);
                v[0] ^= 0xe1;
            } else {
                shift_right_block(v);
            }
        }
    }
}

/* Initialize a GHASH accumulator to zero. */
static void ghash_start(uint8_t *y) {
    memset(y, 0, AES_BLK_LEN);
}

/* Compute GHASH(H, X) where X is xlen bytes.
 * The result is accumulated in y.
 */
static void ghash(const uint8_t *h, const uint8_t *x, uint32_t xlen, uint8_t *y) {
    uint32_t m = xlen / AES_BLK_LEN;
    const uint8_t *xpos = x;
    uint8_t tmp[AES_BLK_LEN];

    for (uint32_t i = 0; i < m; i++) {
        xor_block(y, xpos);
        xpos += AES_BLK_LEN;
        gf_mult(y, h, tmp);
        memcpy(y, tmp, AES_BLK_LEN);
    }

    /* Process any remaining partial block */
    uint32_t rem = xlen & (AES_BLK_LEN - 1);
    if (rem) {
        memcpy(tmp, xpos, rem);
        memset(tmp + rem, 0, AES_BLK_LEN - rem);
        xor_block(y, tmp);
        gf_mult(y, h, tmp);
        memcpy(y, tmp, AES_BLK_LEN);
    }
}

/* GCTR function as specified in GCM.
 * Given an initial counter block (icb), encrypt x (of length xlen bytes)
 * to produce output y.
 */
static void aes_gctr(void *ctx, const uint8_t *icb, const uint8_t *x, uint32_t xlen, uint8_t *y) {
    uint32_t n = xlen / AES_BLK_LEN;
    uint32_t last = xlen % AES_BLK_LEN;
    uint8_t cb[AES_BLK_LEN], tmp[AES_BLK_LEN];
    const uint8_t *xpos = x;
    uint8_t *ypos = y;

    if (xlen == 0)
        return;

    memcpy(cb, icb, AES_BLK_LEN);

    for (uint32_t i = 0; i < n; i++) {
        memcpy(ypos, cb, AES_BLK_LEN);
        aes128_ecb_encrypt(ctx, ypos);
        xor_block(ypos, xpos);
        xpos += AES_BLK_LEN;
        ypos += AES_BLK_LEN;
        inc32(cb);
    }

    if (last) {
        memcpy(tmp, cb, AES_BLK_LEN);
        aes128_ecb_encrypt(ctx, tmp);
        for (uint32_t i = 0; i < last; i++) {
            ypos[i] = xpos[i] ^ tmp[i];
        }
    }
}

/* --- Initialization Helpers --- */

/* Initialize the AES context with the given key. */
static void aes_encrypt_init(aes128_ctx *ctx, const uint8_t *key, uint32_t key_len) {
    (void)key_len;
    aes128_init_ctx(ctx);
    aes128_set_key(ctx, (void *)key);
}

/* Initialize the hash subkey H for GCM.
 * H = AES-128(0^128)
 */
static void aes_gcm_init_hash_subkey(aes128_ctx *ctx, const uint8_t *key, uint32_t key_len, uint8_t *H) {
    aes_encrypt_init(ctx, key, key_len);
    memset(H, 0, AES_BLK_LEN);
    aes128_ecb_encrypt(ctx, H);
}

/* Prepare the pre-counter block J0.
 * If IV is 12 bytes, then J0 = IV || 0x00000001.
 * Otherwise, J0 = GHASH(H, IV || padding || [0^64 || (IV_bit_length)]).
 */
static void aes_gcm_prepare_j0(const uint8_t *iv, uint32_t iv_len, const uint8_t *H, uint8_t *J0) {
    uint8_t len_buf[AES_BLK_LEN];

    if (iv_len == 12) {
        memcpy(J0, iv, iv_len);
        memset(J0 + iv_len, 0, AES_BLK_LEN - iv_len);
        J0[AES_BLK_LEN - 1] = 0x01;
    } else {
        ghash_start(J0);
        ghash(H, iv, iv_len, J0);
        PUT_BE64(len_buf, 0);
        PUT_BE64(len_buf + 8, (uint64_t)iv_len * 8);
        ghash(H, len_buf, AES_BLK_LEN, J0);
    }
}

/* A helper that increments J0 and then calls GCTR.
 */
static void aes_gcm_gctr(void *aes, const uint8_t *J0, const uint8_t *in, uint32_t len, uint8_t *out) {
    uint8_t J0inc[AES_BLK_LEN];

    if (len == 0)
        return;

    memcpy(J0inc, J0, AES_BLK_LEN);
    inc32(J0inc);
    aes_gctr(aes, J0inc, in, len, out);
}

/* Compute GHASH over AAD and ciphertext.
 * S = GHASH(H, AAD || C || [bit lengths])
 */
static void aes_gcm_ghash(const uint8_t *H, const uint8_t *aad, uint32_t aad_len,
                          const uint8_t *crypt, uint32_t crypt_len, uint8_t *S) {
    uint8_t len_buf[AES_BLK_LEN];

    ghash_start(S);
    ghash(H, aad, aad_len, S);
    ghash(H, crypt, crypt_len, S);
    PUT_BE64(len_buf, (uint64_t)aad_len * 8);
    PUT_BE64(len_buf + 8, (uint64_t)crypt_len * 8);
    ghash(H, len_buf, AES_BLK_LEN, S);
}

/* --- GCM Public Functions --- */

/* AES-128 GCM Encryption.
 * Inputs:
 *   key, key_len: AES key.
 *   iv, iv_len: Initialization vector.
 *   plain, plain_len: Plaintext.
 *   aad, aad_len: Additional authenticated data.
 * Outputs:
 *   crypt: Ciphertext (same length as plaintext).
 *   tag: Authentication tag (16 bytes).
 * Returns 0 on success.
 */
int aes128_gcm_encrypt(const uint8_t *key, uint32_t key_len, const uint8_t *iv, uint32_t iv_len,
                       const uint8_t *plain, uint32_t plain_len, const uint8_t *aad, uint32_t aad_len,
                       uint8_t *crypt, uint8_t *tag) {
    uint8_t H[AES_BLK_LEN], J0[AES_BLK_LEN], S[AES_BLK_LEN];
    aes128_ctx ctx;

    if (key_len != AES_KEY_LEN) {
        return -1;
    }

    aes_gcm_init_hash_subkey(&ctx, key, key_len, H);
    aes_gcm_prepare_j0(iv, iv_len, H, J0);
    if (!gcm_ctr_ok(plain_len, J0)) {
        return -1;
    }
    aes_gcm_gctr(&ctx, J0, plain, plain_len, crypt);
    aes_gcm_ghash(H, aad, aad_len, crypt, plain_len, S);
    aes_gctr(&ctx, J0, S, AES_BLK_LEN, tag);

    return 0;
}

/* AES-128 GCM Decryption.
 * Inputs:
 *   key, key_len: AES key.
 *   iv, iv_len: Initialization vector.
 *   crypt, crypt_len: Ciphertext.
 *   aad, aad_len: Additional authenticated data.
 *   tag: Authentication tag (16 bytes).
 * Outputs:
 *   plain: Decrypted plaintext (same length as ciphertext).
 * Returns 0 if authentication succeeds, -1 if authentication fails.
 */
int aes128_gcm_decrypt(const uint8_t *key, uint32_t key_len, const uint8_t *iv, uint32_t iv_len,
                       const uint8_t *crypt, uint32_t crypt_len, const uint8_t *aad, uint32_t aad_len,
                       const uint8_t *tag, uint8_t *plain) {
    uint8_t H[AES_BLK_LEN], J0[AES_BLK_LEN], S[AES_BLK_LEN], T[AES_BLK_LEN];
    aes128_ctx ctx;

    if (key_len != AES_KEY_LEN) {
        return -1;
    }

    aes_gcm_init_hash_subkey(&ctx, key, key_len, H);
    aes_gcm_prepare_j0(iv, iv_len, H, J0);
    if (!gcm_ctr_ok(crypt_len, J0)) {
        return -1;
    }
    aes_gcm_ghash(H, aad, aad_len, crypt, crypt_len, S);
    aes_gctr(&ctx, J0, S, AES_BLK_LEN, T);

    if (!ct_eq16(tag, T)) {
        return -1;
    }

    aes_gcm_gctr(&ctx, J0, crypt, crypt_len, plain);
    return 0;
}
