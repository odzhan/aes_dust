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

#include <aes128_gcm_siv.h>
#include <string.h>

static void xor_block(uint8_t *dst, const uint8_t *src) {
    for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
        dst[i] ^= src[i];
    }
}

static int gcm_siv_ctr_ok(uint32_t len, const uint8_t tag[AES_BLK_LEN]) {
    if (len == 0) {
        return 1;
    }
    uint64_t blocks = ((uint64_t)len + AES_BLK_LEN - 1) / AES_BLK_LEN;
    uint32_t ctr = (uint32_t)tag[0] |
                   ((uint32_t)tag[1] << 8) |
                   ((uint32_t)tag[2] << 16) |
                   ((uint32_t)tag[3] << 24);
    uint64_t remaining = 0x100000000ULL - ctr;
    return blocks <= remaining;
}

static void polyval_mul(const uint8_t *x, const uint8_t *y, uint8_t *out) {
    uint8_t z[AES_BLK_LEN] = {0};
    uint8_t v[AES_BLK_LEN];
    memcpy(v, y, AES_BLK_LEN);

    for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
        for (uint32_t bit = 0; bit < 8; bit++) {
            if (x[i] & (1U << bit)) {
                xor_block(z, v);
            }

            uint8_t carry = 0;
            for (uint32_t j = 0; j < AES_BLK_LEN; j++) {
                uint8_t next = (uint8_t)((v[j] >> 7) & 1U);
                v[j] = (uint8_t)((v[j] << 1) | carry);
                carry = next;
            }
            if (carry) {
                v[0] ^= 0x01;
                v[AES_BLK_LEN - 1] ^= 0xC2;
            }
        }
    }

    memcpy(out, z, AES_BLK_LEN);
}

static void polyval_update(uint8_t y[AES_BLK_LEN], const uint8_t h[AES_BLK_LEN],
                           const uint8_t *data, uint32_t len) {
    uint8_t block[AES_BLK_LEN];
    uint8_t tmp[AES_BLK_LEN];

    while (len >= AES_BLK_LEN) {
        memcpy(block, data, AES_BLK_LEN);
        for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
            tmp[i] = (uint8_t)(y[i] ^ block[i]);
        }
        polyval_mul(tmp, h, y);
        data += AES_BLK_LEN;
        len -= AES_BLK_LEN;
    }

    if (len) {
        memset(block, 0, AES_BLK_LEN);
        memcpy(block, data, len);
        for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
            tmp[i] = (uint8_t)(y[i] ^ block[i]);
        }
        polyval_mul(tmp, h, y);
    }
}

static void write_le64(uint8_t out[8], uint64_t v) {
    for (uint32_t i = 0; i < 8; i++) {
        out[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

static void polyval_hash(uint8_t out[AES_BLK_LEN], const uint8_t h[AES_BLK_LEN],
                         const uint8_t *aad, uint32_t aad_len,
                         const uint8_t *plain, uint32_t plain_len) {
    static const uint8_t polyval_x_inv[AES_BLK_LEN] = {
        0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x92
    };
    uint8_t y[AES_BLK_LEN] = {0};
    uint8_t h_dot[AES_BLK_LEN];
    uint8_t len_block[AES_BLK_LEN];
    uint8_t tmp[AES_BLK_LEN];

    /* POLYVAL uses dot(a, b) = a * b * x^-128. Precompute H * x^-128. */
    polyval_mul(h, polyval_x_inv, h_dot);

    polyval_update(y, h_dot, aad, aad_len);
    polyval_update(y, h_dot, plain, plain_len);

    write_le64(len_block, (uint64_t)aad_len * 8);
    write_le64(len_block + 8, (uint64_t)plain_len * 8);

    for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
        tmp[i] = (uint8_t)(y[i] ^ len_block[i]);
    }
    polyval_mul(tmp, h_dot, y);
    memcpy(out, y, AES_BLK_LEN);
}

static void gcm_siv_derive(const uint8_t *key, const uint8_t *nonce,
                           uint8_t h[AES_BLK_LEN], uint8_t k[AES_BLK_LEN],
                           aes128_ctx *ctx) {
    uint8_t block[AES_BLK_LEN];

    aes128_init_ctx(ctx);
    aes128_set_key(ctx, (void*)key);

    for (uint32_t i = 0; i < 4; i++) {
        block[0] = (uint8_t)(i & 0xFF);
        block[1] = (uint8_t)((i >> 8) & 0xFF);
        block[2] = (uint8_t)((i >> 16) & 0xFF);
        block[3] = (uint8_t)((i >> 24) & 0xFF);
        memcpy(block + 4, nonce, 12);
        aes128_ecb_encrypt(ctx, block);

        if (i == 0) {
            memcpy(h, block, 8);
        } else if (i == 1) {
            memcpy(h + 8, block, 8);
        } else if (i == 2) {
            memcpy(k, block, 8);
        } else {
            memcpy(k + 8, block, 8);
        }
    }
}

static void gcm_siv_ctr(aes128_ctx *ctx, const uint8_t tag[AES_BLK_LEN],
                        const uint8_t *in, uint8_t *out, uint32_t len) {
    uint8_t ctr[AES_BLK_LEN];
    uint8_t stream[AES_BLK_LEN];
    memcpy(ctr, tag, AES_BLK_LEN);
    ctr[AES_BLK_LEN - 1] |= 0x80;

    while (len) {
        memcpy(stream, ctr, AES_BLK_LEN);
        aes128_ecb_encrypt(ctx, stream);

        uint32_t n = len > AES_BLK_LEN ? AES_BLK_LEN : len;
        for (uint32_t i = 0; i < n; i++) {
            out[i] = (uint8_t)(in[i] ^ stream[i]);
        }

        for (uint32_t i = 0; i < 4; i++) {
            ctr[i]++;
            if (ctr[i] != 0) break;
        }

        in += n;
        out += n;
        len -= n;
    }
}

static int ct_eq16(const uint8_t a[16], const uint8_t b[16]) {
    uint32_t d = 0;
    for (int i = 0; i < 16; i++) d |= (uint32_t)(a[i] ^ b[i]);
    d = (d | (uint32_t)(-(int32_t)d)) >> 31;
    return 1 ^ (int)d;
}

int aes128_gcm_siv_encrypt(const uint8_t *key, uint32_t key_len, const uint8_t *nonce, uint32_t nonce_len,
                           const uint8_t *aad, uint32_t aad_len, const uint8_t *plain, uint32_t plain_len,
                           uint8_t *crypt, uint8_t *tag) {
    if (key_len != AES_KEY_LEN || nonce_len != 12) {
        return -1;
    }

    aes128_ctx ctx;
    uint8_t h[AES_BLK_LEN];
    uint8_t k[AES_BLK_LEN];
    uint8_t s[AES_BLK_LEN];

    gcm_siv_derive(key, nonce, h, k, &ctx);
    aes128_set_key(&ctx, (void*)k);

    polyval_hash(s, h, aad, aad_len, plain, plain_len);
    for (uint32_t i = 0; i < 12; i++) {
        s[i] ^= nonce[i];
    }
    s[AES_BLK_LEN - 1] &= 0x7F;

    memcpy(tag, s, AES_BLK_LEN);
    aes128_ecb_encrypt(&ctx, tag);

    if (plain_len) {
        if (!gcm_siv_ctr_ok(plain_len, tag)) {
            return -1;
        }
        gcm_siv_ctr(&ctx, tag, plain, crypt, plain_len);
    }

    return 0;
}

int aes128_gcm_siv_decrypt(const uint8_t *key, uint32_t key_len, const uint8_t *nonce, uint32_t nonce_len,
                           const uint8_t *aad, uint32_t aad_len, const uint8_t *crypt, uint32_t crypt_len,
                           const uint8_t *tag, uint8_t *plain) {
    if (key_len != AES_KEY_LEN || nonce_len != 12) {
        return -1;
    }

    aes128_ctx ctx;
    uint8_t h[AES_BLK_LEN];
    uint8_t k[AES_BLK_LEN];
    uint8_t s[AES_BLK_LEN];
    uint8_t calc[AES_BLK_LEN];

    gcm_siv_derive(key, nonce, h, k, &ctx);
    aes128_set_key(&ctx, (void*)k);

    if (crypt_len) {
        if (!gcm_siv_ctr_ok(crypt_len, tag)) {
            return -1;
        }
        gcm_siv_ctr(&ctx, tag, crypt, plain, crypt_len);
    }

    polyval_hash(s, h, aad, aad_len, plain, crypt_len);
    for (uint32_t i = 0; i < 12; i++) {
        s[i] ^= nonce[i];
    }
    s[AES_BLK_LEN - 1] &= 0x7F;

    memcpy(calc, s, AES_BLK_LEN);
    aes128_ecb_encrypt(&ctx, calc);

    if (!ct_eq16(tag, calc)) {
        if (crypt_len) {
            memset(plain, 0, crypt_len);
        }
        return -1;
    }

    return 0;
}
