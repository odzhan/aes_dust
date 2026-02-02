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

#include <aes128_eax.h>

static void xor_block(uint8_t *dst, const uint8_t *src) {
    for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
        dst[i] ^= src[i];
    }
}

static void gf128_double(uint8_t *out, const uint8_t *in) {
    uint8_t carry = 0;
    for (int i = AES_BLK_LEN - 1; i >= 0; i--) {
        uint8_t byte = in[i];
        out[i] = (uint8_t)((byte << 1) | carry);
        carry = (byte & 0x80) ? 1 : 0;
    }
    if (carry) {
        out[AES_BLK_LEN - 1] ^= 0x87;
    }
}

static void cmac_subkeys(aes128_ctx *ctx, uint8_t k1[AES_BLK_LEN], uint8_t k2[AES_BLK_LEN]) {
    uint8_t L[AES_BLK_LEN] = {0};
    aes128_ecb_encrypt(ctx, L);
    gf128_double(k1, L);
    gf128_double(k2, k1);
}

static void omac_t(uint8_t out[AES_BLK_LEN], aes128_ctx *ctx, const uint8_t k1[AES_BLK_LEN],
                   const uint8_t k2[AES_BLK_LEN], uint8_t tweak, const uint8_t *data, uint32_t len) {
    uint8_t y[AES_BLK_LEN] = {0};
    uint8_t block[AES_BLK_LEN] = {0};

    block[AES_BLK_LEN - 1] = tweak;

    if (len == 0) {
        xor_block(block, k1);
        aes128_ecb_encrypt(ctx, block);
        memcpy(out, block, AES_BLK_LEN);
        return;
    }

    xor_block(block, y);
    aes128_ecb_encrypt(ctx, block);
    memcpy(y, block, AES_BLK_LEN);

    uint32_t full = len / AES_BLK_LEN;
    uint32_t rem  = len % AES_BLK_LEN;
    const uint8_t *p = data;

    if (full > 1) {
        for (uint32_t i = 0; i + 1 < full; i++) {
            for (uint32_t j = 0; j < AES_BLK_LEN; j++) {
                block[j] = (uint8_t)(p[j] ^ y[j]);
            }
            aes128_ecb_encrypt(ctx, block);
            memcpy(y, block, AES_BLK_LEN);
            p += AES_BLK_LEN;
        }
    }

    if (rem == 0) {
        if (full > 0) {
            for (uint32_t j = 0; j < AES_BLK_LEN; j++) {
                block[j] = (uint8_t)(p[j] ^ k1[j] ^ y[j]);
            }
            aes128_ecb_encrypt(ctx, block);
            memcpy(out, block, AES_BLK_LEN);
        }
        return;
    }

    if (full > 0) {
        for (uint32_t j = 0; j < AES_BLK_LEN; j++) {
            block[j] = (uint8_t)(p[j] ^ y[j]);
        }
        aes128_ecb_encrypt(ctx, block);
        memcpy(y, block, AES_BLK_LEN);
        p += AES_BLK_LEN;
    }

    memset(block, 0, AES_BLK_LEN);
    memcpy(block, p, rem);
    block[rem] = 0x80;
    for (uint32_t j = 0; j < AES_BLK_LEN; j++) {
        block[j] = (uint8_t)(block[j] ^ k2[j] ^ y[j]);
    }
    aes128_ecb_encrypt(ctx, block);
    memcpy(out, block, AES_BLK_LEN);
}

static int ctr_inc_be(uint8_t ctr[AES_BLK_LEN]) {
    for (int i = AES_BLK_LEN - 1; i >= 0; i--) {
        ctr[i]++;
        if (ctr[i] != 0) {
            return 1;
        }
    }
    return 0;
}

static int eax_ctr_crypt(aes128_ctx *ctx, const uint8_t nonce[AES_BLK_LEN],
                         const uint8_t *in, uint8_t *out, uint32_t len) {
    uint8_t ctr[AES_BLK_LEN];
    uint8_t stream[AES_BLK_LEN];
    memcpy(ctr, nonce, AES_BLK_LEN);

    while (len) {
        memcpy(stream, ctr, AES_BLK_LEN);
        aes128_ecb_encrypt(ctx, stream);

        uint32_t n = len > AES_BLK_LEN ? AES_BLK_LEN : len;
        for (uint32_t i = 0; i < n; i++) {
            out[i] = (uint8_t)(in[i] ^ stream[i]);
        }

        if (!ctr_inc_be(ctr)) {
            return 0;
        }
        in  += n;
        out += n;
        len -= n;
    }
    return 1;
}

static int ct_eq16(const uint8_t a[16], const uint8_t b[16]) {
    uint32_t d = 0;
    for (int i = 0; i < 16; i++) d |= (uint32_t)(a[i] ^ b[i]);
    d = (d | (uint32_t)(-(int32_t)d)) >> 31;
    return 1 ^ (int)d;
}

int aes128_eax_encrypt(const uint8_t *key, uint32_t key_len, const uint8_t *nonce, uint32_t nonce_len,
                       const uint8_t *aad, uint32_t aad_len, const uint8_t *plain, uint32_t plain_len,
                       uint8_t *crypt, uint8_t *tag) {
    if (key_len != AES_KEY_LEN) {
        return -1;
    }

    aes128_ctx ctx;
    uint8_t k1[AES_BLK_LEN], k2[AES_BLK_LEN];
    uint8_t n[AES_BLK_LEN], h[AES_BLK_LEN], c[AES_BLK_LEN];

    aes128_init_ctx(&ctx);
    aes128_set_key(&ctx, (void*)key);
    cmac_subkeys(&ctx, k1, k2);

    omac_t(n, &ctx, k1, k2, 0, nonce, nonce_len);
    omac_t(h, &ctx, k1, k2, 1, aad, aad_len);

    if (plain_len) {
        if (!eax_ctr_crypt(&ctx, n, plain, crypt, plain_len)) {
            return -1;
        }
    }

    omac_t(c, &ctx, k1, k2, 2, crypt, plain_len);

    for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
        tag[i] = (uint8_t)(n[i] ^ h[i] ^ c[i]);
    }

    return 0;
}

int aes128_eax_decrypt(const uint8_t *key, uint32_t key_len, const uint8_t *nonce, uint32_t nonce_len,
                       const uint8_t *aad, uint32_t aad_len, const uint8_t *crypt, uint32_t crypt_len,
                       const uint8_t *tag, uint8_t *plain) {
    if (key_len != AES_KEY_LEN) {
        return -1;
    }

    aes128_ctx ctx;
    uint8_t k1[AES_BLK_LEN], k2[AES_BLK_LEN];
    uint8_t n[AES_BLK_LEN], h[AES_BLK_LEN], c[AES_BLK_LEN], t[AES_BLK_LEN];

    aes128_init_ctx(&ctx);
    aes128_set_key(&ctx, (void*)key);
    cmac_subkeys(&ctx, k1, k2);

    omac_t(n, &ctx, k1, k2, 0, nonce, nonce_len);
    omac_t(h, &ctx, k1, k2, 1, aad, aad_len);
    omac_t(c, &ctx, k1, k2, 2, crypt, crypt_len);

    for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
        t[i] = (uint8_t)(n[i] ^ h[i] ^ c[i]);
    }

    if (!ct_eq16(tag, t)) {
        if (crypt_len) {
            memset(plain, 0, crypt_len);
        }
        return -1;
    }

    if (crypt_len) {
        if (!eax_ctr_crypt(&ctx, n, crypt, plain, crypt_len)) {
            return -1;
        }
    }

    return 0;
}
