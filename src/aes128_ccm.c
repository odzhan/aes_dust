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

#include <aes128_ccm.h>
#include <string.h>

static void xor_block(uint8_t *dst, const uint8_t *src) {
    for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
        dst[i] ^= src[i];
    }
}

static void ccm_mac_block(aes128_ctx *ctx, uint8_t y[AES_BLK_LEN], const uint8_t block[AES_BLK_LEN]) {
    uint8_t tmp[AES_BLK_LEN];
    memcpy(tmp, block, AES_BLK_LEN);
    xor_block(tmp, y);
    aes128_ecb_encrypt(ctx, tmp);
    memcpy(y, tmp, AES_BLK_LEN);
}

static void ccm_mac_data(aes128_ctx *ctx, uint8_t y[AES_BLK_LEN], const uint8_t *data, uint32_t len) {
    uint8_t block[AES_BLK_LEN];
    while (len) {
        uint32_t n = len > AES_BLK_LEN ? AES_BLK_LEN : len;
        memset(block, 0, AES_BLK_LEN);
        memcpy(block, data, n);
        ccm_mac_block(ctx, y, block);
        data += n;
        len -= n;
    }
}

static void ccm_mac_aad(aes128_ctx *ctx, uint8_t y[AES_BLK_LEN], const uint8_t *aad, uint32_t aad_len) {
    uint8_t block[AES_BLK_LEN];
    uint32_t hdr = 0;

    if (aad_len == 0) {
        return;
    }

    memset(block, 0, AES_BLK_LEN);
    if (aad_len < 0xFF00) {
        block[0] = (uint8_t)(aad_len >> 8);
        block[1] = (uint8_t)(aad_len);
        hdr = 2;
    } else {
        block[0] = 0xFF;
        block[1] = 0xFE;
        block[2] = (uint8_t)(aad_len >> 24);
        block[3] = (uint8_t)(aad_len >> 16);
        block[4] = (uint8_t)(aad_len >> 8);
        block[5] = (uint8_t)(aad_len);
        hdr = 6;
    }

    uint32_t copy = AES_BLK_LEN - hdr;
    if (copy > aad_len) copy = aad_len;
    memcpy(block + hdr, aad, copy);
    ccm_mac_block(ctx, y, block);
    aad += copy;
    aad_len -= copy;

    ccm_mac_data(ctx, y, aad, aad_len);
}

static void ccm_set_len(uint8_t *dst, uint32_t len, uint32_t L) {
    for (uint32_t i = 0; i < L; i++) {
        dst[L - 1 - i] = (uint8_t)(len & 0xFF);
        len >>= 8;
    }
}

static int ccm_ctr_inc(uint8_t ctr[AES_BLK_LEN], uint32_t L) {
    for (int i = AES_BLK_LEN - 1; i >= (int)(AES_BLK_LEN - L); i--) {
        ctr[i]++;
        if (ctr[i] != 0) {
            return 1;
        }
    }
    return 0;
}

static int ccm_ctr_crypt(aes128_ctx *ctx, const uint8_t *nonce, uint32_t nonce_len, uint32_t L,
                         const uint8_t *in, uint8_t *out, uint32_t len) {
    uint8_t ctr[AES_BLK_LEN];
    uint8_t stream[AES_BLK_LEN];
    memset(ctr, 0, AES_BLK_LEN);
    ctr[0] = (uint8_t)(L - 1);
    memcpy(ctr + 1, nonce, nonce_len);
    ccm_set_len(ctr + AES_BLK_LEN - L, 1, L);

    while (len) {
        memcpy(stream, ctr, AES_BLK_LEN);
        aes128_ecb_encrypt(ctx, stream);

        uint32_t n = len > AES_BLK_LEN ? AES_BLK_LEN : len;
        for (uint32_t i = 0; i < n; i++) {
            out[i] = (uint8_t)(in[i] ^ stream[i]);
        }

        if (!ccm_ctr_inc(ctr, L)) {
            return 0;
        }

        in  += n;
        out += n;
        len -= n;
    }
    return 1;
}

static int ccm_params_ok(uint32_t key_len, uint32_t nonce_len, uint32_t tag_len,
                         uint32_t aad_len, uint32_t msg_len) {
    if (key_len != AES_KEY_LEN) return 0;
    if (nonce_len < 7 || nonce_len > 13) return 0;
    if (tag_len < 4 || tag_len > 16 || (tag_len & 1)) return 0;
    (void)aad_len;
    uint32_t L = 15 - nonce_len;
    if (L < 2 || L > 8) return 0;

    uint64_t max_len;
    if (L >= 4) {
        max_len = 0xFFFFFFFFULL;
    } else {
        max_len = (1ULL << (8 * L)) - 1;
    }
    return (uint64_t)msg_len <= max_len;
}

static void ccm_build_b0(uint8_t b0[AES_BLK_LEN], uint32_t nonce_len, uint32_t tag_len,
                         const uint8_t *nonce, uint32_t msg_len, uint8_t has_aad) {
    uint32_t L = 15 - nonce_len;
    uint8_t flags = 0;
    if (has_aad) flags |= 0x40;
    flags |= (uint8_t)(((tag_len - 2) / 2) << 3);
    flags |= (uint8_t)(L - 1);

    memset(b0, 0, AES_BLK_LEN);
    b0[0] = flags;
    memcpy(b0 + 1, nonce, nonce_len);
    ccm_set_len(b0 + AES_BLK_LEN - L, msg_len, L);
}

static void ccm_build_a0(uint8_t a0[AES_BLK_LEN], const uint8_t *nonce, uint32_t nonce_len) {
    uint32_t L = 15 - nonce_len;
    memset(a0, 0, AES_BLK_LEN);
    a0[0] = (uint8_t)(L - 1);
    memcpy(a0 + 1, nonce, nonce_len);
}

static int ct_eq_tag(const uint8_t *a, const uint8_t *b, uint32_t len) {
    uint8_t d = 0;
    for (uint32_t i = 0; i < len; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

int aes128_ccm_encrypt(const uint8_t *key, uint32_t key_len, const uint8_t *nonce, uint32_t nonce_len,
                       const uint8_t *aad, uint32_t aad_len, const uint8_t *plain, uint32_t plain_len,
                       uint8_t *crypt, uint8_t *tag, uint32_t tag_len) {
    if (!ccm_params_ok(key_len, nonce_len, tag_len, aad_len, plain_len)) {
        return -1;
    }

    aes128_ctx ctx;
    uint8_t y[AES_BLK_LEN] = {0};
    uint8_t b0[AES_BLK_LEN];
    uint8_t a0[AES_BLK_LEN];
    uint8_t s0[AES_BLK_LEN];
    uint8_t T[AES_BLK_LEN];

    aes128_init_ctx(&ctx);
    aes128_set_key(&ctx, (void*)key);

    ccm_build_b0(b0, nonce_len, tag_len, nonce, plain_len, aad_len != 0);
    ccm_mac_block(&ctx, y, b0);
    ccm_mac_aad(&ctx, y, aad, aad_len);
    ccm_mac_data(&ctx, y, plain, plain_len);
    memcpy(T, y, AES_BLK_LEN);

    ccm_build_a0(a0, nonce, nonce_len);
    memcpy(s0, a0, AES_BLK_LEN);
    aes128_ecb_encrypt(&ctx, s0);

    if (plain_len) {
        if (!ccm_ctr_crypt(&ctx, nonce, nonce_len, 15 - nonce_len, plain, crypt, plain_len)) {
            return -1;
        }
    }

    for (uint32_t i = 0; i < tag_len; i++) {
        tag[i] = (uint8_t)(T[i] ^ s0[i]);
    }

    return 0;
}

int aes128_ccm_decrypt(const uint8_t *key, uint32_t key_len, const uint8_t *nonce, uint32_t nonce_len,
                       const uint8_t *aad, uint32_t aad_len, const uint8_t *crypt, uint32_t crypt_len,
                       const uint8_t *tag, uint32_t tag_len, uint8_t *plain) {
    if (!ccm_params_ok(key_len, nonce_len, tag_len, aad_len, crypt_len)) {
        return -1;
    }

    aes128_ctx ctx;
    uint8_t y[AES_BLK_LEN] = {0};
    uint8_t b0[AES_BLK_LEN];
    uint8_t a0[AES_BLK_LEN];
    uint8_t s0[AES_BLK_LEN];
    uint8_t T[AES_BLK_LEN];
    uint8_t tag_calc[AES_BLK_LEN];

    aes128_init_ctx(&ctx);
    aes128_set_key(&ctx, (void*)key);

    ccm_build_a0(a0, nonce, nonce_len);
    memcpy(s0, a0, AES_BLK_LEN);
    aes128_ecb_encrypt(&ctx, s0);

    if (crypt_len) {
        if (!ccm_ctr_crypt(&ctx, nonce, nonce_len, 15 - nonce_len, crypt, plain, crypt_len)) {
            return -1;
        }
    }

    ccm_build_b0(b0, nonce_len, tag_len, nonce, crypt_len, aad_len != 0);
    ccm_mac_block(&ctx, y, b0);
    ccm_mac_aad(&ctx, y, aad, aad_len);
    ccm_mac_data(&ctx, y, plain, crypt_len);
    memcpy(T, y, AES_BLK_LEN);

    for (uint32_t i = 0; i < tag_len; i++) {
        tag_calc[i] = (uint8_t)(T[i] ^ s0[i]);
    }

    if (!ct_eq_tag(tag, tag_calc, tag_len)) {
        if (crypt_len) {
            memset(plain, 0, crypt_len);
        }
        return -1;
    }

    return 0;
}
