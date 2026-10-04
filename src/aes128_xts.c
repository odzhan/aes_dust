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

  For more information, please refer to <http://unlicense.org/>
 */

#include <aes128_xts.h>

/* Multiply tweak by x in GF(2^128) using little-endian byte order. */
static void xts_gf_mul_x(uint8_t tweak[AES_BLK_LEN]) {
    uint8_t carry = 0;
    for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
        uint8_t next = (uint8_t)(tweak[i] >> 7);
        tweak[i] = (uint8_t)((tweak[i] << 1) | carry);
        carry = next;
    }
    if (carry) {
        tweak[0] ^= 0x87;
    }
}

static int aes128_xts_crypt(aes128_ctx* data_ctx, aes128_ctx* tweak_ctx,
                            const void* tweak_in, void* data, uint32_t len,
                            int decrypt) {
    uint8_t tweak[AES_BLK_LEN];
    uint8_t block[AES_BLK_LEN];
    uint8_t *p = (uint8_t*)data;

    if (len == 0) {
        return 1;
    }
    if (len & (AES_BLK_LEN - 1)) {
        return 0;
    }

    memcpy(tweak, tweak_in, AES_BLK_LEN);
    aes128_ecb_encrypt(tweak_ctx, tweak);

    while (len) {
        for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
            block[i] = (uint8_t)(p[i] ^ tweak[i]);
        }

        if (decrypt) {
            aes128_ecb_decrypt(data_ctx, block);
        } else {
            aes128_ecb_encrypt(data_ctx, block);
        }

        for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
            p[i] = (uint8_t)(block[i] ^ tweak[i]);
        }

        xts_gf_mul_x(tweak);
        p += AES_BLK_LEN;
        len -= AES_BLK_LEN;
    }

    return 1;
}

int aes128_xts_encrypt(aes128_ctx* data_ctx, aes128_ctx* tweak_ctx,
                       const void* tweak, void* data, uint32_t len) {
    return aes128_xts_crypt(data_ctx, tweak_ctx, tweak, data, len, 0);
}

int aes128_xts_decrypt(aes128_ctx* data_ctx, aes128_ctx* tweak_ctx,
                       const void* tweak, void* data, uint32_t len) {
    return aes128_xts_crypt(data_ctx, tweak_ctx, tweak, data, len, 1);
}
