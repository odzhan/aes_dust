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

#include <aes128_ctr.h>

static int ctr32_inc_be(uint8_t ctr[16]) {
    for (int i = AES_BLK_LEN - 1; i >= 12; i--) {
        ctr[i]++;
        if (ctr[i] != 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * Sets the nonce for AES-128 CTR mode.
 *
 * The nonce must be 12 bytes long. The remaining 4 bytes of the counter
 * block are set to 0.
 *
 * @param c     Pointer to the AES-128 context.
 * @param nonce Pointer to the 12-byte nonce.
 */
void aes128_ctr_set(aes128_ctx* c, const void* nonce) {
    // Clear the entire 16-byte counter block.
    memset(c->ctr, 0, AES_BLK_LEN);
    // Copy the 12-byte nonce into the first 12 bytes.
    memcpy(c->ctr, nonce, 12);
    c->ctr_used = AES_BLK_LEN;
    c->ctr_exhausted = 0;
}

/**
 * Encrypts (or decrypts) data using AES-128 in CTR mode.
 *
 * CTR mode turns a block cipher into a stream cipher by encrypting a counter
 * block and XORing the result with the plaintext. Note that encryption and
 * decryption are identical operations in CTR mode.
 *
 * @param c     Pointer to the AES-128 context containing the key schedule and counter.
 * @param data  Pointer to the data buffer (plaintext or ciphertext).
 * @param len   Length of the data in bytes.
 *
 * @return      1 on success, or 0 if insufficient counter space remains.
 */
int aes128_ctr_encrypt(aes128_ctx* c, void* data, uint32_t len) {
    uint8_t *p = (uint8_t*)data;
    uint32_t buffered = AES_BLK_LEN - c->ctr_used;
    uint64_t needed = len > buffered ? (uint64_t)len - buffered : 0;
    uint64_t blocks = (needed + AES_BLK_LEN - 1) / AES_BLK_LEN;
    uint32_t ctr_val = ((uint32_t)c->ctr[12] << 24) |
                       ((uint32_t)c->ctr[13] << 16) |
                       ((uint32_t)c->ctr[14] << 8) |
                       (uint32_t)c->ctr[15];
    uint64_t available = c->ctr_exhausted ? 0 : 0x100000000ULL - ctr_val;

    /* Reject the entire request before changing either data or context. */
    if (blocks > available) {
        return 0;
    }

    while (len > 0) {
        if (c->ctr_used == AES_BLK_LEN) {
            memcpy(c->ctr_stream, c->ctr, AES_BLK_LEN);
            aes128_ecb_encrypt(c, c->ctr_stream);
            c->ctr_used = 0;
            if (!ctr32_inc_be(c->ctr)) {
                c->ctr_exhausted = 1;
            }
        }
        uint32_t n = AES_BLK_LEN - c->ctr_used;
        if (n > len) n = len;
        for (uint32_t i = 0; i < n; i++) {
            p[i] ^= c->ctr_stream[c->ctr_used + i];
        }
        c->ctr_used = (uint8_t)(c->ctr_used + n);
        p += n;
        len -= n;
    }

    return 1;
}

/**
 * Decrypts data using AES-128 in CTR mode.
 *
 * Since CTR mode encryption is symmetric, decryption is identical to encryption.
 *
 * @param c     Pointer to the AES-128 context.
 * @param data  Pointer to the data buffer.
 * @param len   Length of the data in bytes.
 *
 * @return      1 on success, or 0 if insufficient counter space remains.
 */
int aes128_ctr_decrypt(aes128_ctx* c, void* data, uint32_t len) {
    return aes128_ctr_encrypt(c, data, len);
}

