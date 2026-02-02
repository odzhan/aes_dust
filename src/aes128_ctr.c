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
 * @return      1 on success, or 0 if the 4-byte counter overflows.
 */
int aes128_ctr_encrypt(aes128_ctx* c, void* data, uint32_t len) {
    uint8_t keystream[AES_BLK_LEN];
    uint8_t *p = (uint8_t*)data;

    if (len == 0) {
        return 1;
    }

    uint64_t blocks = ((uint64_t)len + AES_BLK_LEN - 1) / AES_BLK_LEN;
    uint8_t ctr_tmp[AES_BLK_LEN];
    memcpy(ctr_tmp, c->ctr, AES_BLK_LEN);
    for (uint64_t b = 0; b < blocks; b++) {
        if (!ctr32_inc_be(ctr_tmp)) {
            return 0;
        }
    }

    while (len > 0) {
        // Prepare the keystream block by copying the current 16-byte counter block.
        memcpy(keystream, c->ctr, AES_BLK_LEN);

        // Encrypt the counter block using AES-128 ECB mode to generate the keystream.
        aes128_ecb_encrypt(c, keystream);

        // Determine the number of bytes to process in this block.
        uint32_t block_bytes = (len > AES_BLK_LEN) ? AES_BLK_LEN : len;

        // XOR the keystream with the plaintext (or ciphertext).
        for (uint32_t i = 0; i < block_bytes; i++) {
            p[i] ^= keystream[i];
        }

        // Advance the data pointer and decrease the length.
        len -= block_bytes;
        p += block_bytes;

        // Increment only the counter portion (last 4 bytes of c->ctr).
        // The nonce (first 12 bytes) remains unchanged.
        ctr32_inc_be(c->ctr);
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
 * @return      1 on success, or 0 if the counter overflows.
 */
int aes128_ctr_decrypt(aes128_ctx* c, void* data, uint32_t len) {
    return aes128_ctr_encrypt(c, data, len);
}

/**
void aes128_ctr_set(aes128_ctx* c, const void* nonce12) {
    memset(c->ctr, 0, AES_BLK_LEN);
    memcpy(c->ctr, nonce12, 12); // 96-bit nonce; counter is c->ctr[12..15] (big-endian)
}

static inline int ctr32_inc_be(uint8_t ctr[16]) {
    for (int i = 15; i >= 12; i--) {
        ctr[i]++;
        if (ctr[i] != 0) return 1;   // no carry: ok
    }
    return 0; // overflow (all four bytes wrapped)
}

int aes128_ctr_encrypt(aes128_ctx* c, void* data, size_t len) {
    uint8_t keystream[AES_BLK_LEN];
    uint8_t *p = (uint8_t*)data;

    while (len) {
        memcpy(keystream, c->ctr, AES_BLK_LEN);
        aes128_ecb_encrypt(c, keystream);

        size_t n = len > AES_BLK_LEN ? AES_BLK_LEN : len;
        for (size_t i = 0; i < n; i++) p[i] ^= keystream[i];

        p += n;
        len -= n;

        if (!ctr32_inc_be(c->ctr)) return 0; // counter exhausted
    }
    return 1;
}

int aes128_ctr_decrypt(aes128_ctx* c, void* data, size_t len) {
    return aes128_ctr_encrypt(c, data, len);
}
*/
