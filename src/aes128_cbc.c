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

#include <aes128_cbc.h>

/**
 * Encrypts data in-place using AES-128 in CBC mode.
 *
 * @param c     Pointer to the AES-128 context (must hold a valid IV in c->iv).
 * @param data  Pointer to the data buffer (plaintext) to encrypt.
 * @param len   Length in bytes of the data buffer (must be a multiple of AES_BLK_LEN).
 */
void aes128_cbc_encrypt(aes128_ctx* c, void* data, uint32_t len) {
    uint8_t *buf = (uint8_t*)data;
    uint8_t *iv  = c->iv;

    while (len >= AES_BLK_LEN) {
        // XOR the current plaintext block with the IV (or previous ciphertext)
        for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
            buf[i] ^= iv[i];
        }
        // Encrypt the block in-place using AES-128 ECB
        aes128_ecb_encrypt(c, buf);

        // Update IV to the ciphertext block just produced
        iv = buf;
        buf += AES_BLK_LEN;
        len -= AES_BLK_LEN;
    }

    // Update the IV in the AES context
    for (uint32_t i=0; i<AES_BLK_LEN; i++) c->iv[i] = iv[i];
}


/**
 * Decrypts data in-place using AES-128 in CBC mode.
 *
 * @param c     Pointer to the AES-128 context (must hold a valid IV in c->iv).
 * @param data  Pointer to the data buffer (ciphertext) to decrypt.
 * @param len   Length in bytes of the data buffer (must be a multiple of AES_BLK_LEN).
 */
void aes128_cbc_decrypt(aes128_ctx* c, void* data, uint32_t len) {
    uint8_t i, tmp[AES_BLK_LEN], *buf = (uint8_t*)data, *iv = c->iv;

    while (len >= AES_BLK_LEN) {
        // Copy ciphertext to local buffer.
        for (i = 0; i<AES_BLK_LEN; i++) tmp[i] = buf[i];
        // Decrypt ciphertext.
        aes128_ecb_decrypt(c, buf);
        // XOR the result with IV or last ciphertext.
        for (i = 0; i < AES_BLK_LEN; i++) buf[i] ^= iv[i];
        // Update length, IV and position.
        len -= AES_BLK_LEN;
        iv = tmp;
        buf += AES_BLK_LEN;
    }
    for (i=0; i<AES_BLK_LEN; i++) c->iv[i] = iv[i];
}


