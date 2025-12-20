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

#include <aes128_ofb.h>

/**
 * Encrypt (or decrypt) data in-place using AES-128 in Output Feedback (OFB) mode.
 * 
 * @param c     Pointer to the AES-128 context (must hold a valid IV in c->iv).
 * @param data  Pointer to the data buffer to encrypt or decrypt.
 * @param len   Number of bytes in the data buffer.
 */
void aes128_ofb_encrypt(aes128_ctx *c, void *data, uint32_t len) {
    uint8_t i, r, t[AES_BLK_LEN], * p = data, *iv = c->iv;

    // copy IV to local buffer
    for (i = 0; i < AES_BLK_LEN; i++)t[i] = iv[i];

    while (len) {
        // encrypt t
        aes128_ecb_encrypt(c, t);
        // XOR plaintext with ciphertext
        r = len > AES_BLK_LEN ? AES_BLK_LEN : len;
        for (i = 0; i < r; i++) p[i] ^= t[i];
        // update length + position
        len -= r;
        iv = t;        
        p += r;
    }
    // update iv in context
    for (i = 0; i < AES_BLK_LEN; i++) c->iv[i] = iv[i];
}
/**
bool aes128_ofb_crypt(aes128_ctx *c, void *data, size_t len) {
    uint8_t t[AES_BLK_LEN];
    uint8_t *p = (uint8_t*)data;

    // Initialize keystream state from IV
    for (size_t i = 0; i < AES_BLK_LEN; i++) t[i] = c->iv[i];

    while (len) {
        // Generate next 16 bytes of keystream
        aes128_ecb_encrypt(c, t);

        size_t r = len > AES_BLK_LEN ? AES_BLK_LEN : len;
        for (size_t i = 0; i < r; i++) p[i] ^= t[i];

        p   += r;
        len -= r;
    }

    // Carry the updated OFB state
    for (size_t i = 0; i < AES_BLK_LEN; i++) c->iv[i] = t[i];
    return true;
}
*/
/**
 * Decrypt data in-place using AES-128 in Output Feedback (OFB) mode.
 * OFB mode encryption and decryption are identical operations.
 */
void aes128_ofb_decrypt(aes128_ctx *c, void *data, uint32_t len) {
    aes128_ofb_encrypt(c, data, len);
}
