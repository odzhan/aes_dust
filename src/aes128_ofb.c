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
    uint8_t *p = (uint8_t*)data;
    while (len) {
        if (c->ofb_used == AES_BLK_LEN) {
            aes128_ecb_encrypt(c, c->iv);
            c->ofb_used = 0;
        }
        uint32_t n = AES_BLK_LEN - c->ofb_used;
        if (n > len) n = len;
        for (uint32_t i = 0; i < n; i++) {
            p[i] ^= c->iv[c->ofb_used + i];
        }
        c->ofb_used = (uint8_t)(c->ofb_used + n);
        len -= n;
        p += n;
    }
}
/**
 * Decrypt data in-place using AES-128 in Output Feedback (OFB) mode.
 * OFB mode encryption and decryption are identical operations.
 */
void aes128_ofb_decrypt(aes128_ctx *c, void *data, uint32_t len) {
    aes128_ofb_encrypt(c, data, len);
}
