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

#include <aes128_cfb.h>

/**
 * Encrypts data in-place using AES-128 in CFB mode (CFB-128).
 *
 * @param c     Pointer to the AES-128 context (must hold a valid IV in c->iv).
 * @param data  Pointer to the data buffer (plaintext) to encrypt.
 * @param len   Length in bytes of the data buffer (must be a multiple of AES_BLK_LEN).
 */
int aes128_cfb_encrypt(aes128_ctx* c, void* data, uint32_t len) {
    uint8_t keystream[AES_BLK_LEN];
    uint8_t *buf = (uint8_t*)data;
    uint8_t *iv  = c->iv;

    if (len == 0) {
        return 1;
    }
    if (len & (AES_BLK_LEN - 1)) {
        return 0;
    }

    while (len >= AES_BLK_LEN) {
        memcpy(keystream, iv, AES_BLK_LEN);
        aes128_ecb_encrypt(c, keystream);

        for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
            buf[i] ^= keystream[i];
        }

        iv = buf;
        buf += AES_BLK_LEN;
        len -= AES_BLK_LEN;
    }

    for (uint32_t i = 0; i < AES_BLK_LEN; i++) c->iv[i] = iv[i];
    return 1;
}

/**
 * Decrypts data in-place using AES-128 in CFB mode (CFB-128).
 *
 * @param c     Pointer to the AES-128 context (must hold a valid IV in c->iv).
 * @param data  Pointer to the data buffer (ciphertext) to decrypt.
 * @param len   Length in bytes of the data buffer (must be a multiple of AES_BLK_LEN).
 */
int aes128_cfb_decrypt(aes128_ctx* c, void* data, uint32_t len) {
    uint8_t keystream[AES_BLK_LEN];
    uint8_t tmp[AES_BLK_LEN];
    uint8_t *buf = (uint8_t*)data;
    uint8_t *iv  = c->iv;

    if (len == 0) {
        return 1;
    }
    if (len & (AES_BLK_LEN - 1)) {
        return 0;
    }

    while (len >= AES_BLK_LEN) {
        memcpy(keystream, iv, AES_BLK_LEN);
        aes128_ecb_encrypt(c, keystream);
        memcpy(tmp, buf, AES_BLK_LEN);

        for (uint32_t i = 0; i < AES_BLK_LEN; i++) {
            buf[i] ^= keystream[i];
        }

        iv = tmp;
        buf += AES_BLK_LEN;
        len -= AES_BLK_LEN;
    }

    for (uint32_t i = 0; i < AES_BLK_LEN; i++) c->iv[i] = iv[i];
    return 1;
}
