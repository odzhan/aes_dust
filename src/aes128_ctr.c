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

  For more information, please refer to <http://unlicense.org/> */

#include "aes128_ctr.h"

void
aes128_ctr_set(aes128_ctx* c, void* nonce) {
    
}

/**
    Encrypt data inplace using AES-128 in CTR mode.
*/
void 
aes128_ctr_encrypt(aes128_ctx* c, void* data,  u32 len) {
    u8 i, r, t[AES_BLK_LEN], *p = data;

    while (len) {
        // copy counter+nonce to local buffer
        for (i = 0; i < AES_BLK_LEN; i++)t[i] = c->ctr[i];
        // encrypt t
        aes128_ecb_encrypt(c, t);
        // XOR plaintext with ciphertext
        r = len > AES_BLK_LEN ? AES_BLK_LEN : len;
        for (i = 0; i < r; i++) p[i] ^= t[i];
        // update length + position
        len -= r; p += r;
        // update counter.
        for (i = AES_BLK_LEN; i != 0; i--)
            if (++c->ctr[i - 1]) break;
    }
}

/**
    Decrypt data inplace using AES-128 in CTR mode.
*/
void 
aes128_ctr_decrypt(aes128_ctx* c, void* data,  u32 len) {
    aes128_ctr_encrypt(c, data, len);
}
