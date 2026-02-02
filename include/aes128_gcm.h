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

#ifndef AES128_GCM_H
#define AES128_GCM_H

#include <aes128_ecb.h>

#ifdef __cplusplus
extern "C" {
#endif

int aes128_gcm_encrypt(const uint8_t *key, uint32_t key_len, const uint8_t *iv, uint32_t iv_len,
	       const uint8_t *plain, uint32_t plain_len,
	       const uint8_t *aad, uint32_t aad_len, uint8_t *crypt, uint8_t *tag);
           
int aes128_gcm_decrypt(const uint8_t *key, uint32_t key_len, const uint8_t *iv, uint32_t iv_len,
	       const uint8_t *crypt, uint32_t crypt_len,
	       const uint8_t *aad, uint32_t aad_len, const uint8_t *tag, uint8_t *plain);
           
#ifdef __cplusplus
}
#endif

#endif
