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

#ifndef AES128_CTR_H
#define AES128_CTR_H

#include <aes128_ecb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Start a new message with a unique 12-byte nonce and counter zero. Discards
 * buffered bytes and clears exhaustion. To choose a different initial counter,
 * set c->ctr[12..15] (big-endian) immediately after this call, before use. */
void aes128_ctr_set(aes128_ctx* c, const void* nonce);
/* In-place streaming: arbitrary chunk boundaries preserve unused keystream.
 * Returns 1 on success, 0 if insufficient counter space; failure changes neither
 * the data nor context. Remaining bytes from the final block may still be used.
 * A zero-length call succeeds even after exhaustion (data may be NULL).
 * Reset through aes128_ctr_set(), never by modifying a used context's counter. */
int aes128_ctr_encrypt(aes128_ctx* c, void* data,  uint32_t len);
int aes128_ctr_decrypt(aes128_ctx* c, void* data,  uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
