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

#ifndef AES_H
#define AES_H

#define AES_INT_LEN 1   // 1 = 8-bit, 4 for anything else
#define AES_KEY_LEN 16  // 16 = 128-bit, 32 = 256-bit
#define AES_BLK_LEN 16  // always 16 for 128-bit blocks

#if AES_INT_LEN == 1 && AES_KEY_LEN == 32
#error "AES-256 for 8-bit CPUs is currently unsupported."
#endif

typedef unsigned char u8;
typedef char s8;

#if AES_INT_LEN == 1
  typedef unsigned char u32;
#else
  #define R(v,n)(((v)>>(n))|((v)<<(32-(n))))
  typedef unsigned int u32;
#endif

#ifdef __cplusplus
extern "C" { 
#endif

  // mk should point to a 128-bit or 256-bit key
  // data should point to a 128-bit block of plaintext to encrypt
  void aes_ecb(void *mk, void *data);
  
  // len is the amount of bytes to encrypt
  // ctr is the 128-bit counter and nonce
  // data is the plaintext or ciphertext
  // mk is the 128-bit or 256-bit master key
  void aes_ctr(u32 len, void *ctr, void *data, void *mk); 
  
#ifdef __cplusplus
}
#endif

#endif
