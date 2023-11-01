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

#define AES_INT_LEN 4   // 1 = 8-bit, 4 for anything else
#define AES_KEY_LEN 16  // 16 = 128-bit, 32 = 256-bit
#define AES_BLK_LEN 16  // always 16 for 128-bit blocks

#if AES_INT_LEN == 1 && AES_KEY_LEN == 32
#error "AES-256 for 8-bit CPUs is currently unsupported."
#endif

#if AES_KEY_LEN == 32 && defined(ASM)
#error "AES-256 is not supported by the assembly code."
#endif

#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
#  if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || \
      defined(__BYTE_ORDER) && (__BYTE_ORDER == __BIG_ENDIAN) || \
      defined(_BYTE_ORDER) && (_BYTE_ORDER == _BIG_ENDIAN) || \
      defined(BYTE_ORDER) && (BYTE_ORDER) == BIG_ENDIAN || \
      defined(_BIG_ENDIAN) || \
      defined(__ARMEB__) || defined(__THUMBEB__) || defined(__AARCH64EB__) || \
      defined(_MIBSEB) || defined(__MIBSEB) || defined(__MIBSEB__) || \
      defined(_M_PPC)
     //#warning "__BIG_ENDIAN__"
#    define __BIG_ENDIAN__
#  endif
#  if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) /* gcc */ || \
        defined(__BYTE_ORDER) && (__BYTE_ORDER == __LITTLE_ENDIAN) /* linux header */ || \
        defined(_BYTE_ORDER) && (_BYTE_ORDER == _LITTLE_ENDIAN) || \
        defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN) /* mingw header */ ||  \
        defined(_LITTLE_ENDIAN) || /* solaris */ \
        defined(__ARMEL__) || defined(__THUMBEL__) || defined(__AARCH64EL__) || \
        defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__) || \
        defined(_M_IX86) || defined(_M_X64) || defined(_M_IA64) || /* msvc for intel processors */ \
        defined(_M_ARM) /* msvc code on arm executes in little endian mode */
     //#warning "__LITTLE_ENDIAN__"
#    define __LITTLE_ENDIAN__
#  endif
#endif

#if defined(__LITTLE_ENDIAN__) && defined(__BIG_ENDIAN__)
#  error Both __LITTLE_ENDIAN__ and __BIG_ENDIAN__ have been defined!!!
#endif

typedef unsigned char u8;
typedef char s8;

#if AES_INT_LEN == 1
  typedef unsigned char u32;
#else
  #if defined(__BIG_ENDIAN__)
    #define R(v,n)(((v)<<(n))|((v)>>(32-(n))))
    #define SHF_C 24
  #else
    #define R(v,n)(((v)>>(n))|((v)<<(32-(n))))
    #define SHF_C 0
  #endif
  typedef unsigned int u32;
#endif

#ifdef __cplusplus
extern "C" { 
#endif

  #ifdef ASM
    // s should point to 128-bit data and 128-bit key
    void aes_ecb(void *s);
  #else
  // mk should point to a 128-bit or 256-bit key
  // data should point to a 128-bit block of plaintext to encrypt
  void aes_ecb(void *mk, void *data);
  #endif
  
  // len is the amount of bytes to encrypt
  // ctr is the 128-bit counter and nonce
  // data is the plaintext or ciphertext
  // mk is the 128-bit or 256-bit master key
  void aes_ctr(u32 len, void *ctr, void *data, void *mk); 
  
  // iv is the 128-bit initialisation vector.
  void aes_ofb(u32 len, void *iv, void *data, void *mk); 
  
#ifdef __cplusplus
}
#endif

#endif
