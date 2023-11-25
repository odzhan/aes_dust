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

// Test unit for AES-128 ECB and CTR mode
// Odzhan

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "aes.h"

#if AES_KEY_LEN == 32
#error "Only AES-128 is supported by this test unit. Set AES_KEY_LEN in aes.h to 16."
#endif

// 4 128-bit keys
uint8_t 
ecb_keys[4][16]={
  {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
  {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
  {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
  {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
};

// 4 128-bit plain texts
uint8_t 
ecb_plain[4][16]={
  {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a},
  {0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51},
  {0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef},
  {0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10}
};

// 4 128-bit cipher texts
uint8_t 
ecb_cipher[4][16]={
  {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97},
  {0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf},
  {0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88},
  {0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4}
};

uint8_t 
ctr_key[16]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

uint8_t 
ctr_tv[16]={0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};

uint8_t 
ctr_plain[4][16]={
  {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
  {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51},
  {0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef},
  {0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10}};

uint8_t 
ctr_cipher[4][16]={
  {0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce},
  {0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff},
  {0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab},
  {0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee}};

//
// OFB test vectors.
//

// echo -n -e '\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a' | openssl enc -e -aes-128-ofb -nosalt -A -K 
// 2B7E151628AED2A6ABF7158809CF4F3C -iv 000102030405060708090A0B0C0D0E0F | xxd -i
uint8_t 
ofb_key[2][16]={
{  0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c},
  {0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}};

uint8_t 
ofb_iv[2][16]={
{  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
  {0xb7,0xbf,0x3a,0x5d,0xf4,0x39,0x89,0xdd,0x97,0xf0,0xfa,0x97,0xeb,0xce,0x2f,0x4a}};

uint8_t 
ofb_plain[2][16]={
{  0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
  {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}};

uint8_t 
ofb_cipher[2][16]={
{  0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a},
  {0x7a,0x47,0x2d,0xe3,0x24,0x91,0xf9,0x2b,0x4b,0x2c,0x93,0x17,0x28,0x3b,0xb5,0xd4}};

static
void 
bin2hex(char *s, void *p, int len) {
    int i;
    
    printf("%-10s : ", s);
    
    for (i=0; i<len; i++) { 
      printf ("%02x ", ((uint8_t*)p)[i]);
      
			if ((i & 15) == 15)
				printf("\n");
       
    }
}

int 
main (void) {
    int     i, equ;
    uint8_t data[16], key[AES_KEY_LEN];
    
    puts ("\n**** AES-128 ECB Test ****\n");
    
    // ecb tests
    for (i=0; i<4; i++) {
      memcpy(data, ecb_plain[i], 16);
      memcpy(key, ecb_keys[i], AES_KEY_LEN);
      
      #ifdef ASM
        uint8_t s[32];
        memcpy(s, data, 16);
        memcpy(&s[16], key, 16);
        
        aes_ecb(s);
        memcpy(data, s, 16);
      #else
        aes_ecb(key, data);
      #endif
      equ = (memcmp(data, ecb_cipher[i], 16) == 0);
      
      bin2hex("key", key, 16);
      bin2hex("cipher", data, 16);
      
      printf("AES-128 ECB Test #%i : %s\n\n", 
        (i+1), equ ? "OK" : "FAILED");
    }
    
    #ifdef CTR
      puts ("\n**** AES-128 CTR Test ****\n");
      // ctr tests
      bin2hex("key", ctr_key, 16);
        
      for(i=0; i<4; i++) {
        bin2hex("ctr", ctr_tv, 16);
        bin2hex("plain", ctr_plain[i], 16);
        
        memcpy(data, ctr_plain[i], 16);
        
        aes_ctr_encrypt(16, ctr_tv, data, ctr_key);
        equ = (memcmp(data, ctr_cipher[i], 16) == 0);
        
        bin2hex("cipher", data, 16);
        
        printf("AES-128 CTR Test #%i : %s\n\n", 
          (i+1), equ ? "OK" : "FAILED");
      }
    #endif
    
    #ifdef OFB
      puts ("\n**** AES-128 OFB Test ****\n");
  
      for(i=0; i<2; i++) {
        bin2hex("key",    ofb_key[i],    16);
        bin2hex("iv",     ofb_iv[i],     16);
        bin2hex("plain",  ofb_plain[i],  16);
        bin2hex("cipher", ofb_cipher[i], 16);
        
        memcpy(data, ofb_plain[i], 16);
        
        aes_ofb_encrypt(16, ofb_iv[i], data, ofb_key[i]);
        equ = (memcmp(data, ofb_cipher[i], 16) == 0);
        
        bin2hex("result", data, 16);
        
        printf("AES-128 OFB Test #%i : %s\n\n", 
          (i+1), equ ? "OK" : "FAILED"
          );
      }   
    #endif
    return 0;
}
