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

// NIST SP 800-38A known-answer tests for the compact C and assembly backends.

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <aes.h>

#if AES_KEY_LEN == 32
static const uint8_t ecb_key[32] = {
  0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
  0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
};
#else
static const uint8_t ecb_key[16] = {
  0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};
#endif

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
#if AES_KEY_LEN == 32
  {0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8},
  {0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70},
  {0xb6,0xed,0x21,0xb9,0x9c,0xa6,0xf4,0xf9,0xf1,0x53,0xe7,0xb1,0xbe,0xaf,0xed,0x1d},
  {0x23,0x30,0x4b,0x7a,0x39,0xf9,0xf3,0xff,0x06,0x7d,0x8d,0x8f,0x9e,0x24,0xec,0xc7}
#else
  {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97},
  {0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf},
  {0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88},
  {0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4}
#endif
};

static
void 
bin2hex(char *s, void *p, int len) {
    int i;
    
    printf("%-10s : ", s);
    
    for (i=0; i<len; i++) { 
        printf ("%02x ", ((uint8_t*)p)[i]);
        if ((i & 15) == 15) printf("\n");
    }
}

#ifndef ASM
#include "../../tests/compact_ecb_vectors.h"

static int variable_ecb(void) {
    uint8_t key[AES_KEY_LEN + 32], saved_key[AES_KEY_LEN + 32];
    uint8_t data[AES_BLK_LEN + 32], plain[AES_BLK_LEN];
    int failures = 0;
    for (int variable_key = 0; variable_key <= 1; ++variable_key) {
        size_t count = variable_key ? AES_KEY_LEN * 8U : AES_BLK_LEN * 8U;
        for (size_t bit = 0; bit < count; ++bit) {
            size_t offset = 1 + bit % 16, key_offset = 16 - bit % 16;
            const uint8_t *expected = variable_key ? compact_variable_key[bit]
                                                    : compact_variable_plain[bit];
            memset(key, 0xa5, sizeof(key));
            memset(key + key_offset, 0, AES_KEY_LEN);
            memset(plain, 0, sizeof(plain));
            if (variable_key) key[key_offset + bit / 8] = (uint8_t)(1U << (bit % 8));
            else plain[bit / 8] = (uint8_t)(1U << (bit % 8));
            memcpy(saved_key, key, sizeof(key));
            memset(data, 0xa5, sizeof(data));
            memcpy(data + offset, plain, sizeof(plain));
            aes_ecb(key + key_offset, data + offset);
            int failed = memcmp(data + offset, expected, AES_BLK_LEN) != 0 ||
                         memcmp(key, saved_key, sizeof(key)) != 0;
            for (size_t i = 0; i < sizeof(data); ++i) {
                if ((i < offset || i >= offset + AES_BLK_LEN) && data[i] != 0xa5) failed = 1;
            }
            if (failed) {
                printf("Variable-%s ECB bit %u FAILED\n", variable_key ? "key" : "plaintext",
                       (unsigned int)bit);
                ++failures;
            }
        }
    }
    return failures;
}

static int unaligned_ecb(void) {
    uint8_t key[AES_KEY_LEN + 3], data[AES_BLK_LEN + 6];
    int failures = 0;
    size_t ko, offset, j;
    int vector;
    for (ko = 0; ko < 4; ko++) {
        for (offset = 0; offset < 4; offset++) {
            for (vector = 0; vector < 4; vector++) {
                memcpy(key + ko, ecb_key, AES_KEY_LEN);
                memset(data, 0xa5, sizeof(data));
                memcpy(data + offset, ecb_plain[vector], AES_BLK_LEN);
                aes_ecb(key + ko, data + offset);
                if (memcmp(data + offset, ecb_cipher[vector], AES_BLK_LEN) ||
                    memcmp(key + ko, ecb_key, AES_KEY_LEN)) failures++;
                for (j = 0; j < sizeof(data); j++) {
                    if ((j < offset || j >= offset + AES_BLK_LEN) &&
                        data[j] != 0xa5) failures++;
                }
            }
        }
    }
    if (failures) puts("Unaligned ECB regression FAILED");
    return failures;
}
#endif

#if defined(CTR) && defined(OFB) && !defined(ASM)
static int stream_vectors(void) {
#if AES_KEY_LEN == 32
    static const uint8_t ctr_cipher[64] = {
    0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,
    0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5,
    0x2b,0x09,0x30,0xda,0xa2,0x3d,0xe9,0x4c,0xe8,0x70,0x17,0xba,0x2d,0x84,0x98,0x8d,
    0xdf,0xc9,0xc5,0x8d,0xb6,0x7a,0xad,0xa6,0x13,0xc2,0xdd,0x08,0x45,0x79,0x41,0xa6
    };
    static const uint8_t ofb_cipher[64] = {
    0xdc,0x7e,0x84,0xbf,0xda,0x79,0x16,0x4b,0x7e,0xcd,0x84,0x86,0x98,0x5d,0x38,0x60,
    0x4f,0xeb,0xdc,0x67,0x40,0xd2,0x0b,0x3a,0xc8,0x8f,0x6a,0xd8,0x2a,0x4f,0xb0,0x8d,
    0x71,0xab,0x47,0xa0,0x86,0xe8,0x6e,0xed,0xf3,0x9d,0x1c,0x5b,0xba,0x97,0xc4,0x08,
    0x01,0x26,0x14,0x1d,0x67,0xf3,0x7b,0xe8,0x53,0x8f,0x5a,0x8b,0xe7,0x40,0xe4,0x84
    };
#else
    static const uint8_t ctr_cipher[64] = {
    0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
    0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
    0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
    0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee
    };
    static const uint8_t ofb_cipher[64] = {
    0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a,
    0x77,0x89,0x50,0x8d,0x16,0x91,0x8f,0x03,0xf5,0x3c,0x52,0xda,0xc5,0x4e,0xd8,0x25,
    0x97,0x40,0x05,0x1e,0x9c,0x5f,0xec,0xf6,0x43,0x44,0xf7,0xa8,0x22,0x60,0xed,0xcc,
    0x30,0x4c,0x65,0x28,0xf6,0x59,0xc7,0x78,0x66,0xa5,0x10,0xd9,0xc1,0xd6,0xae,0x5e
    };
#endif
    static const uint32_t lengths[] = {0, 1, 15, 16, 17, 31, 32, 33, 63, 64};
    void (*const functions[])(uint32_t, void*, void*, void*) = {
        aes_ctr, aes_ctr_encrypt, aes_ofb, aes_ofb_encrypt
    };
    uint8_t key[AES_KEY_LEN + 1], data[66], iv[17], end_iv[16];
    size_t mode, n, j, split;
    int failures = 0;
    memcpy(key + 1, ecb_key, AES_KEY_LEN);
    for (mode = 0; mode < 4; mode++) {
        const uint8_t *expected = mode < 2 ? ctr_cipher : ofb_cipher;
        for (n = 0; n < sizeof(lengths) / sizeof(lengths[0]); n++) {
            size_t len = lengths[n];
            memset(data, 0xa5, sizeof(data));
            memcpy(data + 1, ecb_plain, len);
            for (j = 0; j < 16; j++)
                iv[j + 1] = (uint8_t)(j + (mode < 2 ? 0xf0 : 0));
            functions[mode](lengths[n], iv + 1, data + 1, key + 1);
            if (memcmp(data + 1, expected, len)) failures++;
            if (data[0] != 0xa5) failures++;
            for (j = len + 1; j < sizeof(data); j++)
                if (data[j] != 0xa5) failures++;
            memcpy(end_iv, iv + 1, sizeof(end_iv));
            if (len == 0) {
                for (j = 0; j < 16; j++)
                    if (iv[j + 1] != (uint8_t)(j + (mode < 2 ? 0xf0 : 0)))
                        failures++;
            } else if (mode >= 2 && len % AES_BLK_LEN == 0) {
                const uint8_t *plain = (const uint8_t *)ecb_plain;
                for (j = 0; j < 16; j++)
                    if (iv[j + 1] != (uint8_t)(expected[len - 16 + j] ^
                                               plain[len - 16 + j])) failures++;
            }
            /* Nonfinal chunks end on block boundaries; the final chunk may
             * be partial, including the 16 + 17 byte split of a 33-byte input. */
            for (split = 0; split <= len; split += AES_BLK_LEN) {
                memcpy(data + 1, ecb_plain, len);
                for (j = 0; j < 16; j++)
                    iv[j + 1] = (uint8_t)(j + (mode < 2 ? 0xf0 : 0));
                functions[mode]((uint32_t)split, iv + 1, data + 1, key + 1);
                functions[mode]((uint32_t)(len - split), iv + 1,
                                data + 1 + split, key + 1);
                if (memcmp(data + 1, expected, len) ||
                    memcmp(iv + 1, end_iv, sizeof(end_iv))) failures++;
            }
            for (j = 0; j < 16; j++)
                iv[j + 1] = (uint8_t)(j + (mode < 2 ? 0xf0 : 0));
            functions[mode](lengths[n], iv + 1, data + 1, key + 1);
            if (memcmp(data + 1, ecb_plain, len) ||
                memcmp(key + 1, ecb_key, AES_KEY_LEN)) failures++;
        }
    }
    if (failures) puts("CTR/OFB regression FAILED");
    return failures;
}

static int stream_length_regressions(void) {
    /* Independent cryptography AES-CTR/OFB vectors: zero plaintext, the key
     * above, CTR IV f0..ff or OFB IV 00..0f. Store bytes 240 through 271 to
     * check the 8-bit length boundary without a large ciphertext fixture. */
    static const uint8_t expected_tail[2][32] = {
#if AES_KEY_LEN == 32
        {0x1d,0xfa,0xa0,0xa6,0xdc,0x99,0x42,0xe2,0x6e,0x47,0x06,0x12,0x01,0xc7,0x7a,0x36,
         0xd6,0x4e,0x42,0xe7,0xe4,0x5c,0xc2,0xf9,0x6a,0x83,0x26,0xb0,0xc1,0xcf,0x55,0x44},
        {0xce,0xeb,0x4c,0x37,0x74,0xab,0xdb,0x47,0x60,0x0f,0x02,0x39,0xbf,0x3c,0xef,0x9c,
         0xf3,0x22,0x23,0x09,0xb5,0x3e,0xa9,0x3b,0x90,0xfc,0x76,0xe6,0x77,0xf0,0x25,0xf8}
#else
        {0x2d,0x9e,0x7e,0x4e,0x84,0xd1,0x72,0x47,0x68,0xf8,0x9e,0x32,0x01,0xbd,0x23,0x79,
         0x6c,0x4e,0xec,0x33,0x46,0x1d,0xa0,0xe3,0x56,0x5a,0x13,0x13,0x2a,0x64,0x24,0x01},
        {0x63,0x48,0xd3,0x61,0xf4,0x47,0x49,0x8a,0x31,0x08,0x35,0xb4,0xd6,0xbb,0xf2,0xc1,
         0x66,0x7f,0x0c,0xf1,0xe0,0x74,0x17,0x96,0x79,0x5e,0x2e,0x45,0x2e,0x62,0x95,0x57}
#endif
    };
    static const uint32_t lengths[] = {255, 256, 257, 272};
    void (*const functions[])(uint32_t, void*, void*, void*) = {
        aes_ctr, aes_ctr_encrypt, aes_ofb, aes_ofb_encrypt
    };
    uint8_t key[AES_KEY_LEN], data[274], iv[16];
    size_t mode, n, j;
    int failures = 0;
    memcpy(key, ecb_key, sizeof(key));
    for (mode = 0; mode < 4; mode++) {
        for (n = 0; n < sizeof(lengths) / sizeof(lengths[0]); n++) {
            uint32_t len = lengths[n];
            memset(data, 0xa5, sizeof(data));
            memset(data + 1, 0, len);
            for (j = 0; j < sizeof(iv); j++)
                iv[j] = (uint8_t)(j + (mode < 2 ? 0xf0 : 0));
            functions[mode](len, iv, data + 1, key);
            if (memcmp(data + 241, expected_tail[mode < 2 ? 0 : 1],
                       len - 240)) failures++;
            if (data[0] != 0xa5) failures++;
            for (j = (size_t)len + 1; j < sizeof(data); j++)
                if (data[j] != 0xa5) failures++;
            for (j = 0; j < sizeof(iv); j++)
                iv[j] = (uint8_t)(j + (mode < 2 ? 0xf0 : 0));
            functions[mode](len, iv, data + 1, key);
            for (j = 1; j <= len; j++)
                if (data[j] != 0) failures++;
            if (memcmp(key, ecb_key, sizeof(key))) failures++;
        }
    }
    if (failures) puts("CTR/OFB long-message regression FAILED");
    return failures;
}
#endif

int 
main (void) {
    int     i, equ, failures = 0;
    uint8_t data[16], key[AES_KEY_LEN];
    
    printf("\n**** AES-%i ECB Test ****\n\n", AES_KEY_LEN * 8);
    
    // ecb tests
    for (i=0; i<4; i++) {
      memcpy(data, ecb_plain[i], 16);
      memcpy(key, ecb_key, AES_KEY_LEN);
      
      #ifdef ASM
        uint8_t s[32];
        memcpy(s, data, 16);
        memcpy(&s[16], key, 16);
        
        aes_ecb_asm(s);
        memcpy(data, s, 16);
      #else
        aes_ecb(key, data);
      #endif
      equ = (memcmp(data, ecb_cipher[i], 16) == 0);
      failures += !equ;
      
      bin2hex("key", key, AES_KEY_LEN);
      bin2hex("cipher", data, 16);
      
      printf("AES-%i ECB Test #%i : %s\n\n",
        AES_KEY_LEN * 8, (i+1), equ ? "OK" : "FAILED");
    }
    
#ifndef ASM
    failures += unaligned_ecb();
    failures += variable_ecb();
#endif
#if defined(CTR) && defined(OFB) && !defined(ASM)
    failures += stream_vectors();
    failures += stream_length_regressions();
#endif
    return failures != 0;
}
