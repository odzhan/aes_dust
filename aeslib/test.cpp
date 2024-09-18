#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "aes128_ecb.h"
#include "aes128_cbc.h"
#include "aes128_ofb.h"

//
// Test vectors for AES-128 in OFB mode.
//
// echo -n -e '\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a' | openssl enc -e -aes-128-ofb -nosalt -A -K 
// 2B7E151628AED2A6ABF7158809CF4F3C -iv 000102030405060708090A0B0C0D0E0F | xxd -i
uint8_t
ofb_key[2][16] = {
{  0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c},
  {0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4} };

uint8_t
ofb_iv[2][16] = {
{ 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
{ 0xb7,0xbf,0x3a,0x5d,0xf4,0x39,0x89,0xdd,0x97,0xf0,0xfa,0x97,0xeb,0xce,0x2f,0x4a} };

uint8_t
ofb_plain[2][16] = {
{ 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
{ 0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51} };

uint8_t
ofb_cipher[2][16] = {
{ 0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a},
{ 0x7a,0x47,0x2d,0xe3,0x24,0x91,0xf9,0x2b,0x4b,0x2c,0x93,0x17,0x28,0x3b,0xb5,0xd4} };

int
ofb_test(void) {
    aes128_ctx c;
    u8         buf[AES_BLK_LEN], key[AES_KEY_LEN];
    u32        i, equ;

    puts("\n**** AES-128 OFB Test ****\n");

    for (i = 0; i < 2; i++) {
        memcpy(buf, ofb_plain[i], AES_BLK_LEN);
        memcpy(key, ofb_key[i], AES_KEY_LEN);
        memcpy(c.iv, ofb_iv[i], AES_IV_LEN);

        printf("\n Key        : ");
        for (int i = 0; i < 16; i++) printf(" %02x", key[i]);

        printf("\n Plaintext  : ");
        for (int i = 0; i < 16; i++) printf(" %02x", buf[i]);

        aes128_init_ctx(&c);
        aes128_set_key(&c, key);
        aes128_ofb_encrypt(&c, buf, sizeof(buf));

        printf("\n Encrypted  : ");
        for (int i = 0; i < 16; i++) printf(" %02x", buf[i]);

        aes128_ofb_decrypt(&c, buf, sizeof(buf));

        printf("\n Decrypted  : ");
        for (int i = 0; i < 16; i++) printf(" %02x", buf[i]);

        equ = (memcmp(buf, ofb_plain[i], AES_BLK_LEN) == 0);
        printf("\n Test #%d : %s\n", (i + 1), equ ? "OK" : "FAILED");
    }
    return 0;
}

//
// Test vectors for AES-128 in CBC mode.
//
u8
cbc_key[2][AES_KEY_LEN] = {
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
{ 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C } };

u8
cbc_iv[2][AES_IV_LEN] = {
{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
{ 0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D } };

u8
cbc_plain[2][AES_BLK_LEN] = {
{ 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A },
{ 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51 } };

u8
cbc_cipher[2][AES_BLK_LEN] = {
{ 0x13, 0xd3, 0x16, 0x3c, 0x67, 0x43, 0x0d, 0xf7, 0xca, 0xad, 0x77, 0x4b, 0xb3, 0xd3, 0xea, 0xcb },
{ 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2 } };

int
cbc_test(void) {
    aes128_ctx c;
    u8 buf[AES_BLK_LEN], key[AES_KEY_LEN];
    u32 i, equ;

    puts("\n**** AES-128 CBC Test ****\n");

    for (i = 0; i < 2; i++) {
        memcpy(buf, cbc_plain[i], AES_BLK_LEN);
        memcpy(key, cbc_key[i], AES_KEY_LEN);
        memcpy(c.iv, cbc_iv[i], AES_IV_LEN);

        printf("\n Key        : ");
        for (int i = 0; i < 16; i++) printf(" %02x", key[i]);

        printf("\n Plaintext  : ");
        for (int i = 0; i < 16; i++) printf(" %02x", buf[i]);

        aes128_init_ctx(&c);
        aes128_set_key(&c, key);
        aes128_cbc_encrypt(&c, buf, sizeof(buf));

        printf("\n Encrypted  : ");
        for (int i = 0; i < 16; i++) printf(" %02x", buf[i]);

        aes128_cbc_decrypt(&c, buf, sizeof(buf));

        printf("\n Decrypted  : ");
        for (int i = 0; i < 16; i++) printf(" %02x", buf[i]);

        equ = (memcmp(buf, cbc_plain[i], AES_BLK_LEN) == 0);
        printf("\n Test #%d : %s\n", (i + 1), equ ? "OK" : "FAILED");
    }
    return 0;
}

//
// Test vectors for AES-128 in ECB mode.
//
uint8_t
ecb_key[4][16] = {
  {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
  {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
  {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
  {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
};

// 4 128-bit plain texts
uint8_t
ecb_plain[4][16] = {
  {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  {0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51},
  {0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef},
  {0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10}
};

// 4 128-bit cipher texts
uint8_t
ecb_cipher[4][16] = {
  {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a},
  {0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf},
  {0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88},
  {0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4}
};

int
ecb_test(void) {
    aes128_ctx c;
    u8         buf[AES_BLK_LEN], key[AES_KEY_LEN];
    u32        i, equ;

    puts("\n**** AES-128 ECB Test ****\n");

    for (i = 0; i < 4; i++) {
        memcpy(buf, ecb_plain[i], AES_BLK_LEN);
        memcpy(key, ecb_key[i], AES_KEY_LEN);

        printf("\n Key        : ");
        for (int i = 0; i < 16; i++) printf(" %02x", key[i]);

        printf("\n Plaintext  : ");
        for (int i = 0; i < 16; i++) printf(" %02x", buf[i]);

        aes128_init_ctx(&c);
        aes128_set_key(&c, key);
        aes128_ecb_encrypt(&c, buf);

        printf("\n Encrypted  : ");
        for (int i = 0; i < 16; i++) printf(" %02x", buf[i]);

        equ = (memcmp(buf, ecb_cipher[i], AES_BLK_LEN) == 0);
        printf("\n Encryption #%d : %s\n", (i + 1), equ ? "OK" : "FAILED");

        aes128_ecb_decrypt(&c, buf);

        printf("\n Decrypted  : ");
        for (int i = 0; i < 16; i++) printf(" %02x", buf[i]);

        equ = (memcmp(buf, ecb_plain[i], AES_BLK_LEN) == 0);
        printf("\n Decryption #%d : %s\n", (i + 1), equ ? "OK" : "FAILED");
    }
    return 0;
}

int
main(void) {
    ecb_test();
    cbc_test();
    ofb_test();

    return 0;
}