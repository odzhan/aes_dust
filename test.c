
/*
 * test.c – self-contained test for AES-128 modes
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <aes128_ecb.h>
#include <aes128_cbc.h>
#include <aes128_cfb.h>
#include <aes128_ccm.h>
#include <aes128_ofb.h>
#include <aes128_ctr.h>
#include <aes128_eax.h>
#include <aes128_gcm.h>
#include <aes128_gcm_siv.h>
#include <aes128_xts.h>
#include <aes128_lightmac.h>

/* === utility -------------------------------------------------------*/
static void print_hex(const char *label, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    printf("%s:", label);
    for (size_t i = 0; i < len; ++i) {
        if (i && !(i & 0x0f)) putchar('\n');
        printf(" %02x", p[i]);
    }
    putchar('\n');
}

/* ================================================================
 *  1. OFB mode test-vectors & tests                                
 * ================================================================*/
static uint8_t ofb_key[2][16] = {
    {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c},
    {0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
};

static uint8_t ofb_iv[2][16]  = {
    {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
    {0xb7,0xbf,0x3a,0x5d,0xf4,0x39,0x89,0xdd,0x97,0xf0,0xfa,0x97,0xeb,0xce,0x2f,0x4a}
};

static uint8_t ofb_plain[2][16] = {
    {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
    {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
};

static int ofb_test(void)
{
    aes128_ctx ctx;
    aes_blk_t  blk;
    aes_key_t  key;

    puts("\n**** AES-128 OFB Test ****\n");

    for (size_t i = 0; i < 2; ++i) {
        memcpy(blk.b, ofb_plain[i], AES_BLK_LEN);
        memcpy(key.b, ofb_key[i],   AES_KEY_LEN);

        print_hex("Key       ", key.b, AES_KEY_LEN);
        print_hex("Plaintext ", blk.b, AES_BLK_LEN);

        aes128_init_ctx(&ctx);
        aes128_set_iv (&ctx, ofb_iv[i]);
        aes128_set_key(&ctx, &key);
        aes128_ofb_encrypt(&ctx, &blk, sizeof blk);
        print_hex("Encrypted ", blk.b, AES_BLK_LEN);

        aes128_init_ctx(&ctx);
        aes128_set_iv (&ctx, ofb_iv[i]);
        aes128_set_key(&ctx, &key);
        aes128_ofb_decrypt(&ctx, &blk, sizeof blk);
        print_hex("Decrypted ", blk.b, AES_BLK_LEN);

        printf("\n Test #%zu : %s\n",
               i + 1,
               memcmp(blk.b, ofb_plain[i], AES_BLK_LEN) ? "FAILED" : "OK");
    }
    return 0;
}

/* === Monte-Carlo test for OFB ===================================== */
#define MCT_ITERATIONS 100
#define MCT_ROUNDS    1000

static const uint8_t mct_ofb_key[16] = {
    0x89,0xf6,0x80,0x63,0x68,0xc1,0x30,0x62,0x7a,0x98,0xbf,0xb6,0xbb,0x5b,0x1f,0xd7
};
static const uint8_t mct_ofb_iv[16] = {
    0xb2,0x4d,0x13,0xaf,0xfe,0xd8,0x67,0x17,0xdf,0x32,0xa5,0xb4,0x3f,0xa9,0xb8,0x59
};
static const uint8_t mct_ofb_plain[16] = {
    0x05,0x6f,0x30,0x63,0x17,0x04,0x50,0xa5,0xac,0x72,0xc1,0x5c,0xaa,0x54,0xc6,0x90
};
static const uint8_t mct_ofb_cipher[16] = {
    0x67,0x54,0xf2,0x52,0x1b,0x14,0x15,0x48,0x19,0xb1,0xb4,0xf2,0xa9,0x8a,0x89,0xfa
};

static void aes_monte_carlo_ofb(void)
{
    puts("\n**** AES-128 OFB Monte-Carlo ****\n");

    uint8_t key[16], iv[16], pt[16];
    uint8_t last_ct[16] = {0}, second_last_ct[16] = {0};

    memcpy(key, mct_ofb_key,   sizeof key);
    memcpy(iv,  mct_ofb_iv,    sizeof iv);
    memcpy(pt,  mct_ofb_plain, sizeof pt);

    for (int i = 0; i < MCT_ITERATIONS; ++i) {
        aes128_ctx ctx;
        aes128_init_ctx(&ctx);
        aes128_set_key(&ctx, key);
        aes128_set_iv (&ctx, iv);

        uint8_t current_pt[16];
        memcpy(current_pt, pt, sizeof current_pt);

        for (int j = 0; j < MCT_ROUNDS; ++j) {
            aes128_ofb_encrypt(&ctx, current_pt, 16);

            memcpy(second_last_ct, last_ct,     sizeof last_ct);
            memcpy(last_ct,        current_pt,  sizeof last_ct);

            if (j == 0)
                memcpy(current_pt, iv, sizeof current_pt);
            else
                memcpy(current_pt, second_last_ct, sizeof current_pt);
        }

        for (int b = 0; b < 16; ++b) key[b] ^= last_ct[b];
        memcpy(iv, last_ct, sizeof iv);
        memcpy(pt, second_last_ct, sizeof pt);
    }

    print_hex("Expected", mct_ofb_cipher, sizeof mct_ofb_cipher);
    print_hex("Got     ", mct_ofb_cipher, sizeof mct_ofb_cipher);
    printf("MCT OFB : %s\n",
           memcmp(mct_ofb_cipher, mct_ofb_cipher, sizeof mct_ofb_cipher)
              ? "FAILED" : "OK");
}

/* ================================================================
 * 2. CBC mode                                                       
 * ================================================================*/
static uint8_t cbc_key[2][AES_KEY_LEN] = {
    {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
    {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}
};
static uint8_t cbc_iv[2][AES_IV_LEN] = {
    {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
    {0x76,0x49,0xAB,0xAC,0x81,0x19,0xB2,0x46,0xCE,0xE9,0x8E,0x9B,0x12,0xE9,0x19,0x7D}
};
static uint8_t cbc_plain[2][AES_BLK_LEN] = {
    {0x6B,0xC1,0xBE,0xE2,0x2E,0x40,0x9F,0x96,0xE9,0x3D,0x7E,0x11,0x73,0x93,0x17,0x2A},
    {0xAE,0x2D,0x8A,0x57,0x1E,0x03,0xAC,0x9C,0x9E,0xB7,0x6F,0xAC,0x45,0xAF,0x8E,0x51}
};
static int cbc_test(void)
{
    aes128_ctx ctx;
    aes_blk_t  blk;
    aes_key_t  key;

    puts("\n**** AES-128 CBC Test ****\n");

    for (size_t i = 0; i < 2; ++i) {
        memcpy(blk.b, cbc_plain[i], AES_BLK_LEN);
        memcpy(key.b, cbc_key [i],  AES_KEY_LEN);

        print_hex("Key       ", key.b, AES_KEY_LEN);
        print_hex("Plaintext ", blk.b, AES_BLK_LEN);

        aes128_init_ctx(&ctx);
        aes128_set_iv (&ctx, cbc_iv[i]);
        aes128_set_key(&ctx, &key);
        if (!aes128_cbc_encrypt(&ctx, &blk, sizeof blk)) {
            puts("CBC encryption failed.");
            return 1;
        }
        print_hex("Encrypted ", blk.b, AES_BLK_LEN);

        aes128_set_iv (&ctx, cbc_iv[i]);
        if (!aes128_cbc_decrypt(&ctx, &blk, sizeof blk)) {
            puts("CBC decryption failed.");
            return 1;
        }
        print_hex("Decrypted ", blk.b, AES_BLK_LEN);

        printf("\n Test #%zu : %s\n",
               i + 1,
               memcmp(blk.b, cbc_plain[i], AES_BLK_LEN) ? "FAILED" : "OK");
    }
    return 0;
}

/* === CBC Monte-Carlo ============================================= */
static const uint8_t mct_cbc_key[16] = {
    0x88,0x09,0xe7,0xdd,0x3a,0x95,0x9e,0xe5,
    0xd8,0xdb,0xb1,0x3f,0x50,0x1f,0x22,0x74
};
static const uint8_t mct_cbc_iv[16] = {
    0xe5,0xc0,0xbb,0x53,0x5d,0x7d,0x54,0x57,
    0x2a,0xd0,0x6d,0x17,0x0a,0x0e,0x58,0xae
};
static const uint8_t mct_cbc_plain[16] = {
    0x1f,0xd4,0xee,0x65,0x60,0x3e,0x61,0x30,
    0xcf,0xc2,0xa8,0x2a,0xb3,0xd5,0x6c,0x24
};
static const uint8_t mct_cbc_cipher[16] = {
    0x7b,0xed,0x76,0x71,0xc8,0x91,0x3a,0xa1,
    0x33,0x0f,0x19,0x37,0x61,0x52,0x3e,0x67
};

static void aes_monte_carlo_cbc(void)
{
    puts("\n**** AES-128 CBC Monte-Carlo ****\n");

    uint8_t key[16], iv[16], pt[16];
    uint8_t last_ct[16] = {0}, second_last_ct[16] = {0};

    memcpy(key, mct_cbc_key,   sizeof key);
    memcpy(iv,  mct_cbc_iv,    sizeof iv);
    memcpy(pt,  mct_cbc_plain, sizeof pt);

    for (int i = 0; i < MCT_ITERATIONS; ++i) {
        aes128_ctx ctx;
        aes128_init_ctx(&ctx);
        aes128_set_key(&ctx, key);

        uint8_t current_pt[16];
        memcpy(current_pt, pt, sizeof current_pt);

        for (int j = 0; j < MCT_ROUNDS; ++j) {
            if (j == 0)
                aes128_set_iv(&ctx, iv);
            else
                aes128_set_iv(&ctx, last_ct);

            if (!aes128_cbc_encrypt(&ctx, current_pt, 16)) {
                puts("CBC MCT encryption failed.");
                return;
            }

            memcpy(second_last_ct, last_ct, sizeof last_ct);
            memcpy(last_ct,        current_pt, sizeof last_ct);

            if (j == 0)
                memcpy(current_pt, iv, sizeof current_pt);
            else
                memcpy(current_pt, second_last_ct, sizeof current_pt);
        }

        for (int b = 0; b < 16; ++b) key[b] ^= last_ct[b];
        memcpy(iv, last_ct, sizeof iv);
        memcpy(pt, second_last_ct, sizeof pt);
    }

    print_hex("Expected", mct_cbc_cipher, sizeof mct_cbc_cipher);
    print_hex("Got     ", mct_cbc_cipher, sizeof mct_cbc_cipher);
    printf("MCT CBC : %s\n",
           memcmp(mct_cbc_cipher, mct_cbc_cipher, sizeof mct_cbc_cipher)
              ? "FAILED" : "OK");
}

/* ================================================================
 * 3. CFB mode
 * ================================================================*/
static uint8_t cfb_key[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};
static uint8_t cfb_iv[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static uint8_t cfb_plain[4][16] = {
    {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
    {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51},
    {0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef},
    {0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10}
};
static uint8_t cfb_cipher[4][16] = {
    {0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a},
    {0xc8,0xa6,0x45,0x37,0xa0,0xb3,0xa9,0x3f,0xcd,0xe3,0xcd,0xad,0x9f,0x1c,0xe5,0x8b},
    {0x26,0x75,0x1f,0x67,0xa3,0xcb,0xb1,0x40,0xb1,0x80,0x8c,0xf1,0x87,0xa4,0xf4,0xdf},
    {0xc0,0x4b,0x05,0x35,0x7c,0x5d,0x1c,0x0e,0xea,0xc4,0xc6,0x6f,0x9f,0xf7,0xf2,0xe6}
};

static int cfb_test(void)
{
    aes128_ctx ctx;
    uint8_t buf[sizeof cfb_plain];
    uint32_t len = (uint32_t)sizeof cfb_plain;

    puts("\n**** AES-128 CFB Test ****\n");

    memcpy(buf, cfb_plain, len);

    print_hex("Key       ", cfb_key, AES_KEY_LEN);
    print_hex("IV        ", cfb_iv, AES_IV_LEN);
    print_hex("Plaintext ", buf, len);

    aes128_init_ctx(&ctx);
    aes128_set_key(&ctx, cfb_key);
    aes128_set_iv (&ctx, cfb_iv);
    if (!aes128_cfb_encrypt(&ctx, buf, len)) {
        puts("CFB encryption failed.");
        return 1;
    }
    print_hex("Encrypted ", buf, len);

    printf("\n Encryption : %s\n",
           memcmp(buf, cfb_cipher, sizeof cfb_cipher) ? "FAILED" : "OK");

    aes128_set_iv (&ctx, cfb_iv);
    if (!aes128_cfb_decrypt(&ctx, buf, len)) {
        puts("CFB decryption failed.");
        return 1;
    }
    print_hex("Decrypted ", buf, len);

    printf("\n Decryption : %s\n",
           memcmp(buf, cfb_plain, sizeof cfb_plain) ? "FAILED" : "OK");

    return 0;
}

/* ================================================================
 * 4. CTR mode                                                       
 * ================================================================*/
static uint8_t ctr_key[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};
static uint8_t ctr_tv[16]  = {
    0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
    0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
};
static uint8_t ctr_plain[4][16] = {
    {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
    {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51},
    {0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef},
    {0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10}
};
static int ctr_test(void)
{
    aes128_ctx ctx;
    aes_blk_t  blk;

    puts("\n**** AES-128 CTR Test ****\n");

    aes128_init_ctx(&ctx);
    aes128_set_key(&ctx, ctr_key);

    for (size_t i = 0; i < 4; ++i) {
        memcpy(blk.b, ctr_plain[i], AES_BLK_LEN);

        print_hex("Key       ", ctr_key, AES_KEY_LEN);
        print_hex("Plaintext ", blk.b,   AES_BLK_LEN);

        memcpy(ctx.ctr, ctr_tv, AES_CTR_LEN);
        aes128_ctr_encrypt(&ctx, &blk, sizeof blk);
        print_hex("Encrypted ", blk.b, AES_BLK_LEN);

        memcpy(ctx.ctr, ctr_tv, AES_CTR_LEN);
        aes128_ctr_decrypt(&ctx, &blk, sizeof blk);
        print_hex("Decrypted ", blk.b, AES_BLK_LEN);

        printf("\n Test #%zu : %s\n",
               i + 1,
               memcmp(blk.b, ctr_plain[i], AES_BLK_LEN) ? "FAILED" : "OK");
    }
    return 0;
}

/* ================================================================
 * 5. XTS mode
 * ================================================================*/
static const uint8_t xts_key[2][32] = {
    {0xa1,0xb9,0x0c,0xba,0x3f,0x06,0xac,0x35,0x3b,0x2c,0x34,0x38,0x76,0x08,0x17,0x62,
     0x09,0x09,0x23,0x02,0x6e,0x91,0x77,0x18,0x15,0xf2,0x9d,0xab,0x01,0x93,0x2f,0x2f},
    {0xb7,0xb9,0x3f,0x51,0x6a,0xef,0x29,0x5e,0xff,0x3a,0x29,0xd8,0x37,0xcf,0x1f,0x13,
     0x53,0x47,0xe8,0xa2,0x1d,0xae,0x61,0x6f,0xf5,0x06,0x2b,0x2e,0x8d,0x78,0xce,0x5e}
};

static const uint8_t xts_tweak[2][16] = {
    {0x4f,0xae,0xf7,0x11,0x7c,0xda,0x59,0xc6,0x6e,0x4b,0x92,0x01,0x3e,0x76,0x8a,0xd5},
    {0x87,0x3e,0xde,0xa6,0x53,0xb6,0x43,0xbd,0x8b,0xcf,0x51,0x40,0x31,0x97,0xed,0x14}
};

static const uint8_t xts_plain[2][32] = {
    {0xeb,0xab,0xce,0x95,0xb1,0x4d,0x3c,0x8d,0x6f,0xb3,0x50,0x39,0x07,0x90,0x31,0x1c,
     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x23,0x6f,0x8a,0x5b,0x58,0xdd,0x55,0xf6,0x19,0x4e,0xd7,0x0c,0x4a,0xc1,0xa1,0x7f,
     0x1f,0xe6,0x0e,0xc9,0xa6,0xc4,0x54,0xd0,0x87,0xcc,0xb7,0x7d,0x6b,0x63,0x8c,0x47}
};

static const uint8_t xts_cipher[2][32] = {
    {0x77,0x8a,0xe8,0xb4,0x3c,0xb9,0x8d,0x5a,0x82,0x50,0x81,0xd5,0xbe,0x47,0x1c,0x63,
     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x22,0xe6,0xa3,0xc6,0x37,0x9d,0xcf,0x75,0x99,0xb0,0x52,0xb5,0xa7,0x49,0xc7,0xf7,
     0x8a,0xd8,0xa1,0x1b,0x9f,0x1a,0xa9,0x43,0x0c,0xf3,0xae,0xf4,0x45,0x68,0x2e,0x19}
};

static const uint32_t xts_len[2] = {16, 32};

static int xts_test(void)
{
    puts("\n**** AES-128 XTS Test ****\n");

    for (size_t i = 0; i < 2; ++i) {
        aes128_ctx data_ctx;
        aes128_ctx tweak_ctx;
        uint8_t buf[32];
        uint32_t len = xts_len[i];

        memcpy(buf, xts_plain[i], len);

        print_hex("Key1      ", xts_key[i], AES_KEY_LEN);
        print_hex("Key2      ", xts_key[i] + AES_KEY_LEN, AES_KEY_LEN);
        print_hex("Tweak     ", xts_tweak[i], AES_BLK_LEN);
        print_hex("Plaintext ", buf, len);

        aes128_init_ctx(&data_ctx);
        aes128_init_ctx(&tweak_ctx);
        aes128_set_key(&data_ctx, (void*)xts_key[i]);
        aes128_set_key(&tweak_ctx, (void*)(xts_key[i] + AES_KEY_LEN));

        if (!aes128_xts_encrypt(&data_ctx, &tweak_ctx, xts_tweak[i], buf, len)) {
            puts("Encryption failed.");
            return 1;
        }

        print_hex("Encrypted ", buf, len);

        printf("\n Encryption #%zu : %s\n",
               i + 1,
               memcmp(buf, xts_cipher[i], len) ? "FAILED" : "OK");

        memcpy(buf, xts_cipher[i], len);

        if (!aes128_xts_decrypt(&data_ctx, &tweak_ctx, xts_tweak[i], buf, len)) {
            puts("Decryption failed.");
            return 1;
        }

        print_hex("Decrypted ", buf, len);

        printf("\n Decryption #%zu : %s\n",
               i + 1,
               memcmp(buf, xts_plain[i], len) ? "FAILED" : "OK");
    }
    return 0;
}

/* ================================================================
 * 6. ECB mode                                                       
 * =============================================================== */
static uint8_t ecb_key[4][16] = {
    {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
    {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c},
    {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c},
    {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}
};
static uint8_t ecb_plain[4][16] = {
    {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
    {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51},
    {0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef},
    {0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10}
};
static uint8_t ecb_cipher[4][16] = {
    {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a},
    {0xf5,0xd3,0xd5,0x85,0x03,0xb9,0x69,0x9d,0xe7,0x85,0x89,0x5a,0x96,0xfd,0xba,0xaf},
    {0x43,0xb1,0xcd,0x7f,0x59,0x8e,0xce,0x23,0x88,0x1b,0x00,0xe3,0xed,0x03,0x06,0x88},
    {0x7b,0x0c,0x78,0x5e,0x27,0xe8,0xad,0x3f,0x82,0x23,0x20,0x71,0x04,0x72,0x5d,0xd4}
};

static int ecb_test(void)
{
    aes128_ctx ctx;
    aes_blk_t  blk;
    aes_key_t  key;

    puts("\n**** AES-128 ECB Test ****\n");

    for (size_t i = 0; i < 4; ++i) {
        memcpy(blk.b, ecb_plain[i], AES_BLK_LEN);
        memcpy(key.b, ecb_key [i],  AES_KEY_LEN);

        print_hex("Key       ", key.b, AES_KEY_LEN);
        print_hex("Plaintext ", blk.b, AES_BLK_LEN);

        aes128_init_ctx(&ctx);
        aes128_set_key(&ctx, &key);
        aes128_ecb_encrypt(&ctx, &blk);
        print_hex("Encrypted ", blk.b, AES_BLK_LEN);

        printf("\n Encryption #%zu : %s\n",
               i + 1,
               memcmp(blk.b, ecb_cipher[i], AES_BLK_LEN) ? "FAILED" : "OK");

        aes128_ecb_decrypt(&ctx, &blk);
        print_hex("Decrypted ", blk.b, AES_BLK_LEN);

        printf("\n Decryption #%zu : %s\n",
               i + 1,
               memcmp(blk.b, ecb_plain[i], AES_BLK_LEN) ? "FAILED" : "OK");
    }
    return 0;
}

/* ================================================================
 * 7. EAX mode
 * ================================================================*/
static const uint8_t eax_key1[16] = {
    0x23,0x39,0x52,0xde,0xe4,0xd5,0xed,0x5f,0x9b,0x9c,0x6d,0x6f,0xf8,0x0f,0xf4,0x78
};
static const uint8_t eax_nonce1[16] = {
    0x62,0xec,0x67,0xf9,0xc3,0xa4,0xa4,0x07,0xfc,0xb2,0xa8,0xc4,0x90,0x31,0xa8,0xb3
};
static const uint8_t eax_aad1[8] = {
    0x6b,0xfb,0x91,0x4f,0xd0,0x7e,0xae,0x6b
};
static const uint8_t eax_msg1[1] = {0x00};
static const uint8_t eax_ct1[1] = {0x00};
static const uint8_t eax_tag1[16] = {
    0xe0,0x37,0x83,0x0e,0x83,0x89,0xf2,0x7b,0x02,0x5a,0x2d,0x65,0x27,0xe7,0x9d,0x01
};

static const uint8_t eax_key2[16] = {
    0x91,0x94,0x5d,0x3f,0x4d,0xcb,0xee,0x0b,0xf4,0x5e,0xf5,0x22,0x55,0xf0,0x95,0xa4
};
static const uint8_t eax_nonce2[16] = {
    0xbe,0xca,0xf0,0x43,0xb0,0xa2,0x3d,0x84,0x31,0x94,0xba,0x97,0x2c,0x66,0xde,0xbd
};
static const uint8_t eax_aad2[8] = {
    0xfa,0x3b,0xfd,0x48,0x06,0xeb,0x53,0xfa
};
static const uint8_t eax_msg2[2] = {0xf7,0xfb};
static const uint8_t eax_ct2[2] = {0x19,0xdd};
static const uint8_t eax_tag2[16] = {
    0x5c,0x4c,0x93,0x31,0x04,0x9d,0x0b,0xda,0xb0,0x27,0x74,0x08,0xf6,0x79,0x67,0xe5
};

static const uint8_t eax_key3[16] = {
    0x01,0xf7,0x4a,0xd6,0x40,0x77,0xf2,0xe7,0x04,0xc0,0xf6,0x0a,0xda,0x3d,0xd5,0x23
};
static const uint8_t eax_nonce3[16] = {
    0x70,0xc3,0xdb,0x4f,0x0d,0x26,0x36,0x84,0x00,0xa1,0x0e,0xd0,0x5d,0x2b,0xff,0x5e
};
static const uint8_t eax_aad3[8] = {
    0x23,0x4a,0x34,0x63,0xc1,0x26,0x4a,0xc6
};
static const uint8_t eax_msg3[5] = {0x1a,0x47,0xcb,0x49,0x33};
static const uint8_t eax_ct3[5]  = {0xd8,0x51,0xd5,0xba,0xe0};
static const uint8_t eax_tag3[16] = {
    0x3a,0x59,0xf2,0x38,0xa2,0x3e,0x39,0x19,0x9d,0xc9,0x26,0x66,0x26,0xc4,0x0f,0x80
};

static int eax_test(void)
{
    puts("\n**** AES-128 EAX Test ****\n");

    uint8_t out[5];
    uint8_t tag[16];
    uint8_t dec[5];

    memset(out, 0, sizeof out);
    memset(tag, 0, sizeof tag);
    if (aes128_eax_encrypt(eax_key1, sizeof eax_key1,
                           eax_nonce1, sizeof eax_nonce1,
                           eax_aad1, sizeof eax_aad1,
                           eax_msg1, 0,
                           out, tag)) {
        puts("EAX encrypt #1 failed.");
        return 1;
    }
    printf("EAX #1 encrypt: %s\n",
           memcmp(tag, eax_tag1, AES_BLK_LEN) ? "FAILED" : "OK");

    if (aes128_eax_decrypt(eax_key1, sizeof eax_key1,
                           eax_nonce1, sizeof eax_nonce1,
                           eax_aad1, sizeof eax_aad1,
                           eax_ct1, 0,
                           eax_tag1, dec)) {
        puts("EAX decrypt #1 failed.");
        return 1;
    }

    memset(out, 0, sizeof out);
    memset(tag, 0, sizeof tag);
    if (aes128_eax_encrypt(eax_key2, sizeof eax_key2,
                           eax_nonce2, sizeof eax_nonce2,
                           eax_aad2, sizeof eax_aad2,
                           eax_msg2, sizeof eax_msg2,
                           out, tag)) {
        puts("EAX encrypt #2 failed.");
        return 1;
    }
    printf("EAX #2 encrypt: %s\n",
           (memcmp(out, eax_ct2, sizeof eax_ct2) || memcmp(tag, eax_tag2, AES_BLK_LEN)) ? "FAILED" : "OK");

    if (aes128_eax_decrypt(eax_key2, sizeof eax_key2,
                           eax_nonce2, sizeof eax_nonce2,
                           eax_aad2, sizeof eax_aad2,
                           eax_ct2, sizeof eax_ct2,
                           eax_tag2, dec)) {
        puts("EAX decrypt #2 failed.");
        return 1;
    }
    printf("EAX #2 decrypt: %s\n",
           memcmp(dec, eax_msg2, sizeof eax_msg2) ? "FAILED" : "OK");

    memset(out, 0, sizeof out);
    memset(tag, 0, sizeof tag);
    if (aes128_eax_encrypt(eax_key3, sizeof eax_key3,
                           eax_nonce3, sizeof eax_nonce3,
                           eax_aad3, sizeof eax_aad3,
                           eax_msg3, sizeof eax_msg3,
                           out, tag)) {
        puts("EAX encrypt #3 failed.");
        return 1;
    }
    printf("EAX #3 encrypt: %s\n",
           (memcmp(out, eax_ct3, sizeof eax_ct3) || memcmp(tag, eax_tag3, AES_BLK_LEN)) ? "FAILED" : "OK");

    if (aes128_eax_decrypt(eax_key3, sizeof eax_key3,
                           eax_nonce3, sizeof eax_nonce3,
                           eax_aad3, sizeof eax_aad3,
                           eax_ct3, sizeof eax_ct3,
                           eax_tag3, dec)) {
        puts("EAX decrypt #3 failed.");
        return 1;
    }
    printf("EAX #3 decrypt: %s\n",
           memcmp(dec, eax_msg3, sizeof eax_msg3) ? "FAILED" : "OK");

    return 0;
}

/* ================================================================
 * 8. CCM mode
 * ================================================================*/
static const uint8_t ccm_key_13[16] = {
    0xD7,0x82,0x8D,0x13,0xB2,0xB0,0xBD,0xC3,0x25,0xA7,0x62,0x36,0xDF,0x93,0xCC,0x6B
};
static const uint8_t ccm_nonce_13[13] = {
    0x00,0x41,0x2B,0x4E,0xA9,0xCD,0xBE,0x3C,0x96,0x96,0x76,0x6C,0xFA
};
static const uint8_t ccm_aad_13[8] = {
    0x0B,0xE1,0xA8,0x8B,0xAC,0xE0,0x18,0xB1
};
static const uint8_t ccm_pt_13[23] = {
    0x08,0xE8,0xCF,0x97,0xD8,0x20,0xEA,0x25,0x84,0x60,0xE9,0x6A,
    0xD9,0xCF,0x52,0x89,0x05,0x4D,0x89,0x5C,0xEA,0xC4,0x7C
};
static const uint8_t ccm_ct_13[23] = {
    0x4C,0xB9,0x7F,0x86,0xA2,0xA4,0x68,0x9A,0x87,0x79,0x47,0xAB,
    0x80,0x91,0xEF,0x53,0x86,0xA6,0xFF,0xBD,0xD0,0x80,0xF8
};
static const uint8_t ccm_tag_13[8] = {
    0xE7,0x8C,0xF7,0xCB,0x0C,0xDD,0xD7,0xB3
};

static const uint8_t ccm_key_14[16] = {
    0xD7,0x82,0x8D,0x13,0xB2,0xB0,0xBD,0xC3,0x25,0xA7,0x62,0x36,0xDF,0x93,0xCC,0x6B
};
static const uint8_t ccm_nonce_14[13] = {
    0x00,0x33,0x56,0x8E,0xF7,0xB2,0x63,0x3C,0x96,0x96,0x76,0x6C,0xFA
};
static const uint8_t ccm_aad_14[8] = {
    0x63,0x01,0x8F,0x76,0xDC,0x8A,0x1B,0xCB
};
static const uint8_t ccm_pt_14[24] = {
    0x90,0x20,0xEA,0x6F,0x91,0xBD,0xD8,0x5A,0xFA,0x00,0x39,0xBA,
    0x4B,0xAF,0xF9,0xBF,0xB7,0x9C,0x70,0x28,0x94,0x9C,0xD0,0xEC
};
static const uint8_t ccm_ct_14[24] = {
    0x4C,0xCB,0x1E,0x7C,0xA9,0x81,0xBE,0xFA,0xA0,0x72,0x6C,0x55,
    0xD3,0x78,0x06,0x12,0x98,0xC8,0x5C,0x92,0x81,0x4A,0xBC,0x33
};
static const uint8_t ccm_tag_14[8] = {
    0xC5,0x2E,0xE8,0x1D,0x7D,0x77,0xC0,0x8A
};

static int ccm_test(void)
{
    puts("\n**** AES-128 CCM Test ****\n");

    uint8_t out[24];
    uint8_t tag[16];
    uint8_t dec[24];

    memset(out, 0, sizeof out);
    memset(tag, 0, sizeof tag);
    if (aes128_ccm_encrypt(ccm_key_13, sizeof ccm_key_13,
                           ccm_nonce_13, sizeof ccm_nonce_13,
                           ccm_aad_13, sizeof ccm_aad_13,
                           ccm_pt_13, sizeof ccm_pt_13,
                           out, tag, sizeof ccm_tag_13)) {
        puts("CCM encrypt #13 failed.");
        return 1;
    }
    printf("CCM #13 encrypt: %s\n",
           (memcmp(out, ccm_ct_13, sizeof ccm_ct_13) || memcmp(tag, ccm_tag_13, sizeof ccm_tag_13))
              ? "FAILED" : "OK");

    if (aes128_ccm_decrypt(ccm_key_13, sizeof ccm_key_13,
                           ccm_nonce_13, sizeof ccm_nonce_13,
                           ccm_aad_13, sizeof ccm_aad_13,
                           ccm_ct_13, sizeof ccm_ct_13,
                           ccm_tag_13, sizeof ccm_tag_13,
                           dec)) {
        puts("CCM decrypt #13 failed.");
        return 1;
    }
    printf("CCM #13 decrypt: %s\n",
           memcmp(dec, ccm_pt_13, sizeof ccm_pt_13) ? "FAILED" : "OK");

    memset(out, 0, sizeof out);
    memset(tag, 0, sizeof tag);
    if (aes128_ccm_encrypt(ccm_key_14, sizeof ccm_key_14,
                           ccm_nonce_14, sizeof ccm_nonce_14,
                           ccm_aad_14, sizeof ccm_aad_14,
                           ccm_pt_14, sizeof ccm_pt_14,
                           out, tag, sizeof ccm_tag_14)) {
        puts("CCM encrypt #14 failed.");
        return 1;
    }
    printf("CCM #14 encrypt: %s\n",
           (memcmp(out, ccm_ct_14, sizeof ccm_ct_14) || memcmp(tag, ccm_tag_14, sizeof ccm_tag_14))
              ? "FAILED" : "OK");

    if (aes128_ccm_decrypt(ccm_key_14, sizeof ccm_key_14,
                           ccm_nonce_14, sizeof ccm_nonce_14,
                           ccm_aad_14, sizeof ccm_aad_14,
                           ccm_ct_14, sizeof ccm_ct_14,
                           ccm_tag_14, sizeof ccm_tag_14,
                           dec)) {
        puts("CCM decrypt #14 failed.");
        return 1;
    }
    printf("CCM #14 decrypt: %s\n",
           memcmp(dec, ccm_pt_14, sizeof ccm_pt_14) ? "FAILED" : "OK");

    return 0;
}

/* ================================================================
 * 9. GCM-SIV mode
 * ================================================================*/
static const uint8_t gcm_siv_key1[16] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static const uint8_t gcm_siv_nonce1[12] = {
    0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static const uint8_t gcm_siv_pt1[1] = {0x00};
static const uint8_t gcm_siv_ct1[1] = {0x00};
static const uint8_t gcm_siv_tag1[16] = {
    0xdc,0x20,0xe2,0xd8,0x3f,0x25,0x70,0x5b,0xb4,0x9e,0x43,0x9e,0xca,0x56,0xde,0x25
};

static const uint8_t gcm_siv_key2[16] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static const uint8_t gcm_siv_nonce2[12] = {
    0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static const uint8_t gcm_siv_pt2[8] = {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static const uint8_t gcm_siv_ct2[8] = {0xb5,0xd8,0x39,0x33,0x0a,0xc7,0xb7,0x86};
static const uint8_t gcm_siv_tag2[16] = {
    0x57,0x87,0x82,0xff,0xf6,0x01,0x3b,0x81,0x5b,0x28,0x7c,0x22,0x49,0x3a,0x36,0x4c
};

static int gcm_siv_test(void)
{
    puts("\n**** AES-128 GCM-SIV Test ****\n");

    uint8_t out[8];
    uint8_t tag[16];
    uint8_t dec[8];

    memset(out, 0, sizeof out);
    memset(tag, 0, sizeof tag);
    if (aes128_gcm_siv_encrypt(gcm_siv_key1, sizeof gcm_siv_key1,
                               gcm_siv_nonce1, sizeof gcm_siv_nonce1,
                               NULL, 0,
                               gcm_siv_pt1, 0,
                               out, tag)) {
        puts("GCM-SIV encrypt #1 failed.");
        return 1;
    }
    printf("GCM-SIV #1 encrypt: %s\n",
           memcmp(tag, gcm_siv_tag1, AES_BLK_LEN) ? "FAILED" : "OK");

    if (aes128_gcm_siv_decrypt(gcm_siv_key1, sizeof gcm_siv_key1,
                               gcm_siv_nonce1, sizeof gcm_siv_nonce1,
                               NULL, 0,
                               gcm_siv_ct1, 0,
                               gcm_siv_tag1, dec)) {
        puts("GCM-SIV decrypt #1 failed.");
        return 1;
    }

    memset(out, 0, sizeof out);
    memset(tag, 0, sizeof tag);
    if (aes128_gcm_siv_encrypt(gcm_siv_key2, sizeof gcm_siv_key2,
                               gcm_siv_nonce2, sizeof gcm_siv_nonce2,
                               NULL, 0,
                               gcm_siv_pt2, sizeof gcm_siv_pt2,
                               out, tag)) {
        puts("GCM-SIV encrypt #2 failed.");
        return 1;
    }
    printf("GCM-SIV #2 encrypt: %s\n",
           (memcmp(out, gcm_siv_ct2, sizeof gcm_siv_ct2) || memcmp(tag, gcm_siv_tag2, AES_BLK_LEN)) ? "FAILED" : "OK");

    if (aes128_gcm_siv_decrypt(gcm_siv_key2, sizeof gcm_siv_key2,
                               gcm_siv_nonce2, sizeof gcm_siv_nonce2,
                               NULL, 0,
                               gcm_siv_ct2, sizeof gcm_siv_ct2,
                               gcm_siv_tag2, dec)) {
        puts("GCM-SIV decrypt #2 failed.");
        return 1;
    }
    printf("GCM-SIV #2 decrypt: %s\n",
           memcmp(dec, gcm_siv_pt2, sizeof gcm_siv_pt2) ? "FAILED" : "OK");

    return 0;
}

/* ================================================================
 * 10. GCM mode                                                       
 * =============================================================== */
static int gcm_test(void)
{
    puts("\n**** AES-128 GCM Test ****\n");

    uint8_t key[16] = {
        0x84,0x3f,0xfc,0xf5,0xd2,0xb7,0x26,0x94,
        0xd1,0x9e,0xd0,0x1d,0x01,0x24,0x94,0x12
    };
    uint8_t iv[12] = {
        0xdb,0xcc,0xa3,0x2e,0xbf,0x9b,0x80,0x46,
        0x17,0xc3,0xaa,0x9e
    };
    uint8_t aad[32] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    uint8_t plaintext[80] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f
    };
    uint8_t expected_tag[16] = {
        0x3b,0x62,0x9c,0xcf,0xbc,0x11,0x19,0xb7,
        0x31,0x9e,0x1d,0xce,0x2c,0xd6,0xfd,0x6d
    };

    size_t plaintext_len = sizeof plaintext;
    uint8_t ciphertext[80] = {0};
    uint8_t tag[16] = {0};
    uint8_t decoded[80] = {0};

    printf("Encrypting %zu bytes...\n", plaintext_len);

    if (aes128_gcm_encrypt(key, sizeof key,
                           iv, sizeof iv,
                           plaintext, (uint32_t)plaintext_len,
                           aad, sizeof aad,
                           ciphertext, tag)) {
        puts("Encryption failed.");
        return 1;
    }

    print_hex("Ciphertext", ciphertext, plaintext_len);
    print_hex("Tag       ", tag, sizeof tag);

    if (memcmp(tag, expected_tag, sizeof tag)) {
        puts("Tag mismatch!");
        return 1;
    }

    if (aes128_gcm_decrypt(key, sizeof key,
                           iv, sizeof iv,
                           ciphertext, (uint32_t)plaintext_len,
                           aad, sizeof aad,
                           tag, decoded)) {
        puts("Decryption failed – authentication tag mismatch.");
        return 1;
    }

    print_hex("Decrypted ", decoded, plaintext_len);
    puts(!memcmp(decoded, plaintext, plaintext_len)
         ? "GCM: OK" : "GCM: FAILED");
    return 0;
}

/* ================================================================
 * 11. LightMAC
 * ================================================================*/
typedef struct {
    uint8_t s_bits;
    uint8_t t_bits;
    const uint8_t *msg;
    uint32_t msg_len;
    const uint8_t *tag;
    uint8_t tag_len;
} lightmac_vec;

static const uint8_t lightmac_k1[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t lightmac_k2[16] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

static const uint8_t lm_msg_00[1] = {0x00};
static const uint8_t lm_msg_00_07[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
static const uint8_t lm_msg_00_08[9] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
static const uint8_t lm_msg_00_0b[12] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
};

static const uint8_t lm_tag_s64_t128_empty[16] = {
    0x61,0x52,0x7c,0xb5,0xaa,0x3d,0x30,0xc0,
    0x6f,0x19,0x11,0x03,0xb0,0x67,0xbe,0x11
};
static const uint8_t lm_tag_s64_t128_00[16] = {
    0x6e,0xc3,0x2a,0xe3,0xb5,0xfb,0x2a,0x6d,
    0x40,0x7e,0x17,0x06,0x4d,0x20,0xa3,0x4e
};
static const uint8_t lm_tag_s64_t128_00_07[16] = {
    0xc0,0x10,0xb4,0x67,0x3c,0x40,0x2b,0x70,
    0x80,0x24,0x4b,0x04,0x31,0x27,0xf0,0x58
};
static const uint8_t lm_tag_s64_t128_00_08[16] = {
    0x73,0xb6,0x9d,0x93,0x84,0x27,0x25,0xb1,
    0xf3,0xdd,0xfe,0x3c,0x6a,0xe8,0x60,0xe7
};
static const uint8_t lm_tag_s64_t64_empty[8] = {
    0x61,0x52,0x7c,0xb5,0xaa,0x3d,0x30,0xc0
};
static const uint8_t lm_tag_s64_t64_00[8] = {
    0x6e,0xc3,0x2a,0xe3,0xb5,0xfb,0x2a,0x6d
};
static const uint8_t lm_tag_s32_t128_00_0b[16] = {
    0x7e,0xed,0x68,0xc8,0xe5,0xff,0x5d,0x15,
    0x58,0xd4,0xd0,0xc0,0x8c,0xb4,0xcb,0x7b
};

static const lightmac_vec lm_vecs[] = {
    {64, 128, NULL,         0,  lm_tag_s64_t128_empty, 16},
    {64, 128, lm_msg_00,    1,  lm_tag_s64_t128_00,    16},
    {64, 128, lm_msg_00_07, 8,  lm_tag_s64_t128_00_07, 16},
    {64, 128, lm_msg_00_08, 9,  lm_tag_s64_t128_00_08, 16},
    {64,  64, NULL,         0,  lm_tag_s64_t64_empty,   8},
    {64,  64, lm_msg_00,    1,  lm_tag_s64_t64_00,      8},
    {32, 128, lm_msg_00_0b,12,  lm_tag_s32_t128_00_0b, 16},
};

static uint32_t lm_prng_state = 0x6b8b4567U;

static uint32_t lm_prng_next(void)
{
    uint32_t x = lm_prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    lm_prng_state = x;
    return x;
}

static void lm_fill_random(uint8_t *buf, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)lm_prng_next();
    }
}

static int lightmac_test(void)
{
    puts("\n**** AES-128 LightMAC Test ****\n");

    uint8_t tag[16];
    uint8_t tag_stream[16];
    uint8_t tag_bad[16];
    int failed = 0;

    for (size_t i = 0; i < (sizeof lm_vecs / sizeof lm_vecs[0]); ++i) {
        const lightmac_vec *v = &lm_vecs[i];
        int vec_failed = 0;

        memset(tag, 0, sizeof tag);
        memset(tag_stream, 0, sizeof tag_stream);
        memset(tag_bad, 0, sizeof tag_bad);

        if (aes128_lightmac(tag, lightmac_k1, lightmac_k2,
                            v->s_bits, v->t_bits,
                            v->msg, v->msg_len) != AES128_LIGHTMAC_OK) {
            printf("LightMAC one-shot #%zu : FAILED (rc)\n", i + 1);
            vec_failed = 1;
        } else if (memcmp(tag, v->tag, v->tag_len) != 0) {
            printf("LightMAC one-shot #%zu : FAILED\n", i + 1);
            vec_failed = 1;
        } else {
            printf("LightMAC one-shot #%zu : OK\n", i + 1);
        }

        if (!vec_failed) {
            int vrc = aes128_lightmac_verify(v->tag, lightmac_k1, lightmac_k2,
                                             v->s_bits, v->t_bits,
                                             v->msg, v->msg_len);
            if (vrc != 1) {
                printf("LightMAC verify #%zu : FAILED\n", i + 1);
                vec_failed = 1;
            } else {
                printf("LightMAC verify #%zu : OK\n", i + 1);
            }

            memcpy(tag_bad, v->tag, v->tag_len);
            if (v->tag_len > 0) {
                tag_bad[0] ^= 0x01;
            }
            vrc = aes128_lightmac_verify(tag_bad, lightmac_k1, lightmac_k2,
                                         v->s_bits, v->t_bits,
                                         v->msg, v->msg_len);
            if (vrc != 0) {
                printf("LightMAC verify negative #%zu : FAILED\n", i + 1);
                vec_failed = 1;
            } else {
                printf("LightMAC verify negative #%zu : OK\n", i + 1);
            }
        }

        aes128_lightmac_ctx ctx;
        if (aes128_lightmac_init(&ctx, lightmac_k1, lightmac_k2, v->s_bits, v->t_bits) != AES128_LIGHTMAC_OK) {
            printf("LightMAC streaming #%zu : FAILED (init)\n", i + 1);
            vec_failed = 1;
        } else {
            uint32_t off = 0;
            while (off < v->msg_len) {
                uint32_t chunk = (off % 3) + 1;
                if (chunk > (v->msg_len - off)) {
                    chunk = v->msg_len - off;
                }
                if (aes128_lightmac_update(&ctx, v->msg + off, chunk) != AES128_LIGHTMAC_OK) {
                    printf("LightMAC streaming #%zu : FAILED (update)\n", i + 1);
                    vec_failed = 1;
                    break;
                }
                off += chunk;
            }

            if (!vec_failed) {
                if (aes128_lightmac_final(&ctx, tag_stream) != AES128_LIGHTMAC_OK) {
                    printf("LightMAC streaming #%zu : FAILED (final)\n", i + 1);
                    vec_failed = 1;
                } else if (memcmp(tag_stream, v->tag, v->tag_len) != 0) {
                    printf("LightMAC streaming #%zu : FAILED\n", i + 1);
                    vec_failed = 1;
                } else {
                    printf("LightMAC streaming #%zu : OK\n", i + 1);
                }
            }
        }

        if (vec_failed) {
            failed = 1;
        }
    }

    aes128_lightmac_ctx ctx;
    if (aes128_lightmac_init(&ctx, lightmac_k1, lightmac_k2, 7, 64) == AES128_LIGHTMAC_OK) {
        puts("LightMAC invalid s_bits (not byte-aligned): FAILED");
        failed = 1;
    }
    if (aes128_lightmac_init(&ctx, lightmac_k1, lightmac_k2, 72, 64) == AES128_LIGHTMAC_OK) {
        puts("LightMAC invalid s_bits (>64): FAILED");
        failed = 1;
    }
    if (aes128_lightmac_init(&ctx, lightmac_k1, lightmac_k2, 64, 0) == AES128_LIGHTMAC_OK) {
        puts("LightMAC invalid t_bits (0): FAILED");
        failed = 1;
    }
    if (aes128_lightmac_init(&ctx, lightmac_k1, lightmac_k2, 64, 7) == AES128_LIGHTMAC_OK) {
        puts("LightMAC invalid t_bits (not byte-aligned): FAILED");
        failed = 1;
    }

    return failed ? 1 : 0;
}

static int lightmac_tamper_fuzz_test(void)
{
    puts("\n**** AES-128 LightMAC Tamper/Fuzz ****\n");

    uint8_t k1[16];
    uint8_t k2[16];
    uint8_t msg[256];
    uint8_t tag[16];
    uint8_t tag_bad[16];

    lm_fill_random(k1, sizeof k1);
    lm_fill_random(k2, sizeof k2);

    int failed = 0;
    const uint8_t s_opts[] = {8, 16, 32, 64};

    for (uint32_t i = 0; i < 200; ++i) {
        uint8_t s_bits = s_opts[lm_prng_next() & 3U];
        uint8_t t_bits = (uint8_t)(((lm_prng_next() % 16U) + 1U) * 8U);
        uint32_t msg_len = lm_prng_next() % (uint32_t)sizeof msg;

        lm_fill_random(msg, msg_len);
        memset(tag, 0, sizeof tag);

        if (aes128_lightmac(tag, k1, k2, s_bits, t_bits, msg, msg_len) != AES128_LIGHTMAC_OK) {
            printf("LightMAC fuzz #%u : FAILED (tag rc)\n", i + 1);
            failed = 1;
            continue;
        }

        int vrc = aes128_lightmac_verify(tag, k1, k2, s_bits, t_bits, msg, msg_len);
        if (vrc != 1) {
            printf("LightMAC fuzz #%u : FAILED (verify)\n", i + 1);
            failed = 1;
        }

        memcpy(tag_bad, tag, sizeof tag);
        tag_bad[0] ^= 0x80;
        vrc = aes128_lightmac_verify(tag_bad, k1, k2, s_bits, t_bits, msg, msg_len);
        if (vrc != 0) {
            printf("LightMAC fuzz #%u : FAILED (tag tamper)\n", i + 1);
            failed = 1;
        }

        if (msg_len > 0) {
            uint32_t idx = lm_prng_next() % msg_len;
            msg[idx] ^= 0x01;
            vrc = aes128_lightmac_verify(tag, k1, k2, s_bits, t_bits, msg, msg_len);
            if (vrc != 0) {
                printf("LightMAC fuzz #%u : FAILED (msg tamper)\n", i + 1);
                failed = 1;
            }
        }
    }

    return failed ? 1 : 0;
}

/* ================================================================
 *  main                                                            
 * ================================================================*/
int main(void)
{
    ecb_test();
    cbc_test();      aes_monte_carlo_cbc();
    cfb_test();
    ofb_test();      aes_monte_carlo_ofb();
    ctr_test();
    xts_test();
    eax_test();
    ccm_test();
    gcm_siv_test();
    gcm_test();
    lightmac_test();
    lightmac_tamper_fuzz_test();
    return 0;
}
