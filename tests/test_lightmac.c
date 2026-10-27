/*
 * test_lightmac.c – standalone tests for AES-128 LightMAC
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <aes128_lightmac.h>

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
    0xdf,0x6d,0x36,0xdd,0x9b,0xf4,0xfa,0xe9,
    0x3b,0xc5,0xa3,0x1a,0xd8,0xa1,0x4f,0x44
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
    0x7e,0x89,0x32,0xed,0x6f,0xa3,0x10,0xca,
    0x79,0x84,0x87,0x55,0x8f,0xd9,0x94,0xb7
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

#define LM_CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); return 1; \
} } while (0)

/*
 * Keys are 00..0f and 10..1f; message bytes are 00,01,... .
 * Expected tags follow the authors' reference, using independent .NET AES:
 * https://github.com/KULeuven-COSIC/lightmac/blob/master/c/src/lightmac.c
 * Each row covers r-1, r, r+1, 2r-1, 2r and 2r+1 bytes.
 */
static const uint8_t lm_boundary_tags[8][6][16] = {
    { /* s = 8, r = 15 */
        {0xae,0x01,0x35,0x8a,0x16,0xb7,0x05,0x04,0xc0,0x6d,0xcd,0x1d,0xda,0x12,0x6c,0xd2}, /* 14 bytes */
        {0x85,0xb0,0x3e,0x82,0xbc,0xc0,0xf8,0x76,0xaa,0xd9,0x67,0x06,0x95,0x10,0xad,0x36}, /* 15 bytes */
        {0xe0,0xaa,0xb7,0x89,0x6d,0x7e,0x6b,0x60,0x3e,0xf6,0x7e,0x9b,0x7e,0xce,0xc0,0x33}, /* 16 bytes */
        {0xb6,0xb3,0x25,0x9b,0xb6,0x44,0x29,0x98,0xb0,0x9d,0xda,0x2a,0x09,0xb8,0x48,0x77}, /* 29 bytes */
        {0x8c,0x6b,0x79,0xcd,0xea,0x90,0xd5,0x4d,0xf9,0x25,0x4d,0x98,0xec,0x3f,0x49,0x96}, /* 30 bytes */
        {0xfa,0x37,0x96,0x40,0xbb,0x21,0xcc,0x0e,0x17,0x6f,0x4e,0xd8,0xa0,0x37,0x76,0x03}, /* 31 bytes */
    },
    { /* s = 16, r = 14 */
        {0xb1,0x3a,0x33,0x72,0x8c,0x6e,0x87,0x7b,0x4f,0xa5,0x32,0xd1,0x70,0x04,0x1e,0x14}, /* 13 bytes */
        {0xf8,0x3b,0xcc,0xfa,0xf0,0x68,0x7e,0xf4,0x9e,0xc5,0x25,0x64,0xcf,0x07,0x9a,0x54}, /* 14 bytes */
        {0xd5,0x7e,0xb6,0x83,0x48,0x64,0xeb,0xeb,0xc3,0xcc,0x23,0xd6,0x01,0x47,0xff,0x5c}, /* 15 bytes */
        {0x67,0x5f,0x78,0x96,0x62,0xd7,0x15,0x6f,0xf3,0xb4,0x6a,0xc5,0x17,0x92,0x8b,0x64}, /* 27 bytes */
        {0xe0,0x0c,0x38,0xfd,0x33,0xbb,0x56,0x66,0x17,0x1b,0x4e,0x78,0x38,0xbb,0x6c,0x9b}, /* 28 bytes */
        {0xd6,0xbc,0x90,0x16,0xd9,0x8e,0xa4,0xd2,0xec,0xfe,0x19,0xcc,0x3e,0x34,0xff,0x0a}, /* 29 bytes */
    },
    { /* s = 24, r = 13 */
        {0x7e,0xed,0x68,0xc8,0xe5,0xff,0x5d,0x15,0x58,0xd4,0xd0,0xc0,0x8c,0xb4,0xcb,0x7b}, /* 12 bytes */
        {0x39,0xbc,0x11,0x9f,0xf5,0xa6,0xc9,0xdf,0xd2,0x9c,0x7b,0x9e,0x7b,0x7c,0x41,0x90}, /* 13 bytes */
        {0x1c,0x91,0x48,0xd9,0x40,0x5b,0xf4,0xf8,0x99,0x18,0xe0,0x88,0xdb,0x7f,0x81,0xd4}, /* 14 bytes */
        {0x9b,0xc4,0xaf,0xc1,0x85,0xf3,0x5f,0xf7,0x40,0x1d,0x1c,0x08,0x2c,0x16,0x8e,0x09}, /* 25 bytes */
        {0x9c,0x14,0xa0,0xf2,0x41,0xc2,0xe3,0x78,0x72,0x91,0x4f,0x48,0xcf,0xe3,0x73,0xf5}, /* 26 bytes */
        {0x7a,0x2a,0x20,0xf6,0x11,0x39,0x8a,0x1d,0x9b,0xf4,0xb5,0x6f,0x9a,0x68,0x5c,0x30}, /* 27 bytes */
    },
    { /* s = 32, r = 12 */
        {0x12,0x1b,0x26,0x2c,0x4a,0x9f,0x8f,0x98,0x46,0xe5,0x64,0x0b,0xfc,0xcd,0xd3,0x97}, /* 11 bytes */
        {0x7e,0x89,0x32,0xed,0x6f,0xa3,0x10,0xca,0x79,0x84,0x87,0x55,0x8f,0xd9,0x94,0xb7}, /* 12 bytes */
        {0x73,0x85,0x27,0x1c,0xa7,0x0d,0x49,0xb9,0xa4,0x41,0x51,0x53,0x5d,0x5c,0x1f,0x71}, /* 13 bytes */
        {0xeb,0x4f,0x4d,0x53,0x5e,0x3c,0x57,0xc0,0x6c,0xc9,0xc3,0x37,0xc2,0x05,0x91,0xa6}, /* 23 bytes */
        {0x6f,0x3d,0x4e,0x09,0x5b,0x91,0xaf,0x5b,0xec,0x12,0xd7,0x48,0x02,0x66,0xcf,0x0a}, /* 24 bytes */
        {0x19,0x75,0xe2,0x76,0x4a,0x93,0x1f,0x4e,0x5b,0xd6,0x46,0xd9,0x54,0x28,0xb4,0x0f}, /* 25 bytes */
    },
    { /* s = 40, r = 11 */
        {0x82,0x2b,0x94,0x6c,0x71,0x62,0x47,0xe8,0x81,0x10,0x31,0x7c,0x1c,0xa9,0x1d,0x72}, /* 10 bytes */
        {0x87,0x13,0x60,0x17,0x00,0xa8,0xee,0xcf,0x1b,0xc3,0x06,0xba,0x05,0x8d,0x21,0xbb}, /* 11 bytes */
        {0x4b,0xaf,0x9d,0x56,0xf3,0xb0,0xde,0x11,0xc5,0x50,0x05,0xc7,0xee,0xfa,0x48,0x03}, /* 12 bytes */
        {0xf5,0x37,0xb8,0xda,0x76,0xd9,0x34,0xd1,0xdd,0x40,0xfe,0x5a,0x20,0x76,0x6e,0xee}, /* 21 bytes */
        {0x84,0xbe,0x31,0x72,0x64,0x2a,0x59,0x05,0xd4,0x39,0xff,0x40,0xb2,0xf3,0xb9,0x09}, /* 22 bytes */
        {0xaf,0x0b,0x30,0xa0,0x43,0x45,0x3f,0x3d,0xcd,0xdc,0x42,0x84,0xc0,0x8d,0x3d,0xe6}, /* 23 bytes */
    },
    { /* s = 48, r = 10 */
        {0xb4,0x67,0xe3,0x1b,0xd9,0x1d,0x24,0xc2,0x0f,0x47,0xf6,0x89,0xf8,0xc3,0x55,0x14}, /* 9 bytes */
        {0xd6,0x3f,0x99,0xc4,0xcd,0x4b,0x89,0x5f,0xa0,0x3c,0x0b,0x9f,0xbd,0xf1,0x29,0x56}, /* 10 bytes */
        {0x1d,0x19,0x64,0xf8,0x2d,0x82,0xa8,0x2d,0xe0,0xc0,0x76,0x5b,0xe9,0xd2,0xeb,0x4a}, /* 11 bytes */
        {0xf2,0xf8,0x0f,0x10,0x7c,0x3a,0x89,0xc4,0x11,0x80,0xaf,0xe1,0x0a,0xb4,0x10,0x4c}, /* 19 bytes */
        {0xb3,0x96,0x8d,0x40,0x76,0xf4,0x8b,0xa8,0x31,0x15,0xaa,0x86,0x40,0xf6,0x9a,0xde}, /* 20 bytes */
        {0xcb,0xcb,0x6d,0x10,0x82,0x64,0xfd,0xf6,0x4e,0x7a,0xef,0xa0,0x2e,0x46,0xc4,0xad}, /* 21 bytes */
    },
    { /* s = 56, r = 9 */
        {0xc0,0x10,0xb4,0x67,0x3c,0x40,0x2b,0x70,0x80,0x24,0x4b,0x04,0x31,0x27,0xf0,0x58}, /* 8 bytes */
        {0xf7,0x89,0x44,0xdc,0x90,0x45,0x1d,0x3f,0x25,0xaa,0x0d,0x16,0x03,0xf1,0xf8,0xa9}, /* 9 bytes */
        {0x13,0xb3,0x4e,0x25,0x6e,0x06,0x7d,0x81,0xda,0x2c,0x0e,0x46,0xf6,0x87,0xa9,0x79}, /* 10 bytes */
        {0x01,0x3f,0x76,0x42,0xb0,0xe1,0x38,0x7c,0x85,0x03,0x41,0x57,0x4f,0x71,0xc3,0xa8}, /* 17 bytes */
        {0xad,0x20,0x5d,0x27,0x0d,0xd4,0x9e,0xa2,0xf3,0x34,0x4e,0x99,0xfe,0xed,0x07,0xa1}, /* 18 bytes */
        {0x35,0x2f,0xde,0x14,0x85,0x52,0x69,0xe8,0x19,0x58,0x38,0xb7,0x00,0x5c,0xa3,0xa2}, /* 19 bytes */
    },
    { /* s = 64, r = 8 */
        {0xf5,0x2c,0xa8,0x47,0x1a,0x2e,0x83,0xa4,0x08,0xf4,0xf9,0x5d,0x89,0x15,0x84,0xb0}, /* 7 bytes */
        {0xdf,0x6d,0x36,0xdd,0x9b,0xf4,0xfa,0xe9,0x3b,0xc5,0xa3,0x1a,0xd8,0xa1,0x4f,0x44}, /* 8 bytes */
        {0x73,0xb6,0x9d,0x93,0x84,0x27,0x25,0xb1,0xf3,0xdd,0xfe,0x3c,0x6a,0xe8,0x60,0xe7}, /* 9 bytes */
        {0xc1,0x11,0x1f,0x3a,0xe4,0xc0,0x81,0x02,0x84,0x85,0xe7,0x20,0x38,0x39,0x10,0x95}, /* 15 bytes */
        {0x5c,0x61,0xf9,0x5f,0xf8,0xf7,0xef,0xe2,0x86,0x26,0xef,0x8f,0xc2,0x77,0x15,0x33}, /* 16 bytes */
        {0x33,0xd3,0xe2,0x54,0x77,0xbd,0x19,0x1e,0xf9,0xa5,0x9d,0xdf,0xe0,0x03,0x21,0xf8}, /* 17 bytes */
    },
};

static int run_boundaries(void)
{
    uint8_t msg[31];
    uint8_t tag[16];
    aes128_lightmac_ctx ctx;
    for (uint32_t i = 0; i < sizeof msg; ++i) {
        msg[i] = (uint8_t)i;
    }

    for (uint32_t s_bytes = 1; s_bytes <= 8; ++s_bytes) {
        uint8_t s_bits = (uint8_t)(s_bytes * 8);
        uint32_t rate = 16 - s_bytes;
        const uint32_t lengths[] = {rate - 1, rate, rate + 1,
                                    2 * rate - 1, 2 * rate, 2 * rate + 1};
        for (uint32_t v = 0; v < 6; ++v) {
            uint32_t len = lengths[v];
            const uint8_t *expected = lm_boundary_tags[s_bytes - 1][v];
            LM_CHECK(aes128_lightmac(tag, lightmac_k1, lightmac_k2,
                                    s_bits, 128, msg, len) == AES128_LIGHTMAC_OK);
            LM_CHECK(memcmp(tag, expected, sizeof tag) == 0);
            LM_CHECK(aes128_lightmac(tag, lightmac_k1, lightmac_k2,
                                    s_bits, 64, msg, len) == AES128_LIGHTMAC_OK);
            LM_CHECK(memcmp(tag, expected, 8) == 0);

            for (uint32_t split = 0; split <= len; ++split) {
                LM_CHECK(aes128_lightmac_init(&ctx, lightmac_k1, lightmac_k2,
                                             s_bits, 128) == AES128_LIGHTMAC_OK);
                LM_CHECK(aes128_lightmac_update(&ctx, msg, split) == AES128_LIGHTMAC_OK);
                LM_CHECK(aes128_lightmac_update(&ctx, NULL, 0) == AES128_LIGHTMAC_OK);
                LM_CHECK(aes128_lightmac_update(&ctx, msg + split,
                                               len - split) == AES128_LIGHTMAC_OK);
                LM_CHECK(aes128_lightmac_final(&ctx, tag) == AES128_LIGHTMAC_OK);
                LM_CHECK(memcmp(tag, expected, sizeof tag) == 0);
            }

            LM_CHECK(aes128_lightmac_init(&ctx, lightmac_k1, lightmac_k2,
                                         s_bits, 128) == AES128_LIGHTMAC_OK);
            for (uint32_t i = 0; i < len; ++i) {
                LM_CHECK(aes128_lightmac_update(&ctx, msg + i, 1) == AES128_LIGHTMAC_OK);
            }
            LM_CHECK(aes128_lightmac_final(&ctx, tag) == AES128_LIGHTMAC_OK);
            LM_CHECK(memcmp(tag, expected, sizeof tag) == 0);
        }
    }
    return 0;
}

static int run_counter_limits(void)
{
    /* s=8 permits 255 complete 15-byte blocks and at most 14 final bytes. */
    static const uint8_t max_tag[16] = {
        0x1c,0xe9,0xf5,0x0d,0x30,0x7d,0xf0,0xc6,
        0x6f,0xb8,0xc9,0x3a,0x8c,0x94,0xc7,0x90
    };
    uint8_t msg[3840];
    uint8_t tag[16];
    uint8_t unchanged[16];
    aes128_lightmac_ctx ctx;
    for (uint32_t i = 0; i < sizeof msg; ++i) {
        msg[i] = (uint8_t)i;
    }
    LM_CHECK(aes128_lightmac(tag, lightmac_k1, lightmac_k2,
                            8, 128, msg, 3839) == AES128_LIGHTMAC_OK);
    LM_CHECK(memcmp(tag, max_tag, sizeof tag) == 0);
    LM_CHECK(aes128_lightmac_verify(max_tag, lightmac_k1, lightmac_k2,
                                   8, 128, msg, 3839) == 1);
    memset(tag, 0xa5, sizeof tag);
    memcpy(unchanged, tag, sizeof unchanged);
    LM_CHECK(aes128_lightmac(tag, lightmac_k1, lightmac_k2,
                            8, 128, msg, 3840) == AES128_LIGHTMAC_TOO_LONG);
    LM_CHECK(memcmp(tag, unchanged, sizeof tag) == 0);
    LM_CHECK(aes128_lightmac_verify(max_tag, lightmac_k1, lightmac_k2,
                                   8, 128, msg, 3840) == AES128_LIGHTMAC_TOO_LONG);

    LM_CHECK(aes128_lightmac_init(&ctx, lightmac_k1, lightmac_k2,
                                 8, 128) == AES128_LIGHTMAC_OK);
    LM_CHECK(aes128_lightmac_update(&ctx, msg, 3825) == AES128_LIGHTMAC_OK);
    LM_CHECK(aes128_lightmac_update(&ctx, msg + 3825, 14) == AES128_LIGHTMAC_OK);
    LM_CHECK(aes128_lightmac_final(&ctx, tag) == AES128_LIGHTMAC_OK);
    LM_CHECK(memcmp(tag, max_tag, sizeof tag) == 0);

    aes128_lightmac_reset(&ctx);
    LM_CHECK(aes128_lightmac_update(&ctx, msg, 3839) == AES128_LIGHTMAC_OK);
    LM_CHECK(aes128_lightmac_update(&ctx, msg + 3839, 1) == AES128_LIGHTMAC_TOO_LONG);
    memset(tag, 0xa5, sizeof tag);
    LM_CHECK(aes128_lightmac_final(&ctx, tag) == AES128_LIGHTMAC_TOO_LONG);
    LM_CHECK(memcmp(tag, unchanged, sizeof tag) == 0);
    LM_CHECK(aes128_lightmac_update(&ctx, NULL, 0) == AES128_LIGHTMAC_TOO_LONG);
    aes128_lightmac_reset(&ctx);
    LM_CHECK(aes128_lightmac_final(&ctx, tag) == AES128_LIGHTMAC_OK);
    LM_CHECK(memcmp(tag, lm_tag_s64_t128_empty, sizeof tag) == 0);

    /* Reach the 64-bit counter boundary without processing 2^64 blocks. */
    LM_CHECK(aes128_lightmac_init(&ctx, lightmac_k1, lightmac_k2,
                                 64, 128) == AES128_LIGHTMAC_OK);
    ctx.block_index = UINT64_MAX;
    LM_CHECK(aes128_lightmac_update(&ctx, msg, 8) == AES128_LIGHTMAC_OK);
    LM_CHECK(ctx.block_index == 0);
    LM_CHECK(aes128_lightmac_update(&ctx, msg + 8, 7) == AES128_LIGHTMAC_OK);
    LM_CHECK(aes128_lightmac_final(&ctx, tag) == AES128_LIGHTMAC_OK);

    aes128_lightmac_reset(&ctx);
    ctx.block_index = UINT64_MAX;
    LM_CHECK(aes128_lightmac_update(&ctx, msg, 8) == AES128_LIGHTMAC_OK);
    LM_CHECK(aes128_lightmac_update(&ctx, msg + 8, 7) == AES128_LIGHTMAC_OK);
    LM_CHECK(aes128_lightmac_update(&ctx, msg + 15, 1) == AES128_LIGHTMAC_TOO_LONG);
    memset(tag, 0xa5, sizeof tag);
    LM_CHECK(aes128_lightmac_final(&ctx, tag) == AES128_LIGHTMAC_TOO_LONG);
    LM_CHECK(memcmp(tag, unchanged, sizeof tag) == 0);
    return 0;
}

static int run_lifecycle(void)
{
    uint8_t tag[16], unchanged[16];
    aes128_lightmac_ctx ctx, saved;

    for (size_t i = 0; i < sizeof lm_vecs / sizeof lm_vecs[0]; ++i) {
        const lightmac_vec *v = &lm_vecs[i];
        memset(&ctx, 0, sizeof ctx);
        LM_CHECK(aes128_lightmac_init(&ctx, lightmac_k1, lightmac_k2,
                                     v->s_bits, v->t_bits) == AES128_LIGHTMAC_OK);
        LM_CHECK(aes128_lightmac_update(&ctx, v->msg, v->msg_len) == AES128_LIGHTMAC_OK);

        /* Invalid arguments must not consume an otherwise valid message. */
        memcpy(&saved, &ctx, sizeof saved);
        LM_CHECK(aes128_lightmac_final(&ctx, NULL) == AES128_LIGHTMAC_BAD_PARAM);
        LM_CHECK(aes128_lightmac_update(&ctx, NULL, 1) == AES128_LIGHTMAC_BAD_PARAM);
        LM_CHECK(memcmp(&ctx, &saved, sizeof ctx) == 0);
        LM_CHECK(aes128_lightmac_final(&ctx, tag) == AES128_LIGHTMAC_OK);
        LM_CHECK(memcmp(tag, v->tag, v->tag_len) == 0);

        /* No operation may continue a finalized message, even an empty update. */
        memcpy(&saved, &ctx, sizeof saved);
        memset(tag, 0xa5, sizeof tag);
        memcpy(unchanged, tag, sizeof unchanged);
        LM_CHECK(aes128_lightmac_final(&ctx, tag) == AES128_LIGHTMAC_BAD_STATE);
        LM_CHECK(memcmp(tag, unchanged, sizeof tag) == 0);
        LM_CHECK(aes128_lightmac_update(&ctx, lm_msg_00, 1) == AES128_LIGHTMAC_BAD_STATE);
        LM_CHECK(aes128_lightmac_update(&ctx, NULL, 0) == AES128_LIGHTMAC_BAD_STATE);
        LM_CHECK(memcmp(&ctx, &saved, sizeof ctx) == 0);

        /* Reset retains both keys and permits a fresh message. */
        aes128_lightmac_reset(&ctx);
        LM_CHECK(aes128_lightmac_update(&ctx, v->msg, v->msg_len) == AES128_LIGHTMAC_OK);
        LM_CHECK(aes128_lightmac_final(&ctx, tag) == AES128_LIGHTMAC_OK);
        LM_CHECK(memcmp(tag, v->tag, v->tag_len) == 0);
    }
    return 0;
}

static int run_kat(void)
{
    uint8_t tag[16];
    uint8_t tag_bad[16];
    int failed = 0;

    for (size_t i = 0; i < (sizeof lm_vecs / sizeof lm_vecs[0]); ++i) {
        const lightmac_vec *v = &lm_vecs[i];
        memset(tag, 0, sizeof tag);

        if (aes128_lightmac(tag, lightmac_k1, lightmac_k2,
                            v->s_bits, v->t_bits,
                            v->msg, v->msg_len) != AES128_LIGHTMAC_OK) {
            printf("KAT #%zu : FAILED (tag rc)\n", i + 1);
            failed = 1;
            continue;
        }
        if (memcmp(tag, v->tag, v->tag_len) != 0) {
            printf("KAT #%zu : FAILED (mismatch)\n", i + 1);
            failed = 1;
        }

        int vrc = aes128_lightmac_verify(v->tag, lightmac_k1, lightmac_k2,
                                         v->s_bits, v->t_bits,
                                         v->msg, v->msg_len);
        if (vrc != 1) {
            printf("KAT verify #%zu : FAILED\n", i + 1);
            failed = 1;
        }

        for (uint8_t offset = 0; offset < v->tag_len; ++offset) {
            for (uint8_t bit = 0; bit < 8; ++bit) {
                memcpy(tag_bad, v->tag, v->tag_len);
                tag_bad[offset] ^= (uint8_t)(1U << bit);
                vrc = aes128_lightmac_verify(tag_bad, lightmac_k1, lightmac_k2,
                                             v->s_bits, v->t_bits,
                                             v->msg, v->msg_len);
                if (vrc != 0) {
                    printf("KAT negative #%zu, tag byte %u bit %u : FAILED\n",
                           i + 1, (unsigned int)offset, (unsigned int)bit);
                    failed = 1;
                }
            }
        }
    }

    return failed ? 1 : 0;
}

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

static int run_fuzz(uint32_t iterations)
{
    uint8_t k1[16];
    uint8_t k2[16];
    uint8_t msg[256];
    uint8_t tag[16];
    uint8_t tag_bad[16];

    lm_fill_random(k1, sizeof k1);
    lm_fill_random(k2, sizeof k2);

    int failed = 0;
    const uint8_t s_opts[] = {8, 16, 32, 64};

    for (uint32_t i = 0; i < iterations; ++i) {
        uint8_t s_bits = s_opts[lm_prng_next() & 3U];
        uint8_t t_bits = (uint8_t)(((lm_prng_next() % 16U) + 1U) * 8U);
        uint32_t msg_len = lm_prng_next() % (uint32_t)sizeof msg;

        lm_fill_random(msg, msg_len);
        memset(tag, 0, sizeof tag);

        if (aes128_lightmac(tag, k1, k2, s_bits, t_bits, msg, msg_len) != AES128_LIGHTMAC_OK) {
            printf("Fuzz #%u : FAILED (tag rc)\n", i + 1);
            failed = 1;
            continue;
        }

        int vrc = aes128_lightmac_verify(tag, k1, k2, s_bits, t_bits, msg, msg_len);
        if (vrc != 1) {
            printf("Fuzz #%u : FAILED (verify)\n", i + 1);
            failed = 1;
        }

        memcpy(tag_bad, tag, sizeof tag);
        tag_bad[0] ^= 0x80;
        vrc = aes128_lightmac_verify(tag_bad, k1, k2, s_bits, t_bits, msg, msg_len);
        if (vrc != 0) {
            printf("Fuzz #%u : FAILED (tag tamper)\n", i + 1);
            failed = 1;
        }

        if (msg_len > 0) {
            uint32_t idx = lm_prng_next() % msg_len;
            msg[idx] ^= 0x01;
            /* A changed message can legitimately share a truncated tag. */
            if (aes128_lightmac(tag_bad, k1, k2, s_bits, t_bits,
                               msg, msg_len) != AES128_LIGHTMAC_OK) {
                printf("Fuzz #%u : FAILED (modified tag rc)\n", i + 1);
                failed = 1;
                continue;
            }
            int matches = memcmp(tag, tag_bad, t_bits / 8U) == 0;
            vrc = aes128_lightmac_verify(tag, k1, k2, s_bits, t_bits, msg, msg_len);
            if (vrc != matches) {
                printf("Fuzz #%u : FAILED (msg tamper)\n", i + 1);
                failed = 1;
            }
        }
    }

    return failed ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc <= 1 || strcmp(argv[1], "kat") == 0) {
        int rc = run_kat();
        rc |= run_boundaries();
        rc |= run_counter_limits();
        rc |= run_lifecycle();
        return rc;
    }

    if (strcmp(argv[1], "fuzz") == 0) {
        uint32_t iters = 200;
        if (argc > 2) {
            iters = (uint32_t)strtoul(argv[2], NULL, 10);
            if (iters == 0) {
                iters = 1;
            }
        }
        return run_fuzz(iters);
    }

    fprintf(stderr, "Usage: %s [kat|fuzz [iterations]]\n", argv[0]);
    return 2;
}
