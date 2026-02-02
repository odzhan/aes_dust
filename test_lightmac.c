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

        memcpy(tag_bad, v->tag, v->tag_len);
        if (v->tag_len > 0) {
            tag_bad[0] ^= 0x01;
        }
        vrc = aes128_lightmac_verify(tag_bad, lightmac_k1, lightmac_k2,
                                     v->s_bits, v->t_bits,
                                     v->msg, v->msg_len);
        if (vrc != 0) {
            printf("KAT negative #%zu : FAILED\n", i + 1);
            failed = 1;
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
            vrc = aes128_lightmac_verify(tag, k1, k2, s_bits, t_bits, msg, msg_len);
            if (vrc != 0) {
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
        return run_kat();
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
