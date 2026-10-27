/* Independent key-pattern vectors, feedback continuation, and buffer contracts. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <aes128_cbc.h>
#include <aes128_cfb.h>
#include <aes128_xts.h>
#include "mode_vectors.h"

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); return 1; \
} } while (0)
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static void pattern(uint8_t *out, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(seed + 29U * i);
}

static int filled(const uint8_t *p, size_t len, uint8_t value) {
    for (size_t i = 0; i < len; i++) if (p[i] != value) return 0;
    return 1;
}

static void setup(aes128_ctx *ctx, const uint8_t key[16], const uint8_t iv[16]) {
    memset(ctx, 0, sizeof(*ctx));
    aes128_init_ctx(ctx);
    aes128_set_key(ctx, key);
    if (iv) aes128_set_iv(ctx, iv);
}

static int key_patterns(void) {
    aes128_ctx ctx;
    uint8_t key[48], saved_key[48], data[48], plain[16];
    for (int variable_key = 0; variable_key <= 1; variable_key++) {
        for (size_t bit = 0; bit < 128; bit++) {
            size_t offset = 1 + bit % 16, key_offset = 16 - bit % 16;
            const uint8_t *expected = variable_key ? ecb_variable_key[bit] : ecb_variable_plain[bit];
            memset(key, 0xa5, sizeof(key));
            memset(key + key_offset, 0, 16);
            memset(plain, 0, sizeof(plain));
            if (variable_key) key[key_offset + bit / 8] = (uint8_t)(1U << (bit % 8));
            else plain[bit / 8] = (uint8_t)(1U << (bit % 8));
            memcpy(saved_key, key, sizeof(key));
            setup(&ctx, key + key_offset, NULL);
            memset(data, 0xa5, sizeof(data));
            memcpy(data + offset, plain, 16);
            aes128_ecb_encrypt(&ctx, data + offset);
            CHECK(memcmp(data + offset, expected, 16) == 0);
            CHECK(filled(data, offset, 0xa5));
            CHECK(filled(data + offset + 16, sizeof(data) - offset - 16, 0xa5));
            /* Decrypt an independent ciphertext, not just the preceding result. */
            memcpy(data + offset, expected, 16);
            aes128_ecb_decrypt(&ctx, data + offset);
            CHECK(memcmp(data + offset, plain, 16) == 0);
            CHECK(filled(data, offset, 0xa5));
            CHECK(filled(data + offset + 16, sizeof(data) - offset - 16, 0xa5));
            CHECK(memcmp(key, saved_key, sizeof(key)) == 0);
        }
    }
    return 0;
}

typedef int (*feedback_fn)(aes128_ctx *, void *, uint32_t);

static int feedback_modes(void) {
    const feedback_fn encrypt[] = {aes128_cbc_encrypt, aes128_cfb_encrypt};
    const feedback_fn decrypt[] = {aes128_cbc_decrypt, aes128_cfb_decrypt};
    const feedback_vector *vectors[] = {cbc_continuation_vectors, cfb_continuation_vectors};
    const uint32_t invalid[] = {1, 15, 17, 31, 127, UINT32_MAX};
    for (size_t mode = 0; mode < COUNT(encrypt); mode++) {
        for (size_t v = 0; v < COUNT(cbc_continuation_vectors); v++) {
            const feedback_vector *vec = &vectors[mode][v];
            uint8_t key[16], iv[16], plain[128], data[160];
            aes128_ctx ctx, saved;
            pattern(key, sizeof(key), vec->key_seed);
            pattern(iv, sizeof(iv), vec->iv_seed);
            pattern(plain, vec->len, vec->plain_seed);
            for (int dec = 0; dec <= 1; dec++) {
                feedback_fn crypt = dec ? decrypt[mode] : encrypt[mode];
                const uint8_t *input = dec ? vec->crypt : plain;
                const uint8_t *expected = dec ? plain : vec->crypt;
                for (uint32_t split = 0; split <= vec->len; split += 16) {
                    setup(&ctx, key, iv);
                    memcpy(&saved, &ctx, sizeof(ctx));
                    memset(data, 0xa5, sizeof(data));
                    memcpy(data + 3, input, vec->len);
                    CHECK(crypt(&ctx, data + 3, split));
                    CHECK(memcmp(ctx.iv, split ? vec->crypt + split - 16 : iv, 16) == 0);
                    aes128_ctx mid;
                    memcpy(&mid, &ctx, sizeof(ctx));
                    CHECK(crypt(&ctx, NULL, 0));
                    CHECK(memcmp(&ctx, &mid, sizeof(ctx)) == 0);
                    CHECK(crypt(&ctx, data + 3 + split, vec->len - split));
                    CHECK(memcmp(data + 3, expected, vec->len) == 0);
                    CHECK(memcmp(ctx.iv, vec->len ? vec->crypt + vec->len - 16 : iv, 16) == 0);
                    CHECK(filled(data, 3, 0xa5));
                    CHECK(filled(data + 3 + vec->len, sizeof(data) - 3 - vec->len, 0xa5));
                    /* Only feedback may change; the key schedule and stream state stay intact. */
                    memcpy(ctx.iv, saved.iv, sizeof(ctx.iv));
                    CHECK(memcmp(&ctx, &saved, sizeof(ctx)) == 0);
                }
                setup(&ctx, key, iv);
                memcpy(&saved, &ctx, sizeof(ctx));
                memset(data, 0xa5, sizeof(data));
                for (size_t i = 0; i < COUNT(invalid); i++) {
                    CHECK(!crypt(&ctx, data + 3, invalid[i]));
                    CHECK(memcmp(&ctx, &saved, sizeof(ctx)) == 0);
                    CHECK(filled(data, sizeof(data), 0xa5));
                }
                /* Restore the IV after processing a prefix and start a fresh message. */
                memcpy(data + 3, input, vec->len);
                if (vec->len) CHECK(crypt(&ctx, data + 3, 16));
                aes128_set_iv(&ctx, iv);
                memcpy(data + 3, input, vec->len);
                CHECK(crypt(&ctx, data + 3, vec->len));
                CHECK(memcmp(data + 3, expected, vec->len) == 0);
            }
        }
    }
    return 0;
}

static int xts_units(void) {
    for (size_t v = 0; v < COUNT(xts_long_vectors); v++) {
        const xts_vector *vec = &xts_long_vectors[v];
        uint8_t key[32], saved_key[32], tweak[16], saved_tweak[16], plain[512], data[544];
        aes128_ctx data_ctx, tweak_ctx, saved_data_ctx, saved_tweak_ctx;
        pattern(key, sizeof(key), vec->key_seed);
        pattern(tweak, sizeof(tweak), vec->tweak_seed);
        pattern(plain, vec->len, vec->plain_seed);
        memcpy(saved_key, key, sizeof(key));
        memcpy(saved_tweak, tweak, sizeof(tweak));
        setup(&data_ctx, key, NULL);
        setup(&tweak_ctx, key + 16, NULL);
        memcpy(&saved_data_ctx, &data_ctx, sizeof(data_ctx));
        memcpy(&saved_tweak_ctx, &tweak_ctx, sizeof(tweak_ctx));
        for (size_t offset = 1; offset <= 16; offset++) {
            memset(data, 0xa5, sizeof(data));
            memcpy(data + offset, plain, vec->len);
            CHECK(aes128_xts_encrypt(&data_ctx, &tweak_ctx, tweak, data + offset, vec->len));
            CHECK(memcmp(data + offset, vec->crypt, vec->len) == 0);
            CHECK(filled(data, offset, 0xa5));
            CHECK(filled(data + offset + vec->len, sizeof(data) - offset - vec->len, 0xa5));
            memcpy(data + offset, vec->crypt, vec->len);
            CHECK(aes128_xts_decrypt(&data_ctx, &tweak_ctx, tweak, data + offset, vec->len));
            CHECK(memcmp(data + offset, plain, vec->len) == 0);
            CHECK(filled(data, offset, 0xa5));
            CHECK(filled(data + offset + vec->len, sizeof(data) - offset - vec->len, 0xa5));
            CHECK(memcmp(&data_ctx, &saved_data_ctx, sizeof(data_ctx)) == 0);
            CHECK(memcmp(&tweak_ctx, &saved_tweak_ctx, sizeof(tweak_ctx)) == 0);
            CHECK(memcmp(key, saved_key, sizeof(key)) == 0);
            CHECK(memcmp(tweak, saved_tweak, sizeof(tweak)) == 0);
        }
    }
    return 0;
}

int main(void) {
    int failed = key_patterns();
    failed |= feedback_modes();
    failed |= xts_units();
    if (!failed) puts("Independent AES key-pattern, feedback-state, and XTS tests passed.");
    return failed;
}
