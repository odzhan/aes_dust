/* Assembly backend KATs and state/buffer regressions. Expectations are
 * independently generated; see tests/assembly_generate_vectors.py. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef ASM
#define ASM 1
#endif
#include "aes.h"
#include "test_asm_vectors.h"

#ifdef AES_ASM_ABI_PROBE
extern void aes_test_abi_ecb(void *intended, void *decoy);
#endif

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); return 1; \
} } while (0)

static int filled(const uint8_t *data, size_t length, uint8_t value)
{
    for (size_t i = 0; i < length; ++i) if (data[i] != value) return 0;
    return 1;
}

static int ecb_tests(void)
{
    uint8_t storage[48];
#ifdef AES_ASM_ABI_PROBE
    {
        /* Run this before ordinary calls: a wrong ABI then touches a controlled
         * decoy buffer and fails cleanly instead of dereferencing a stray GPR. */
        uint8_t intended[32], decoy[32], saved[32];
        memcpy(intended, asm_ecb_plain[0], 16);
        memcpy(intended + 16, asm_ecb_keys[0], 16);
        memset(decoy, 0xa5, sizeof decoy);
        memcpy(saved, decoy, sizeof saved);
        aes_test_abi_ecb(intended, decoy);
        CHECK(memcmp(intended, asm_ecb_cipher[0], 16) == 0);
        CHECK(memcmp(intended + 16, asm_ecb_keys[0], 16) == 0);
        CHECK(memcmp(decoy, saved, sizeof decoy) == 0);
    }
#endif
    for (size_t v = 0; v < sizeof asm_ecb_keys / sizeof asm_ecb_keys[0]; ++v) {
        /* Exercise aligned and unaligned caller storage without losing guards. */
        for (size_t offset = 1; offset <= 8; ++offset) {
            memset(storage, 0xa5, sizeof storage);
            memcpy(storage + offset, asm_ecb_plain[v], 16);
            memcpy(storage + offset + 16, asm_ecb_keys[v], 16);
            aes_ecb_asm(storage + offset);
            CHECK(memcmp(storage + offset, asm_ecb_cipher[v], 16) == 0);
            CHECK(memcmp(storage + offset + 16, asm_ecb_keys[v], 16) == 0);
            CHECK(filled(storage, offset, 0xa5));
            CHECK(filled(storage + offset + 32, sizeof storage - offset - 32, 0xa5));
        }
    }
    return 0;
}

#ifdef AES_ASM_CTR
static void advance_counter(uint8_t counter[16], uint32_t blocks)
{
    while (blocks--) {
        for (size_t i = 16; i > 0; --i) if (++counter[i - 1] != 0) break;
    }
}

static void message(uint8_t *data, uint32_t length)
{
    for (uint32_t i = 0; i < length; ++i) data[i] = (uint8_t)(i * 29U + 7U);
}

typedef void (*ctr_function)(uint32_t, void *, void *, void *);

static int ctr_tests(ctr_function crypt)
{
    static const uint32_t lengths[] = {0, 1, 15, 16, 17, 255, 256, 257};
    uint8_t data[259], counter_storage[18], key_storage[18], expected_counter[16];
    uint8_t *counter = counter_storage + 1, *key = key_storage + 1;
    for (size_t v = 0; v < sizeof asm_ctr_initial / sizeof asm_ctr_initial[0]; ++v) {
        for (size_t l = 0; l < sizeof lengths / sizeof lengths[0]; ++l) {
            uint32_t length = lengths[l];
            memset(data, 0xa5, sizeof data);
            memset(counter_storage, 0xa5, sizeof counter_storage);
            memset(key_storage, 0xa5, sizeof key_storage);
            message(data + 1, length);
            memcpy(counter, asm_ctr_initial[v], 16);
            memcpy(key, asm_ecb_keys[0], 16);
            memcpy(expected_counter, counter, 16);
            advance_counter(expected_counter, (length + 15U) / 16U);
            crypt(length, counter, data + 1, key);
            CHECK(memcmp(data + 1, asm_ctr_cipher[v], length) == 0);
            CHECK(memcmp(counter, expected_counter, 16) == 0);
            CHECK(memcmp(key, asm_ecb_keys[0], 16) == 0);
            CHECK(data[0] == 0xa5 && filled(data + 1 + length, sizeof data - 1 - length, 0xa5));
            CHECK(counter_storage[0] == 0xa5 && counter_storage[17] == 0xa5);
            CHECK(key_storage[0] == 0xa5 && key_storage[17] == 0xa5);
            /* Restore the original counter for decryption. */
            memcpy(counter, asm_ctr_initial[v], 16);
            crypt(length, counter, data + 1, key);
            for (uint32_t i = 0; i < length; ++i) CHECK(data[i + 1] == (uint8_t)(i * 29U + 7U));
            CHECK(memcmp(counter, expected_counter, 16) == 0);
        }
        /* Every block-aligned continuation split, then a final partial byte. */
        for (uint32_t split = 0; split <= 256; split += 16) {
            memset(data, 0xa5, sizeof data);
            message(data + 1, 257);
            memcpy(counter, asm_ctr_initial[v], 16);
            memcpy(key, asm_ecb_keys[0], 16);
            crypt(split, counter, data + 1, key);
            crypt(257 - split, counter, data + 1 + split, key);
            CHECK(memcmp(data + 1, asm_ctr_cipher[v], 257) == 0);
            memcpy(expected_counter, asm_ctr_initial[v], 16);
            advance_counter(expected_counter, 17);
            CHECK(memcmp(counter, expected_counter, 16) == 0);
            CHECK(data[0] == 0xa5 && data[258] == 0xa5);
            CHECK(memcmp(key, asm_ecb_keys[0], 16) == 0);
        }
    }
    return 0;
}
#endif

int main(void)
{
    int failed = ecb_tests();
    if (failed) return failed;
#ifdef AES_ASM_CTR
    failed |= ctr_tests(aes_ctr);
    failed |= ctr_tests(aes_ctr_encrypt);
#endif
    if (!failed) puts("Assembly known-answer, ABI, and buffer/state regressions passed.");
    return failed;
}
