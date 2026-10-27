/* Independent AEAD vectors, authentication rejection, and buffer contracts.
 * Expected outputs are generated outside AES-dust; see generate_aead_vectors.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <aes128_ccm.h>
#include <aes128_eax.h>
#include <aes128_gcm.h>
#include <aes128_gcm_siv.h>

enum aead_mode { AEAD_CCM, AEAD_EAX, AEAD_GCM, AEAD_GCM_SIV };
static const char *phase = "initialization";
static size_t case_number;

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s, case %zu: %s\n", \
            __FILE__, __LINE__, phase, case_number, #expr); return 1; \
} } while (0)

struct aead_fixture {
    enum aead_mode mode;
    uint32_t seed, nonce_len, tag_len, aad_len, plain_len;
    uint8_t crypt[33], tag[16];
};
struct cipher_window { uint32_t offset; uint8_t bytes[32]; };
#include "aead_vectors.h"

enum { GUARD_LEN = 16, FILL = 0xa5 };
struct guarded {
    uint8_t *allocation, *data;
    uint32_t len;
};

static struct guarded allocate_guarded(uint32_t len) {
    struct guarded result;
    result.allocation = (uint8_t *)malloc((size_t)len + 2 * GUARD_LEN);
    result.data = result.allocation ? result.allocation + GUARD_LEN : NULL;
    result.len = len;
    if (result.allocation) memset(result.allocation, FILL, (size_t)len + 2 * GUARD_LEN);
    return result;
}

static int bytes_are(const uint8_t *data, uint32_t len, uint8_t value) {
    for (uint32_t i = 0; i < len; ++i) if (data[i] != value) return 0;
    return 1;
}

static int guards_ok(const struct guarded *buffer) {
    return bytes_are(buffer->allocation, GUARD_LEN, FILL) &&
           bytes_are(buffer->data + buffer->len, GUARD_LEN, FILL);
}

static void pattern(uint8_t *data, uint32_t len, uint32_t salt) {
    for (uint32_t i = 0; i < len; ++i) data[i] = (uint8_t)(i * 29U + salt + (i >> 8));
}

static int is_pattern(const uint8_t *data, uint32_t len, uint32_t salt) {
    for (uint32_t i = 0; i < len; ++i)
        if (data[i] != (uint8_t)(i * 29U + salt + (i >> 8))) return 0;
    return 1;
}

static int seal(enum aead_mode mode, const uint8_t *key, uint32_t key_len,
                const uint8_t *nonce, uint32_t nonce_len, const uint8_t *aad, uint32_t aad_len,
                const uint8_t *plain, uint32_t len, uint8_t *crypt, uint8_t *tag, uint32_t tag_len) {
    switch (mode) {
    case AEAD_CCM: return aes128_ccm_encrypt(key, key_len, nonce, nonce_len, aad, aad_len,
                                            plain, len, crypt, tag, tag_len);
    case AEAD_EAX: return aes128_eax_encrypt(key, key_len, nonce, nonce_len, aad, aad_len,
                                            plain, len, crypt, tag);
    case AEAD_GCM: return aes128_gcm_encrypt(key, key_len, nonce, nonce_len, plain, len,
                                            aad, aad_len, crypt, tag);
    case AEAD_GCM_SIV: return aes128_gcm_siv_encrypt(key, key_len, nonce, nonce_len, aad, aad_len,
                                                    plain, len, crypt, tag);
    }
    return -1;
}

static int open_message(enum aead_mode mode, const uint8_t *key, uint32_t key_len,
                        const uint8_t *nonce, uint32_t nonce_len, const uint8_t *aad, uint32_t aad_len,
                        const uint8_t *crypt, uint32_t len, const uint8_t *tag,
                        uint32_t tag_len, uint8_t *plain) {
    switch (mode) {
    case AEAD_CCM: return aes128_ccm_decrypt(key, key_len, nonce, nonce_len, aad, aad_len,
                                            crypt, len, tag, tag_len, plain);
    case AEAD_EAX: return aes128_eax_decrypt(key, key_len, nonce, nonce_len, aad, aad_len,
                                            crypt, len, tag, plain);
    case AEAD_GCM: return aes128_gcm_decrypt(key, key_len, nonce, nonce_len, crypt, len,
                                            aad, aad_len, tag, plain);
    case AEAD_GCM_SIV: return aes128_gcm_siv_decrypt(key, key_len, nonce, nonce_len, aad, aad_len,
                                                    crypt, len, tag, plain);
    }
    return -1;
}

static int run_vector(const struct aead_fixture *v) {
    uint8_t key[16], nonce[33];
    struct guarded aad = allocate_guarded(v->aad_len);
    struct guarded plain = allocate_guarded(v->plain_len);
    struct guarded crypt = allocate_guarded(v->plain_len);
    struct guarded decoded = allocate_guarded(v->plain_len);
    struct guarded tag = allocate_guarded(v->tag_len);
    CHECK(aad.allocation && plain.allocation && crypt.allocation && decoded.allocation && tag.allocation);
    pattern(key, sizeof(key), v->seed);
    pattern(nonce, v->nonce_len, v->seed + 17);
    pattern(aad.data, v->aad_len, v->seed + 53);
    pattern(plain.data, v->plain_len, v->seed + 101);

    CHECK(seal(v->mode, key, sizeof(key), v->nonce_len ? nonce : NULL, v->nonce_len,
               v->aad_len ? aad.data : NULL, v->aad_len,
               v->plain_len ? plain.data : NULL, v->plain_len, crypt.data, tag.data, v->tag_len) == 0);
    CHECK(memcmp(crypt.data, v->crypt, v->plain_len) == 0);
    CHECK(memcmp(tag.data, v->tag, v->tag_len) == 0);
    CHECK(guards_ok(&crypt) && guards_ok(&tag) && guards_ok(&plain) && guards_ok(&aad));
    CHECK(is_pattern(plain.data, v->plain_len, v->seed + 101));

    /* Decrypt the independent ciphertext/tag, never just our encryption output. */
    CHECK(open_message(v->mode, key, sizeof(key), v->nonce_len ? nonce : NULL, v->nonce_len,
                       v->aad_len ? aad.data : NULL, v->aad_len, v->crypt, v->plain_len,
                       v->tag, v->tag_len, decoded.data) == 0);
    CHECK(is_pattern(decoded.data, v->plain_len, v->seed + 101));
    CHECK(guards_ok(&decoded));

    CHECK(seal(v->mode, key, sizeof(key), v->nonce_len ? nonce : NULL, v->nonce_len,
               v->aad_len ? aad.data : NULL, v->aad_len,
               plain.data, v->plain_len, plain.data, tag.data, v->tag_len) == 0);
    CHECK(memcmp(plain.data, v->crypt, v->plain_len) == 0);
    CHECK(memcmp(tag.data, v->tag, v->tag_len) == 0);
    CHECK(guards_ok(&plain) && guards_ok(&tag));
    CHECK(open_message(v->mode, key, sizeof(key), v->nonce_len ? nonce : NULL, v->nonce_len,
                       v->aad_len ? aad.data : NULL, v->aad_len,
                       plain.data, v->plain_len, v->tag, v->tag_len, plain.data) == 0);
    CHECK(is_pattern(plain.data, v->plain_len, v->seed + 101));
    CHECK(guards_ok(&plain) && guards_ok(&aad));
    CHECK(is_pattern(key, sizeof(key), v->seed));
    CHECK(is_pattern(nonce, v->nonce_len, v->seed + 17));
    CHECK(is_pattern(aad.data, v->aad_len, v->seed + 53));

    if (!v->plain_len) {
        CHECK(seal(v->mode, key, sizeof(key), v->nonce_len ? nonce : NULL, v->nonce_len,
                   v->aad_len ? aad.data : NULL, v->aad_len, NULL, 0, NULL, tag.data, v->tag_len) == 0);
        CHECK(memcmp(tag.data, v->tag, v->tag_len) == 0);
        CHECK(open_message(v->mode, key, sizeof(key), v->nonce_len ? nonce : NULL, v->nonce_len,
                           v->aad_len ? aad.data : NULL, v->aad_len,
                           NULL, 0, v->tag, v->tag_len, NULL) == 0);
    }
    free(aad.allocation); free(plain.allocation); free(crypt.allocation);
    free(decoded.allocation); free(tag.allocation);
    return 0;
}

/* Reject each individual tag bit, and each byte of ciphertext/AAD/nonce.
 * 33-byte messages exercise two full blocks and a final partial block.
 * CCM repeats this for every supported tag length, including truncated tags.
 */
static int tampering(enum aead_mode mode, uint32_t tag_len) {
    uint8_t key[16], nonce[13], aad[33], plain[33], crypt[33], tag[16], bad_tag[16];
    uint32_t nonce_len = mode == AEAD_CCM ? 13U : 12U;
    struct guarded output = allocate_guarded(sizeof(plain));
    CHECK(output.allocation);
    pattern(key, sizeof(key), 19); pattern(nonce, nonce_len, 31);
    pattern(aad, sizeof(aad), 47); pattern(plain, sizeof(plain), 61);
    CHECK(seal(mode, key, sizeof(key), nonce, nonce_len, aad, sizeof(aad),
               plain, sizeof(plain), crypt, tag, tag_len) == 0);
    for (uint32_t field = 0; field < 4; ++field) {
        uint32_t length = field == 0 ? tag_len : field == 3 ? nonce_len : (uint32_t)sizeof(plain);
        uint32_t bits = field == 0 ? 8U : 1U;
        for (uint32_t offset = 0; offset < length; ++offset) {
            for (uint32_t bit = 0; bit < bits; ++bit) {
                uint8_t changed_crypt[33], changed_aad[33], changed_nonce[13];
                memcpy(bad_tag, tag, tag_len); memcpy(changed_crypt, crypt, sizeof(crypt));
                memcpy(changed_aad, aad, sizeof(aad)); memcpy(changed_nonce, nonce, nonce_len);
                if (field == 0) bad_tag[offset] ^= (uint8_t)(1U << bit);
                if (field == 1) changed_crypt[offset] ^= 1;
                if (field == 2) changed_aad[offset] ^= 1;
                if (field == 3) changed_nonce[offset] ^= 1;
                memset(output.data, FILL, output.len);
                CHECK(open_message(mode, key, sizeof(key), changed_nonce, nonce_len,
                                   changed_aad, sizeof(aad), changed_crypt, sizeof(crypt),
                                   bad_tag, tag_len, output.data) == -1);
                CHECK(bytes_are(output.data, output.len, mode == AEAD_GCM ? FILL : 0));
                CHECK(guards_ok(&output));
                memcpy(output.data, changed_crypt, sizeof(crypt));
                CHECK(open_message(mode, key, sizeof(key), changed_nonce, nonce_len,
                                   changed_aad, sizeof(aad), output.data, output.len,
                                   bad_tag, tag_len, output.data) == -1);
                CHECK(mode == AEAD_GCM ? memcmp(output.data, changed_crypt, sizeof(crypt)) == 0
                                       : bytes_are(output.data, output.len, 0));
                CHECK(guards_ok(&output));
            }
        }
    }
    /* Empty-message authentication still checks every tag byte. */
    CHECK(seal(mode, key, sizeof(key), nonce, nonce_len, aad, sizeof(aad),
               NULL, 0, NULL, tag, tag_len) == 0);
    for (uint32_t offset = 0; offset < tag_len; ++offset) {
        memcpy(bad_tag, tag, tag_len); bad_tag[offset] ^= 1;
        memset(output.data, FILL, output.len);
        CHECK(open_message(mode, key, sizeof(key), nonce, nonce_len, aad, sizeof(aad),
                           NULL, 0, bad_tag, tag_len, output.data) == -1);
        CHECK(bytes_are(output.data, output.len, FILL) && guards_ok(&output));
    }
    free(output.allocation);
    return 0;
}

static int rejected_parameters(enum aead_mode mode, uint32_t key_len,
                               uint32_t nonce_len, uint32_t tag_len, uint32_t len) {
    uint8_t key[32] = {0}, nonce[16] = {0}, data[33] = {0}, tag[32];
    struct guarded output = allocate_guarded(sizeof(data));
    struct guarded tag_output = allocate_guarded(sizeof(tag));
    CHECK(output.allocation && tag_output.allocation);
    memset(tag, 0x3c, sizeof(tag));
    /* Invalid lengths must be rejected before processing len bytes. For an
     * oversized CCM message these small buffers also expose a missing preflight. */
    CHECK(seal(mode, key, key_len, nonce, nonce_len, NULL, 0, data, len,
               output.data, tag_output.data, tag_len) == -1);
    CHECK(bytes_are(output.data, output.len, FILL) && guards_ok(&output));
    CHECK(bytes_are(tag_output.data, tag_output.len, FILL) && guards_ok(&tag_output));
    CHECK(open_message(mode, key, key_len, nonce, nonce_len, NULL, 0, data, len,
                       tag, tag_len, output.data) == -1);
    CHECK(bytes_are(output.data, output.len, FILL) && guards_ok(&output));
    memcpy(output.data, data, sizeof(data));
    CHECK(seal(mode, key, key_len, nonce, nonce_len, NULL, 0, output.data, len,
               output.data, tag_output.data, tag_len) == -1);
    CHECK(memcmp(output.data, data, sizeof(data)) == 0 && guards_ok(&output));
    CHECK(bytes_are(tag_output.data, tag_output.len, FILL) && guards_ok(&tag_output));
    CHECK(open_message(mode, key, key_len, nonce, nonce_len, NULL, 0, output.data, len,
                       tag, tag_len, output.data) == -1);
    CHECK(memcmp(output.data, data, sizeof(data)) == 0 && guards_ok(&output));
    free(output.allocation); free(tag_output.allocation);
    return 0;
}

static int parameter_boundaries(void) {
    const uint32_t bad_keys[] = {0, 1, 15, 17, 24, 32, UINT32_MAX};
    const uint32_t bad_ccm_nonces[] = {0, 1, 6, 14, 16, UINT32_MAX};
    const uint32_t bad_siv_nonces[] = {0, 1, 11, 13, 16, UINT32_MAX};
    const uint32_t bad_ccm_tags[] = {0, 1, 2, 3, 5, 7, 9, 11, 13, 15, 17, UINT32_MAX};
    for (enum aead_mode mode = AEAD_CCM; mode <= AEAD_GCM_SIV; mode = (enum aead_mode)(mode + 1)) {
        for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); ++i)
            CHECK(rejected_parameters(mode, bad_keys[i], 12, 16, 33) == 0);
    }
    for (size_t i = 0; i < sizeof(bad_ccm_nonces) / sizeof(bad_ccm_nonces[0]); ++i)
        CHECK(rejected_parameters(AEAD_CCM, 16, bad_ccm_nonces[i], 16, 33) == 0);
    for (size_t i = 0; i < sizeof(bad_siv_nonces) / sizeof(bad_siv_nonces[0]); ++i)
        CHECK(rejected_parameters(AEAD_GCM_SIV, 16, bad_siv_nonces[i], 16, 33) == 0);
    for (size_t i = 0; i < sizeof(bad_ccm_tags) / sizeof(bad_ccm_tags[0]); ++i)
        CHECK(rejected_parameters(AEAD_CCM, 16, 12, bad_ccm_tags[i], 33) == 0);
    CHECK(rejected_parameters(AEAD_GCM, 16, 0, 16, 33) == 0);
    CHECK(rejected_parameters(AEAD_CCM, 16, 13, 16, 65536) == 0);
    CHECK(rejected_parameters(AEAD_CCM, 16, 12, 16, 16777216) == 0);
    return 0;
}

static int ccm_maximum_message(void) {
    uint8_t key[16], nonce[13], aad[17], tag[16];
    struct guarded plain = allocate_guarded(65535);
    struct guarded crypt = allocate_guarded(65535);
    CHECK(plain.allocation && crypt.allocation);
    pattern(key, sizeof(key), 997); pattern(nonce, sizeof(nonce), 1014);
    pattern(aad, sizeof(aad), 1050); pattern(plain.data, plain.len, 1098);
    CHECK(aes128_ccm_encrypt(key, sizeof(key), nonce, sizeof(nonce), aad, sizeof(aad),
                            plain.data, plain.len, crypt.data, tag, sizeof(tag)) == 0);
    CHECK(memcmp(tag, ccm_max_tag, sizeof(tag)) == 0);
    for (size_t i = 0; i < sizeof(ccm_max_windows) / sizeof(ccm_max_windows[0]); ++i)
        CHECK(memcmp(crypt.data + ccm_max_windows[i].offset, ccm_max_windows[i].bytes, 32) == 0);
    CHECK(guards_ok(&crypt) && guards_ok(&plain));
    CHECK(aes128_ccm_decrypt(key, sizeof(key), nonce, sizeof(nonce), aad, sizeof(aad),
                            crypt.data, crypt.len, ccm_max_tag, sizeof(ccm_max_tag), crypt.data) == 0);
    CHECK(is_pattern(crypt.data, crypt.len, 1098) && guards_ok(&crypt));
    free(plain.allocation); free(crypt.allocation);
    return 0;
}

int main(void) {
    phase = "independent AEAD vector";
    for (case_number = 0; case_number < sizeof(aead_fixtures) / sizeof(aead_fixtures[0]); ++case_number)
        if (run_vector(&aead_fixtures[case_number])) return 1;
    phase = "authentication rejection";
    for (enum aead_mode mode = AEAD_CCM; mode <= AEAD_GCM_SIV; mode = (enum aead_mode)(mode + 1)) {
        case_number = (size_t)mode;
        if (mode == AEAD_CCM) {
            for (uint32_t tag_len = 4; tag_len <= 16; tag_len += 2)
                if (tampering(mode, tag_len)) return 1;
        } else if (tampering(mode, 16)) return 1;
    }
    phase = "invalid parameter rejection";
    if (parameter_boundaries()) return 1;
    phase = "CCM maximum message";
    if (ccm_maximum_message()) return 1;
    printf("AEAD tests passed: %zu independent vectors, tag-bit rejection, parameters, and canaries.\n",
           sizeof(aead_fixtures) / sizeof(aead_fixtures[0]));
    return 0;
}
