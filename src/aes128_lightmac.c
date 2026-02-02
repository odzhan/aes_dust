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

#include <aes128_lightmac.h>

static void lightmac_encode_counter(uint64_t counter, uint8_t *output, uint8_t s_bytes) {
    for (int i = (int)s_bytes - 1; i >= 0; --i) {
        output[i] = (uint8_t)counter;
        counter >>= 8;
    }
}

static void lightmac_xor_block(uint8_t *dst, const uint8_t *src) {
    for (uint8_t i = 0; i < AES_BLK_LEN; ++i) {
        dst[i] ^= src[i];
    }
}

static int lightmac_use_k1(aes128_lightmac_ctx *ctx) {
    if (ctx->key_state != 1) {
        aes128_set_key(&ctx->aes, ctx->k1);
        ctx->key_state = 1;
    }
    return AES128_LIGHTMAC_OK;
}

static int lightmac_use_k2(aes128_lightmac_ctx *ctx) {
    if (ctx->key_state != 2) {
        aes128_set_key(&ctx->aes, ctx->k2);
        ctx->key_state = 2;
    }
    return AES128_LIGHTMAC_OK;
}

static int lightmac_process_buf(aes128_lightmac_ctx *ctx) {
    if (ctx->s_bits < 64) {
        uint64_t limit = (1ULL << ctx->s_bits) - 1;
        if (ctx->block_index > limit) {
            ctx->status = AES128_LIGHTMAC_TOO_LONG;
            return ctx->status;
        }
    }

    uint8_t block[AES_BLK_LEN];
    lightmac_encode_counter(ctx->block_index, block, ctx->s_bytes);
    memcpy(block + ctx->s_bytes, ctx->buf, ctx->r_bytes);
    aes128_ecb_encrypt(&ctx->aes, block);
    lightmac_xor_block(ctx->v, block);
    ctx->block_index++;
    return AES128_LIGHTMAC_OK;
}

int aes128_lightmac_init(aes128_lightmac_ctx *ctx, const uint8_t *k1, const uint8_t *k2,
                         uint8_t s_bits, uint8_t t_bits) {
    if (ctx == NULL || k1 == NULL || k2 == NULL) {
        return AES128_LIGHTMAC_BAD_PARAM;
    }
    if ((s_bits == 0) || (s_bits > 64) || (s_bits & 7)) {
        return AES128_LIGHTMAC_BAD_PARAM;
    }
    if ((t_bits == 0) || (t_bits > 128) || (t_bits & 7)) {
        return AES128_LIGHTMAC_BAD_PARAM;
    }

    ctx->s_bits = s_bits;
    ctx->t_bits = t_bits;
    ctx->s_bytes = (uint8_t)(s_bits >> 3);
    ctx->t_bytes = (uint8_t)(t_bits >> 3);
    ctx->r_bytes = (uint8_t)(AES_BLK_LEN - ctx->s_bytes);

    memcpy(ctx->k1, k1, AES_KEY_LEN);
    memcpy(ctx->k2, k2, AES_KEY_LEN);

    aes128_init_ctx(&ctx->aes);
    ctx->status = AES128_LIGHTMAC_OK;
    aes128_lightmac_reset(ctx);
    return AES128_LIGHTMAC_OK;
}

void aes128_lightmac_reset(aes128_lightmac_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }

    memset(ctx->v, 0, AES_BLK_LEN);
    ctx->buf_len = 0;
    ctx->block_index = 1;
    ctx->status = AES128_LIGHTMAC_OK;
    aes128_set_key(&ctx->aes, ctx->k1);
    ctx->key_state = 1;
}

int aes128_lightmac_update(aes128_lightmac_ctx *ctx, const uint8_t *data, uint32_t len) {
    if (ctx == NULL || (data == NULL && len != 0)) {
        return AES128_LIGHTMAC_BAD_PARAM;
    }
    if (ctx->status != AES128_LIGHTMAC_OK) {
        return ctx->status;
    }
    if (len == 0) {
        return AES128_LIGHTMAC_OK;
    }

    lightmac_use_k1(ctx);

    if (ctx->buf_len == ctx->r_bytes) {
        if (lightmac_process_buf(ctx) != AES128_LIGHTMAC_OK) {
            return ctx->status;
        }
        ctx->buf_len = 0;
    }

    const uint8_t *p = data;
    while (len > 0) {
        uint32_t take = (uint32_t)(ctx->r_bytes - ctx->buf_len);
        if (take > len) {
            take = len;
        }
        memcpy(ctx->buf + ctx->buf_len, p, take);
        ctx->buf_len = (uint8_t)(ctx->buf_len + take);
        p += take;
        len -= take;

        if (ctx->buf_len == ctx->r_bytes && len > 0) {
            if (lightmac_process_buf(ctx) != AES128_LIGHTMAC_OK) {
                return ctx->status;
            }
            ctx->buf_len = 0;
        }
    }

    return AES128_LIGHTMAC_OK;
}

int aes128_lightmac_final(aes128_lightmac_ctx *ctx, uint8_t *tag) {
    if (ctx == NULL || tag == NULL) {
        return AES128_LIGHTMAC_BAD_PARAM;
    }
    if (ctx->status != AES128_LIGHTMAC_OK) {
        return ctx->status;
    }

    uint8_t last[AES_BLK_LEN];
    memset(last, 0, sizeof last);
    if (ctx->buf_len > 0) {
        memcpy(last, ctx->buf, ctx->buf_len);
    }
    last[ctx->buf_len] = 0x80;

    lightmac_xor_block(ctx->v, last);

    lightmac_use_k2(ctx);
    uint8_t out[AES_BLK_LEN];
    memcpy(out, ctx->v, AES_BLK_LEN);
    aes128_ecb_encrypt(&ctx->aes, out);

    memcpy(tag, out, ctx->t_bytes);
    return AES128_LIGHTMAC_OK;
}

int aes128_lightmac(uint8_t *tag, const uint8_t *k1, const uint8_t *k2,
                    uint8_t s_bits, uint8_t t_bits,
                    const uint8_t *msg, uint32_t msg_len) {
    aes128_lightmac_ctx ctx;
    int rc = aes128_lightmac_init(&ctx, k1, k2, s_bits, t_bits);
    if (rc != AES128_LIGHTMAC_OK) {
        return rc;
    }
    rc = aes128_lightmac_update(&ctx, msg, msg_len);
    if (rc != AES128_LIGHTMAC_OK) {
        return rc;
    }
    return aes128_lightmac_final(&ctx, tag);
}

int aes128_lightmac_verify(const uint8_t *tag, const uint8_t *k1, const uint8_t *k2,
                           uint8_t s_bits, uint8_t t_bits,
                           const uint8_t *msg, uint32_t msg_len) {
    if (tag == NULL) {
        return AES128_LIGHTMAC_BAD_PARAM;
    }

    uint8_t calc[AES_BLK_LEN];
    int rc = aes128_lightmac(calc, k1, k2, s_bits, t_bits, msg, msg_len);
    if (rc != AES128_LIGHTMAC_OK) {
        return rc;
    }

    uint8_t t_bytes = (uint8_t)(t_bits >> 3);
    uint8_t diff = 0;
    for (uint8_t i = 0; i < t_bytes; ++i) {
        diff |= (uint8_t)(calc[i] ^ tag[i]);
    }

    return diff == 0 ? 1 : 0;
}
