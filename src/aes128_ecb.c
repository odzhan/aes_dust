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
  
  For more information, please refer to <http://unlicense.org/>
 */

#include <aes128_ecb.h>

static inline uint32_t rotr32(uint32_t v, uint32_t n) {
    return (v >> n) | (v << (32 - n));
}

/* Multiply each byte of x by 2 in GF(2^8) across the four bytes */
static inline uint32_t M(uint32_t x) {
    uint32_t t = x & 0x80808080;
    return ((x ^ t) << 1) ^ ((t >> 7) * 0x1b);
}

/**
 * Initializes the AES context.
 * This function builds the S-box (c->sbox) for encryption and its inverse (c->sbox_inv)
 * for decryption. It only needs to be called once per context.
 */
void aes128_init_ctx(aes128_ctx* c) {
    uint32_t x = 1, i;
    uint8_t gf_exp[256];

    /* Build the GF(2^8) exponentiation lookup table */
    for (i = 0; i < 256; i++) {
        gf_exp[i] = (uint8_t)x;
        x ^= M(x);
    }

    /* Generate the S-box */
    c->sbox[0] = 99;
    
    for (i = 0; i < 255; i++) {
        x = gf_exp[255 - i];
        x |= x << 8;
        x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7);
        c->sbox[gf_exp[i]] = (uint8_t)((x ^ 99) & 0xFF);
    }
    
    /* Compute the inverse S-box */
    for (i = 0; i < 256; i++) {
        c->sbox_inv[c->sbox[i]] = (uint8_t)i;
    }
}

void aes128_set_iv(aes128_ctx* c, void* iv) {
    memcpy(c->iv, iv, AES_IV_LEN);
}


/**
 * Creates round keys for AES-128 encryption.
 * This should be called after aes128_init_ctx() and before any encryption.
 */
void aes128_set_key(aes128_ctx* c, void* key) {
    uint32_t i, w;
    aes_key_t k;
    aes_key_t *rk = (aes_key_t*)c->rkeys;
    aes_key_t *mk = (aes_key_t*)key;
    
    /* Copy master key (16 bytes = 4 words) into local buffer */
    for (i = 0; i < 4; i++) {
        k.w[i] = mk->w[i];
    }
    
    /* Generate the round keys.
       The loop continues until the round constant (rc) equals 216.
       This should produce the 11 round keys (44 words) required for AES-128.
    */
    for (uint32_t rc = 1; rc != 216; rc = M(rc)) {
        /* Save the current key words as the next round key */
        for (i = 0; i < 4; i++) {
            rk->w[i] = k.w[i];
        }
        /* Expand the key:
           - Rotate the last word and substitute its bytes using the S-box.
           - Rotate the result and XOR with the round constant.
           - XOR the result into each of the key words.
         */
        w = k.w[3];
        
        for (i = 0; i < 4; i++) {
            w = (w & -256) | c->sbox[w & 255];
            w = rotr32(w, 8);
        }
        w = rotr32(w, 8) ^ rc;
        
        for (i = 0; i < 4; i++) {
            w = k.w[i] ^= w;
        }
        rk++;
    }
}

/**
 * Encrypts a single 16-byte block in-place using AES-128 in ECB mode.
 */
void aes128_ecb_encrypt(aes128_ctx* c, void* data) {
    uint32_t nr = 0, i, w;
    aes_blk_t x;
    aes_blk_t *s = (aes_blk_t*)data;
    aes_key_t *rk = (aes_key_t*)c->rkeys;
    
    /* Copy input block into local state */
    for (i = 0; i < 4; i++) {
        x.w[i] = s->w[i];
    }

    /* Perform the rounds */
    for (;;) {
        // AddRoundKey
        for (i = 0; i < 4; i++) {
            s->w[i] = x.w[i] ^ rk->w[i];
        }
        
        rk++;
        
        if (nr++ == 10)
            break;

        // SubBytes and ShiftRows
        for (w = i = 0; i < 16; i++) {
            x.b[w] = c->sbox[s->b[i]];
            w = (w - 3) & 15;
        }
        
        if (nr != 10) {
            // MixColumns
            for (i = 0; i < 4; i++) {
                w = x.w[i];
                x.w[i] = rotr32(w, 8) ^ rotr32(w, 16) ^ rotr32(w, 24) ^ M(rotr32(w, 8) ^ w);
            }
        }
    }
}

/**
 * Decrypts a single 16-byte block in-place using AES-128 in ECB mode.
 */
void aes128_ecb_decrypt(aes128_ctx* c, void* data) {
    uint32_t nr = 10, i, w;
    
    aes_blk_t x;
    aes_blk_t *s = (aes_blk_t*)data;
    aes_key_t *rk = (aes_key_t*)&c->rkeys[10];

    // AddRoundKey
    for (i = 0; i < 4; i++) {
        s->w[i] ^= rk->w[i];
    }

    for (;;) {
        rk--;
        
        // InvSubBytes and InvShiftRows
        for (w = 0, i = 15; (int)i >= 0; i--) {
            w = (w + 3) & 15;
            x.b[i] = c->sbox_inv[s->b[w]];
        }
        
        // AddRoundKey
        for (i = 0; i < 4; i++) {
            s->w[i] = x.w[i] ^ rk->w[i];
        }
        
        if (--nr == 0)
            break;
        
        // InvMixColumns
        for (i = 0; i < 4; i++) {
            w = s->w[i];
            w ^= M(M(rotr32(w, 16) ^ w));
            s->w[i] = rotr32(w, 8) ^ rotr32(w, 16) ^ rotr32(w, 24) ^ M(rotr32(w, 8) ^ w);
        }
    }
}
