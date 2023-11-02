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
  
#include "aes128_ecb.h"

u32 
M(u32 x) {
    u32 t = x & 0x80808080;
    return((x ^ t) << 1) ^ ((t >> 7) * 0x1b);
}

/**
    Initialises AES context.
    This creates the sbox for encryption and inverse for decryption.
    It only needs to be called once.
*/
void
aes128_init_ctx(aes128_ctx* c) {
    u32 x=1, i;
    u8 gf_exp[256];
    
    // Create lookup table for the exponentiation of the Galois Field (GF)
    for (i = 0; i < 256; i++) {
        gf_exp[i] = x;
        x ^= M(x);
    }

    // Generate S-box values for each byte (0-255)
    c->sbox[0] = 99;

    for (i = 0; i < 255; i++) {
        x = gf_exp[255 - i];
        x |= x << 8;
        x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7);
        c->sbox[gf_exp[i]] = (x ^ 99) & 0xFF;
    }
    
    // Compute the inverse S-box.
    for (i=0; i<256; i++) {
        c->sbox_inv[c->sbox[i]] = i;
    }
}

/**
    Creates round keys for AES-128 encryption.
    This should be called after aes128_init_ctx()
*/
void
aes128_set_key(aes128_ctx* c, void* mk) {
    u32 i, w, k[4], *rk=(u32*)c->rkeys;
    
    // Copy master key to local buffer
    for (i = 0; i < 4; i++) {
        k[i] = ((u32*)mk)[i];
    }
    
    // Create 10 round keys
    for (u32 rc = 1; rc != 216; rc = M(rc)) {
        // Copy round key to context
        for (i = 0; i < 4; i++) rk[i] = k[i];
        // First part of ExpandKey
        w = k[3];
        for (i = 0; i < 4; i++) {
            w = (w & -256) | c->sbox[w & 255], w = R(w, 8);
        }
        // AddConstant
        w = R(w, 8) ^ rc;
        // Second part of ExpandKey
        for (i = 0; i < 4; i++) {
            w = k[i] ^= w;
        }
        rk += 4;
    }
}

/**
    Encrypt data inplace using AES-128 in ECB mode.
*/
void 
aes128_ecb_encrypt(aes128_ctx* c, void* data) {
    u32 nr=0, i, w, x[4], *s = (u32*)data, *rk=(u32*)c->rkeys;
    
    // Copy data to local buffer
    for (i = 0; i < 4; i++) {
        x[i] = s[i];
    }

    for (;;) {
        // AddRoundKey
        for (i = 0; i < 4; i++) {
            s[i] = x[i] ^ rk[i];
        }
        // Advance to next round key.
        rk += 4;
        // Last round? Stop
        if (nr++ == 10) break;
        // SubBytes and ShiftRows
        for (w = i = 0; i < 16; i++) {
            ((u8*)x)[w] = c->sbox[((u8*)s)[i]], w = (w - 3) & 15;
        }
        if (nr != 10) {
            // MixColumns
            for (i = 0; i < 4; i++) {
                w = x[i], x[i] = R(w, 8) ^ R(w, 16) ^ R(w, 24) ^ M(R(w, 8) ^ w);
            }
        }
    }
}

/**
    Decrypt data inplace using AES-128 in ECB mode.
*/
void 
aes128_ecb_decrypt(aes128_ctx* c, void* data) {
    u32 nr=10, i, w, x[4], *s = (u32*)data, *rk=(u32*)c->rkeys[10];

    // AddRoundKey
    for (i = 0; i < 4; i++) {
        s[i] ^= rk[i];
    }

    // Loop ten times
    for (;;) {
        // Subtract 16-bytes from round keys buffer.
        rk -= 4;
        // InvShiftRows and InvSubBytes
        for (w = 0, i = 15; (int)i>=0; i--) {
            w = (w + 3) & 15, ((u8*)x)[i] = c->sbox_inv[((u8*)s)[w]];
        }
        // AddRoundKey
        for (i = 0; i < 4; i++) {
            s[i] = x[i] ^ rk[i];
        }
        if (--nr == 0) break;
        // InvMixColumns
        for (i = 0; i < 4; i++) {
            w = s[i], w ^= M(M(R(w, 16) ^ w));
            s[i] = R(w, 8) ^ R(w, 16) ^ R(w, 24) ^ M(R(w, 8) ^ w);
        }
    }
}
