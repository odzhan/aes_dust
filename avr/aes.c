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
  
#include "aes.h"

// Multiplication over GF(2**8)
#if AES_INT_LEN == 1
  #define M(x)(((x)<<1)^((-((x)>>7))&0x1b))
#else
  u32 M(u32 x) {
      u32 t=x&0x80808080;
      return((x^t)<<1)^((t>>7)*0x1b);
  }
#endif
// the sbox array is used by default for optimal speed
#ifndef DYNAMIC
  u8 sbox[256]=
  {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 
   0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 
   0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 
   0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 
   0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 
   0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 
   0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 
   0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 
   0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 
   0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 
   0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 
   0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 
   0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 
   0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 
   0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 
   0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 
   0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
  #define S(x) sbox[x]
#else
  // SubByte
  u8 S(u8 x) {
      u8 i,y,c;
      if(x) {
        for(c=i=0,y=1;--i;y=(!c&&y==x)?c=1:y,y^=M(y));
        x=y;
        for(i=0;i<4;i++) {
          x^=y=(y<<1)|(y>>7);
        }
      }
      return x^99;
  }
#endif

#if AES_INT_LEN == 1
  // 128-bit version for 8-bit architectures

  void aes_ecb(void *mk, void *data) {
      u8 a,b,c,d,i,j,t,w,x[AES_BLK_LEN],k[AES_KEY_LEN],rc=1,*s=(u8*)data;
      
      // copy 128-bit plain text + 128-bit master key to x
      for(i=0;i<AES_BLK_LEN;i++) {
        x[i]=s[i], k[i]=((u8*)mk)[i];
      }

      for(;;) {
        // AddRoundKey
        for(i=0;i<AES_BLK_LEN;i++) {
          s[i]=x[i]^k[i];
        }
        // if round 11, stop
        if(rc==108)break;
        // AddConstant
        k[0]^=rc; rc=M(rc);
        // ExpandKey
        for(i=0;i<4;i++) {
          k[i]^=S(k[12+((i-3)&3)]);
        }
        for(i=0;i<12;i++) {
          k[i+4]^=k[i];
        }
        // SubBytes and ShiftRows
        for(w=i=0;i<AES_BLK_LEN;i++) {
          ((u8*)x)[w] = S(((u8*)s)[i]), w=(w-3)&15;
        }
        // if not round 11
        if(rc!=108) {
          // MixColumns
          for(i=0;i<AES_BLK_LEN;i+=4) {
            a=x[i],b=x[i+1],c=x[i+2],d=x[i+3];
            for(j=0;j<4;j++) {
              x[i+j]^=a^b^c^d^M(a^b);
              t=a,a=b,b=c,c=d,d=t;
            }
          }
        }
      }
  }
#else
  // 32-bit or 64-bit versions

  #if AES_KEY_LEN == 32

    void aes_ecb(void *mk, void *data) {
        u32 c=1,i,r=0,w,x[4],k[8], *s=(u32*)data;

        // copy 128-bit plain text
        for(i=0;i<4;i++) {
          x[i] = s[i];
        }
        // copy 256-bit master key
        for(i=0;i<8;i++) {
          k[i] = ((u32*)mk)[i];
        }

        for(;;) {
          // 1st part of ExpandKey
          w=k[r?3:7];
          for(i=0;i<4;i++) {
            w=(w&-256) | S(w&255),w=R(w,8);
          } 
          // AddConstant, update constant
          if(!r)w=R(w,8)^c,c=M(c);
          // AddRoundKey, 2nd part of ExpandKey
          for(i=0;i<4;i++) {
            ((u32*)s)[i]=x[i]^k[r*4+i], w=k[r*4+i]^=w;
          }
          // if round 15, stop
          if(c==27) break;
          r=(r+1)&1;
          // SubBytes and ShiftRows
          for(w=i=0;i<AES_BLK_LEN;i++) {
            ((u8*)x)[w] = S(((u8*)s)[i]), w = (w-3)&15;
          }
          // if not round 15, MixColumns    
          if((c!=128) | r) {
            for(i=0;i<4;i++) {
              w=x[i],x[i]=R(w,8)^R(w,16)^R(w,24)^M(R(w,8)^w);
            }
          }
        }
    }
  #else
    void aes_ecb(void *mk, void *data) {
        u32 c=1,i,w,x[4],k[4],*s=(u32*)data;

        // copy 128-bit plain text + 128-bit master key to x
        for(i=0;i<4;i++) {
          x[i]=s[i], k[i]=((u32*)mk)[i];
        }
        for(;;) {
          // 1st part of ExpandKey
          w=k[3];
          for(i=0;i<4;i++) {
            w=(w&-256)|S(w&255), w=R(w,8);
          }
          // AddConstant, AddRoundKey, 2nd part of ExpandKey
          w=R(w, 8)^c;
          for(i=0;i<4;i++) {
            ((u32*)s)[i]=x[i]^k[i], w=k[i]^=w;
          }
          // if round 11, stop
          if(c==108)break; 
          // update constant
          c=M(c);
          // SubBytes and ShiftRows
          for(w=i=0;i<AES_BLK_LEN;i++) {
            ((u8*)x)[w] = S(((u8*)s)[i]), w = (w-3)&15;
          }
          // if not round 11, MixColumns
          if(c!=108) {
            for(i=0;i<4;i++) {
              w=x[i],x[i]=R(w,8)^R(w,16)^R(w,24)^M(R(w,8)^w);
            }
          }
        }
    }
  #endif
#endif

#ifdef CTR
  // encrypt using Counter (CTR) mode
  void aes_ctr(u32 len, void *ctr, void *data, void *mk) {
      u8 i, r, t[AES_BLK_LEN], *p=data, *c=ctr;
      
      while(len) {
        // copy counter+nonce to local buffer
        for(i=0;i<AES_BLK_LEN;i++)t[i] = c[i];
        // encrypt t
        aes_ecb(mk, t);
        // XOR plaintext with ciphertext
        r = len > AES_BLK_LEN ? AES_BLK_LEN : len;
        for(i=0;i<r;i++) p[i] ^= t[i];
        // update length + position
        len -= r; p += r;
        // update counter.
        for(i=AES_BLK_LEN;i!=0;i--)
          if(++c[i-1]) break;
      }
  }
#endif
