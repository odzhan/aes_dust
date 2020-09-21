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
  
// AES-128 Encryption in ARM32 assembly
// 352 bytes

    .arch armv7-a
    .text

    .global aes_ecb_asm

// *****************************
// Multiplication over GF(2**8)
// *****************************
M:
    ldr      r7, =#0x80808080
    and      r7, r11, r7
    mov      r9, #27
    lsr      r6, r7, #7
    mul      r6, r6, r9
    eor      r7, r11, r7
    eor      r7, r6, r7, lsl #1
    bx       lr

// *****************************
// B SubByte(B x);
// *****************************
S:
    push     {lr}
    ands     r5, r10, #0xFF
    beq      SB2

    mov      r11, #1
    mov      r12, #0
    mov      r3, #0xFF
SB0:
    cmp      r12, #0
    cmpeq    r11, r5
    moveq    r11, #1
    moveq    r12, #1
    bl       M
    eor      r11, r11, r7
    subs     r3, r3, #1
    bne      SB0

    and      r5, r11, #255
    mov      r3, #4
SB1:
    lsr      r7, r11, #7
    orr      r11, r7, r11, lsl #1
    eor      r5, r5, r11
    subs     r3, r3, #1
    bne      SB1
SB2:
    eor      r5, r5, #99
    uxtb     r5, r5
    bic      r10, r10, #255
    orr      r10, r5, r10
    pop      {pc}
    
// *****************************
// void aes_ecb(void *s);
// *****************************
aes_ecb_asm:
    push    {r0-r12,lr}
    sub     sp, sp, #32
    
    // copy plain text + master key to x
    // F(8)x[i]=((W*)s)[i];
    ldm     r0, {r4-r12}
    stm     sp, {r4-r12}
    
    // c = 1
    mov     r4, #1
    
    // AddRoundKey, 1st part of ExpandRoundKey
    // w=k[3];F(4)w=(w&-256)|S(w),w=R(w,8),((W*)s)[i]=x[i]^k[i];
L0:
    mov     r2, #0
    ldr     r10, [sp, #16+3*4]
    add     r1, sp, #16
L1:
    bl      S
    ror     r10, r10, #8
    ldr     r7, [sp, r2, lsl #2]
    ldr     r8, [r1, r2, lsl #2]
    eor     r7, r7, r8
    str     r7, [r0, r2, lsl #2]

    add     r2, r2, #1
    cmp     r2, #4
    bne     L1
    
    // AddRoundConstant, perform 2nd part of ExpandRoundKey
    // w=R(w,8)^c;F(4)w=k[i]^=w;
    eor     r10, r4, r10, ror #8
L2:
    ldr     r7, [r1]
    eor     r10, r10, r7
    str     r10, [r1], #4
    
    subs    r2, r2, #1
    bne     L2
    
    // if round 11, stop; 
    // if(c==108)break; 
    cmp     r4, #108
    beq     L5

    // update c
    // c=M(c);
    mov     r11, r4
    bl      M
    mov     r4, r7
    
    // SubBytes and ShiftRows
    // F(16)((u8*)x)[w]=S(((u8*)s)[i]), w=(w-3)&15;
L3:
    ldrb    r10, [r0, r2]
    bl      S
    and     r7, r2, #3
    lsr     r8, r2, #2
    sub     r8, r8, r7
    and     r8, r8, #3
    add     r7, r7, r8, lsl #2
    uxtb    r7, r7
    strb    r10, [sp, r7]

    add     r2, r2, #1
    cmp     r2, #16
    bne     L3

    // if not round 11, MixColumns
    // if(c!=108)
    cmp     r4, #108
L4:
    beq     L0
    subs    r2, r2, #4

    // F(4)w=x[i],x[i]=R(w,8)^R(w,16)^R(w,24)^M(R(w,8)^w);
    ldr     r10, [sp, r2]
    eor     r11, r10, r10, ror #8
    bl      M
    eor     r11, r7, r10,  ror #8
    eor     r11, r11, r10, ror #16
    eor     r11, r11, r10, ror #24
    str     r11, [sp, r2]

    b       L4
L5:
    add     sp, sp, #32
    pop     {r0-r12,pc}
