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
  
// AES-128 encryption for little-endian ARMv7-A, using Thumb-2.
// 206 bytes of .text; no lookup table or literal pool.
// s points to a word-aligned 32-byte block: plaintext followed by the key.
// Encrypts the first 16 bytes in place, preserving the key and r0-r12.
// Maximum stack usage: 104 bytes, including saved registers and helper calls.

    .syntax unified
    .arch armv7-a
    .thumb
    .text
    .p2align 1
    .global aes_ecb_asm
    .type aes_ecb_asm, %function
    .thumb_func
aes_ecb_asm:
    push    {r0-r12,lr}
    // Loading the base register suppresses LDM writeback. Copy exactly 32 bytes.
    ldm     r0, {r0-r7}
    push    {r0-r7}
    ldr     r0, [sp, #32]       // recover the saved input pointer
    mov     r5, sp              // local state; local key starts at r5 + 16
    movs    r4, #1              // round constant
    movs    r3, #27
    mov     r12, r3             // shared GF(2^8) reduction constant

.Lround:
    movs    r2, #0
    ldr     r3, [sp, #28]
    add     r1, sp, #16
.Lkey:
    // SubWord(k[3]) and AddRoundKey share the four-word loop.
    bl      .Lsbox
    ror     r3, r3, #8
    ldr     r6, [r5, r2]
    ldr     r7, [r1, r2]
    eors    r6, r7
    str     r6, [r0, r2]
    adds    r2, #4
    cmp     r2, #16
    bne     .Lkey

    eor     r3, r4, r3, ror #8
.Lexpand:
    ldr     r7, [r1]
    eors    r3, r7
    stm     r1!, {r3}
    subs    r2, #4
    bne     .Lexpand
    cmp     r4, #108
    beq     .Ldone

    mov     r6, r4
    bl      .Lmul
    mov     r4, r7
    mov     r2, r0
    movs    r1, #0
.Lshift:
    // SubBytes/ShiftRows: visit destinations w = (w - 3) & 15.
    ldrb    r3, [r2], #1
    bl      .Lsbox
    strb    r3, [r5, r1]
    subs    r1, #3
    ands    r1, r1, #15
    bne     .Lshift

    movs    r2, #16
    cmp     r4, #108            // skip MixColumns in the final round
.Lmix:
    // Later iterations use Z from SUBS below; all intervening ops preserve it.
    beq     .Lround
    subs    r2, #4
    ldr     r3, [r5, r2]
    eor     r6, r3, r3, ror #8
    bl      .Lmul
    // ROR(r6,16) combines ROR(w,16) and ROR(w,24).
    eor     r7, r7, r6, ror #16
    eor     r7, r7, r3, ror #8
    str     r7, [r5, r2]
    b       .Lmix
.Ldone:
    add     sp, sp, #32
    pop     {r0-r12,pc}

// Packed xtime: r7 = M(r6). Clobbers r1, preserves r6 and condition flags.
.Lmul:
    and     r7, r6, #0x80808080
    eor     r1, r6, r7
    lsr.w   r7, r7, #7          // must not set flags: see .Lmix
    mul     r7, r7, r12
    eor     r7, r7, r1, lsl #1
    bx      lr

// Substitute only the low byte of r3; r6/r7 and flags are scratch.
.Lsbox:
    push    {r1,r2,r5,lr}       // keep helper calls eight-byte stack aligned
    uxtb    r5, r3
    cbz     r5, .Laffine_end
    movs    r6, #1
    movs    r2, #255
.Linverse:
    cmp     r6, r5
    itt     eq
    moveq   r6, #1
    moveq   r5, #0              // a nonzero field element cannot match again
    bl      .Lmul
    eors    r6, r7
    subs    r2, #1
    bne     .Linverse
    uxtb    r5, r6
    movs    r2, #4
.Laffine:
    lsrs    r7, r6, #7
    orr     r6, r7, r6, lsl #1
    eors    r5, r6
    subs    r2, #1
    bne     .Laffine
.Laffine_end:
    movs    r7, #99
    eors    r5, r7
    bfi     r3, r5, #0, #8
    pop     {r1,r2,r5,pc}
    .size aes_ecb_asm, .-aes_ecb_asm
