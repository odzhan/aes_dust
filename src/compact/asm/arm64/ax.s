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

// AES-128 encryption for little-endian ARMv8-A, using only integer instructions.
// 292 bytes of .text; no lookup table or literal pool. Maximum stack: 32 bytes.
// s points to 32 bytes: plaintext followed by the key. Encrypts the first
// 16 bytes in place, preserving the key and the AAPCS64 callee-saved registers.

    .arch armv8-a
    .text
    .p2align 2
    .global aes_ecb_asm
    .type aes_ecb_asm, %function
aes_ecb_asm:
    // Helpers are local: x16/x17 can hold return addresses without stack spills.
    mov      x16, x30
    ldp      x5, x6, [x0]
    stp      x5, x6, [sp, -32]!
    ldp      x7, x8, [x0, 16]
    stp      x7, x8, [sp, 16]
    mov      w4, 1              // round constant
    mov      w12, 27            // shared field reduction and affine constant

.Lround:
    mov      w2, 16
    ldr      w13, [sp, 28]
    add      x1, sp, 16
.Lkey:
    // SubWord(k[3]) and AddRoundKey share the descending four-word loop.
    // The S-box also rotates w13 by eight bits.
    bl       .Lsbox
    subs     w2, w2, 4
    ldr      w10, [sp, x2]
    ldr      w11, [x1, x2]
    eor      w10, w10, w11
    str      w10, [x0, x2]
    bne      .Lkey

    eor      w13, w4, w13, ror 8
.Lexpand:
    ldr      w10, [x1]
    eor      w13, w13, w10
    str      w13, [x1], 4
    tst      x1, 15             // the aligned key ends after four word stores
    bne      .Lexpand
    cmp      w4, 108
    beq      .Ldone

    mov      w14, w4
    bl       .Lmul
    mov      w4, w10
    mov      x1, x0
.Lshift:
    // SubBytes/ShiftRows: visit destinations w = (w - 3) & 15.
    // w2 is already zero on entry from .Lkey.
    ldrb     w13, [x1], 1
    bl       .Lsbox
    strb     w7, [sp, x2]
    sub      w2, w2, 3
    ands     w2, w2, 15
    bne      .Lshift

    mov      w2, 16
    cmp      w4, 108            // skip MixColumns in the final round
.Lmix:
    // Later iterations use Z from SUBS; all intervening operations preserve it.
    beq      .Lround
    subs     w2, w2, 4
    ldr      w13, [sp, x2]
    eor      w14, w13, w13, ror 8
    bl       .Lmul
    // ROR(w14,16) combines ROR(w13,16) and ROR(w13,24).
    eor      w10, w10, w14, ror 16
    eor      w10, w10, w13, ror 8
    str      w10, [sp, x2]
    b        .Lmix
.Ldone:
    add      sp, sp, 32
    ret      x16

// Packed xtime: w10 = M(w14). Clobbers w8, preserves w14 and condition flags.
.Lmul:
    and      w10, w14, 0x80808080
    lsr      w8, w10, 7
    mul      w8, w8, w12
    eor      w10, w14, w10
    eor      w10, w8, w10, lsl 1
    ret

// Substitute the low byte of w13, then rotate the word right by eight bits.
// The substituted byte is also available in w7[7:0] for ShiftRows.
// Clobbers x17, w3, w7, w8, w10, w14, x30 and flags; w12 must contain 27.
.Lsbox:
    mov      x17, x30
    and      w7, w13, 255
    cbz      w7, .Laffine_end
    mov      w14, 1
    mov      w3, 255
.Linverse:
    cmp      w14, w7
    csinc    w14, w14, wzr, ne   // reset the generator to one on the first match
    csel     w7, wzr, w7, eq    // zero cannot match a nonzero field element again
    bl       .Lmul
    eor      w14, w14, w10
    subs     w3, w3, 1
    bne      .Linverse

    // Form t = y ^ (y<<1) ^ (y<<2) ^ (y<<3) ^ (y<<4), then fold its high bits.
    eor      w7, w14, w14, lsl 1
    eor      w7, w7, w7, lsl 2
    eor      w7, w7, w14, lsl 4
.Laffine_end:
    // Folding 27<<5 (0x360) also injects the affine constant 0x63.
    eor      w7, w7, w12, lsl 5
    eor      w7, w7, w7, lsr 8
    extr     w13, w7, w13, 8
    ret      x17
    .size aes_ecb_asm, .-aes_ecb_asm
