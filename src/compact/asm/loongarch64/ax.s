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
  
# AES-128 Encryption in LoongArch64 assembly
# 352 bytes

    .text
	
    .globl  aes_ecb_asm

aes_ecb_asm:
    # Prologue: save return address and allocate 32-byte local buffer 'x'
    addi.d      $sp, $sp, -16
    st.d        $ra, $sp, 0
    addi.d      $sp, $sp, -32

    # Copy plaintext + master key from *s (a0) into local x[8] on stack
    ld.d        $t4, $a0, 0        # x[0..1]
    ld.d        $t5, $a0, 8        # x[2..3]
    ld.d        $t6, $a0, 16       # x[4..5]
    ld.d        $t7, $a0, 24       # x[6..7]

    st.d        $t4, $sp, 0
    st.d        $t5, $sp, 8
    st.d        $t6, $sp, 16
    st.d        $t7, $sp, 24

    # c = 1  (round constant)
    li.w        $t3, 1             # w4

L0:
    # AddRoundKey, 1st part of ExpandRoundKey
    # w = k[3]; for i in 0..3:
    #   w = (w & ~0xFF) | S(w);
    #   w = ROR(w, 8);
    #   ((W*)s)[i] = x[i] ^ k[i];

    move        $t1, $zero         # x2 = 0
    ld.w        $a4, $sp, 28       # w13 = x[7] = k[3]
    addi.d      $t0, $sp, 16       # x1 = &x[4] (k)

L1:
    bl          S                  # S() operates on low 8 bits of w13 (a4)
    rotri.w     $a4, $a4, 8        # w13 = ROR(w13, 8)

    # w10 = x[i]
    slli.d      $t4, $t1, 2
    ldx.w       $a1, $sp, $t4      # w10 = x[i]

    # w11 = k[i]
    ldx.w       $a2, $t0, $t4      # w11 = k[i]

    xor         $a1, $a1, $a2      # w10 ^= w11

    # ((W*)s)[i] = x[i] ^ k[i]
    stx.w       $a1, $a0, $t4

    addi.d      $t1, $t1, 1
    addi.d      $t2, $t1, -4
    bne         $t2, $zero, L1

    # AddRoundConstant, 2nd part of ExpandRoundKey
    # w = ROR(w, 8) ^ c; for i in 0..3: w = k[i] ^= w;
    rotri.w     $a5, $a4, 8        # temp = ROR(w13, 8)
    xor         $a4, $t3, $a5      # w13 = temp ^ c

L2:
    ld.w        $a1, $t0, 0        # w10 = *k
    xor         $a4, $a4, $a1      # w13 ^= w10
    st.w        $a4, $t0, 0        # *k = w13
    addi.d      $t0, $t0, 4        # ++k

    addi.d      $t1, $t1, -1       # --x2
    bne         $t1, $zero, L2

    # If round 11, stop: if (c == 108) break;
    li.w        $a1, 108
    beq         $t3, $a1, L5

    # Update round constant: c = M(c);
    move        $a5, $t3           # w14 = w4 = c
    bl          M                  # M(c) -> w10 (a1)
    move        $t3, $a1           # w4 = w10

    # -------- SubBytes + ShiftRows --------
    # F(16) ((u8*)x)[w] = S(((u8*)s)[i]), w = (w-3) & 15;
    move        $t1, $zero         # i = 0
    move        $t8, $zero         # w = 0 (byte index into x)

L3:
    ldx.bu      $a4, $a0, $t1      # w13 = ((u8*)s)[i]
    bl          S                  # w13 = S(w13)

    stx.b       $a4, $sp, $t8      # ((u8*)x)[w] = S(...)
    addi.d      $t8, $t8, -3       # w = (w - 3) & 15
    andi        $t8, $t8, 15

    addi.d      $t1, $t1, 1        # ++i
    addi.d      $t2, $t1, -16
    bne         $t2, $zero, L3

    # If (c != 108) do MixColumns
    li.w        $a1, 108
    beq         $t3, $a1, L0       # if c == 108 skip MixColumns and start next loop

    # MixColumns: for i = 0..3
    #   w = x[i];
    #   x[i] = R(w,8)^R(w,16)^R(w,24)^M(R(w,8)^w);
    # At this point, t1 == 16 (byte offset past last state word).
    # We walk backwards over x[3],x[2],x[1],x[0] using byte offsets 12,8,4,0.
L4:
    addi.d      $t1, $t1, -4       # x2 -= 4  (byte offset)

    ldx.w       $a4, $sp, $t1      # w13 = x[i]
    rotri.w     $a5, $a4, 8
    xor         $a5, $a5, $a4      # w14 = w13 ^ ROR(w13,8)

    bl          M                  # M(w14) -> w10 (a1)

    rotri.w     $a2, $a4, 8
    xor         $a5, $a1, $a2      # w14 = M(R(w,8)^w) ^ R(w,8)
    rotri.w     $a2, $a4, 16
    xor         $a5, $a5, $a2      # ^ R(w,16)
    rotri.w     $a2, $a4, 24
    xor         $a5, $a5, $a2      # ^ R(w,24)

    stx.w       $a5, $sp, $t1      # x[i] = new column

    bne         $t1, $zero, L4     # while (x2 != 0)

    b           L0

L5:
    # Epilogue: free local buffer and restore return address
    addi.d      $sp, $sp, 32
    ld.d        $ra, $sp, 0
    addi.d      $sp, $sp, 16
    jr          $ra

    # *****************************
    # Multiplication over GF(2**8)
    # *****************************
    # Input : w14 in $a5 (low 32 bits)
    # Output: w10 in $a1 (low 32 bits)
M:
    # t = w14 & 0x80808080
    li.w        $a3, 0x80808080    # w12 = mask
    and         $a1, $a5, $a3      # w10 = w14 & mask

    # w12 = 27
    li.w        $a3, 27

    # w8 = (t >> 7) * 27
    srli.w      $t7, $a1, 7        # w8 = w10 >> 7
    mul.w       $t7, $t7, $a3      # w8 *= 27

    # w10 = (w14 ^ t)
    xor         $a1, $a5, $a1

    # w10 = w8 ^ ((w14 ^ t) << 1)
    slli.w      $a2, $a1, 1
    xor         $a1, $t7, $a2
    jr          $ra

    # *****************************
    # B SubByte(B x);
    # *****************************
    # Input : w13 in $a4 (low 8 bits)
    # Output: w13 in $a4 (low 8 bits substituted)
S:
    # Save return address
    addi.d      $sp, $sp, -16
    st.d        $ra, $sp, 0

    # w7 = w13 & 0xFF
    andi        $t6, $a4, 0xFF
    beq         $t6, $zero, SB2

    li.w        $a5, 1             # w14 = 1
    li.w        $a6, 1             # w15 = 1
    li.d        $t2, 0xFF          # x3  = 0xFF

SB0:
    # if (w15 == 1 && w14 == w7) { w14 = w15; w15 = 0; }
    li.w        $a1, 1
    bne         $a6, $a1, 1f
    bne         $a5, $t6, 1f
    move        $a5, $a6           # w14 = w15 (==1)
    li.w        $a6, 0             # w15 = 0
1:
    bl          M                  # M(w14) -> w10 (a1)
    xor         $a5, $a5, $a1      # w14 ^= w10
    addi.d      $t2, $t2, -1
    bne         $t2, $zero, SB0

    andi        $t6, $a5, 0xFF     # w7 = w14 & 0xFF
    li.d        $t2, 4             # x3 = 4

SB1:
    srli.w      $a1, $a5, 7        # w10 = w14 >> 7
    slli.w      $a2, $a5, 1
    or          $a5, $a1, $a2      # w14 = (w14<<1) | (w14>>7)
    xor         $t6, $t6, $a5      # w7 ^= w14
	
    addi.d      $t2, $t2, -1
    bne         $t2, $zero, SB1

SB2:
    li.w        $a1, 99            # w10 = 99
    xor         $t6, $t6, $a1      # w7 ^= 99

    # Insert low 8 bits of w7 into w13
    bstrins.w   $a4, $t6, 7, 0     # w13[7:0] = w7[7:0]

    ld.d        $ra, $sp, 0        # Restore return address and return
    addi.d      $sp, $sp, 16
    jr          $ra
