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
  
# AES-128 encryption for little-endian LoongArch64, using integer instructions.
# 348 bytes of .text (previously 432); no lookup table or literal pool.
# Maximum stack: 32 bytes. Input is 32 bytes: plaintext followed by the key.
# Encrypts the first 16 bytes in place, preserving the key and ABI-saved registers.

    .text
    .p2align 2
    .globl aes_ecb_asm
    .type aes_ecb_asm, @function
aes_ecb_asm:
    # Local helpers leave a7/a6 available for return addresses.
    move        $a7, $ra
    addi.d      $sp, $sp, -32
    li.w        $t1, 32
.Lcopy:
    # Copy exactly four doublewords to the local state and key.
    addi.d      $t1, $t1, -8
    ldx.d       $t4, $a0, $t1
    stx.d       $t4, $sp, $t1
    bnez        $t1, .Lcopy
    li.w        $t3, 1             # round constant
    li.w        $a3, 108           # final round constant
    li.w        $t5, 0x80808080    # shared packed field mask

.Lround:
    li.w        $t1, 16
    ld.w        $a4, $sp, 28
    addi.d      $t0, $sp, 16
.Lkey:
    # SubWord(k[3]) and AddRoundKey share the descending four-word loop.
    # The S-box also rotates a4 right by eight bits.
    bl          .Lsbox
    addi.d      $t1, $t1, -4
    ldx.w       $a1, $sp, $t1
    ldx.w       $a2, $t0, $t1
    xor         $a1, $a1, $a2
    stx.w       $a1, $a0, $t1
    bnez        $t1, .Lkey

    rotri.w     $a5, $a4, 8
    xor         $a4, $t3, $a5
.Lexpand:
    ld.w        $a1, $t0, 0
    xor         $a4, $a4, $a1
    st.w        $a4, $t0, 0
    addi.d      $t0, $t0, 4
    andi        $a1, $t0, 15       # aligned key ends after four word stores
    bnez        $a1, .Lexpand
    beq         $t3, $a3, .Ldone

    move        $a5, $t3
    bl          .Lmul
    move        $t3, $a1
    move        $t0, $zero
.Lshift:
    # t1 is already zero; destination w = (w - 3) & 15 visits all 16 bytes.
    ldx.bu      $a4, $a0, $t1
    bl          .Lsbox
    stx.b       $t6, $sp, $t0
    addi.d      $t0, $t0, -3
    andi        $t0, $t0, 15
    addi.d      $t1, $t1, 1
    bnez        $t0, .Lshift

    beq         $t3, $a3, .Lround  # skip MixColumns in the final round
.Lmix:
    # t1 is now 16. Walk the four columns backwards.
    addi.d      $t1, $t1, -4
    ldx.w       $a4, $sp, $t1
    rotri.w     $a5, $a4, 8
    xor         $a5, $a5, $a4
    bl          .Lmul
    # ROR(a5,16) combines ROR(a4,16) and ROR(a4,24).
    rotri.w     $a2, $a5, 16
    xor         $a1, $a1, $a2
    rotri.w     $a2, $a4, 8
    xor         $a1, $a1, $a2
    stx.w       $a1, $sp, $t1
    bnez        $t1, .Lmix
    b           .Lround
.Ldone:
    addi.d      $sp, $sp, 32
    jr          $a7

# Packed xtime: a1 = M(a5), using t5's mask. Clobbers a2/t7, preserves a5.
.Lmul:
    and         $a1, $a5, $t5
    srli.w      $t7, $a1, 7
    alsl.w      $t7, $t7, $t7, 3  # 9 times the per-byte carry bits
    alsl.w      $t7, $t7, $t7, 1  # 27 times; no carry between byte lanes
    xor         $a1, $a5, $a1
    slli.w      $a2, $a1, 1
    xor         $a1, $t7, $a2
    jr          $ra

# Substitute a4's low byte, then rotate the word right by eight bits.
# The substituted byte is also available in t6[7:0] for ShiftRows.
# Clobbers a1/a2/a5/a6/t2/t6/t7/ra; preserves a3/t5/a7.
.Lsbox:
    move        $a6, $ra
    andi        $t6, $a4, 255
    beqz        $t6, .Laffine_end
    li.w        $a5, 1
    li.w        $t2, 255
.Linverse:
    bne         $a5, $t6, .Lnext
    li.w        $a5, 1
    move        $t6, $zero         # zero cannot match a nonzero field element
.Lnext:
    bl          .Lmul
    xor         $a5, $a5, $a1
    addi.d      $t2, $t2, -1
    bnez        $t2, .Linverse

    # Form y ^ (y<<1) ^ (y<<2) ^ (y<<3) ^ (y<<4), then fold its high bits.
    slli.w      $a1, $a5, 1
    xor         $t6, $a5, $a1
    slli.w      $a1, $t6, 2
    xor         $t6, $t6, $a1
    slli.w      $a1, $a5, 4
    xor         $t6, $t6, $a1
    srli.w      $a1, $t6, 8
    xor         $t6, $t6, $a1
.Laffine_end:
    xori        $t6, $t6, 99
    bytepick.w  $a4, $a4, $t6, 3  # insert S-byte and rotate in one instruction
    jr          $a6
    .size aes_ecb_asm, .-aes_ecb_asm
