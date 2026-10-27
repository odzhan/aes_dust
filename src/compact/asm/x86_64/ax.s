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

# AES-128 encryption for x86-64, using baseline integer instructions.
# Default ECB: 210 bytes, table-free and slower. STATIC=1 selects the faster table.
# DYNAMIC=1 is still accepted and takes precedence if both flags are defined.
# WIN=1 selects Microsoft x64 arguments; otherwise use System V AMD64.
# CTR=1 exports aes_ctr/aes_ctr_encrypt and their underscore-prefixed aliases.
# ECB input is 32 bytes: plaintext then key. The key and all GPRs are preserved.
# Peak ECB stack, excluding the caller's return address: 152 bytes, or 128 STATIC.
# The direction flag must be clear, as required by both calling conventions.

    .ifndef STATIC
      .ifndef DYNAMIC
        .equ DYNAMIC, 1
      .endif
    .endif
    .arch generic64
    .intel_syntax noprefix
    .text
    .global aes_ecb_asm
    .global _aes_ecb_asm
aes_ecb_asm:
_aes_ecb_asm:
    push   rax
    push   rbx
    push   rcx
    push   rdx
    push   rsi
    push   rdi
    push   rbp
.ifdef WIN
    push   rcx
.else
    push   rdi
.endif
    pop    rsi
    push   1
    pop    rax
    cdq                       # EAX = round constant 1, EDX = ShiftRows index 0
    push   4
    pop    rcx
.Lcopy:
    # Descending pushes both allocate and copy the 32-byte state/key buffer.
    push   qword ptr [rsi+rcx*8-8]
    loop   .Lcopy
    mov    cl, 4
    push   rsp
    pop    rdi

    # Save the helper's position-independent address for two-byte CALL RBP.
    call   .Lafter_mul
.Lmul:
    # Packed xtime: multiply all four bytes of EAX by two; preserve RCX.
    push   rcx
    mov    cl, 4
.Lmul_byte:
    add    al, al
    jnc    .Lmul_rotate
    xor    al, 27
.Lmul_rotate:
    ror    eax, 8
    loop   .Lmul_byte
    pop    rcx
    ret
.Lafter_mul:
    pop    rbp

.Lround:
    # RCX stays four between rounds; helpers and MixColumns preserve it.
    push   rcx
    push   rsi
    push   rdi
    xchg   eax, edx            # keep the round constant in EDX
    xchg   rsi, rdi
    mov    eax, [rsi+28]
    ror    eax, 8
.Lkey:
    mov    ebx, [rsi+16]
    xor    [rsi], ebx
    movsd
    call   .Lsbox
.ifndef DYNAMIC
    ror    eax, 8              # the table-free helper already rotates
.endif
    loop   .Lkey
    xor    eax, edx
    mov    cl, 4
.Lexpand:
    xor    [rsi], eax
    lodsd
    loop   .Lexpand
    pop    rdi
    pop    rsi
    pop    rcx
    xchg   eax, edx            # restore the small, positive round constant
    cdq                       # discard the expanded key word; reset ShiftRows
    cmp    al, 108
    jne    .Lupdate
    add    rsp, 32
    pop    rbp
    pop    rdi
    pop    rsi
    pop    rdx
    pop    rcx
    pop    rbx
    pop    rax
    ret

.Lupdate:
    call   rbp
    push   rax
    push   rsi
.Lshift:
    lodsb
    call   .Lsbox
.ifdef DYNAMIC
    mov    [rdi+rdx], bl       # helper also returns the substituted byte in BL
.else
    mov    [rdi+rdx], al
.endif
    sub    edx, 3
    and    edx, 15
    jnz    .Lshift
    pop    rsi
    pop    rax
    cmp    al, 108
    je     .Lround

    push   rax
    push   rcx
    push   rdi
.Lmix:
    mov    eax, [rdi]
    mov    edx, eax
    ror    edx, 8
    xor    eax, edx
    mov    ebx, eax            # d = w ^ ROR(w,8), preserved by xtime
    call   rbp
    ror    ebx, 16             # ROR(d,16) = ROR(w,16) ^ ROR(w,24)
    xor    eax, ebx
    xor    eax, edx
    stosd
    loop   .Lmix
    pop    rdi
    pop    rcx
    pop    rax
    jmp    .Lround

# Both S-box variants may clobber RBX, which is saved by the public entry point.
.Lsbox:
.ifndef DYNAMIC
    call   .Ltable_end
    .byte 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5
    .byte 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    .byte 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0
    .byte 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
    .byte 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc
    .byte 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15
    .byte 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a
    .byte 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
    .byte 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0
    .byte 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
    .byte 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b
    .byte 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf
    .byte 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85
    .byte 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8
    .byte 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5
    .byte 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
    .byte 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17
    .byte 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73
    .byte 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88
    .byte 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
    .byte 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c
    .byte 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79
    .byte 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9
    .byte 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08
    .byte 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6
    .byte 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a
    .byte 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e
    .byte 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e
    .byte 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94
    .byte 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
    .byte 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68
    .byte 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
.Ltable_end:
    pop    rbx
    xlatb
.else
    # Keep the original word in EBX and compute its substituted byte in AL.
    push   rcx
    push   rdx
    xchg   eax, ebx
    test   bl, bl
    setnz  al                  # nonzero input starts the field generator at one
    jz     .Laffine_end
    mov    cl, -1
.Linverse:
    cmp    al, bl
    jne    .Linverse_next
    mov    al, 1
    xor    bl, bl              # zero cannot match a nonzero field element again
.Linverse_next:
    mov    dh, al
    call   rbp
    xor    al, dh
    loop   .Linverse
    mov    dl, al
    mov    cl, 4
.Laffine:
    rol    dl, 1
    xor    al, dl
    loop   .Laffine
.Laffine_end:
    xor    al, 99
    # Fuse low-byte insertion and ROR8; BL retains the substituted byte.
    shrd   ebx, eax, 8
    xchg   eax, ebx
    pop    rdx
    pop    rcx
.endif
    ret

.ifdef CTR
    .global aes_ctr
    .global _aes_ctr
    .global aes_ctr_encrypt
    .global _aes_ctr_encrypt

# void aes_ctr(uint32_t len, void *ctr, void *data, const void *key);
# The 16-byte counter is incremented in big-endian order after each block.
aes_ctr_encrypt:
_aes_ctr_encrypt:
aes_ctr:
_aes_ctr:
    push   rbx
    push   rbp
    push   rsi
    push   rdi
.ifdef WIN
    push   rdx
    pop    rbp
    push   r9
    pop    rsi
    mov    rdx, r8
    sub    rsp, 72          # 32-byte shadow space, 32-byte buffer, alignment
    lea    rdi, [rsp+48]
.else
    push   rsi
    pop    rbp
    push   rcx
    pop    rsi
    mov    ecx, edi         # normalize the 32-bit length
    sub    rsp, 40          # 32-byte buffer and call alignment
    lea    rdi, [rsp+16]
.endif
    movsq
    movsq
.Lctr_loop:
    jecxz  .Lctr_done
.ifdef WIN
    lea    rdi, [rsp+32]
.else
    push   rsp
    pop    rdi
.endif
    push   rbp
    pop    rsi
    push   rdi
    movsq
    movsq
    pop    rdi
.ifdef WIN
    # ECB preserves RAX/RCX: retain the length while passing its pointer in RCX.
    xchg   eax, ecx
    push   rdi
    pop    rcx
.endif
    call   aes_ecb_asm
.ifdef WIN
    xchg   eax, ecx
.endif
    xor    eax, eax
.Lctr_xor:
    mov    bl, [rdi+rax]
    xor    [rdx], bl
    inc    rdx
    inc    eax
    cmp    al, 16
    loopne .Lctr_xor
    xchg   eax, ecx
    mov    cl, 16
.Lctr_inc:
    inc    byte ptr [rbp+rcx-1]
    loopz  .Lctr_inc
    xchg   eax, ecx
    jmp    .Lctr_loop
.Lctr_done:
.ifdef WIN
    add    rsp, 72
.else
    add    rsp, 40
.endif
    pop    rdi
    pop    rsi
    pop    rbp
    pop    rbx
    ret
.endif
