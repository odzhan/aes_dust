;
; This is free and unencumbered software released into the public domain.
;
; Anyone is free to copy, modify, publish, use, compile, sell, or
; distribute this software, either in source code form or as a compiled
; binary, for any purpose, commercial or non-commercial, and by any
; means.

; In jurisdictions that recognize copyright laws, the author or authors
; of this software dedicate any and all copyright interest in the
; software to the public domain. We make this dedication for the benefit
; of the public at large and to the detriment of our heirs and
; successors. We intend this dedication to be an overt act of
; relinquishment in perpetuity of all present and future rights to this
; software under copyright law.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
; EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
; MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
; IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
; OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
; ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
; OTHER DEALINGS IN THE SOFTWARE.
;
; For more information, please refer to <http://unlicense.org/>
;
;

; AES-128 encryption, NASM 32-bit, cdecl: void aes_ecb_asm(void *s).
; aes_ecb/_aes_ecb remain aliases for callers using the historic symbols.
; s[0..15] is plaintext, replaced by ciphertext; s[16..31] is the unchanged key.
; All general-purpose registers are preserved. The direction flag must be clear.
; Default ECB: 177 bytes, table-free. CTR=1 adds 67 bytes (244 bytes total).
; STATIC=1 selects the faster 399-byte table build (466 bytes with CTR).
; DYNAMIC=1 remains accepted and overrides STATIC when both are defined.
; The exponentiation S-box favors size over speed; it is substantially slower.
; Peak ECB stack excludes the caller's return slot: 136 bytes, or 104 STATIC.
; Flat binary: nasm -f bin -DBIN ax.asm -o ax.bin
; Win32 object: nasm -f win32 ax.asm -o ax.obj
; CTR exports aes_ctr/aes_ctr_encrypt and their underscore-prefixed aliases.
;
; Uses the reference's byte xtime, exponentiation, and indirect helper layout;
; MixColumns combines two rotations through ROR16(w ^ ROR8(w)).

bits 32

%ifndef STATIC
  %ifndef DYNAMIC
    %define DYNAMIC 1
  %endif
%endif


%ifndef BIN
    section .text
    global aes_ecb_asm, _aes_ecb_asm, aes_ecb, _aes_ecb

%endif

_aes_ecb_asm:
aes_ecb_asm:
_aes_ecb:
aes_ecb:
    pushad
    xor     ecx, ecx
    mul     ecx                 ; EAX = EDX = 0
    inc     eax                 ; round constant
    mov     cl, 4
    pushad                      ; 32-byte state/key workspace
    mov     esi, [esp+68]
    mov     edi, esp
    pushad
    add     ecx, ecx
    rep     movsd
    popad
    call    .xtime_end

; Multiply AL by 2 in GF(2^8), preserving EAX's upper bytes.
.xtime:
    add     al, al
    jnc     .xtime_ret
    xor     al, 0x1b
.xtime_ret:
    ret

; Compute AL's inverse and affine transform; internal callers supply ECX<=255.
; Preserve registers and return AL through PUSHAD's saved EAX.
; Neither helper requires a particular carry flag.
.sbox:
%ifndef DYNAMIC
    push    ebx
    add     ebx, .table-.sbox
    xlatb
    pop     ebx
    ret
.table:
    db 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5
    db 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    db 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0
    db 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
    db 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc
    db 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15
    db 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a
    db 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
    db 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0
    db 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
    db 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b
    db 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf
    db 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85
    db 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8
    db 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5
    db 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
    db 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17
    db 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73
    db 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88
    db 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
    db 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c
    db 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79
    db 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9
    db 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08
    db 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6
    db 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a
    db 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e
    db 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e
    db 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94
    db 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
    db 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68
    db 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
%else
    pushad
    mov     dl, al
    mov     cl, 253
.power:
    push    byte 8
    pop     ebx                 ; BH=0, BL=8
    xchg    al, bh              ; multiplier in BH, accumulator AL=0
.product:
    call    ebp
    add     bh, bh
    jnc     .no_add
    xor     al, dl
.no_add:
    dec     ebx                 ; BL counts down; BH is zero after eight shifts
    jnz     .product
    loop    .power

; The 253 products turn x into x^254 (the inverse, with 0 mapped to 0).
    mov     dl, al
    mov     cl, 4
.affine:
    rol     dl, 1
    xor     al, dl
    loop    .affine
.affine_constant:
    xor     al, 0x63
    mov     [esp+28], al        ; replace saved AL with the S-box result
    popad
    ret

%endif

.xtime_end:
    pop     ebp                 ; callable, position-independent xtime
    lea     ebx, [ebp+.sbox-.xtime] ; nearby helper permits short indirect calls

.round:
    pushad
    xchg    esi, edi
    mov     eax, [esi+28]
    ror     eax, 8
.add_key:
    mov     edx, [esi+16]
    xor     [esi], edx
    movsd                       ; publish current state
    call    ebx
    ror     eax, 8
    loop    .add_key
    xor     eax, [esp+28]        ; round constant already saved by PUSHAD
    mov     cl, 4
.expand_key:
    xor     [esi], eax
    lodsd
    loop    .expand_key
    popad
    cmp     al, 0x6c            ; ten rounds completed
    jne     .next_round
    popad
    popad
    ret
.next_round:
    call    ebp                 ; outer EAX contains only the byte round constant
    pushad
.sub_shift:
    lodsb
    call    ebx
    mov     [edi+edx], al
    sub     edx, 3
    and     edx, 15
    jnz     .sub_shift
    popad
    cmp     al, 0x6c
    je      .round              ; final round omits MixColumns
    pushad
.mix_columns:
    mov     eax, [edi]
    mov     edx, eax
    ror     edx, 8
    xor     eax, edx
    mov     esi, eax            ; d = w ^ ROR8(w)
    push    ecx
    mov     cl, 4
.mix_xtime:
    call    ebp
    ror     eax, 8
    loop    .mix_xtime
    pop     ecx
    ror     esi, 16             ; ROR16(d) = ROR16(w) ^ ROR24(w)
    xor     eax, esi
    xor     eax, edx
    stosd
    loop    .mix_columns
    popad
    jmp     .round

%ifdef CTR
    %ifndef BIN
      global aes_ctr, _aes_ctr, aes_ctr_encrypt, _aes_ctr_encrypt
    %endif

    ; void aes_ctr(W len, B *ctr, B *in, B *key)
_aes_ctr_encrypt:
aes_ctr_encrypt:
_aes_ctr:
aes_ctr:
    pushad
    lea    esi,[esp+32+4]
    lodsd
    xchg   eax, ecx          ; ecx = len
    lodsd
    xchg   eax, ebp          ; ebp = ctr
    lodsd
    xchg   eax, edx          ; edx = in
    lodsd
    xchg   esi, eax          ; esi = key
    pushad                    ; alloca(32)

    ; copy master key to local buffer
    ; F(16)t[i+16]=key[i]
    lea    edi, [esp+16]     ; edi = &t[16]
    movsd
    movsd
    movsd
    movsd
aes_l0:
    xor    eax, eax
    jecxz  aes_l3            ; while(len){

    ; copy counter+nonce to local buffer
    ; F(16)t[i]=ctr[i]
    mov    edi, esp          ; edi = t
    mov    esi, ebp          ; esi = ctr
    push   edi
    movsd
    movsd
    movsd
    movsd
    ; encrypt t
    call   aes_ecb       ; E(t)
    pop    edi
aes_l1:
    ; xor plaintext with ciphertext
    ; r=len>16?16:len
    ; F(r)in[i]^=t[i]
    mov    bl, [edi+eax]     ;
    xor    [edx], bl         ; *in++^=t[i]
    inc    edx               ;
    inc    eax               ; i++
    cmp    al, 16            ;
    loopne aes_l1            ; while(i!=16 && --ecx!=0)

    ; update counter
    xchg   eax, ecx          ;
    mov    cl, 16
aes_l2:
    inc    byte[ebp+ecx-1]   ;
    loopz  aes_l2            ; while(++c[i]==0 && --ecx!=0)
    xchg   eax, ecx
    jmp    aes_l0
aes_l3:
    popad
    popad
    ret
%endif
