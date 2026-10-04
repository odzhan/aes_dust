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
; -----------------------------------------------
; AES-128 Encryption in x86 assembly
;
; size: 188 bytes for ECB, 255 for CTR
;
; global calls use cdecl convention
;
; -----------------------------------------------

    bits 32
    
    %ifndef BIN
      global _aes_ecb
      global aes_ecb
    %endif
    
    ; *****************************
    ; void aes_ecb(void *s);
    ; *****************************
_aes_ecb:
aes_ecb:
    pusha
    xor    ecx, ecx           ; ecx = 0
    mul    ecx                ; eax = 0, edx = 0
    inc    eax                ; c = 1
    mov    cl, 4
    pusha                     ; alloca(32)
    
    ; F(8)x[i]=((W*)s)[i]
    mov    esi, [esp+64+4]    ; esi = s
    mov    edi, esp
    pusha
    add    ecx, ecx           ; copy state + master key to stack
    rep    movsd
    popa
    ; *****************************
    ; Multiplication over GF(2**8)
    ; *****************************
    call   $+21               ; save address      
    push   ecx                ; save ecx
    mov    cl, 4              ; 4 bytes
    add    al, al             ; al <<= 1
    jnc    $+4                ;
    xor    al, 27             ;
    ror    eax, 8             ; rotate for next byte
    loop   $-9                ; 
    pop    ecx                ; restore ecx
    ret
    pop    ebp
enc_main:
    ; *****************************
    ; AddRoundKey, AddRoundConstant, ExpandRoundKey
    ; *****************************
    ; w=k[3]; F(4)w=(w&-256)|S(w),w=R(w,8),((W*)s)[i]=x[i]^k[i];
    ; w=R(w,8)^c;F(4)w=k[i]^=w;
    pusha
    xchg   eax, edx
    xchg   esi, edi
    mov    eax, [esi+16+12]  ; w=R(k[3],8)
    ror    eax, 8
xor_key:
    mov    ebx, [esi+16]     ; t=k[i]
    xor    [esi], ebx        ; x[i]^=t
    movsd                    ; s[i]=x[i]
    ; w=(w&-256)|S(w)
    call   S                 ; al=S(al)
    ror    eax, 8            ; w=R(w,8)
    loop   xor_key
    ; w=R(w,8)^c
    xor    eax, edx          ; w^=c
    ; F(4)w=k[i]^=w
    mov    cl, 4
exp_key:
    xor    [esi], eax        ; k[i]^=w
    lodsd                    ; w=k[i]
    loop   exp_key
    popa
    
    ; ****************************
    ; if(c==108) break;
    cmp    al, 108
    jne    upd_con
    popa
    popa
    ret
upd_con:
    call   ebp
    ; ***************************
    ; ShiftRows and SubBytes
    ; ***************************
    ; F(16)((u8*)x)[w]=S(((u8*)s)[i]), w=(w-3)&15;
    pusha
shift_rows:
    lodsb                    ; al = S(s[i])
    call   S
    mov    [edi+edx], al
    sub    edx, 3
    and    edx, 15
    jnz    shift_rows
    popa
    ; *****************************
    ; if(c!=108){
    cmp    al, 108
    je     enc_main
    ; *****************************
    ; MixColumns
    ; *****************************
    ; F(4)w=x[i],x[i]=R(w,8)^R(w,16)^R(w,24)^M(R(w, 8)^w);
    pusha
mix_cols:
    mov    eax, [edi]       ; w = x[i]
    mov    edx, eax         ; t = R(w, 8)
    ror    edx, 8           ; 
    xor    eax, edx         ; w ^= t
    call   ebp              ; 
    xor    eax, edx
    ror    edx, 8
    xor    eax, edx
    ror    edx, 8
    xor    eax, edx
    stosd
    loop   mix_cols
    popa
    jmp    enc_main
    ; *****************************
    ; B SubByte(B x)
    ; *****************************
S:
%ifndef DYNAMIC
    push   ebx
    call   init_sbox
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
init_sbox:
    pop    ebx
    xlatb
    pop    ebx
%else
    pusha 
    test   al, al            ; if(x){
    jz     sb_l6
    xchg   eax, edx
    mov    cl, -1            ; i=255 
; for(c=i=0,y=1;--i;y=(!c&&y==x)?c=1:y,y^=M(y))
sb_l0:
    mov    al, 1             ; y=1
sb_l1:
    test   ah, ah            ; !c
    jnz    sb_l2    
    cmp    al, dl            ; y!=x
    setz   ah
    jz     sb_l0
sb_l2:
    mov    dh, al            ; y^=M(y)
    call   ebp               ;
    xor    al, dh
    loop   sb_l1             ; --i
; F(4)x^=y=(y<<1)|(y>>7);
    mov    dl, al            ; dl=y
    mov    cl, 4             ; i=4  
sb_l5:
    rol    dl, 1             ; y=R(y,1)
    xor    al, dl            ; x^=y
    loop   sb_l5             ; i--
sb_l6:
    xor    al, 99            ; return x^99
    mov    [esp+28], al
    popa
%endif
    ret
    

%ifdef CTR
    global aes_ctr
    global _aes_ctr
      
    ; void aes_ctr(W len, B *ctr, B *in, B *key)
_aes_ctr:
aes_ctr:
    pusha
    lea    esi,[esp+32+4]
    lodsd
    xchg   eax, ecx          ; ecx = len
    lodsd
    xchg   eax, ebp          ; ebp = ctr
    lodsd
    xchg   eax, edx          ; edx = in
    lodsd
    xchg   esi, eax          ; esi = key
    pusha                    ; alloca(32)
    
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
    popa
    popa
    ret
%endif
 
