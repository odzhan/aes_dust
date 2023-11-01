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
; size: 205 bytes for ECB, 272 for CTR
;
; global calls use cdecl convention
;
; -----------------------------------------------

    bits 32
    
    global _E
    global E
    ; *****************************
    ; void E(void *s);
    ; *****************************
_E:
E:
    pusha
    xor    ecx, ecx           ; ecx = 0
    mul    ecx                ; eax = 0, edx = 0
    inc    eax                ; c = 1
    mov    cl, 16
    pusha                    ; alloca(32)
    
    ; F(32)x[i]=s[i]
    mov    esi, [esp+64+4]    ; esi = s
    mov    edi, esp
    pusha
    add    ecx, ecx           ; copy state + master key to stack
    rep    movsd
    popa
enc_main:
    ; AddRoundKey
    ; F(16)s[i]=x[i]^k[i];
    ; ****************************
    ; if(c==108) break;
    cmp    al, 108
    jne    upd_con
    popa
    popa
    ret
    ; ExpandKey
    ; F(4)k[i]^=S(k[12+((i-3)&3)])
exp_key:    
    pusha
    mov    cl, 4
xor_key:
    lea    ebx, [edx-3]
    and    ebx, 3
    mov    al, [esi+ebx+28]
    call   S
    xor    [esi+16], al
    movsb
    loop   xor_key
    popa
    ; k[0]^=rc;
    xor    [esi+16], al
    ; update round constant
    ; rc=M(rc);
upd_con:
    add    al, al
    jnc    $+4
    xor    al, 27
    ; SubBytes and ShiftRows
    ; F(16)k[i+4]^=k[i], 
    ;   x[(i&3)+(((W)(i/4)-(i&3))&3)*4]=S(s[i]);
    pusha
shift_rows:
    lodsb                    ; al = S(s[i])
    call   S
    mov    ebx, edx          ; ebx = i%4
    mov    ebp, edx
    and    ebp, 3            ;
    shr    ebx, 2            ; (i/4 - ebx) % 4
    sub    ebx, ebp          ; 
    and    ebx, 3            ; 
    lea    ebx, [ebp+ebx*4]  ; ebx = (ebx+edx*4)
    mov    [edi+ebx], al     ; x[ebx] = al
    inc    edx
    loop   shift_rows
    popa
    ; *****************************
    ; if(c!=108){
    cmp    al, 108
    je     enc_main
    ; *****************************
    ; MixColumns
    ; *****************************
    ; F(4)w=x[i],x[i]=R(w,8)^R(w,16)^R(w,24)^M(R(w,8)^w);
    pusha
mix_cols:
    mov    eax, [edi]        ; w0 = x[i]
    mov    ebx, eax          ; w1 = w0
    ror    eax, 8            ; w0 = R(w0,8)
    mov    edx, eax          ; w2 = w0
    xor    eax, ebx          ; w0^= w1
    ; W t=x&0x80808080;
    ;   return((x^t)*2)^((t>>7)*27);
    
    call   ebp               ; w0 = M(w0)
    xor    eax, edx          ; w0^= w2
    ror    ebx, 16           ; w1 = R(w1,16)
    xor    eax, ebx          ; w0^= w1
    ror    ebx, 8            ; w1 = R(w1,8)
    xor    eax, ebx          ; w0^= w1
    stosd                    ; x[i] = w0
    loop   mix_cols
    popa
    jmp    enc_main
    ; *****************************
    ; B S(B x)
    ; *****************************
S:  
    push   ecx
    push   edx
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
    add    dh, dh            ; dh <<= 1
    jnc    $+4               ;
    xor    dh, 27            ;
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
    pop    edx
    pop    ecx
    ret
    

%ifdef CTR
    global encrypt
    global _encrypt
      
    ; void encrypt(W len, B *ctr, B *in, B *key)
_encrypt:
encrypt:
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
    call   _E                ; E(t)
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
 
