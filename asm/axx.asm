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

  For more information, please refer to <http:#unlicense.org/> */
  
#
# -----------------------------------------------
# AES-128 Encryption in AMD64 assembly
#
# -----------------------------------------------
#
    .intel_syntax noprefix
    
    .global E
    
    .ifdef WIN
      .equ arg_0, rcx
      .equ arg_1, rdx
      .equ arg_2, r8
      .equ arg_3, r9
    .else
      .equ arg_0, rdi
      .equ arg_1, rsi
      .equ arg_2, rdx
      .equ arg_3, rcx
    .endif
# *****************************
# void E(void *s)
# *****************************
E:
    push   rax
    push   rbx
    push   rcx
    push   rdx
    push   rsi
    push   rdi
    push   rbp
    
    push   arg_0
    pop    rsi
    xor    ecx, ecx           # ecx = 0
    mul    ecx                # eax = 0, edx = 0
    inc    eax                # c = 1
    mov    cl, 4
    sub    rsp, 32           # alloca(32)
# F(8)x[i]=((W*)s)[i]
    push   rsp
    pop    rdi
    push   rcx
    push   rsi
    push   rdi
    rep    movsq
    pop    rdi
    pop    rsi
    pop    rcx
# *****************************
# Multiplication over GF(2**8)
# *****************************
    call   $+21               # save address      
gf_mul:
    push   rcx                # save ecx
    mov    cl, 4              # 4 bytes
    add    al, al             # al <<= 1
    jnc    $+4                #
    xor    al, 27             #
    ror    eax, 8             # rotate for next byte
    loop   $-9                # 
    pop    rcx                # restore ecx
    ret
    pop    rbp
enc_main:
# *****************************
# AddRoundKey, AddRoundConstant, ExpandRoundKey
# *****************************
# w=k[3]#F(4)w=(w&-256)|S(w),w=R(w,8),((W*)s)[i]=x[i]^k[i]
# w=R(w,8)^c#F(4)w=k[i]^=w

    push   rax
    push   rcx
    push   rdx
    push   rsi
    push   rdi
    
    xchg   eax, edx
    xchg   rsi, rdi
    mov    eax, [rsi+16+12]  # w=R(k[3],8)
    ror    eax, 8
xor_key:
    mov    ebx, [rsi+16]     # t=k[i]
    xor    [rsi], ebx        # x[i]^=t
    movsd                    # s[i]=x[i]
# w=(w&-256)|S(w)
    call   sub_byte          # al=S(al)
    ror    eax, 8            # w=R(w,8)
    loop   xor_key
# w=R(w,8)^c#
    xor    eax, edx          # w^=c
# F(4)w=k[i]^=w#
    mov    cl, 4
exp_key:
    xor    [rsi], eax        # k[i]^=w
    lodsd                    # w=k[i]
    loop   exp_key
    
    pop    rdi
    pop    rsi
    pop    rdx
    pop    rcx
    pop    rax
# ****************************
# if(c==108) break#
    cmp    al, 108
    jne    upd_con
    add    rsp, 32
    
    pop    rbp
    pop    rdi
    pop    rsi
    pop    rdx
    pop    rcx
    pop    rbx
    pop    rax
    
    ret
upd_con:
    call   rbp
# ***************************
# ShiftRows and SubBytes
# ***************************
# F(16)((B*)x)[(i%4)+(((i/4)-(i%4))%4)*4]=S(((B*)s)[i])

    push   rax
    push   rcx
    push   rsi
    push   rdi
    
    mov    cl, 16
shift_rows:
    lodsb                    # al = S(s[i])
    call   sub_byte
    push   rdx
    mov    ebx, edx          # ebx = i%4
    and    ebx, 3            #
    shr    edx, 2            # (i/4 - ebx) % 4
    sub    edx, ebx          # 
    and    edx, 3            # 
    lea    ebx, [ebx+edx*4]  # ebx = (ebx+edx*4)
    mov    [rdi+rbx], al     # x[ebx] = al
    pop    rdx
    add    dl, 1
    loop   shift_rows
    
    pop    rdi
    pop    rsi
    pop    rcx
    pop    rax
# *****************************
    # if(c!=108){
    cmp    al, 108
    je     enc_main
# *****************************
# MixColumns
# *****************************
# F(4)w=x[i],x[i]=R(w,8)^R(w,16)^R(w,24)^M(R(w,8)^w)
    push   rax
    push   rcx
    push   rdx
    push   rdi
mix_cols:
    mov    eax, [rdi]        # w0 = x[i]
    mov    ebx, eax          # w1 = w0
    ror    eax, 8            # w0 = R(w0,8)
    mov    edx, eax          # w2 = w0
    xor    eax, ebx          # w0^= w1
    call   rbp               # w0 = M(w0)
    xor    eax, edx          # w0^= w2
    ror    ebx, 16           # w1 = R(w1,16)
    xor    eax, ebx          # w0^= w1
    ror    ebx, 8            # w1 = R(w1,8)
    xor    eax, ebx          # w0^= w1
    stosd                    # x[i] = w0
    loop   mix_cols
    pop    rdi
    pop    rdx
    pop    rcx
    pop    rax
    jmp    enc_main
# *****************************
# B SubByte(B x)
# *****************************
sub_byte:
    push   rax
    push   rcx
    push   rdx
    
    test   al, al            # if(x){
    jz     sb_l6
    xchg   eax, edx
    mov    cl, -1            # i=255 
# for(c=i=0,y=1#--i#y=(!c&&y==x)?c=1:y,y^=M(y))
sb_l0:
    mov    al, 1             # y=1
sb_l1:
    test   ah, ah            # !c
    jnz    sb_l2    
    cmp    al, dl            # y!=x
    setz   ah
    jz     sb_l0
sb_l2:
    mov    dh, al            # y^=M(y)
    call   gf_mul               #
    xor    al, dh
    loop   sb_l1             # --i
# F(4)x^=y=(y<<1)|(y>>7)#
    mov    dl, al            # dl=y
    mov    cl, 4             # i=4  
sb_l5:
    rol    dl, 1             # y=R(y,1)
    xor    al, dl            # x^=y
    loop   sb_l5             # i--
sb_l6:
    xor    al, 99            # return x^99
    mov    [rsp+16], al
    pop    rdx
    pop    rcx
    pop    rax
    ret
    

.ifdef CTR
    .global encrypt
      
# void encrypt(W len, B *ctr, B *in, B *key)
encrypt:
    push   rbx
    push   rbp
    push   rsi
    push   rdi
    
    push   arg_1    # rsi/rcx or ctr
    pop    rbp
    push   arg_3    # rcx/rdx or key
    pop    rsi
    push   arg_0    # rdi/r8 or len
    pop    rcx
    push   arg_2    # rdx/r9 or in
    pop    rdx
    sub    rsp, 32           # alloca(32)
# copy master key to local buffer
# F(16)t[i+16]=key[i]#
    lea    rdi, [rsp+16]     # edi = &t[16]
    movsq
    movsq
aes_l0:
    xor    eax, eax
    jecxz  aes_l3            # while(len){
# copy counter+nonce to local buffer
# F(16)t[i]=ctr[i]
    push   rsp
    pop    rdi
    push   rbp
    pop    rsi
    push   rdi
    movsq
    movsq
    pop    rdi
# encrypt t    
    call   EX                # E(t)
aes_l1:
# xor plaintext with ciphertext
# r=len>16?16:len
# F(r)in[i]^=t[i]
    mov    bl, [rdi+rax]     # 
    xor    [rdx], bl         # *in++^=t[i]
    inc    rdx
    add    al, 1
    cmp    al, 16            #
    loopne aes_l1            # while(i!=16 && --ecx!=0)
# update counter
    xchg   eax, ecx          # 
    mov    cl, 16
aes_l2:
    inc    byte[rbp+rcx-1]   #
    loopz  aes_l2            # while(++c[i]==0 && --ecx!=0)
    xchg   eax, ecx
    jmp    aes_l0
aes_l3:
    add    rsp, 32
    pop    rdi
    pop    rsi
    pop    rbp
    pop    rbx
    ret
.endif
 
