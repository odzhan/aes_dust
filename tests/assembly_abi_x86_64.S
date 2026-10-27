/* Deliberately put a decoy in the other ABI's argument register. The C
 * compiler, rather than the AES assembler options, chooses this wrapper's ABI.
 * Omitting WIN=1 from the Windows AES build must fail this regression. */
.intel_syntax noprefix
.text
.global aes_test_abi_ecb
aes_test_abi_ecb:
#if defined(_WIN32) || defined(__CYGWIN__) || defined(__MSYS__)
    push rdi
    sub rsp, 32
    mov rdi, rdx
    call aes_ecb_asm
    add rsp, 32
    pop rdi
#else
    sub rsp, 8
    mov rcx, rsi
    call aes_ecb_asm
    add rsp, 8
#endif
    ret
#if !defined(_WIN32) && !defined(__CYGWIN__) && !defined(__MSYS__)
.section .note.GNU-stack,"",@progbits
#endif
