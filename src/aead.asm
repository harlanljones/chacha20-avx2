; W9: AEAD composition chacha20_poly1305_encrypt (src/aead.asm)
;
; TDD 3.1 signature:
; int chacha20_poly1305_encrypt(uint8_t *ciphertext, uint8_t tag[16],
;     const uint8_t *plaintext, size_t plaintext_len, const uint8_t *aad,
;     size_t aad_len, const uint8_t nonce[12], const uint8_t key[32])
;
; Stack frame:
; rsp+0:   poly1305_ctx_bmi2 (64 bytes)
; rsp+64:  otk (32 bytes)
; rsp+96:  scratch pad (16 bytes)
; rsp+112: trailer (16 bytes)
; rsp+128: saved nonce ptr (8 bytes)
; rsp+136: saved key ptr (8 bytes)
; rsp+144: saved rbx, rbp, r12-r15 (48 bytes)

DEFAULT REL

section .text

extern chacha20_xor_tail_avx2
extern poly1305_init_bmi2
extern poly1305_update_bmi2
extern poly1305_final_bmi2

global chacha20_poly1305_encrypt:function

chacha20_poly1305_encrypt:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 144  ; 144 bytes local stack, 16-byte aligned

    ; Save all input parameters
    mov r12, rdi          ; r12 = ciphertext
    mov r13, rsi          ; r13 = tag
    mov r14, rdx          ; r14 = plaintext
    mov r15, rcx          ; r15 = plaintext_len
    mov rbx, r8           ; rbx = aad
    mov rbp, r9           ; rbp = aad_len

    ; Get stack args (nonce and key ptrs) and save them at end of local stack
    mov rax, [rsp+144+48+8]  ; rsp+144 (locals) +48 (saved regs) +8 (ret addr)
    mov [rsp+128], rax        ; save nonce ptr
    mov rax, [rsp+144+48+16]
    mov [rsp+136], rax        ; save key ptr

    ; Step 1: Encrypt plaintext (counter =1)
    mov rdi, r12
    mov rsi, r14
    mov rdx, r15
    mov rcx, [rsp+136]
    mov r8, [rsp+128]
    mov r9d,1
    call chacha20_xor_tail_avx2

    ; Step 2: Generate OTK (counter=0, 32 bytes): zero out otk first, then xor with 0
    lea rdi, [rsp+64]
    xor eax,eax
    mov ecx,32/8
.zero_otk:
    stosq
    dec ecx
    jnz .zero_otk
    lea rdi, [rsp+64]
    mov rsi, rdi  ; src is 0s, so dst = 0 ^ keystream = keystream
    mov rdx, 32
    mov rcx, [rsp+136]
    mov r8, [rsp+128]
    mov r9d,0
    call chacha20_xor_tail_avx2

    ; Step3: Initialize poly1305 with OTK
    mov rdi, rsp
    lea rsi, [rsp+64]
    call poly1305_init_bmi2

    ; Step4: Update poly1305 with AAD
    mov rdi, rsp
    mov rsi, rbx
    mov rdx, rbp
    call poly1305_update_bmi2

    ; Step5: Pad AAD to 16 bytes if needed
    mov rax, rbp
    and rax,15
    jz .aad_pad_ok
    mov rdx,16
    sub rdx,rax        ; rdx = pad count (rep stosb preserves rdx)
    lea rdi, [rsp+96]
    xor eax,eax
    mov rcx,rdx
    rep stosb          ; zero pad buffer (rcx -> 0, rdx preserved)
    mov rdi, rsp
    lea rsi, [rsp+96]
    call poly1305_update_bmi2   ; rdx still = pad count
.aad_pad_ok:

    ; Step6: Update with ciphertext
    mov rdi, rsp
    mov rsi, r12
    mov rdx, r15
    call poly1305_update_bmi2

    ; Step7: Pad ciphertext to 16 bytes if needed
    mov rax, r15
    and rax,15
    jz .ct_pad_ok
    mov rdx,16
    sub rdx,rax        ; rdx = pad count
    lea rdi, [rsp+96]
    xor eax,eax
    mov rcx,rdx
    rep stosb          ; zero pad buffer
    mov rdi, rsp
    lea rsi, [rsp+96]
    call poly1305_update_bmi2   ; rdx still = pad count
.ct_pad_ok:

    ; Step8: Update with trailer (little-endian aad len, little-endian ct len)
    lea rdi, [rsp+112]
    mov rax,rbp
    stosq
    mov rax,r15
    stosq
    mov rdi,rsp
    lea rsi, [rsp+112]
    mov rdx,16
    call poly1305_update_bmi2

    ; Step9: Finalize and write tag
    mov rdi, rsp
    mov rsi, r13
    call poly1305_final_bmi2

    ; Scrub secret state from stack and YMM registers
    vpxor ymm0, ymm0, ymm0
    lea r10, [rsp+144]  ; scrub full 144-byte local frame (144/32 = 4.5 -> 5 dwords)
    mov ecx, 5
.scrub_loop:
    sub r10,32
    vmovdqu [r10],ymm0
    dec ecx
    jnz .scrub_loop
    vzeroupper

    ; Restore and return 0
    add rsp,144
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    xor eax,eax
    ret
