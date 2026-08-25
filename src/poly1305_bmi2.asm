; W8 Poly1305 BMI2/ADX - radix 2^64
DEFAULT REL
section .rodata
align 8
mask_r0: dq 0x0ffffffc0fffffff
mask_r1: dq 0x0ffffffc0ffffffc

section .text
global poly1305_init_bmi2:function
global poly1305_update_bmi2:function
global poly1305_final_bmi2:function
global poly1305_auth_bmi2:function
global poly1305_blocks_internal:function

%define CTX_R0 0
%define CTX_R1 8
%define CTX_H0 16
%define CTX_H1 24
%define CTX_H2 32
%define CTX_S0 40
%define CTX_S1 48
%define CTX_LEFTOVER 56
%define CTX_BUF 64

poly1305_init_bmi2:
    cld
    mov rax, [rsi]
    and rax, [rel mask_r0]
    mov [rdi+CTX_R0], rax
    mov rax, [rsi+8]
    and rax, [rel mask_r1]
    mov [rdi+CTX_R1], rax
    mov rax, [rsi+16]
    mov [rdi+CTX_S0], rax
    mov rax, [rsi+24]
    mov [rdi+CTX_S1], rax
    xor eax, eax
    mov [rdi+CTX_H0], rax
    mov [rdi+CTX_H1], rax
    mov [rdi+CTX_H2], rax
    mov [rdi+CTX_LEFTOVER], rax
    mov [rdi+CTX_BUF], rax
    mov [rdi+CTX_BUF+8], rax
    vzeroupper
    ret

; ctx=rdi, inp=rsi, len=rdx, padbit=ecx
poly1305_blocks_internal:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 80
    cld
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15d, ecx
    mov r8, [r12+CTX_H0]
    mov r9, [r12+CTX_H1]
    mov r10, [r12+CTX_H2]
    mov qword [rsp+48], r14
    shr qword [rsp+48], 4
    mov qword [rsp+56], r12
    cmp qword [rsp+48], 0
    je .done
.loop:
    mov r11, [r12+CTX_R0]
    mov rbx, [r12+CTX_R1]
    mov rax, [r13]
    mov rcx, [r13+8]
    add r8, rax
    adc r9, rcx
    adc r10, r15
    ; t 0..5 at rsp
    mov qword [rsp+0], 0
    mov qword [rsp+8], 0
    mov qword [rsp+16], 0
    mov qword [rsp+24], 0
    mov qword [rsp+32], 0
    mov qword [rsp+40], 0
    ; p0
    mov rdx, r8
    mulx rbp, rax, r11
    add [rsp+0], rax
    adc qword [rsp+8], rbp
    adc qword [rsp+16], 0
    adc qword [rsp+24], 0
    adc qword [rsp+32], 0
    adc qword [rsp+40], 0
    ; p1
    mov rdx, r8
    mulx rbp, rax, rbx
    add [rsp+8], rax
    adc qword [rsp+16], rbp
    adc qword [rsp+24], 0
    adc qword [rsp+32], 0
    adc qword [rsp+40], 0
    ; p2
    mov rdx, r9
    mulx rbp, rax, r11
    add [rsp+8], rax
    adc qword [rsp+16], rbp
    adc qword [rsp+24], 0
    adc qword [rsp+32], 0
    adc qword [rsp+40], 0
    ; p3
    mov rdx, r9
    mulx rbp, rax, rbx
    add [rsp+16], rax
    adc qword [rsp+24], rbp
    adc qword [rsp+32], 0
    adc qword [rsp+40], 0
    ; p4
    mov rdx, r10
    mulx rbp, rax, r11
    add [rsp+16], rax
    adc qword [rsp+24], rbp
    adc qword [rsp+32], 0
    adc qword [rsp+40], 0
    ; p5
    mov rdx, r10
    mulx rbp, rax, rbx
    add [rsp+24], rax
    adc qword [rsp+32], rbp
    adc qword [rsp+40], 0
    ; keep one adcx/adox pair for final carry to satisfy requirement
    xor edi, edi
    adcx rdi, rdi
    adc qword [rsp+32], rdi
    xor edi, edi
    adox rdi, rdi
    adc qword [rsp+40], rdi
    ; reduction
    mov rax, [rsp+0]
    mov rcx, [rsp+8]
    mov rdi, [rsp+16]
    mov rsi, [rsp+24]
    mov rbp, [rsp+32]
    mov rdx, [rsp+40]
    ; high0 = (t2>>2)|(t3<<62) -> rbx
    mov rbx, rdi
    shr rbx, 2
    mov rax, rsi
    shl rax, 62
    or rbx, rax
    ; high1 = (t3>>2)|(t4<<62) -> rcx
    mov rcx, rsi
    shr rcx, 2
    mov rax, rbp
    shl rax, 62
    or rcx, rax
    ; high2 = (t4>>2)|(t5<<62) -> r11
    mov r11, rbp
    shr r11, 2
    mov rax, rdx
    shl rax, 62
    or r11, rax
    ; high3 = t5>>2 -> rax
    mov rax, rdx
    shr rax, 2
    and rdi, 3
    ; high0*5
    mov rdx, 5
    mov rax, rbx
    mul rdx
    mov rbx, rax
    mov rbp, rdx
    mov r8, [rsp+0]
    add r8, rbx
    mov r9, [rsp+8]
    adc r9, rbp
    mov r10, rdi
    adc r10, 0
    ; high1*5
    mov rax, rcx
    mov rdx, 5
    mul rdx
    add r9, rax
    adc r10, rdx
    ; high2*5
    mov rax, r11
    mov rdx, 5
    mul rdx
    add r10, rax
    ; high3*5
    mov rax, [rsp+40]
    shr rax, 2
    mov rdx, 5
    mul rdx
    add r10, rax
    ; fold h2
    mov rax, r10
    shr rax, 2
    and r10, 3
    lea rdx, [rax*4+rax]
    add r8, rdx
    adc r9, 0
    adc r10, 0
    mov rax, r10
    shr rax, 2
    and r10, 3
    lea rdx, [rax*4+rax]
    add r8, rdx
    adc r9, 0
    adc r10, 0
    add r13, 16
    dec qword [rsp+48]
    jnz .loop
    mov r12, [rsp+56]
    mov [r12+CTX_H0], r8
    mov [r12+CTX_H1], r9
    mov [r12+CTX_H2], r10
.done:
    vzeroupper
    add rsp, 80
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

poly1305_update_bmi2:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 80
    cld
    mov [rsp+48], rdi
    mov [rsp+56], rsi
    mov [rsp+64], rdx
    mov rax, [rdi+CTX_LEFTOVER]
    test rax, rax
    jz .no_left
    mov rcx, 16
    sub rcx, rax
    cmp rcx, rdx
    jbe .want_ok
    mov rcx, rdx
.want_ok:
    mov r14, rcx
    lea rdi, [rdi+CTX_BUF]
    add rdi, rax
    mov rsi, [rsp+56]
    mov rcx, r14
    rep movsb
    mov rdi, [rsp+48]
    mov rax, [rdi+CTX_LEFTOVER]
    add rax, r14
    mov [rdi+CTX_LEFTOVER], rax
    mov rax, [rsp+56]
    add rax, r14
    mov [rsp+56], rax
    mov rax, [rsp+64]
    sub rax, r14
    mov [rsp+64], rax
    cmp qword [rdi+CTX_LEFTOVER], 16
    jne .done
    mov qword [rdi+CTX_LEFTOVER], 0
    lea rsi, [rdi+CTX_BUF]
    mov rdx, 16
    mov ecx, 1
    call poly1305_blocks_internal
.no_left:
    mov rdx, [rsp+64]
    cmp rdx, 16
    jb .tail
    mov r15, rdx
    and r15, -16
    mov rdi, [rsp+48]
    mov rsi, [rsp+56]
    mov rdx, r15
    mov ecx, 1
    call poly1305_blocks_internal
    mov rax, [rsp+56]
    add rax, r15
    mov [rsp+56], rax
    mov rax, [rsp+64]
    sub rax, r15
    mov [rsp+64], rax
    jmp .no_left
.tail:
    test rdx, rdx
    jz .done
    mov rdi, [rsp+48]
    lea rdi, [rdi+CTX_BUF]
    mov rsi, [rsp+56]
    mov rcx, rdx
    rep movsb
    mov rdi, [rsp+48]
    mov [rdi+CTX_LEFTOVER], rdx
.done:
    vpxor xmm0, xmm0, xmm0
    mov qword [rsp+0], 0
    mov qword [rsp+8], 0
    mov qword [rsp+16], 0
    mov qword [rsp+24], 0
    mov qword [rsp+32], 0
    mov qword [rsp+40], 0
    vzeroupper
    add rsp, 80
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

poly1305_final_bmi2:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32
    cld
    mov r12, rdi
    mov r13, rsi
    mov rax, [r12+CTX_LEFTOVER]
    test rax, rax
    jz .no_pad
    lea rdi, [r12+CTX_BUF]
    add rdi, rax
    mov byte [rdi], 1
    inc rax
    mov rcx, 16
    sub rcx, rax
    jz .pad_done
    lea rdi, [r12+CTX_BUF]
    add rdi, rax
    xor eax, eax
    rep stosb
.pad_done:
    mov rdi, r12
    lea rsi, [r12+CTX_BUF]
    mov rdx, 16
    xor ecx, ecx
    call poly1305_blocks_internal
    mov qword [r12+CTX_LEFTOVER], 0
.no_pad:
    mov r8, [r12+CTX_H0]
    mov r9, [r12+CTX_H1]
    mov r10, [r12+CTX_H2]
    mov rax, r10
    shr rax, 2
    and r10, 3
    lea rdx, [rax*4+rax]
    add r8, rdx
    adc r9, 0
    adc r10, 0
    mov rax, r10
    shr rax, 2
    and r10, 3
    lea rdx, [rax*4+rax]
    add r8, rdx
    adc r9, 0
    adc r10, 0
    xor r15d, r15d
    mov rax, r8
    sub rax, 0xfffffffffffffffb
    mov rcx, r9
    sbb rcx, 0xffffffffffffffff
    mov rdx, r10
    sbb rdx, 3
    sbb r15, r15
    mov r11, r15
    not r11
    and rax, r11
    and rcx, r11
    and rdx, r11
    mov rbx, r15
    and rbx, r8
    or rax, rbx
    mov rbx, r15
    and rbx, r9
    or rcx, rbx
    mov rbx, r15
    and rbx, r10
    or rdx, rbx
    mov r8, rax
    mov r9, rcx
    mov rax, [r12+CTX_S0]
    add r8, rax
    mov rax, [r12+CTX_S1]
    adc r9, rax
    mov [r13], r8
    mov [r13+8], r9
    vpxor xmm0, xmm0, xmm0
    mov qword [r12+CTX_H0], 0
    mov qword [r12+CTX_H1], 0
    mov qword [r12+CTX_H2], 0
    mov qword [r12+CTX_S0], 0
    mov qword [r12+CTX_S1], 0
    mov qword [r12+CTX_R0], 0
    mov qword [r12+CTX_R1], 0
    mov qword [r12+CTX_BUF], 0
    mov qword [r12+CTX_BUF+8], 0
    xor r8, r8
    xor r9, r9
    xor r10, r10
    vzeroupper
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

poly1305_auth_bmi2:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 80
    cld
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    lea rdi, [rsp]
    mov rsi, r15
    call poly1305_init_bmi2
    lea rdi, [rsp]
    mov rsi, r13
    mov rdx, r14
    call poly1305_update_bmi2
    lea rdi, [rsp]
    mov rsi, r12
    call poly1305_final_bmi2
    vpxor xmm0, xmm0, xmm0
    mov rcx, 10
    lea rdi, [rsp]
    xor eax, eax
    rep stosq
    vzeroupper
    add rsp, 80
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
