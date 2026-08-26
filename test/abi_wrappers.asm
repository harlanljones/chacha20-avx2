; W14 ABI conformance probes (test/abi_wrappers.asm)
;
; One wrapper per exported symbol under test. Each wrapper:
;   1. stages incoming stack args (7th/8th) so forwarding keeps the
;      callee-visible layout identical to a direct C call,
;   2. saves the caller's rbx, rbp, r12-r15 in scratch slots ABOVE the
;      callee's red-zone reach,
;   3. poisons rbx, rbp, r12-r15 with known patterns,
;   4. calls the real symbol with rsp 16-byte aligned at the call site
;      (callee sees rsp % 16 == 8 per System V AMD64),
;   5. builds a violation bitmask branchlessly in eax:
;        bit0 direction flag set on return (ABI requires DF=0)
;        bit1 rbx   bit2 rbp   bit3 r12   bit4 r13   bit5 r14   bit6 r15
;   6. restores the caller's registers and returns the mask.
;
; The wrapped function's return value is intentionally not forwarded;
; functional behavior is covered by the vector suite.
;
; abi_violator_impl / abi_violator_r15_impl are deliberate
; callee-saved/DF trashers used as negative controls: the harness must
; detect 0x3 (DF+rbx) and 0x40 (r15) respectively.

section .text

extern chacha20_block_ref
extern chacha20_init_state_ref
extern chacha20_xor_ref
extern poly1305_init_ref
extern poly1305_update_ref
extern poly1305_final_ref
extern poly1305_otk_ref
extern chacha20_poly1305_encrypt_ref
extern chacha20_blocks4_avx2
extern chacha20_blocks8_avx2
extern chacha20_keystream_avx2
extern chacha20_xor_tail_avx2
extern poly1305_init_bmi2
extern poly1305_update_bmi2
extern poly1305_final_bmi2
extern poly1305_auth_bmi2
extern poly1305_blocks_internal
extern chacha20_poly1305_encrypt

; ---- helper macro: eax = (eax << 1) | (reg != pattern) ----
%macro PROBE_REG 2        ; %1 = register, %2 = 64-bit pattern
    mov     rcx, %2
    xor     rcx, %1
    setnz   cl
    shl     eax, 1
    or      al, cl
%endmacro

; %1 = symbol to wrap
%macro ABI_WRAP 1
global abi_wrap_%1:function
abi_wrap_%1:
    sub     rsp, 72                     ; entry rsp%16==8 -> now rsp%16==0
    mov     [rsp+16], rbx               ; save caller regs (slots 16..63)
    mov     [rsp+24], rbp
    mov     [rsp+32], r12
    mov     [rsp+40], r13
    mov     [rsp+48], r14
    mov     [rsp+56], r15

    mov     rax, [rsp+80]               ; stage arg7 (was [entry rsp+8])
    mov     [rsp+0], rax                ; callee will see it at [rsp+8]
    mov     rax, [rsp+88]               ; stage arg8 (was [entry rsp+16])
    mov     [rsp+8], rax                ; callee will see it at [rsp+16]

    movabs  rbx, 0x1111111111110001     ; poison callee-saved set
    movabs  rbp, 0x2222222222220002
    movabs  r12, 0x3333333333330003
    movabs  r13, 0x4444444444440004
    movabs  r14, 0x5555555555550005
    movabs  r15, 0x6666666666660006

    call    %1                          ; rsp%16==0 here -> callee sees 8

    ; violation mask, built msb-first so r15 lands on bit6, DF on bit0
    xor     eax, eax
    PROBE_REG r15, 0x6666666666660006
    PROBE_REG r14, 0x5555555555550005
    PROBE_REG r13, 0x4444444444440004
    PROBE_REG r12, 0x3333333333330003
    PROBE_REG rbp, 0x2222222222220002
    PROBE_REG rbx, 0x1111111111110001

    pushfq                               ; direction flag probe -> bit5
    pop     rcx
    shr     rcx, 10
    and     rcx, 1
    shl     eax, 1
    or      al, cl
    cld                                 ; never leak DF=1 back to the C caller

    mov     rbx, [rsp+16]               ; restore caller regs
    mov     rbp, [rsp+24]
    mov     r12, [rsp+32]
    mov     r13, [rsp+40]
    mov     r14, [rsp+48]
    mov     r15, [rsp+56]
    add     rsp, 72
    ret
%endmacro

ABI_WRAP chacha20_block_ref
ABI_WRAP chacha20_init_state_ref
ABI_WRAP chacha20_xor_ref
ABI_WRAP poly1305_init_ref
ABI_WRAP poly1305_update_ref
ABI_WRAP poly1305_final_ref
ABI_WRAP poly1305_otk_ref
ABI_WRAP chacha20_poly1305_encrypt_ref
ABI_WRAP chacha20_blocks4_avx2
ABI_WRAP chacha20_blocks8_avx2
ABI_WRAP chacha20_keystream_avx2
ABI_WRAP chacha20_xor_tail_avx2
ABI_WRAP poly1305_init_bmi2
ABI_WRAP poly1305_update_bmi2
ABI_WRAP poly1305_final_bmi2
ABI_WRAP poly1305_auth_bmi2
ABI_WRAP poly1305_blocks_internal
ABI_WRAP chacha20_poly1305_encrypt

; Negative control. The impl is deliberately non-conforming; it is run
; through ABI_WRAP so the mask the test inspects is the one the detector
; actually computed, rather than whatever happened to be left in rax.
abi_violator_impl:
    xor     ebx, ebx                    ; deliberate callee-saved trash...
    std                                 ; ...and deliberate DF=1 on return.
    ret

ABI_WRAP abi_violator_impl

; Negative control for the r15 probe specifically (W7 is the first
; exported symbol that relies on r15 preservation).
abi_violator_r15_impl:
    xor     r15d, r15d
    ret

ABI_WRAP abi_violator_r15_impl
