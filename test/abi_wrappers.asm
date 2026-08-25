; W14 ABI conformance probes (test/abi_wrappers.asm)
;
; One wrapper per exported symbol under test. Each wrapper:
;   1. stages incoming stack args (7th/8th) so forwarding keeps the
;      callee-visible layout identical to a direct C call,
;   2. saves the caller's rbx, rbp, r12-r14 in scratch slots ABOVE the
;      callee's red-zone reach,
;   3. poisons rbx, rbp, r12-r14 with known patterns,
;   4. calls the real symbol with rsp 16-byte aligned at the call site
;      (callee sees rsp % 16 == 8 per System V AMD64),
;   5. builds a violation bitmask branchlessly in eax:
;        bit0 rbx   bit1 rbp   bit2 r12   bit3 r13   bit4 r14
;        bit5 direction flag set on return (ABI requires DF=0)
;   6. restores the caller's registers and returns the mask.
;
; The wrapped function's return value is intentionally not forwarded;
; functional behavior is covered by the vector suite.
;
; abi_violator_stub is a deliberate callee-saved/DF trasher used as a
; negative control: the harness must detect bits 0 and 5 both set.

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
extern chacha20_keystream_avx2

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
    sub     rsp, 56                     ; entry rsp%16==8 -> now rsp%16==0
    mov     [rsp+16], rbx               ; save caller regs (slots 16..55)
    mov     [rsp+24], rbp
    mov     [rsp+32], r12
    mov     [rsp+40], r13
    mov     [rsp+48], r14

    mov     rax, [rsp+64]               ; stage arg7 (was [entry rsp+8])
    mov     [rsp+0], rax                ; callee will see it at [rsp+8]
    mov     rax, [rsp+72]               ; stage arg8 (was [entry rsp+16])
    mov     [rsp+8], rax                ; callee will see it at [rsp+16]

    movabs  rbx, 0x1111111111110001     ; poison callee-saved set
    movabs  rbp, 0x2222222222220002
    movabs  r12, 0x3333333333330003
    movabs  r13, 0x4444444444440004
    movabs  r14, 0x5555555555550005

    call    %1                          ; rsp%16==0 here -> callee sees 8

    ; violation mask, built msb-first so rbx lands on bit0, DF on bit5
    xor     eax, eax
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

    mov     rbx, [rsp+16]               ; restore caller regs
    mov     rbp, [rsp+24]
    mov     r12, [rsp+32]
    mov     r13, [rsp+40]
    mov     r14, [rsp+48]
    add     rsp, 56
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
ABI_WRAP chacha20_keystream_avx2

global abi_violator_stub:function
abi_violator_stub:
    xor     ebx, ebx                    ; deliberate callee-saved trash...
    std                                 ; ...and deliberate DF=1 on return.
    ret                                 ; Detector must flag bits 0 AND 5.
