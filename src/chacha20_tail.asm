; W7: constant-time tail / scalar fallback path (src/chacha20_tail.asm)
;
; Handles payloads that are not a whole number of 4-block (256 B) groups:
; short messages (< 256 B) and the partial final group / partial final
; block of any longer message. Builds on the W6 core rather than
; reimplementing the round function -- src/chacha20_avx2.asm stays owned
; by W6 (AGENTS.md 6, one writer per file).
;
; Exports:
;   void chacha20_xor_tail_avx2(uint8 *dst, const uint8 *src, size_t len,
;       const uint8 key[32], const uint8 nonce[12], uint32 counter)
;
; Encrypt == decrypt (keystream XOR). Exact aliasing dst == src is
; supported (masked load happens before the masked store of the same
; lanes); any other overlap is undefined, matching include/ref.h.
;
; Constant-time posture (AGENTS.md 3.3):
;   - `len` is PUBLIC in this construction: the ciphertext length is
;     observable on the wire, and RFC 8439 does not hide it. Control flow
;     and memory addressing here depend on `len` and on nothing else.
;   - No branch, index, or shift count derives from key, nonce, plaintext,
;     ciphertext, or keystream bytes.
;   - The partial group is consumed with vpmaskmovd masked load/store, so
;     the store touches exactly the requested bytes: no read-modify-write
;     of dst past `len`, hence no over-write of caller memory and no
;     length-dependent fault behaviour.
;   - Residue of len mod 4 (0..3 bytes) is finished by a bounded scalar
;     loop; AVX2 has no byte-granular masked store, and a vpblendvb
;     round-trip would write up to 31 bytes past the buffer. The loop trip
;     count is (len & 3) -- public -- and its body is branch-free.
;   - The 256 B keystream scratch is scrubbed on every return path, and
;     vzeroupper is issued before every ret.

DEFAULT REL

section .rodata
align 32
dw_idx: dd 0, 1, 2, 3, 4, 5, 6, 7      ; lane indices for the tail mask

section .text

extern chacha20_blocks4_avx2
extern chacha20_blocks8_avx2
global chacha20_xor_tail_avx2:function

; rdi=dst rsi=src rdx=len rcx=key r8=nonce r9d=counter
;
; frame (after sub rsp,520): 0..511 = 512 B keystream scratch, 512..519 pad
; keeping rsp 16-byte aligned at the inner call sites.
chacha20_xor_tail_avx2:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 520

    mov     r12, rdi                    ; dst cursor
    mov     r13, rsi                    ; src cursor
    mov     r14, rdx                    ; bytes remaining
    mov     rbx, rcx                    ; key
    mov     rbp, r8                     ; nonce
    mov     r15d, r9d                   ; rolling block counter

    ; ---- whole 512 B groups (8-block core: full register bandwidth) ----
.groups:
    cmp     r14, 512
    jb      .groups256
    lea     rdi, [rsp]
    mov     rsi, rbx
    mov     rdx, rbp
    mov     ecx, r15d
    call    chacha20_blocks8_avx2
%assign off 0
%rep 16
    vmovdqu ymm1, [r13 + off]
    vpxor   ymm1, ymm1, [rsp + off]
    vmovdqu [r12 + off], ymm1
%assign off off + 32
%endrep
    add     r12, 512
    add     r13, 512
    add     r15d, 8
    sub     r14, 512
    jmp     .groups

    ; ---- whole 256 B groups (4-block core fallback) ----
.groups256:
    cmp     r14, 256
    jb      .tail
    lea     rdi, [rsp]
    mov     rsi, rbx
    mov     rdx, rbp
    mov     ecx, r15d
    call    chacha20_blocks4_avx2
%assign off 0
%rep 8
    vmovdqu ymm1, [r13 + off]
    vpxor   ymm1, ymm1, [rsp + off]
    vmovdqu [r12 + off], ymm1
%assign off off + 32
%endrep
    add     r12, 256
    add     r13, 256
    add     r15d, 4
    sub     r14, 256
    jmp     .groups256

    ; ---- partial group: 1..255 bytes ----
.tail:
    test    r14, r14
    jz      .scrub                      ; len was a clean multiple of 256:
                                        ; scratch still holds keystream
    lea     rdi, [rsp]
    mov     rsi, rbx
    mov     rdx, rbp
    mov     ecx, r15d
    call    chacha20_blocks4_avx2

    mov     r10, r14
    shr     r10, 2                      ; whole dwords in the tail (public)
    xor     eax, eax                    ; dword offset
.dwloop:
    cmp     rax, r10
    jae     .bytes
    mov     r11, r10
    sub     r11, rax                    ; dwords still owed (>= 1)
    vmovd   xmm0, r11d
    vpbroadcastd ymm0, xmm0
    vpcmpgtd ymm0, ymm0, [rel dw_idx]   ; lane i live iff i < owed
    vpmaskmovd ymm1, ymm0, [r13 + rax*4]
    vpxor   ymm1, ymm1, [rsp + rax*4]   ; keystream read stays in scratch:
                                        ; rax*4 + 32 <= 256 for len <= 255
    vpmaskmovd [r12 + rax*4], ymm0, ymm1
    add     rax, 8
    jmp     .dwloop

    ; ---- residue: len mod 4 bytes (0..3), public trip count ----
.bytes:
    mov     rcx, r14
    and     rcx, 3
    jz      .scrub
    mov     r10, r14
    and     r10, -4                     ; byte offset of the residue
.byteloop:
    mov     al, [r13 + r10]
    xor     al, [rsp + r10]
    mov     [r12 + r10], al
    inc     r10
    dec     rcx
    jnz     .byteloop

    ; ---- scrub keystream scratch + secret-bearing YMMs ----
.scrub:
    vpxor   ymm0, ymm0, ymm0
    lea     r10, [rsp]
    mov     ecx, 512 / 32
.scrubloop:
    vmovdqu [r10], ymm0
    add     r10, 32
    dec     ecx
    jnz     .scrubloop
    vpxor   ymm1, ymm1, ymm1
    xor     eax, eax                    ; al carried a plaintext byte in the
                                        ; residue loop; do not leak it out
    vzeroupper

    add     rsp, 520
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
