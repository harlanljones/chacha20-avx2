; W6: AVX2 ChaCha20 4-block-interleave core (src/chacha20_avx2.asm)
;
; Layout (row-broadcast, TDD 2.1): YMM_i = word_i replicated over 4
; lanes, lane j = block j. In this layout a quarter round's four words
; are always four distinct registers, for column AND diagonal rounds
; alike -- no intra-register diagonalization shuffles exist to need
; (D6 evidence: see ticket; shuffle-cost proxy measured separately).
;
; R8 resolution (TDD 3.2 leaves 16 YMMs to state: no rotate scratch,
; no feedforward copy):
;   ymm0-y13 : state words w0-w13, resident
;   w14, w15 : staged through stack slots WORK14/WORK15 around the two
;              rounds each joins per double round (8 L1 stores/loads per
;              double round vs 96 arithmetic ops -- measured cost deferred
;              to W13 tuning; correctness first)
;   ymm15    : dedicated rotate scratch
;   feedforward: initial state saved to stack once at init
;
; Exports:
;   uint32_t-none void chacha20_blocks4_avx2(uint8 dst[256],
;       const uint8 key[32], const uint8 nonce[12], uint32 counter)
;   void chacha20_keystream_avx2(uint8 *dst, const uint8 key[32],
;       const uint8 nonce[12], uint32 counter, size_t nblocks)
;
; Constant-time posture: no branches on key/nonce/state data; control
; flow depends only on the public block count. Secret-bearing YMMs and
; stack slots are scrubbed before every return; vzeroupper on every
; return path.

DEFAULT REL

section .rodata
align 32
sig0: dd 0x61707865
sig1: dd 0x3320646e
sig2: dd 0x79622d32
sig3: dd 0x6b206574
rol16_mask:                         ; byte-rotate left 16 within dword
    db 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
    db 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
rol8_mask:                          ; byte-rotate left 8 within dword
    db 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14
    db 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14
ctr_inc:                            ; lane j gets counter + j (4-block core)
    dd 0,1,2,3, 0,1,2,3
ctr_inc8:                           ; lane j gets counter + j (8-block core)
    dd 0,1,2,3, 4,5,6,7

section .text

global chacha20_blocks4_avx2:function
global chacha20_blocks8_avx2:function
global chacha20_keystream_avx2:function

; ---- rotation helpers ----
%macro ROT16 1                      ; dword ROL 16 via pshufb
    vpshufb %1, %1, [rel rol16_mask]
%endmacro
%macro ROT8 1                       ; dword ROL 8 via pshufb
    vpshufb %1, %1, [rel rol8_mask]
%endmacro
%macro ROTL 2                       ; dword ROL %2 via shift pair, ymm15 scratch
    vpslld  ymm15, %1, %2
    vpsrld  %1, %1, (32 - %2)
    vpor    %1, %1, ymm15
%endmacro

; ---- quarter round: a += b; d ^= a; d<<<16; c += d; b ^= c; b<<<12;
;                     a += b; d ^= a; d<<<8;  c += d; b ^= c; b<<<7 ----
%macro QR 4                         ; a, b, c, d (all ymm regs)
    vpaddd  %1, %1, %2
    vpxor   %4, %4, %1
    ROT16   %4
    vpaddd  %3, %3, %4
    vpxor   %2, %2, %3
    ROTL    %2, 12
    vpaddd  %1, %1, %2
    vpxor   %4, %4, %1
    ROT8    %4
    vpaddd  %3, %3, %4
    vpxor   %2, %2, %3
    ROTL    %2, 7
%endmacro

; ---- one double round incl. w14/w15 staging ----
; CHACHA_NO_DIAG and DR_COUNT exist as assemble-time knobs for the
; D6/R8 bisection harnesses; defaults build the full kernel.
%macro DOUBLE_ROUND 0
    ; column rounds
%ifndef CHACHA_COL_N
%define CHACHA_COL_N 4
%endif
%if CHACHA_COL_N >= 1
    QR ymm0, ymm4, ymm8, ymm12
%endif
%if CHACHA_COL_N >= 2
    QR ymm1, ymm5, ymm9, ymm13
%endif
%if CHACHA_COL_N >= 3
    vmovdqu ymm14, [rsp + 512]
    QR ymm2, ymm6, ymm10, ymm14
    vmovdqu [rsp + 512], ymm14
%endif
%if CHACHA_COL_N >= 4
    vmovdqu ymm14, [rsp + 544]
    QR ymm3, ymm7, ymm11, ymm14
    vmovdqu [rsp + 544], ymm14
%endif
%ifdef CHACHA_NO_DIAG
%else
    ; diagonal rounds
%ifndef CHACHA_DIAG_N
%define CHACHA_DIAG_N 4
%endif
%if CHACHA_DIAG_N >= 1
    vmovdqu ymm14, [rsp + 544]
    QR ymm0, ymm5, ymm10, ymm14
    vmovdqu [rsp + 544], ymm14
%endif
%if CHACHA_DIAG_N >= 2
    QR ymm1, ymm6, ymm11, ymm12
%endif
%if CHACHA_DIAG_N >= 3
    QR ymm2, ymm7, ymm8, ymm13
%endif
%if CHACHA_DIAG_N >= 4
    vmovdqu ymm14, [rsp + 512]
    QR ymm3, ymm4, ymm9, ymm14
    vmovdqu [rsp + 512], ymm14
%endif
%endif
%endmacro

%ifndef DR_COUNT
%define DR_COUNT 10
%endif

; frame layout (rsp-relative, after sub rsp,1120):
;     0..511   initial state copies INIT0..INIT15
;   512..543   WORK14
;   544..575   WORK15
;   576..1087  OUTSCRATCH (final words, 16 x 32B)

chacha20_blocks4_core:
    ; rdi=dst rsi=key rdx=nonce ecx=counter
    sub     rsp, 1120

    vpbroadcastd ymm0, [rel sig0]
    vpbroadcastd ymm1, [rel sig1]
    vpbroadcastd ymm2, [rel sig2]
    vpbroadcastd ymm3, [rel sig3]
    vpbroadcastd ymm4, [rsi]
    vpbroadcastd ymm5, [rsi + 4]
    vpbroadcastd ymm6, [rsi + 8]
    vpbroadcastd ymm7, [rsi + 12]
    vpbroadcastd ymm8, [rsi + 16]
    vpbroadcastd ymm9, [rsi + 20]
    vpbroadcastd ymm10, [rsi + 24]
    vpbroadcastd ymm11, [rsi + 28]
    vmovd   xmm15, ecx                 ; borrow ymm15 pre-loop (no state yet)
    vpbroadcastd ymm12, xmm15
    vpaddd  ymm12, ymm12, [rel ctr_inc] ; lane j = counter + j
    vpbroadcastd ymm13, [rdx]
    vpbroadcastd ymm14, [rdx + 4]

    ; save initial state (feedforward copy)
    vmovdqu [rsp + 0], ymm0
    vmovdqu [rsp + 32], ymm1
    vmovdqu [rsp + 64], ymm2
    vmovdqu [rsp + 96], ymm3
    vmovdqu [rsp + 128], ymm4
    vmovdqu [rsp + 160], ymm5
    vmovdqu [rsp + 192], ymm6
    vmovdqu [rsp + 224], ymm7
    vmovdqu [rsp + 256], ymm8
    vmovdqu [rsp + 288], ymm9
    vmovdqu [rsp + 320], ymm10
    vmovdqu [rsp + 352], ymm11
    vmovdqu [rsp + 384], ymm12
    vmovdqu [rsp + 416], ymm13
    ; w14 = nonce[1], w15 = nonce[2]: build, park in slots
    vpbroadcastd ymm15, [rdx + 8]      ; w15 value via scratch (still pre-loop)
    vmovdqu [rsp + 448], ymm14         ; INIT14
    vmovdqu [rsp + 512], ymm14         ; WORK14
    vmovdqu [rsp + 480], ymm15         ; INIT15
    vmovdqu [rsp + 544], ymm15         ; WORK15

%rep DR_COUNT
    DOUBLE_ROUND
%endrep

    ; feedforward
%ifndef CHACHA_NO_FF
    vpaddd ymm0, ymm0, [rsp + 0]
    vpaddd ymm1, ymm1, [rsp + 32]
    vpaddd ymm2, ymm2, [rsp + 64]
    vpaddd ymm3, ymm3, [rsp + 96]
    vpaddd ymm4, ymm4, [rsp + 128]
    vpaddd ymm5, ymm5, [rsp + 160]
    vpaddd ymm6, ymm6, [rsp + 192]
    vpaddd ymm7, ymm7, [rsp + 224]
    vpaddd ymm8, ymm8, [rsp + 256]
    vpaddd ymm9, ymm9, [rsp + 288]
    vpaddd ymm10, ymm10, [rsp + 320]
    vpaddd ymm11, ymm11, [rsp + 352]
    vpaddd ymm12, ymm12, [rsp + 384]
    vpaddd ymm13, ymm13, [rsp + 416]
    vmovdqu ymm14, [rsp + 512]
    vpaddd ymm14, ymm14, [rsp + 448]
    vmovdqu [rsp + 576 + 14 * 32], ymm14
    vmovdqu ymm14, [rsp + 544]
    vpaddd ymm14, ymm14, [rsp + 480]
    vmovdqu [rsp + 576 + 15 * 32], ymm14
%endif
    vmovdqu [rsp + 576 + 0 * 32], ymm0
    vmovdqu [rsp + 576 + 1 * 32], ymm1
    vmovdqu [rsp + 576 + 2 * 32], ymm2
    vmovdqu [rsp + 576 + 3 * 32], ymm3
    vmovdqu [rsp + 576 + 4 * 32], ymm4
    vmovdqu [rsp + 576 + 5 * 32], ymm5
    vmovdqu [rsp + 576 + 6 * 32], ymm6
    vmovdqu [rsp + 576 + 7 * 32], ymm7
    vmovdqu [rsp + 576 + 8 * 32], ymm8
    vmovdqu [rsp + 576 + 9 * 32], ymm9
    vmovdqu [rsp + 576 + 10 * 32], ymm10
    vmovdqu [rsp + 576 + 11 * 32], ymm11
    vmovdqu [rsp + 576 + 12 * 32], ymm12
    vmovdqu [rsp + 576 + 13 * 32], ymm13

    ; serialize: block j gets dword j of every word vector.
    ; NOTE (R8/W13 note): broadcasts mirror each word into dwords 0..3
    ; AND 4..7; only the low half is consumed, so this core does 4
    ; useful blocks per invocation at half register-bandwidth. The
    ; high half is reserved for an 8-block upgrade in perf tuning.
    lea     r10, [rsp + 576]            ; OUTSCRATCH
    xor     r8d, r8d                    ; j = block index
.lane:
    mov     r11d, 16                    ; i = word index
.word:
    mov     eax, [r10 + r8 * 4]
    mov     [rdi], eax
    add     r10, 32
    add     rdi, 4
    dec     r11d
    jnz     .word
    sub     r10, 16 * 32                ; rewind vector base
    inc     r8d
    cmp     r8d, 4
    jb      .lane

    ; scrub secret-bearing state: initial-state copies, work slots,
    ; keystream scratch (all key-derived), then all YMMs
    vpxor   ymm0, ymm0, ymm0
    lea     r10, [rsp + 1088]
    mov     r8d, 1088 / 32
.scrub:
    sub     r10, 32
    vmovdqu [r10], ymm0
    dec     r8d
    jnz     .scrub
    vpxor   ymm0, ymm0, ymm0
    vpxor   ymm1, ymm1, ymm1
    vpxor   ymm2, ymm2, ymm2
    vpxor   ymm3, ymm3, ymm3
    vpxor   ymm4, ymm4, ymm4
    vpxor   ymm5, ymm5, ymm5
    vpxor   ymm6, ymm6, ymm6
    vpxor   ymm7, ymm7, ymm7
    vpxor   ymm8, ymm8, ymm8
    vpxor   ymm9, ymm9, ymm9
    vpxor   ymm10, ymm10, ymm10
    vpxor   ymm11, ymm11, ymm11
    vpxor   ymm12, ymm12, ymm12
    vpxor   ymm13, ymm13, ymm13
    vpxor   ymm14, ymm14, ymm14
    vpxor   ymm15, ymm15, ymm15
    vzeroupper
    add     rsp, 1120
    ret

; ---- 8-block core (HJ-430): consume all 8 ymm lanes. ----
; Identical round/frame as the 4-block core, but lanes 4..7 hold the
; DISTINCT blocks 4..7 (ctr_inc8 -> w12 = counter + lane), so one
; invocation produces 512 bytes of schedule for the same round cost as
; the 4-block core's 256 bytes: no wasted high half. The 4-block core
; stays byte-exact and unchanged; this core is kept INTERNAL (not
; exported); chacha20_keystream_avx2 selects it when >= 8 blocks remain.
;   rdi=dst (512B) rsi=key rdx=nonce ecx=counter
chacha20_blocks8_core:
    sub     rsp, 1120

    vpbroadcastd ymm0, [rel sig0]
    vpbroadcastd ymm1, [rel sig1]
    vpbroadcastd ymm2, [rel sig2]
    vpbroadcastd ymm3, [rel sig3]
    vpbroadcastd ymm4, [rsi]
    vpbroadcastd ymm5, [rsi + 4]
    vpbroadcastd ymm6, [rsi + 8]
    vpbroadcastd ymm7, [rsi + 12]
    vpbroadcastd ymm8, [rsi + 16]
    vpbroadcastd ymm9, [rsi + 20]
    vpbroadcastd ymm10, [rsi + 24]
    vpbroadcastd ymm11, [rsi + 28]
    vmovd   xmm15, ecx                 ; borrow ymm15 pre-loop (no state yet)
    vpbroadcastd ymm12, xmm15
    vpaddd  ymm12, ymm12, [rel ctr_inc8] ; lane j = counter + j, j = 0..7
    vpbroadcastd ymm13, [rdx]
    vpbroadcastd ymm14, [rdx + 4]

    ; save initial state (feedforward copy)
    vmovdqu [rsp + 0], ymm0
    vmovdqu [rsp + 32], ymm1
    vmovdqu [rsp + 64], ymm2
    vmovdqu [rsp + 96], ymm3
    vmovdqu [rsp + 128], ymm4
    vmovdqu [rsp + 160], ymm5
    vmovdqu [rsp + 192], ymm6
    vmovdqu [rsp + 224], ymm7
    vmovdqu [rsp + 256], ymm8
    vmovdqu [rsp + 288], ymm9
    vmovdqu [rsp + 320], ymm10
    vmovdqu [rsp + 352], ymm11
    vmovdqu [rsp + 384], ymm12
    vmovdqu [rsp + 416], ymm13
    ; w14 = nonce[1], w15 = nonce[2]: build, park in slots
    vpbroadcastd ymm15, [rdx + 8]      ; w15 value via scratch (still pre-loop)
    vmovdqu [rsp + 448], ymm14         ; INIT14
    vmovdqu [rsp + 512], ymm14         ; WORK14
    vmovdqu [rsp + 480], ymm15         ; INIT15
    vmovdqu [rsp + 544], ymm15         ; WORK15

%rep DR_COUNT
    DOUBLE_ROUND
%endrep

    ; feedforward
%ifndef CHACHA_NO_FF
    vpaddd ymm0, ymm0, [rsp + 0]
    vpaddd ymm1, ymm1, [rsp + 32]
    vpaddd ymm2, ymm2, [rsp + 64]
    vpaddd ymm3, ymm3, [rsp + 96]
    vpaddd ymm4, ymm4, [rsp + 128]
    vpaddd ymm5, ymm5, [rsp + 160]
    vpaddd ymm6, ymm6, [rsp + 192]
    vpaddd ymm7, ymm7, [rsp + 224]
    vpaddd ymm8, ymm8, [rsp + 256]
    vpaddd ymm9, ymm9, [rsp + 288]
    vpaddd ymm10, ymm10, [rsp + 320]
    vpaddd ymm11, ymm11, [rsp + 352]
    vpaddd ymm12, ymm12, [rsp + 384]
    vpaddd ymm13, ymm13, [rsp + 416]
    vmovdqu ymm14, [rsp + 512]
    vpaddd ymm14, ymm14, [rsp + 448]
    vmovdqu [rsp + 576 + 14 * 32], ymm14
    vmovdqu ymm14, [rsp + 544]
    vpaddd ymm14, ymm14, [rsp + 480]
    vmovdqu [rsp + 576 + 15 * 32], ymm14
%endif
    vmovdqu [rsp + 576 + 0 * 32], ymm0
    vmovdqu [rsp + 576 + 1 * 32], ymm1
    vmovdqu [rsp + 576 + 2 * 32], ymm2
    vmovdqu [rsp + 576 + 3 * 32], ymm3
    vmovdqu [rsp + 576 + 4 * 32], ymm4
    vmovdqu [rsp + 576 + 5 * 32], ymm5
    vmovdqu [rsp + 576 + 6 * 32], ymm6
    vmovdqu [rsp + 576 + 7 * 32], ymm7
    vmovdqu [rsp + 576 + 8 * 32], ymm8
    vmovdqu [rsp + 576 + 9 * 32], ymm9
    vmovdqu [rsp + 576 + 10 * 32], ymm10
    vmovdqu [rsp + 576 + 11 * 32], ymm11
    vmovdqu [rsp + 576 + 12 * 32], ymm12
    vmovdqu [rsp + 576 + 13 * 32], ymm13

    ; serialize: block j gets dword j of every word vector; j = 0..7,
    ; so all 8 ymm lanes are consumed (512 bytes, full register width).
    lea     r10, [rsp + 576]            ; OUTSCRATCH
    xor     r8d, r8d                    ; j = block index
.lane8:
    mov     r11d, 16                    ; i = word index
.word8:
    mov     eax, [r10 + r8 * 4]
    mov     [rdi], eax
    add     r10, 32
    add     rdi, 4
    dec     r11d
    jnz     .word8
    sub     r10, 16 * 32                ; rewind vector base
    inc     r8d
    cmp     r8d, 8
    jb      .lane8

    ; scrub secret-bearing state: initial-state copies, work slots,
    ; keystream scratch (all key-derived), then all YMMs
    vpxor   ymm0, ymm0, ymm0
    lea     r10, [rsp + 1088]
    mov     r8d, 1088 / 32
.scrub8:
    sub     r10, 32
    vmovdqu [r10], ymm0
    dec     r8d
    jnz     .scrub8
    vpxor   ymm0, ymm0, ymm0
    vpxor   ymm1, ymm1, ymm1
    vpxor   ymm2, ymm2, ymm2
    vpxor   ymm3, ymm3, ymm3
    vpxor   ymm4, ymm4, ymm4
    vpxor   ymm5, ymm5, ymm5
    vpxor   ymm6, ymm6, ymm6
    vpxor   ymm7, ymm7, ymm7
    vpxor   ymm8, ymm8, ymm8
    vpxor   ymm9, ymm9, ymm9
    vpxor   ymm10, ymm10, ymm10
    vpxor   ymm11, ymm11, ymm11
    vpxor   ymm12, ymm12, ymm12
    vpxor   ymm13, ymm13, ymm13
    vpxor   ymm14, ymm14, ymm14
    vpxor   ymm15, ymm15, ymm15
    vzeroupper
    add     rsp, 1120
    ret

chacha20_blocks4_avx2:
    jmp     chacha20_blocks4_core

; exported alias so the composed AEAD bulk path (W7) and the ABI probe
; can drive the 8-block core directly.
chacha20_blocks8_avx2:
    jmp     chacha20_blocks8_core

; void chacha20_keystream_avx2(uint8 *dst, const uint8 key[32],
;                              const uint8 nonce[12], uint32 counter,
;                              size_t nblocks)
; rdi=dst rsi=key rdx=nonce ecx=counter r8=nblocks
; Loop state rides in callee-saved rbx/r12/r13 (saved/restored here).
; The core treats rsi/rdx as read-only inputs, so they survive calls.
; Branches depend only on the public block count (documented; W7 owns
; the mask-based CT tail treatment for the composed AEAD path).
chacha20_keystream_avx2:
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, 280                    ; 256B scratch at [rsp]; call sites stay ABI-aligned

    mov     ebx, r8d                    ; blocks remaining
    mov     r12d, ecx                   ; rolling block counter
    mov     r13, rdi                    ; output cursor
.groups:
    cmp     ebx, 8
    jb      .groups4
    mov     ecx, r12d
    mov     rdi, r13
    call    chacha20_blocks8_core       ; writes a full 512B group directly
    add     r12d, 8
    add     r13, 512
    sub     ebx, 8
    jmp     .groups
.groups4:
    cmp     ebx, 4
    jb      .tail
    mov     ecx, r12d
    mov     rdi, r13
    call    chacha20_blocks4_core       ; writes a full 256B group directly
    add     r12d, 4
    add     r13, 256
    sub     ebx, 4
    jmp     .groups4
.tail:
    test    ebx, ebx
    jz      .done
    mov     ecx, r12d
    lea     rdi, [rsp]                  ; remainder group -> stack scratch
    call    chacha20_blocks4_core
    mov     rdi, r13
    lea     rsi, [rsp]
    mov     rcx, rbx
    shl     rcx, 3                      ; rem*64 bytes = rem*8 qwords
    rep     movsq
    vpxor   ymm0, ymm0, ymm0            ; scrub keystream scratch
    lea     r10, [rsp + 256]
    mov     ecx, 256 / 32
.scrub_tail:
    sub     r10, 32
    vmovdqu [r10], ymm0
    dec     ecx
    jnz     .scrub_tail
    vzeroupper
.done:
    vzeroupper
    add     rsp, 280
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
