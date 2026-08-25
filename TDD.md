# **Technical Design Document: High-Throughput ChaCha20-Poly1305 SIMD Kernel**

## **1\. Overview & Objectives**

This document specifies the technical design for a standalone, high-throughput implementation of the **ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD)** construction (RFC 8439), written in hand-tuned **x86-64 Assembly (NASM)** utilizing the **AVX2** (256-bit) instruction set.

### **Core Goals**

* **Maximum Throughput:** Outperform standard gcc \-O3 compiled C implementations by saturating vector execution ports and unrolling critical loops.  
* **Side-Channel Resistance:** Strictly constant-time execution paths; zero secret-dependent branching or table lookups.  
* **Standard Conformance:** Zero external runtime dependencies (no libc required in the kernel) with full System V AMD64 ABI compliance.

## **2\. Architecture & Algorithmic Blueprint**

The implementation consists of two decoupled mathematical engines unified under a single AEAD API:

                  \+-----------------------------------+  
                  |  AEAD Input: Key, Nonce, AAD, PT  |  
                  \+-----------------+-----------------+  
                                    |  
            \+-----------------------+-----------------------+  
            |                                               |  
            v                                               v  
\+-----------------------+                       \+-----------------------+  
|  ChaCha20 Engine      |                       |  Poly1305 Engine      |  
|  \- 4-Block AVX2 Inter-|                       |  \- Radix-$2^{64}$ or  |  
|    leave (256 bytes)  |                       |    Radix-$2^{26}$     |  
|  \- Generates Key \+ CT |                       |  \- Authenticates AAD  |  
\+-----------+-----------+                       |    and Ciphertext     |  
            |                                   \+-----------+-----------+  
            \+-----------------------+-----------------------+  
                                    |  
                                    v  
                  \+-----------------------------------+  
                  |  Output: Ciphertext \+ 16-Byte Tag |  
                  \+-----------------------------------+

### **2.1 ChaCha20 Quarter-Round Mapping (AVX2)**

The ChaCha20 state comprises sixteen 32-bit words ($4 \\times 4$ matrix). Using 256-bit AVX2 registers (ymm0–ymm15), the engine processes **4 full blocks (256 bytes) in parallel**:

* **State Layout:** Each 256-bit register holds one state word across 4 independent blocks:  
  $$\\text{YMM}\_i \= \[w\_i^{(\\text{block } 3)} \\mid w\_i^{(\\text{block } 2)} \\mid w\_i^{(\\text{block } 1)} \\mid w\_i^{(\\text{block } 0)}\]$$  
* **Quarter-Round Arithmetic:**  
  * **Addition:** vpaddd  
  * **XOR:** vpxor  
  * **Rotations:**  
    * $\\text{ROL}(16)$: vpshufb using a precomputed broadcast mask.  
    * $\\text{ROL}(8)$: vpshufb using a precomputed broadcast mask.  
    * $\\text{ROL}(12), \\text{ROL}(7)$: vpslld \+ vpsrld combined via vpor.  
* **State Diagonalization:** Handled via intra-register lane shuffles (vpshufd) to switch between column rounds and diagonal rounds without spilling to memory.

### **2.2 Poly1305 MAC Architecture**

Poly1305 evaluates a polynomial modulo the prime $2^{130} \- 5$:

$$A\_{i} \= ((A\_{i-1} \+ C\_i) \\times r) \\pmod{2^{130} \- 5}$$

* **Radix Strategy:** Use multi-precision 64-bit integer arithmetic with scalar registers (rax, rdx, r8–r11) using mulx, adcx, and adox (BMI2 / ADX extensions) for carry-chain interleaving.  
* **Clamping:** The evaluation key $r$ is clamped directly during initialization using fixed bitwise masks.

## **3\. ABI & Data Structures**

### **3.1 C-Compatible API Definition**

The kernel exposes the standard System V AMD64 calling convention:

C  
\#**include** \<stdint.h\>  
\#**include** \<stddef.h\>

typedef struct {  
    uint8\_t key\[32\];  
} chacha20\_poly1305\_ctx;

// Core AEAD Encrypt & Authenticate Entry Point  
int chacha20\_poly1305\_encrypt(  
    uint8\_t \*ciphertext,             // rdi  
    uint8\_t tag\[16\],                 // rsi  
    const uint8\_t \*plaintext,        // rdx  
    size\_t plaintext\_len,            // rcx  
    const uint8\_t \*aad,              // r8  
    size\_t aad\_len,                  // r9  
    const uint8\_t nonce\[12\],         // \[rsp \+ 8\] (Stack)  
    const uint8\_t key\[32\]            // \[rsp \+ 16\] (Stack)  
);

### **3.2 Register Allocation Map**

| Register Group | Allocated Function / State | Volatility |
| :---- | :---- | :---- |
| ymm0 – ymm3 | ChaCha20 State Rows 0–3 (Constants, Key) | Volatile |
| ymm4 – ymm7 | ChaCha20 State Rows 4–7 (Key, Counter, Nonce) | Volatile |
| ymm8 – ymm11 | Working Registers / Intermediate Operands | Volatile |
| ymm12 – ymm15 | Pre-broadcast Shuffle Masks & Constants | Volatile |
| rax, rdx, rcx | Scratch / Length Trackers / Hardware Multiply | Volatile |
| rsi, rdi | Source (Plaintext/AAD) / Dest (Ciphertext) Pointers | Volatile |
| r8 – r11 | Poly1305 Accumulator ($h\_0, h\_1, h\_2$) & Clamped Key ($r\_0, r\_1$) | Volatile |
| rbx, rbp, r12–r15 | Callee-saved (Preserved on stack if used) | Non-volatile |

## **4\. Implementation Plan & Milestones**

Phase 1: Scalar Reference & Test Harness (Days 1–3)  
├── Implement standard RFC 8439 test vectors in C  
└── Set up cycle-accurate benchmarking harness (rdtsc/rdtscp)

Phase 2: ChaCha20 AVX2 Vector Core (Days 4–8)  
├── Implement 4-block 256-bit parallel state setup  
├── Implement constant-time rotation primitives via VPSHUFB  
└── Optimize loop unrolling (20 rounds \= 10 iterations of double-round)

Phase 3: Poly1305 ADX Engine (Days 9–12)  
├── Implement scalar 64-bit multi-precision modular accumulator  
├── Integrate ADX carry chains (adcx / adox)  
└── Build padding and tag generation logic

Phase 4: Pipeline Integration & Verification (Days 13–16)  
├── Interleave ChaCha20 keystream generation with Poly1305 consumption  
├── Implement scalar fallback tail for payloads \< 256 bytes  
└── Run differential fuzzing against OpenSSL / libsodium

## **5\. Security & Verification Strategies**

### **5.1 Side-Channel Mitigation**

* **Branch Elimination:** No conditional branches depend on secret keys, nonce, plaintext, or intermediate state words.  
* **Lookup Table Free:** S-Box-less architecture ensures immunity to cache-timing attacks (e.g., Prime+Probe).  
* **Zeroing Secret State:** Stack frames and vector registers must be overwritten with vpxor / vzeroall prior to function return.

### **5.2 Test Vectors & Validation**

* **RFC 8439 Appendix A:** Strict verification against standardized test vectors for:  
  * ChaCha20 block function.  
  * Poly1305 authenticator single-step evaluations.  
  * Combined AEAD encrypt/decrypt with associated data.  
* **Differential Fuzzing:** A dedicated fuzz harness comparing outputs of the assembly kernel against libsodium using **AFL++** or **libFuzzer** across randomized payload lengths (0 to $10^6$ bytes).