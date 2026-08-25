#ifndef CHACHA20_POLY1305_REF_H
#define CHACHA20_POLY1305_REF_H

#include <stddef.h>
#include <stdint.h>

/*
 * Portable scalar C reference implementation of RFC 8439
 * ChaCha20-Poly1305 AEAD. Correctness oracle for tests, benchmark
 * baseline comparator (gcc -O3, decision D5), and fuzz seed source.
 *
 * Buffer semantics (proposed for the exported kernel contract, D8):
 * exact pointer overlap (dst == src) is supported; any other overlap
 * between dst/src/aad regions is undefined.
 */

/* Raw ChaCha20 block function: 16 x 32-bit words in, 16 out. */
void chacha20_block_ref(uint32_t out[16], const uint32_t in[16]);

/* Pack key/nonce/counter into the initial ChaCha20 state (constants included). */
void chacha20_init_state_ref(uint32_t st[16], const uint8_t key[32],
                             const uint8_t nonce[12], uint32_t counter);

/* Keystream XOR (encrypt == decrypt) starting at the given block counter. */
void chacha20_xor_ref(uint8_t *dst, const uint8_t *src, size_t len,
                      const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter);

/* Streaming Poly1305 (RFC 8439 section 2.5). */
typedef struct {
    uint32_t r[5];       /* clamped r, radix 2^26          */
    uint32_t h[5];       /* accumulator, radix 2^26        */
    uint32_t pad[4];     /* second half of the one-time key */
    size_t   leftover;
    uint8_t  buffer[16];
} poly1305_ctx_ref;

void poly1305_init_ref(poly1305_ctx_ref *ctx, const uint8_t key[32]);
void poly1305_update_ref(poly1305_ctx_ref *ctx, const uint8_t *msg, size_t len);
void poly1305_final_ref(poly1305_ctx_ref *ctx, uint8_t tag[16]);

/*
 * One-time key derivation (RFC 8439 section 2.6, ratified as G-D7):
 * otk = ChaCha20_block(key, nonce, counter = 0)[0..31].
 */
void poly1305_otk_ref(uint8_t otk[32], const uint8_t key[32],
                      const uint8_t nonce[12]);

/*
 * AEAD encrypt-and-authenticate (RFC 8439 section 2.8).
 * Mirrors the kernel entry-point signature (TDD 3.1). Returns 0.
 */
int chacha20_poly1305_encrypt_ref(
    uint8_t *ciphertext,
    uint8_t tag[16],
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t nonce[12],
    const uint8_t key[32]);

#endif /* CHACHA20_POLY1305_REF_H */
