/*
 * HJ-329: differential libFuzzer harness.
 *
 * Compares the shipped kernel chacha20_poly1305_encrypt (src/aead.asm)
 * against libsodium crypto_aead_chacha20poly1305_ietf_encrypt on the same
 * randomized inputs. Any difference in return code, ciphertext, or the
 * 16-byte tag triggers __builtin_trap(), which libFuzzer reports as a crash
 * together with the minimal reproducer input.
 *
 * Deterministic data layout (so any mismatch is reproducible):
 *   [0,32)   key
 *   [32,44)  nonce
 *   [44,...) aad || plaintext
 *
 * The aad/plaintext boundary is derived from two bytes inside the nonce
 * region (always present once size >= 44), so it is deterministic and
 * independent of the exact input length. Both aad_len and plaintext_len can
 * be 0, covering the empty-tail edge cases; the total consumed length is
 * capped at FUZZ_MAX_TOTAL (1 MiB).
 *
 * Build/link (see Makefile `fuzz-aead`): clang -fsanitize=fuzzer,address,undefined
 * with the nasm-built kernel objects + the libsodium oracle adapter.
 */
#include "aead_oracle.h"

#include <sodium.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Kernel entry point (src/aead.asm), TDD 3.1. */
extern int chacha20_poly1305_encrypt(uint8_t *ciphertext, uint8_t tag[16],
                                     const uint8_t *plaintext, size_t plaintext_len,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t nonce[12], const uint8_t key[32]);

/* ~1 MiB cap so a single fuzzed input cannot balloon memory. */
#define FUZZ_MAX_TOTAL (1024u * 1024u)

enum { KEY_LEN = 32, NONCE_LEN = 12, HEADER_LEN = KEY_LEN + NONCE_LEN };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t sodium_ready = 0;

    if (!sodium_ready) {
        if (sodium_init() < 0)
            return 0; /* libsodium unusable; nothing to compare */
        sodium_ready = 1;
    }

    /* Need at least key + nonce to form an input. */
    if (size < HEADER_LEN)
        return 0;

    const uint8_t *key = data;                 /* 32 bytes  */
    const uint8_t *nonce = data + KEY_LEN;     /* 12 bytes  */
    const uint8_t *buf = data + HEADER_LEN;    /* aad||ct? -> aad||pt */

    size_t rem = size - HEADER_LEN;
    if (rem > FUZZ_MAX_TOTAL)
        rem = FUZZ_MAX_TOTAL;

    /* Boundary in [0, rem]; the two nonce bytes are always present. */
    uint16_t ratio = (uint16_t)(nonce[10] | ((uint16_t)nonce[11] << 8));
    size_t aad_len = (size_t)(((uint64_t)ratio * (rem + 1u)) >> 16);
    size_t pt_len = rem - aad_len;

    const uint8_t *aad = buf;
    const uint8_t *pt = buf + aad_len;

    uint8_t *ct_kern = malloc(pt_len ? pt_len : 1u);
    uint8_t *ct_lib = malloc(pt_len ? pt_len : 1u);
    uint8_t tag_kern[16], tag_lib[16];
    int rk, rl;
    int ok;

    if (!ct_kern || !ct_lib) {
        free(ct_kern);
        free(ct_lib);
        return 0;
    }

    rk = chacha20_poly1305_encrypt(ct_kern, tag_kern,
                                   pt, pt_len, aad, aad_len, nonce, key);
    rl = aead_encrypt_libsodium(ct_lib, tag_lib,
                                pt, pt_len, aad, aad_len, nonce, key);

    ok = (rk == rl)
      && (memcmp(tag_kern, tag_lib, 16) == 0)
      && (pt_len == 0 || memcmp(ct_kern, ct_lib, pt_len) == 0);

    free(ct_kern);
    free(ct_lib);

    if (!ok)
        __builtin_trap();

    return 0;
}
