/*
 * HJ-329: deterministic differential smoke check (non-fuzz, has a main).
 *
 * For a fixed list of plaintext/AAD lengths (0, 1, 63, 64, 65, 255, 256,
 * 257, 1024), compare the kernel chacha20_poly1305_encrypt against the
 * libsodium oracle aead_encrypt_libsodium on deterministic pseudo-random
 * key/nonce/aad/plaintext. This exercises the tail/fallback paths that the
 * fuzz loop hits only by luck, and gives explicit evidence that the two
 * implementations agree before the differential fuzz claims pass.
 *
 * Build: clang -fsanitize=address,undefined ... (see Makefile `check-diff`).
 */
#include "aead_oracle.h"

#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern int chacha20_poly1305_encrypt(uint8_t *ciphertext, uint8_t tag[16],
                                     const uint8_t *plaintext, size_t plaintext_len,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t nonce[12], const uint8_t key[32]);

#define FIXED_LENS_MAX 1024u

typedef struct {
    uint64_t s;
} prng;

static uint32_t prng_next(prng *r)
{
    uint64_t x = r->s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    r->s = x;
    return (uint32_t)(x >> 32);
}

static void fill(prng *r, uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        p[i] = (uint8_t)prng_next(r);
}

int main(void)
{
    static const size_t lens[] = {0, 1, 63, 64, 65, 255, 256, 257, 1024};
    prng r = {0x9E3779B97F4A7C15ULL};

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 2;
    }

    for (size_t li = 0; li < sizeof(lens) / sizeof(*lens); li++) {
        size_t pt_len = lens[li];
        size_t aad_len = pt_len / 3; /* vary the aad length too */
        uint8_t key[32], nonce[12];
        uint8_t aad[FIXED_LENS_MAX / 3];
        uint8_t pt[FIXED_LENS_MAX];
        uint8_t ct_kern[FIXED_LENS_MAX], ct_lib[FIXED_LENS_MAX];
        uint8_t tag_kern[16], tag_lib[16];
        int rk, rl, ok;

        fill(&r, key, sizeof(key));
        fill(&r, nonce, sizeof(nonce));
        fill(&r, aad, aad_len);
        fill(&r, pt, pt_len);

        rk = chacha20_poly1305_encrypt(ct_kern, tag_kern,
                                       pt, pt_len, aad, aad_len, nonce, key);
        rl = aead_encrypt_libsodium(ct_lib, tag_lib,
                                    pt, pt_len, aad, aad_len, nonce, key);

        ok = (rk == rl)
          && (memcmp(tag_kern, tag_lib, 16) == 0)
          && memcmp(ct_kern, ct_lib, pt_len) == 0;

        printf("%s diff aad=%3zu pt=%3zu (rc %d/%d)\n",
               ok ? "PASS" : "FAIL", aad_len, pt_len, rk, rl);
        if (!ok)
            return 1;
    }

    printf("%zu/%zu differential smoke checks passed\n",
           sizeof(lens) / sizeof(*lens), sizeof(lens) / sizeof(*lens));
    return 0;
}
