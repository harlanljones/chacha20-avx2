/*
 * W9: AEAD composition chacha20_poly1305_encrypt validation.
 *
 * - RFC 8439 Appendix A.2 test vector (sunscreen)
 * - Differential vs reference for payload lengths 0..600
 */
#include "ref.h"
#include "rfc_vectors_data.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern int chacha20_poly1305_encrypt(uint8_t *ciphertext, uint8_t tag[16],
                                      const uint8_t *plaintext, size_t plaintext_len,
                                      const uint8_t *aad, size_t aad_len,
                                      const uint8_t nonce[12], const uint8_t key[32]);

#define TAIL_MAX 600u
static unsigned passed, total;

static void report(const char *name, int ok)
{
    total++;
    if (ok) {
        passed++;
        printf("PASS %s\n", name);
    } else {
        printf("FAIL %s\n", name);
    }
}

int main(void)
{
    uint8_t ct_asm[TAIL_MAX], ct_ref[TAIL_MAX], tag_asm[16], tag_ref[16];
    size_t pt_len;

    /* RFC 8439 Appendix A.2 test vector */
    pt_len = strlen(sun_pt);
    chacha20_poly1305_encrypt_ref(ct_ref, tag_ref,
                                  (const uint8_t *)sun_pt, pt_len,
                                  sun_aad, 12,
                                  sun_nonce, sun_key);
    chacha20_poly1305_encrypt(ct_asm, tag_asm,
                              (const uint8_t *)sun_pt, pt_len,
                              sun_aad, 12,
                              sun_nonce, sun_key);
    report("asm_aead_rfc_a2_sunscreen",
           memcmp(ct_asm, ct_ref, pt_len) == 0 &&
           memcmp(tag_asm, tag_ref, 16) == 0);

    /* Differential vs reference: payload lengths 0..600 */
    {
        static const size_t lens[] = {0,   1,   63,  64,  65,  127, 128,
                                      255, 256, 257, 320, 384,
                                      511, 512, 513, 600};
        for (size_t li = 0; li < sizeof(lens) / sizeof(*lens); li++) {
            char name[64];
            pt_len = lens[li];
            chacha20_poly1305_encrypt_ref(ct_ref, tag_ref,
                                          mtx_pt, pt_len,
                                          mtx_aad12, 12,
                                          mtx_nonce, mtx_key);
            chacha20_poly1305_encrypt(ct_asm, tag_asm,
                                      mtx_pt, pt_len,
                                      mtx_aad12, 12,
                                      mtx_nonce, mtx_key);
            snprintf(name, sizeof(name), "asm_aead_len_%zu", pt_len);
            report(name, memcmp(ct_asm, ct_ref, pt_len) == 0 &&
                   memcmp(tag_asm, tag_ref, 16) == 0);
        }
    }

    printf("%u/%u aead asm checks passed\n", passed, total);
    return passed == total ? 0 : 1;
}
