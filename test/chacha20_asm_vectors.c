/*
 * W6: AVX2 assembly ChaCha20 validation, wired into `make test`.
 *
 *  - A.1 #1 block vector through chacha20_blocks4_avx2 (counter=1)
 *  - keystream differential vs the C reference for payload lengths
 *    0..600 (prefix compare; full-length-matrix differential lands
 *    with W9/W11 composition work)
 */
#include "ref.h"
#include "rfc_vectors_data.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

void chacha20_blocks4_avx2(uint8_t dst[256], const uint8_t key[32],
                           const uint8_t nonce[12], uint32_t ctr);
void chacha20_keystream_avx2(uint8_t *dst, const uint8_t key[32],
                             const uint8_t nonce[12], uint32_t ctr,
                             size_t nblocks);

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
    uint8_t ks[1024];
    static const uint8_t zeros[1024] = {0};
    uint8_t refct[1024], tag[16];

    /* A.1 #1 via 4-block core: A.1 inputs, counter=1 */
    {
        uint8_t a1key[32], a1nonce[12] = {0,0,0,0x09,0,0,0,0x4a,0,0,0,0};
        int i;
        for (i = 0; i < 32; i++)
            a1key[i] = (uint8_t)i;
        memset(ks, 0xAA, sizeof ks);
        chacha20_blocks4_avx2(ks, a1key, a1nonce, 1);
        report("asm_blocks4_rfc_A1_tv1",
               memcmp(ks, blkfn_tv1_expected, 64) == 0);
    }

    /* keystream prefix differential vs reference */
    {
        static const size_t lens[] = {0,1,63,64,65,127,128,255,256,257,400,600};
        size_t li;
        for (li = 0; li < sizeof lens / sizeof *lens; li++) {
            char name[64];
            size_t n = lens[li];
            size_t nb = (n + 63) / 64;
            snprintf(name, sizeof name, "asm_ks_len_%zu", n);
            chacha20_poly1305_encrypt_ref(refct, tag, zeros, n,
                                          mtx_aad12, 12, mtx_nonce, mtx_key);
            memset(ks, 0x55, sizeof ks);
            chacha20_keystream_avx2(ks, mtx_key, mtx_nonce, 1, nb ? nb : 1);
            report(name, memcmp(ks, refct, n) == 0);
        }
    }

    printf("%u/%u asm checks passed\n", passed, total);
    return passed == total ? 0 : 1;
}
