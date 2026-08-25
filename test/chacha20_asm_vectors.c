/*
 * W6: AVX2 assembly ChaCha20 validation, wired into `make test`.
 *
 *  - A.1 #1 block vector through chacha20_blocks4_avx2 (counter=1)
 *  - keystream differential vs the C reference for payload lengths
 *    0..600 (prefix compare; full-length-matrix differential lands
 *    with W9/W11 composition work)
 *
 * W7 additions: constant-time tail/scalar fallback path
 * (chacha20_xor_tail_avx2) checked bit-exact against chacha20_xor_ref
 * over an exhaustive 0..600 length sweep, plus in-place aliasing,
 * out-of-bounds write detection, and non-zero start counters.
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
void chacha20_xor_tail_avx2(uint8_t *dst, const uint8_t *src, size_t len,
                            const uint8_t key[32], const uint8_t nonce[12],
                            uint32_t ctr);

#define TAIL_MAX  600u
#define TAIL_GUARD 64u
#define GUARD_BYTE 0xCCu

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


/*
 * W7 tail-path harness.
 *
 * `pt` is a non-constant pattern so a keystream/plaintext mix-up cannot
 * pass by symmetry the way an all-zero plaintext can. Every destination
 * buffer carries a guard band so a masked store that writes past `len`
 * is caught rather than silently tolerated.
 */
static uint8_t tail_pt[TAIL_MAX];
static uint8_t tail_got[TAIL_MAX + TAIL_GUARD];
static uint8_t tail_exp[TAIL_MAX];

static void tail_init_pattern(void)
{
    size_t i;
    for (i = 0; i < TAIL_MAX; i++)
        tail_pt[i] = (uint8_t)(i * 7u + (i >> 3) + 1u);
}

/* Returns 1 when the guard band past `len` is still pristine. */
static int guard_intact(size_t len)
{
    size_t i;
    for (i = len; i < len + TAIL_GUARD; i++)
        if (tail_got[i] != GUARD_BYTE)
            return 0;
    return 1;
}

static void w7_tail_checks(void)
{
    static const size_t named[] = {0,   1,   63,  64,  65,  127, 128, 255,
                                   256, 257, 320, 384, 511, 512, 513, 600};
    size_t li, n;
    int sweep_ok = 1, guard_ok = 1, inplace_ok = 1, ctr_ok = 1;
    size_t sweep_first_bad = (size_t)-1, guard_first_bad = (size_t)-1;
    size_t inplace_first_bad = (size_t)-1, ctr_first_bad = (size_t)-1;

    tail_init_pattern();

    /* Explicitly named lengths from the ticket / AGENTS.md 3.5. */
    for (li = 0; li < sizeof named / sizeof *named; li++) {
        char name[64];
        n = named[li];
        chacha20_xor_ref(tail_exp, tail_pt, n, mtx_key, mtx_nonce, 1);
        memset(tail_got, GUARD_BYTE, sizeof tail_got);
        chacha20_xor_tail_avx2(tail_got, tail_pt, n, mtx_key, mtx_nonce, 1);
        snprintf(name, sizeof name, "asm_tail_len_%zu", n);
        report(name, memcmp(tail_got, tail_exp, n) == 0 && guard_intact(n));
    }

    /* Exhaustive sweep: every length 0..600, aggregated. */
    for (n = 0; n <= TAIL_MAX; n++) {
        chacha20_xor_ref(tail_exp, tail_pt, n, mtx_key, mtx_nonce, 1);
        memset(tail_got, GUARD_BYTE, sizeof tail_got);
        chacha20_xor_tail_avx2(tail_got, tail_pt, n, mtx_key, mtx_nonce, 1);
        if (memcmp(tail_got, tail_exp, n) != 0) {
            if (sweep_ok)
                sweep_first_bad = n;
            sweep_ok = 0;
        }
        if (!guard_intact(n)) {
            if (guard_ok)
                guard_first_bad = n;
            guard_ok = 0;
        }
    }
    report("asm_tail_sweep_0_600", sweep_ok);
    if (!sweep_ok)
        printf("     first mismatching length: %zu\n", sweep_first_bad);
    report("asm_tail_no_write_past_len", guard_ok);
    if (!guard_ok)
        printf("     first over-write at length: %zu\n", guard_first_bad);

    /* In-place: dst == src must produce the same ciphertext. */
    for (n = 0; n <= TAIL_MAX; n++) {
        chacha20_xor_ref(tail_exp, tail_pt, n, mtx_key, mtx_nonce, 1);
        memset(tail_got, GUARD_BYTE, sizeof tail_got);
        memcpy(tail_got, tail_pt, n);
        chacha20_xor_tail_avx2(tail_got, tail_got, n, mtx_key, mtx_nonce, 1);
        if (memcmp(tail_got, tail_exp, n) != 0 || !guard_intact(n)) {
            if (inplace_ok)
                inplace_first_bad = n;
            inplace_ok = 0;
        }
    }
    report("asm_tail_inplace_0_600", inplace_ok);
    if (!inplace_ok)
        printf("     first in-place mismatch at length: %zu\n",
               inplace_first_bad);

    /*
     * Non-zero / wrapping start counters: W9 enters the tail path at
     * counter 1 after the D7 KDF burns block 0, and a long message can
     * carry the 32-bit counter over.
     */
    {
        static const uint32_t ctrs[] = {0u, 1u, 2u, 7u, 0xFFFFFFFEu,
                                        0xFFFFFFFFu};
        static const size_t clens[] = {1, 63, 64, 65, 255, 256, 257, 600};
        size_t ci, cj;
        for (ci = 0; ci < sizeof ctrs / sizeof *ctrs; ci++) {
            for (cj = 0; cj < sizeof clens / sizeof *clens; cj++) {
                n = clens[cj];
                chacha20_xor_ref(tail_exp, tail_pt, n, mtx_key, mtx_nonce,
                                 ctrs[ci]);
                memset(tail_got, GUARD_BYTE, sizeof tail_got);
                chacha20_xor_tail_avx2(tail_got, tail_pt, n, mtx_key,
                                       mtx_nonce, ctrs[ci]);
                if (memcmp(tail_got, tail_exp, n) != 0 || !guard_intact(n)) {
                    if (ctr_ok)
                        ctr_first_bad = n;
                    ctr_ok = 0;
                }
            }
        }
    }
    report("asm_tail_counter_variants", ctr_ok);
    if (!ctr_ok)
        printf("     first counter-variant mismatch at length: %zu\n",
               ctr_first_bad);
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

    w7_tail_checks();

    printf("%u/%u asm checks passed\n", passed, total);
    return passed == total ? 0 : 1;
}
