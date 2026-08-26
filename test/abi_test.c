/*
 * W14 ABI conformance harness (AGENTS.md section 3.4).
 *
 * Every exported symbol is invoked through an asm probe wrapper
 * (abi_wrappers.asm) that poisons rbx/rbp/r12-r14, forwards the call
 * with ABI-correct stack layout (including the 7th/8th stack args of
 * the AEAD entry point), and reports a violation bitmask:
 *   bit0 direction flag set on return
 *   bit1 rbx  bit2 rbp  bit3 r12  bit4 r13  bit5 r14  bit6 r15
 *
 * A deliberate violator stub proves the detector works (negative
 * control). Kernel symbols get added to this list when they land (W9).
 */
#include "ref.h"
#include "poly1305_bmi2.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern uint64_t abi_wrap_chacha20_block_ref(uint32_t out[16], const uint32_t in[16]);
extern uint64_t abi_wrap_chacha20_init_state_ref(uint32_t st[16], const uint8_t key[32],
                                                 const uint8_t nonce[12], uint32_t ctr);
extern uint64_t abi_wrap_chacha20_xor_ref(uint8_t *dst, const uint8_t *src, size_t len,
                                          const uint8_t key[32], const uint8_t nonce[12],
                                          uint32_t ctr);
extern uint64_t abi_wrap_poly1305_init_ref(poly1305_ctx_ref *ctx, const uint8_t key[32]);
extern uint64_t abi_wrap_poly1305_update_ref(poly1305_ctx_ref *ctx, const uint8_t *m,
                                             size_t n);
extern uint64_t abi_wrap_poly1305_final_ref(poly1305_ctx_ref *ctx, uint8_t tag[16]);
extern uint64_t abi_wrap_poly1305_otk_ref(uint8_t otk[32], const uint8_t key[32],
                                          const uint8_t nonce[12]);
extern uint64_t abi_wrap_chacha20_poly1305_encrypt_ref(
    uint8_t *ct, uint8_t tag[16], const uint8_t *pt, size_t ptlen,
    const uint8_t *aad, size_t aadlen,
    const uint8_t nonce[12], const uint8_t key[32]);
extern uint64_t abi_wrap_chacha20_blocks4_avx2(
    uint8_t dst[256], const uint8_t key[32], const uint8_t nonce[12],
    uint32_t ctr);
extern uint64_t abi_wrap_chacha20_blocks8_avx2(
    uint8_t dst[512], const uint8_t key[32], const uint8_t nonce[12],
    uint32_t ctr);
extern uint64_t abi_wrap_chacha20_keystream_avx2(
    uint8_t *dst, const uint8_t key[32], const uint8_t nonce[12],
    uint32_t ctr, size_t nblocks);
extern uint64_t abi_wrap_chacha20_xor_tail_avx2(
    uint8_t *dst, const uint8_t *src, size_t len, const uint8_t key[32],
    const uint8_t nonce[12], uint32_t ctr);
extern uint64_t abi_wrap_poly1305_init_bmi2(poly1305_ctx_bmi2 *ctx, const uint8_t key[32]);
extern uint64_t abi_wrap_poly1305_update_bmi2(poly1305_ctx_bmi2 *ctx, const uint8_t *m, size_t n);
extern uint64_t abi_wrap_poly1305_final_bmi2(poly1305_ctx_bmi2 *ctx, uint8_t tag[16]);
extern uint64_t abi_wrap_poly1305_auth_bmi2(uint8_t tag[16], const uint8_t *m, size_t n, const uint8_t key[32]);
extern uint64_t abi_wrap_poly1305_blocks_internal(poly1305_ctx_bmi2 *ctx, const uint8_t *m, size_t n, uint32_t pad);
extern uint64_t abi_wrap_chacha20_poly1305_encrypt(
    uint8_t *ct, uint8_t tag[16], const uint8_t *pt, size_t ptlen,
    const uint8_t *aad, size_t aadlen,
    const uint8_t nonce[12], const uint8_t key[32]);
extern uint64_t abi_wrap_abi_violator_impl(void);
extern uint64_t abi_wrap_abi_violator_r15_impl(void);

#define VIOL_EXPECT     0x3u   /* DF + rbx, per the probe bit order */
#define VIOL_R15_EXPECT 0x40u  /* r15 alone */

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
    static uint8_t buf1[1024], buf2[1024];
    static uint32_t st[16], out[16];
    poly1305_ctx_ref mac;
    uint8_t tag[16], otk[32];

    memset(buf1, 0x2a, sizeof buf1);
    memset(buf2, 0x00, sizeof buf2);

#define CHECK(sym, call) \
    report("abi_" #sym, (abi_wrap_##sym call) == 0)

    CHECK(chacha20_block_ref, (out, st));
    CHECK(chacha20_init_state_ref, (st, buf1, buf2, 1));
    CHECK(chacha20_xor_ref, (buf2, buf1, 600, buf1, buf2 + 12, 1));
    CHECK(poly1305_init_ref, (&mac, buf1));
    CHECK(poly1305_update_ref, (&mac, buf1, 600));
    CHECK(poly1305_final_ref, (&mac, tag));
    CHECK(poly1305_otk_ref, (otk, buf1, buf2 + 12));
    CHECK(chacha20_poly1305_encrypt_ref,
          (buf2, tag, buf1, 600, buf1 + 600, 12, buf2 + 12, buf1));
    CHECK(chacha20_blocks4_avx2, (buf2, buf1, buf1 + 32, 1));
    CHECK(chacha20_blocks8_avx2, (buf2, buf1, buf1 + 32, 1));
    CHECK(chacha20_keystream_avx2, (buf2, buf1, buf1 + 32, 1, 4));
    CHECK(chacha20_xor_tail_avx2, (buf2, buf1, 600, buf1, buf1 + 32, 1));
    {
        poly1305_ctx_bmi2 bmi;
        CHECK(poly1305_init_bmi2, (&bmi, buf1));
        CHECK(poly1305_update_bmi2, (&bmi, buf1, 600));
        CHECK(poly1305_final_bmi2, (&bmi, tag));
        CHECK(poly1305_auth_bmi2, (tag, buf1, 600, buf1));
        CHECK(poly1305_blocks_internal, (&bmi, buf1, 16, 1));
    }
    CHECK(chacha20_poly1305_encrypt,
          (buf2, tag, buf1, 600, buf1 + 600, 12, buf2 + 12, buf1));

#undef CHECK

    /* negative control: detector must catch the deliberate violator */
    {
        uint64_t m = abi_wrap_abi_violator_impl();
        printf("     violator mask = 0x%llx\n", (unsigned long long)m);
        report("abi_violator_detected", (m & VIOL_EXPECT) == VIOL_EXPECT);

        m = abi_wrap_abi_violator_r15_impl();
        printf("     r15 violator mask = 0x%llx\n", (unsigned long long)m);
        report("abi_violator_r15_detected", m == VIOL_R15_EXPECT);
    }

    printf("%u/%u ABI checks passed\n", passed, total);
    return passed == total ? 0 : 1;
}
