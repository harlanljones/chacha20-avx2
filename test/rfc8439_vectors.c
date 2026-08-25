/*
 * W4: RFC 8439 vector suite wired into `make test`.
 *
 * Expected values live in rfc_vectors_data.h (checked in). Provenance:
 * generated from the W3 reference implementation, every case
 * cross-asserted against libsodium at generation time, and anchored to
 * published RFC 8439 hex where available (A.1 #1 first row, 2.8.2
 * ciphertext head + tag). The suite grows monotonically and is never
 * weakened to force a pass (AGENTS.md section 3.1).
 */
#include "ref.h"
#include "rfc_vectors_data.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

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

static int check_block_fn(void)
{
    uint8_t key[32], nonce[12] = {0,0,0,0x09,0,0,0,0x4a,0,0,0,0};
    uint32_t st[16], out[16];
    uint8_t ser[64];
    int i;

    for (i = 0; i < 32; i++)
        key[i] = (uint8_t)i;
    chacha20_init_state_ref(st, key, nonce, 1);
    chacha20_block_ref(out, st);
    for (i = 0; i < 16; i++) {
        ser[i*4+0] = (uint8_t)(out[i] & 0xff);
        ser[i*4+1] = (uint8_t)((out[i] >> 8) & 0xff);
        ser[i*4+2] = (uint8_t)((out[i] >> 16) & 0xff);
        ser[i*4+3] = (uint8_t)((out[i] >> 24) & 0xff);
    }
    return memcmp(ser, blkfn_tv1_expected, 64) == 0;
}

static int check_otk(void)
{
    uint8_t key[32], nonce[12] = {0,0,0,0,0,1,2,3,4,5,6,7}, otk[32];
    int i;

    for (i = 0; i < 32; i++)
        key[i] = (uint8_t)(0x80 + i);
    poly1305_otk_ref(otk, key, nonce);
    return memcmp(otk, otk_262_expected, 32) == 0;
}

/* RFC 8439 section 2.5.2, hex as published in the RFC. */
static int check_poly_252(void)
{
    static const char *msg = "Cryptographic Forum Research Group";
    static const uint8_t key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,
        0x42,0xd5,0x06,0xa8,0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b };
    static const uint8_t want[16] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
        0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9 };
    poly1305_ctx_ref c;
    uint8_t got[16];

    poly1305_init_ref(&c, key);
    poly1305_update_ref(&c, (const uint8_t *)msg, strlen(msg));
    poly1305_final_ref(&c, got);
    return memcmp(got, want, 16) == 0;
}

static int check_sunscreen(void)
{
    uint8_t ct[sizeof sun_ct_expected], tag[16];

    chacha20_poly1305_encrypt_ref(ct, tag, (const uint8_t *)sun_pt,
                                  sizeof sun_ct_expected,
                                  sun_aad, sizeof sun_aad,
                                  sun_nonce, sun_key);
    return memcmp(ct, sun_ct_expected, sizeof sun_ct_expected) == 0 &&
           memcmp(tag, sun_tag_expected, 16) == 0;
}

typedef struct {
    size_t len;
    const uint8_t *ct;
    const uint8_t *tag;
} aead_case;

static const aead_case kAeadCases[] = {
    {0,   NULL,               mtx_len0_tag},
    {1,   mtx_len1_ct,        mtx_len1_tag},
    {63,  mtx_len63_ct,       mtx_len63_tag},
    {64,  mtx_len64_ct,       mtx_len64_tag},
    {65,  mtx_len65_ct,       mtx_len65_tag},
    {127, mtx_len127_ct,      mtx_len127_tag},
    {128, mtx_len128_ct,      mtx_len128_tag},
    {255, mtx_len255_ct,      mtx_len255_tag},
    {256, mtx_len256_ct,      mtx_len256_tag},
    {257, mtx_len257_ct,      mtx_len257_tag},
    {400, mtx_len400_ct,      mtx_len400_tag},
    {600, mtx_len600_ct,      mtx_len600_tag},
};

static int check_aead_case(const aead_case *tc)
{
    uint8_t ct[600], tag[16];
    int ok;

    chacha20_poly1305_encrypt_ref(ct, tag, mtx_pt, tc->len,
                                  mtx_aad12, 12, mtx_nonce, mtx_key);
    ok = memcmp(tag, tc->tag, 16) == 0;
    if (tc->len)
        ok = ok && memcmp(ct, tc->ct, tc->len) == 0;
    return ok;
}

typedef struct {
    size_t len;
    const uint8_t *tag;
} poly_case;

static const poly_case kPolyCases[] = {
    {0,  pm_len0_tag},
    {1,  pm_len1_tag},
    {15, pm_len15_tag},
    {16, pm_len16_tag},
    {17, pm_len17_tag},
    {31, pm_len31_tag},
    {32, pm_len32_tag},
    {63, pm_len63_tag},
};

static int check_poly_case(const poly_case *pc)
{
    poly1305_ctx_ref c;
    uint8_t got[16];

    poly1305_init_ref(&c, pm_key);
    poly1305_update_ref(&c, pm_msg, pc->len);
    poly1305_final_ref(&c, got);
    return memcmp(got, pc->tag, 16) == 0;
}

int main(void)
{
    size_t i;

    report("block_fn_rfc8439_A1_tv1", check_block_fn());
    report("poly_rfc8439_252", check_poly_252());
    report("otk_derivation_rfc8439_262", check_otk());
    report("aead_rfc8439_282_sunscreen", check_sunscreen());
    for (i = 0; i < sizeof kAeadCases / sizeof kAeadCases[0]; i++) {
        char name[64];
        snprintf(name, sizeof name, "aead_len_%zu%s",
                 kAeadCases[i].len,
                 kAeadCases[i].len == 0 ? "_aad_only" : "");
        report(name, check_aead_case(&kAeadCases[i]));
    }
    for (i = 0; i < sizeof kPolyCases / sizeof kPolyCases[0]; i++) {
        char name[64];
        snprintf(name, sizeof name, "poly_len_%zu", kPolyCases[i].len);
        report(name, check_poly_case(&kPolyCases[i]));
    }

    printf("%u/%u vectors passed\n", passed, total);
    return passed == total ? 0 : 1;
}
