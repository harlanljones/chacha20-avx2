/*
 * W8: Poly1305 BMI2/ADX validation, wired into `make test`.
 *  - RFC 8439 2.5.2 and pm_* vectors
 *  - Sweep 0..600 vs reference, split-update, and auth single-shot
 */
#include "ref.h"
#include "poly1305_bmi2.h"
#include "rfc_vectors_data.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static unsigned passed, total;
static void report(const char *name, int ok) {
    total++;
    if (ok) { passed++; printf("PASS %s\n", name); } else printf("FAIL %s\n", name);
}

static int check_rfc252(void) {
    static const char *msg = "Cryptographic Forum Research Group";
    static const uint8_t key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,
        0x42,0xd5,0x06,0xa8,0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b };
    static const uint8_t want[16] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
        0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9 };
    poly1305_ctx_bmi2 c;
    uint8_t got[16];
    poly1305_init_bmi2(&c, key);
    poly1305_update_bmi2(&c, (const uint8_t*)msg, strlen(msg));
    poly1305_final_bmi2(&c, got);
    return memcmp(got, want, 16)==0;
}

static int check_pm_case(size_t len, const uint8_t *want) {
    poly1305_ctx_bmi2 c;
    uint8_t got[16];
    poly1305_init_bmi2(&c, pm_key);
    poly1305_update_bmi2(&c, pm_msg, len);
    poly1305_final_bmi2(&c, got);
    return memcmp(got, want, 16)==0;
}

int main(void) {
    size_t i;
    uint8_t msg[600];
    for (i=0;i<600;i++) msg[i]=(uint8_t)(i*7+11);

    report("poly_bmi2_rfc252", check_rfc252());

    // pm vectors via update/final
    {
        struct { size_t len; const uint8_t *tag; } cases[] = {
            {0, pm_len0_tag}, {1, pm_len1_tag}, {15, pm_len15_tag}, {16, pm_len16_tag},
            {17, pm_len17_tag}, {31, pm_len31_tag}, {32, pm_len32_tag}, {63, pm_len63_tag},
        };
        for (i=0;i<sizeof cases/sizeof cases[0];i++) {
            char name[64];
            snprintf(name,sizeof name,"poly_bmi2_pm_len_%zu", cases[i].len);
            report(name, check_pm_case(cases[i].len, cases[i].tag));
        }
    }
    // auth single-shot vs reference
    {
        int ok=1;
        for (i=0;i<8;i++) {
            static const size_t lens[]={0,1,15,16,17,31,32,63};
            size_t len=lens[i];
            uint8_t tr[16], tb[16];
            poly1305_ctx_ref r;
            poly1305_init_ref(&r, pm_key);
            poly1305_update_ref(&r, pm_msg, len);
            poly1305_final_ref(&r, tr);
            poly1305_auth_bmi2(tb, pm_msg, len, pm_key);
            if(memcmp(tr,tb,16)!=0) ok=0;
        }
        report("poly_bmi2_auth_vs_ref", ok);
    }
    // sweep 0..600 vs ref
    {
        int ok=1; size_t first_bad=(size_t)-1;
        for (i=0;i<=600;i++) {
            uint8_t tr[16], tb[16];
            poly1305_ctx_ref r;
            poly1305_ctx_bmi2 b;
            poly1305_init_ref(&r, pm_key);
            poly1305_update_ref(&r, msg, i);
            poly1305_final_ref(&r, tr);
            poly1305_init_bmi2(&b, pm_key);
            poly1305_update_bmi2(&b, msg, i);
            poly1305_final_bmi2(&b, tb);
            if(memcmp(tr,tb,16)!=0){ if(ok) first_bad=i; ok=0; }
        }
        report("poly_bmi2_sweep_0_600", ok);
        if(!ok) printf("  first mismatch %zu\n", first_bad);
    }
    // split update: 2 parts
    {
        int ok=1; size_t first_bad=(size_t)-1;
        for (i=0;i<=600;i++) {
            size_t split = i/2;
            uint8_t tr[16], tb[16];
            poly1305_ctx_ref r;
            poly1305_ctx_bmi2 b;
            poly1305_init_ref(&r, pm_key);
            poly1305_update_ref(&r, msg, split);
            poly1305_update_ref(&r, msg+split, i-split);
            poly1305_final_ref(&r, tr);
            poly1305_init_bmi2(&b, pm_key);
            poly1305_update_bmi2(&b, msg, split);
            poly1305_update_bmi2(&b, msg+split, i-split);
            poly1305_final_bmi2(&b, tb);
            if(memcmp(tr,tb,16)!=0){ if(ok) first_bad=i; ok=0; }
        }
        report("poly_bmi2_split_0_600", ok);
        if(!ok) printf("  first split mismatch %zu\n", first_bad);
    }
    // test vectors from rfc_vectors_data.h via auth
    {
        // use pm_key/msg already, also test with mtx
        (void)0;
    }

    printf("%u/%u poly_bmi2 checks passed\n", passed, total);
    return passed==total?0:1;
}
