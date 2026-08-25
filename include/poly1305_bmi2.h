#ifndef POLY1305_BMI2_H
#define POLY1305_BMI2_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t r0;
    uint64_t r1;
    uint64_t h0;
    uint64_t h1;
    uint64_t h2;
    uint64_t s0;
    uint64_t s1;
    size_t leftover;
    uint8_t buf[16];
} poly1305_ctx_bmi2;

void poly1305_init_bmi2(poly1305_ctx_bmi2 *ctx, const uint8_t key[32]);
void poly1305_update_bmi2(poly1305_ctx_bmi2 *ctx, const uint8_t *m, size_t len);
void poly1305_final_bmi2(poly1305_ctx_bmi2 *ctx, uint8_t tag[16]);
void poly1305_auth_bmi2(uint8_t tag[16], const uint8_t *m, size_t len, const uint8_t key[32]);
void poly1305_blocks_internal(poly1305_ctx_bmi2 *ctx, const uint8_t *m, size_t len, uint32_t padbit);

#endif
