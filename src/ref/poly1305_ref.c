#include "ref.h"

/*
 * Poly1305, radix 2^26 scalar reference (RFC 8439 section 2.5).
 * The r limbs are pre-clamped at init, so the block loop needs no
 * clamp masks; finalize uses mask selects only (no secret branches).
 */

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void poly1305_init_ref(poly1305_ctx_ref *ctx, const uint8_t key[32])
{
    uint32_t t0, t1, t2, t3;
    int i;

    /* RFC clamp applied to the raw little-endian words before the
       radix-2^26 split: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff.
       In limb space the cleared bits land at 2..7 (r1), 8..13 (r2),
       14..19 (r3); r4 carries the remaining 20 bits (r < 2^124). */
    t0 = load32_le(key + 0);
    t1 = load32_le(key + 4);
    t2 = load32_le(key + 8);
    t3 = load32_le(key + 12);

    ctx->r[0] = t0 & 0x3ffffff;
    ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    ctx->r[4] = (t3 >> 8) & 0x00fffff;

    for (i = 0; i < 4; i++)
        ctx->pad[i] = load32_le(key + 16 + i * 4);

    ctx->h[0] = ctx->h[1] = ctx->h[2] = ctx->h[3] = ctx->h[4] = 0;
    ctx->leftover = 0;
}

static void poly1305_blocks_ref(poly1305_ctx_ref *st, const uint8_t *m,
                                size_t bytes, uint32_t hibit)
{
    const uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2],
                   r3 = st->r[3], r4 = st->r[4];
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2],
             h3 = st->h[3], h4 = st->h[4];

    while (bytes >= 16) {
        uint64_t d0, d1, d2, d3, d4;
        uint32_t c, t0, t1, t2, t3;

        t0 = load32_le(m + 0);
        t1 = load32_le(m + 4);
        t2 = load32_le(m + 8);
        t3 = load32_le(m + 12);

        h0 += t0 & 0x3ffffff;
        h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h4 += (t3 >> 8) | hibit;

        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 +
             (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 +
             (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 +
             (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 +
             (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 +
             (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        bytes -= 16;
        m += 16;
    }

    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2;
    st->h[3] = h3; st->h[4] = h4;
}

void poly1305_update_ref(poly1305_ctx_ref *ctx, const uint8_t *msg, size_t len)
{
    size_t i;

    if (ctx->leftover) {
        size_t want = 16 - ctx->leftover;
        if (want > len)
            want = len;
        for (i = 0; i < want; i++)
            ctx->buffer[ctx->leftover + i] = msg[i];
        ctx->leftover += want;
        len -= want;
        msg += want;

        if (ctx->leftover < 16)
            return;
        poly1305_blocks_ref(ctx, ctx->buffer, 16, 1u << 24);
        ctx->leftover = 0;
    }

    if (len >= 16) {
        size_t take = len & ~(size_t)15;
        poly1305_blocks_ref(ctx, msg, take, 1u << 24);
        msg += take;
        len -= take;
    }

    if (len) {
        for (i = 0; i < len; i++)
            ctx->buffer[i] = msg[i];
        ctx->leftover = len;
    }
}

void poly1305_final_ref(poly1305_ctx_ref *ctx, uint8_t tag[16])
{
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4, mask;
    uint64_t f;
    uint8_t mp[16];
    size_t i;

    if (ctx->leftover) {
        i = ctx->leftover;
        ctx->buffer[i++] = 1;
        for (; i < 16; i++)
            ctx->buffer[i] = 0;
        poly1305_blocks_ref(ctx, ctx->buffer, 16, 0);
    }

    /* full carry */
    h0 = ctx->h[0]; h1 = ctx->h[1]; h2 = ctx->h[2];
    h3 = ctx->h[3]; h4 = ctx->h[4];

    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    /* compute h + -p; select via mask, not branch */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    mask = (g4 >> ((sizeof(uint32_t) * 8) - 1)) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h0 + h1*2^26 + ... mod 2^128 */
    h0 = (h0) | (h1 << 26);
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);

    f = (uint64_t)h0 + ctx->pad[0];               h0 = (uint32_t)f;
    f = (uint64_t)h1 + ctx->pad[1] + (f >> 32);   h1 = (uint32_t)f;
    f = (uint64_t)h2 + ctx->pad[2] + (f >> 32);   h2 = (uint32_t)f;
    f = (uint64_t)h3 + ctx->pad[3] + (f >> 32);   h3 = (uint32_t)f;

    store32_le(tag + 0, h0);
    store32_le(tag + 4, h1);
    store32_le(tag + 8, h2);
    store32_le(tag + 12, h3);
}
