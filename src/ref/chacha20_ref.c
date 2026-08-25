#include "ref.h"

#define ROTL(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define QR(a, b, c, d)                  \
    (a) += (b); (d) ^= (a); (d) = ROTL((d), 16); \
    (c) += (d); (b) ^= (c); (b) = ROTL((b), 12); \
    (a) += (b); (d) ^= (a); (d) = ROTL((d), 8);  \
    (c) += (d); (b) ^= (c); (b) = ROTL((b), 7);

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void chacha20_init_state_ref(uint32_t st[16], const uint8_t key[32],
                             const uint8_t nonce[12], uint32_t counter)
{
    static const char sigma[16] = "expand 32-byte k";

    st[0]  = load32_le((const uint8_t *)sigma + 0);
    st[1]  = load32_le((const uint8_t *)sigma + 4);
    st[2]  = load32_le((const uint8_t *)sigma + 8);
    st[3]  = load32_le((const uint8_t *)sigma + 12);
    st[4]  = load32_le(key + 0);
    st[5]  = load32_le(key + 4);
    st[6]  = load32_le(key + 8);
    st[7]  = load32_le(key + 12);
    st[8]  = load32_le(key + 16);
    st[9]  = load32_le(key + 20);
    st[10] = load32_le(key + 24);
    st[11] = load32_le(key + 28);
    st[12] = counter;
    st[13] = load32_le(nonce + 0);
    st[14] = load32_le(nonce + 4);
    st[15] = load32_le(nonce + 8);
}

void chacha20_block_ref(uint32_t out[16], const uint32_t in[16])
{
    uint32_t x[16];
    int i;

    for (i = 0; i < 16; i++)
        x[i] = in[i];

    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[ 8], x[12])
        QR(x[1], x[5], x[ 9], x[13])
        QR(x[2], x[6], x[10], x[14])
        QR(x[3], x[7], x[11], x[15])
        QR(x[0], x[5], x[10], x[15])
        QR(x[1], x[6], x[11], x[12])
        QR(x[2], x[7], x[ 8], x[13])
        QR(x[3], x[4], x[ 9], x[14])
    }

    for (i = 0; i < 16; i++)
        out[i] = x[i] + in[i];
}

void chacha20_xor_ref(uint8_t *dst, const uint8_t *src, size_t len,
                      const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter)
{
    uint32_t st[16], ks[16];
    uint8_t block[64];
    size_t off = 0;
    int i;

    while (off < len) {
        chacha20_init_state_ref(st, key, nonce, counter++);
        chacha20_block_ref(ks, st);

        for (i = 0; i < 16; i++) {
            uint32_t w = ks[i];
            block[i * 4 + 0] = (uint8_t)w;
            block[i * 4 + 1] = (uint8_t)(w >> 8);
            block[i * 4 + 2] = (uint8_t)(w >> 16);
            block[i * 4 + 3] = (uint8_t)(w >> 24);
        }

        {
            size_t n = len - off < 64 ? len - off : 64;
            size_t j;
            for (j = 0; j < n; j++)
                dst[off + j] = src[off + j] ^ block[j];
            off += n;
        }
    }
}
