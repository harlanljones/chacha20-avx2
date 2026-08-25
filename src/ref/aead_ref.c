#include "ref.h"

/*
 * RFC 8439 section 2.8 AEAD composition (encrypt direction).
 *
 * G-D7 ratified wiring: the Poly1305 one-time key is the first 32
 * bytes of ChaCha20_block(key, nonce, counter = 0); otk[0..15] is the
 * clamped r half, otk[16..27] the s (pad) half. MAC input framing:
 * AAD || pad16 || ciphertext || pad16 || le64(aad_len) || le64(ct_len).
 * Ciphertext keystream starts at block counter 1; counter 0 is the KDF.
 */
int chacha20_poly1305_encrypt_ref(
    uint8_t *ciphertext,
    uint8_t tag[16],
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t nonce[12],
    const uint8_t key[32])
{
    poly1305_ctx_ref mac;
    uint8_t otk[32];
    uint8_t block[16];
    uint64_t alen = (uint64_t)aad_len;
    uint64_t clen = (uint64_t)plaintext_len;

    chacha20_xor_ref(ciphertext, plaintext, plaintext_len,
                     key, nonce, 1);

    poly1305_otk_ref(otk, key, nonce);
    poly1305_init_ref(&mac, otk);

    if (aad_len)
        poly1305_update_ref(&mac, aad, aad_len);
    if (aad_len % 16) {
        size_t pad = 16 - (aad_len % 16);
        size_t i;
        for (i = 0; i < pad; i++)
            block[i] = 0;
        poly1305_update_ref(&mac, block, pad);
    }

    if (plaintext_len)
        poly1305_update_ref(&mac, ciphertext, plaintext_len);
    if (plaintext_len % 16) {
        size_t pad = 16 - (plaintext_len % 16);
        size_t i;
        for (i = 0; i < pad; i++)
            block[i] = 0;
        poly1305_update_ref(&mac, block, pad);
    }

    {
        uint8_t trailer[16];
        size_t i;
        for (i = 0; i < 8; i++) {
            trailer[i]     = (uint8_t)(alen >> (8 * i));
            trailer[8 + i] = (uint8_t)(clen >> (8 * i));
        }
        poly1305_update_ref(&mac, trailer, 16);
    }

    poly1305_final_ref(&mac, tag);

    for (size_t i = 0; i < 32; i++)
        otk[i] = 0;

    return 0;
}

void poly1305_otk_ref(uint8_t otk[32], const uint8_t key[32],
                      const uint8_t nonce[12])
{
    uint32_t st[16], out[16];
    int i;

    chacha20_init_state_ref(st, key, nonce, 0);
    chacha20_block_ref(out, st);

    /* serialize first 32 bytes little-endian */
    for (i = 0; i < 8; i++) {
        uint32_t w = out[i];
        otk[i * 4 + 0] = (uint8_t)w;
        otk[i * 4 + 1] = (uint8_t)(w >> 8);
        otk[i * 4 + 2] = (uint8_t)(w >> 16);
        otk[i * 4 + 3] = (uint8_t)(w >> 24);
    }
}
