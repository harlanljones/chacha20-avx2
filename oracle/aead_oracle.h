#ifndef AEAD_ORACLE_H
#define AEAD_ORACLE_H

#include <stddef.h>
#include <stdint.h>

/*
 * HJ-329 differential oracle adapter.
 *
 * Exposes libsodium's crypto_aead_chacha20poly1305_ietf_encrypt under the
 * SAME contract as the shipped kernel (TDD 3.1): separate key/nonce/aad/
 * plaintext inputs plus separate ciphertext and 16-byte tag outputs.
 *
 * libsodium appends the 16-byte tag to the ciphertext into a single buffer;
 * this adapter splits it back into (ciphertext, tag) so the fuzz harness can
 * call kernel and oracle with one identical interface and compare each
 * component byte-for-byte. libsodium's IETF variant is RFC 8439 with a
 * 12-byte nonce and 32-byte key, so it maps 1:1 onto the kernel (no nonce
 * reinterpretation).
 *
 * Returns 0 on success, or -1 if libsodium reports failure / the output
 * length is inconsistent. Inputs must not be NULL when their length > 0.
 */
int aead_encrypt_libsodium(uint8_t *ciphertext, uint8_t tag[16],
                           const uint8_t *plaintext, size_t plaintext_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t nonce[12], const uint8_t key[32]);

#endif /* AEAD_ORACLE_H */
