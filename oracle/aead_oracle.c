#include "aead_oracle.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

int aead_encrypt_libsodium(uint8_t *ciphertext, uint8_t tag[16],
                           const uint8_t *plaintext, size_t plaintext_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t nonce[12], const uint8_t key[32])
{
    unsigned long long clen = 0;
    size_t scratch_sz = plaintext_len + 16u;
    uint8_t *scratch;
    int rc;

    scratch = malloc(scratch_sz ? scratch_sz : 1u);
    if (!scratch)
        return -1;

    /* libsodium writes ciphertext||tag into one buffer, tag = 16 bytes. */
    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
        scratch, &clen,
        plaintext, (unsigned long long)plaintext_len,
        aad, (unsigned long long)aad_len,
        NULL, nonce, key);
    if (rc != 0 || clen != plaintext_len + 16u) {
        free(scratch);
        return -1;
    }

    memcpy(ciphertext, scratch, plaintext_len);
    memcpy(tag, scratch + plaintext_len, 16u);
    free(scratch);
    return 0;
}
