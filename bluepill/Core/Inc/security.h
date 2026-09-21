#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_SIZE 32
#define HMAC_SHA256_SIZE   32

/*
 * SHA-256
 */
void SHA256(const uint8_t *data, size_t len,
            uint8_t hash[SHA256_DIGEST_SIZE]);

/*
 * HMAC-SHA256
 */
void HMAC_SHA256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t mac[HMAC_SHA256_SIZE]);

/*
 * Constant-time HMAC verification
 *
 * Returns:
 *   1 = valid
 *   0 = invalid / tampered
 */
int HMAC_Verify(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                const uint8_t expected_mac[HMAC_SHA256_SIZE]);

#endif /* SECURITY_H */
