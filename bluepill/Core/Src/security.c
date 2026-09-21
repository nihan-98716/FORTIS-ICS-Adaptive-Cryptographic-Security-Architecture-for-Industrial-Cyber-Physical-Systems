#include "security.h"
#include <string.h>
#include <stdlib.h>
/* SHA-256 constants */
static const uint32_t K[64] =
{
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32U - (n))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define EP0(x) (ROTR((x),2) ^ ROTR((x),13) ^ ROTR((x),22))
#define EP1(x) (ROTR((x),6) ^ ROTR((x),11) ^ ROTR((x),25))
#define SIG0(x) (ROTR((x),7) ^ ROTR((x),18) ^ ((x) >> 3))
#define SIG1(x) (ROTR((x),17) ^ ROTR((x),19) ^ ((x) >> 10))

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         | ((uint32_t)p[3]);
}

static void store_be32(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

static void sha256_transform(uint32_t state[8],
                             const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    uint32_t i;

    for (i = 0; i < 16; i++)
    {
        w[i] = load_be32(&block[i * 4]);
    }

    for (i = 16; i < 64; i++)
    {
        w[i] = SIG1(w[i - 2])
             + w[i - 7]
             + SIG0(w[i - 15])
             + w[i - 16];
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (i = 0; i < 64; i++)
    {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void SHA256(const uint8_t *data,
            size_t len,
            uint8_t hash[SHA256_DIGEST_SIZE])
{
    uint32_t state[8] =
    {
        0x6a09e667UL,
        0xbb67ae85UL,
        0x3c6ef372UL,
        0xa54ff53aUL,
        0x510e527fUL,
        0x9b05688cUL,
        0x1f83d9abUL,
        0x5be0cd19UL
    };

    uint8_t block[64];
    uint64_t bit_len;
    size_t full_blocks;
    size_t remainder;
    size_t i;

    full_blocks = len / 64U;
    remainder = len % 64U;

    for (i = 0; i < full_blocks; i++)
    {
        sha256_transform(state, &data[i * 64U]);
    }

    memset(block, 0, sizeof(block));

    if (remainder > 0U)
    {
        memcpy(block, &data[full_blocks * 64U], remainder);
    }

    block[remainder] = 0x80U;

    bit_len = (uint64_t)len * 8ULL;

    if (remainder >= 56U)
    {
        sha256_transform(state, block);
        memset(block, 0, sizeof(block));
    }

    block[56] = (uint8_t)(bit_len >> 56);
    block[57] = (uint8_t)(bit_len >> 48);
    block[58] = (uint8_t)(bit_len >> 40);
    block[59] = (uint8_t)(bit_len >> 32);
    block[60] = (uint8_t)(bit_len >> 24);
    block[61] = (uint8_t)(bit_len >> 16);
    block[62] = (uint8_t)(bit_len >> 8);
    block[63] = (uint8_t)bit_len;

    sha256_transform(state, block);

    for (i = 0; i < 8; i++)
    {
        store_be32(&hash[i * 4U], state[i]);
    }
}

void HMAC_SHA256(const uint8_t *key,
                 size_t key_len,
                 const uint8_t *data,
                 size_t data_len,
                 uint8_t mac[HMAC_SHA256_SIZE])
{
    uint8_t key_block[64];
    uint8_t inner_pad[64];
    uint8_t outer_pad[64];

    uint8_t inner_hash[SHA256_DIGEST_SIZE];

    uint8_t *inner_message;
    uint8_t *outer_message;

    size_t i;

    memset(key_block, 0, sizeof(key_block));

    if (key_len > 64U)
    {
        SHA256(key, key_len, key_block);
    }
    else
    {
        memcpy(key_block, key, key_len);
    }

    for (i = 0; i < 64U; i++)
    {
        inner_pad[i] = key_block[i] ^ 0x36U;
        outer_pad[i] = key_block[i] ^ 0x5CU;
    }

    inner_message = (uint8_t *)malloc(64U + data_len);

    if (inner_message == NULL)
    {
        memset(mac, 0, HMAC_SHA256_SIZE);
        return;
    }

    memcpy(inner_message, inner_pad, 64U);

    if (data_len > 0U)
    {
        memcpy(&inner_message[64], data, data_len);
    }

    SHA256(inner_message,
           64U + data_len,
           inner_hash);

    free(inner_message);

    outer_message = (uint8_t *)malloc(64U + SHA256_DIGEST_SIZE);

    if (outer_message == NULL)
    {
        memset(mac, 0, HMAC_SHA256_SIZE);
        return;
    }

    memcpy(outer_message, outer_pad, 64U);
    memcpy(&outer_message[64], inner_hash, SHA256_DIGEST_SIZE);

    SHA256(outer_message,
           64U + SHA256_DIGEST_SIZE,
           mac);

    free(outer_message);

    memset(key_block, 0, sizeof(key_block));
    memset(inner_pad, 0, sizeof(inner_pad));
    memset(outer_pad, 0, sizeof(outer_pad));
    memset(inner_hash, 0, sizeof(inner_hash));
}

int HMAC_Verify(const uint8_t *key,
                size_t key_len,
                const uint8_t *data,
                size_t data_len,
                const uint8_t expected_mac[HMAC_SHA256_SIZE])
{
    uint8_t calculated_mac[HMAC_SHA256_SIZE];
    uint8_t difference = 0;
    size_t i;

    HMAC_SHA256(key,
                key_len,
                data,
                data_len,
                calculated_mac);

    for (i = 0; i < HMAC_SHA256_SIZE; i++)
    {
        difference |= calculated_mac[i] ^ expected_mac[i];
    }

    memset(calculated_mac, 0, sizeof(calculated_mac));

    return (difference == 0U) ? 1 : 0;
}
