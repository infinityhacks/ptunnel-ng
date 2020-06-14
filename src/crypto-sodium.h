#ifndef CRYPTO_SODIUM_H
#define CRYPTO_SODIUM_H 1

#include <sodium.h>
#include <stdint.h>

struct longterm_keypair {
    uint8_t publickey[crypto_kx_PUBLICKEYBYTES];
    uint8_t secretkey[crypto_kx_SECRETKEYBYTES];
};

struct longterm_keypair * generate_keypair_from_secretkey_hexstr_sodium(char const * const secretkey_hexstr,
                                                                        size_t secretkey_hexstr_len)
{
    struct longterm_keypair * keypair = (struct longterm_keypair *)malloc(sizeof(*keypair));

    if (keypair == NULL) {
        return NULL;
    }

    if (sodium_hex2bin(keypair->secretkey, sizeof(keypair->secretkey),
                       secretkey_hexstr, secretkey_hexstr_len, NULL, NULL, NULL) != 0)
    {
        goto error;
    }

    if (crypto_scalarmult_base(keypair->publickey, keypair->secretkey) != 0) {
        goto error;
    }

    sodium_mlock(keypair, sizeof(*keypair));

    return keypair;
error:
    free(keypair);
    return NULL;
}

#endif
