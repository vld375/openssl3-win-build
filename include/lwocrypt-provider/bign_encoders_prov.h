// bign_encoders_prov.h
#ifndef LWOCRYPT_BIGN_ENCODERS_PROV_H
#define LWOCRYPT_BIGN_ENCODERS_PROV_H

#include <openssl/core_dispatch.h>
#include <lwocrypt-provider/lwocrypt_prov_main.h>

extern const OSSL_DISPATCH ossl_bign_encoder_der_privkey_functions[];
extern const OSSL_DISPATCH ossl_bign_encoder_pem_privkey_functions[];
typedef struct {
    OSSL_LIB_CTX* libctx;
    LWOCRYPT_PROVIDER_CTX* provctx; // Add provctx here
    char* propq; // Property query string
} BIGN_ENCODER_CTX;
#endif /* LWOCRYPT_BIGN_ENCODERS_PROV_H */