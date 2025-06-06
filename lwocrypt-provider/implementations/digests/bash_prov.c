/*
 * Copyright 2023
 */

#include <openssl/crypto.h>
#include <lwocrypt-alg/bash.h>


#include <lwocrypt-provider/names.h>
#include <lwocrypt-provider/digestcommon.h>
#include <lwocrypt-provider/implementations.h>

int ossl_bash256_init(void *ctx)
{
    fprintf(stderr, "**** LWOCrypt ossl_bash256_init called \n");
    return BASH_Init((BASH_CTX *)ctx, 128);
}

int ossl_bash384_init(void *ctx)
{
    fprintf(stderr, "**** LWOCrypt ossl_bash384_init called \n");
    return BASH_Init((BASH_CTX *)ctx, 192);
}

int ossl_bash512_init(void *ctx)
{
    fprintf(stderr, "**** LWOCrypt ossl_bash512_init called \n");
    return BASH_Init((BASH_CTX *)ctx, 256);
}

/* ossl_bash256_functions */
IMPLEMENT_digest_functions(bash256, BASH_CTX,
                           128, 32, 0,
                           ossl_bash256_init, BASH_Update, BASH_Final)

/* ossl_bash384_functions */
IMPLEMENT_digest_functions(bash384, BASH_CTX,
                           96, 48, 0,
                           ossl_bash384_init, BASH_Update, BASH_Final)

/* ossl_bash512_functions */
IMPLEMENT_digest_functions(bash512, BASH_CTX,
                           64, 64, 0,
                           ossl_bash512_init, BASH_Update, BASH_Final)
