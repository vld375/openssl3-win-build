/*
 * Copyright 2023
 */

#include <openssl/crypto.h>

#include <lwocrypt-alg/belt.h>

#include <lwocrypt-provider/names.h>
#include <lwocrypt-provider/digestcommon.h>
#include <lwocrypt-provider/implementations.h>

/* ossl_belt-hash_functions */
IMPLEMENT_digest_functions(belthash, BELThash_CTX,
                           32, 32, 0,
                           BELT_hash_Init, BELT_hash_Update, BELT_hash_Final)
