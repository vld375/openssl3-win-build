/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This implemments a dummy key manager for legacy KDFs that still support the
 * old way of performing a KDF via EVP_PKEY_derive(). New KDFs should not be
 * implemented this way. In reality there is no key data for such KDFs, so this
 * key manager does very little.
 */
#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include <lwocrypt-provider/lwocrypt_prov_main.h>
#include <lwocrypt-provider/implementations.h>
#include <lwocrypt-provider/providercommon.h>
#include <lwocrypt-provider/provider_ctx.h>
#include <lwocrypt-alg/bign_local.h>

 



static OSSL_FUNC_signature_newctx_fn bign_signature_newctx;
static OSSL_FUNC_signature_freectx_fn bign_signature_freectx;
static OSSL_FUNC_signature_sign_init_fn bign_signature_sign_init;
static OSSL_FUNC_signature_sign_fn bign_signature_sign;
static OSSL_FUNC_signature_verify_init_fn bign_signature_verify_init;
static OSSL_FUNC_signature_verify_fn bign_signature_verify;
static OSSL_FUNC_signature_digest_sign_init_fn bign_signature_digest_sign_init;
static OSSL_FUNC_signature_digest_verify_init_fn bign_signature_digest_verify_init;

typedef struct {
    EVP_PKEY* pkey;
    const OSSL_PARAM* params;
    OSSL_LIB_CTX* libctx;
} BIGN_SIGNATURE_CTX;

static void* bign_signature_newctx(void* provctx)
{
    BIGN_SIGNATURE_CTX* ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    // Получаем libctx из provctx
    LWOCRYPT_PROVIDER_CTX* pctx = provctx;
    ctx->libctx = pctx->libctx;

    return ctx;
}

static void bign_signature_freectx(void* vctx)
{
    BIGN_SIGNATURE_CTX* ctx = vctx;
    EVP_PKEY_free(ctx->pkey);
    OPENSSL_free(ctx);
}

static int bign_signature_sign_init(void* vctx, void* provkey, const OSSL_PARAM params[])
{
    BIGN_SIGNATURE_CTX* ctx = vctx;
    if (!EVP_PKEY_up_ref(provkey))
        return 0;

    ctx->pkey = provkey;
    ctx->params = params;
    return 1;
}

static int bign_signature_sign(void* vctx, unsigned char* sig, size_t* siglen,
    size_t sigsize, const unsigned char* tbs, size_t tbslen)
{
    BIGN_SIGNATURE_CTX* ctx = vctx;
    EVP_MD_CTX* md_ctx = NULL;
    unsigned char digest[32]; // BELT hash is 256 bits
    size_t digest_len = sizeof(digest);
    EVP_PKEY_CTX* pkey_ctx = NULL;
    int ret = 0;

    if (!ctx || !ctx->pkey || !ctx->libctx) {
        fprintf(stderr, "bign_signature_sign: Invalid context or key\n");
        return 0;
    }

    // Compute BELT hash of tbs
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx || !EVP_DigestInit_ex(md_ctx, EVP_get_digestbyname("BELT-HASH"), NULL) ||
        !EVP_DigestUpdate(md_ctx, tbs, tbslen) ||
        !EVP_DigestFinal_ex(md_ctx, digest, &digest_len)) {
        fprintf(stderr, "bign_signature_sign: Failed to compute BELT hash: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
        goto err;
    }

    // Initialize signing with the private key
    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx, ctx->pkey, NULL);
    if (!pkey_ctx || EVP_PKEY_sign_init(pkey_ctx) <= 0) {
        fprintf(stderr, "bign_signature_sign: Failed to initialize signing: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
        goto err;
    }

    // Determine signature size
    if (sig == NULL) {
        if (EVP_PKEY_sign(pkey_ctx, NULL, siglen, digest, digest_len) <= 0) {
            fprintf(stderr, "bign_signature_sign: Failed to get signature size: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
            goto err;
        }
        ret = 1;
        goto err;
    }

    // Check buffer size
    if (sigsize < *siglen) {
        fprintf(stderr, "bign_signature_sign: Buffer too small (%zu < %zu)\n", sigsize, *siglen);
        goto err;
    }

    // Sign the digest
    if (EVP_PKEY_sign(pkey_ctx, sig, siglen, digest, digest_len) <= 0) {
        fprintf(stderr, "bign_signature_sign: Failed to sign: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
        goto err;
    }

    ret = 1;

err:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pkey_ctx);
    return ret;
}
static int bign_signature_verify_init(void* vctx, void* provkey, const OSSL_PARAM params[])
{
    BIGN_SIGNATURE_CTX* ctx = vctx;
    if (!ctx || !provkey) {
        fprintf(stderr, "bign_signature_verify_init: Invalid context or key\n");
        return 0;
    }

    if (!EVP_PKEY_up_ref(provkey)) {
        fprintf(stderr, "bign_signature_verify_init: Failed to increment key reference: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }

    EVP_PKEY_free(ctx->pkey); // Free existing key, if any
    ctx->pkey = provkey;
    ctx->params = params;
    return 1;
}
static int bign_signature_verify(void* vctx, const unsigned char* sig, size_t siglen,
    const unsigned char* tbs, size_t tbslen)
{
    BIGN_SIGNATURE_CTX* ctx = vctx;
    EVP_MD_CTX* md_ctx = NULL;
    unsigned char digest[32]; // BELT hash is 256 bits
    size_t digest_len = sizeof(digest);
    EVP_PKEY_CTX* pkey_ctx = NULL;
    int ret = 0;

    if (!ctx || !ctx->pkey || !ctx->libctx || !sig) {
        fprintf(stderr, "bign_signature_verify: Invalid context, key, or signature\n");
        return 0;
    }

    // Compute BELT hash of tbs
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx || !EVP_DigestInit_ex(md_ctx, EVP_get_digestbyname("BELT-HASH"), NULL) ||
        !EVP_DigestUpdate(md_ctx, tbs, tbslen) ||
        !EVP_DigestFinal_ex(md_ctx, digest, &digest_len)) {
        fprintf(stderr, "bign_signature_verify: Failed to compute BELT hash: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
        goto err;
    }

    // Initialize verification with the public key
    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx, ctx->pkey, NULL);
    if (!pkey_ctx || EVP_PKEY_verify_init(pkey_ctx) <= 0) {
        fprintf(stderr, "bign_signature_verify: Failed to initialize verification: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
        goto err;
    }

    // Verify the signature
    ret = EVP_PKEY_verify(pkey_ctx, sig, siglen, digest, digest_len);
    if (ret <= 0) {
        fprintf(stderr, "bign_signature_verify: Verification failed: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    }

err:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pkey_ctx);
    return ret;
}
static int bign_signature_digest_sign_init(void* vctx, void* provkey, const OSSL_PARAM params[])
{
    
    return bign_signature_sign_init(vctx, provkey, params); // Reuse sign_init
}
static int bign_signature_digest_verify(void* vctx, void* provkey, const OSSL_PARAM params[])
{
    return bign_signature_verify_init(vctx, provkey, params); // Reuse verify_init
}
static int bign_signature_digest_verify_init(void* vctx, void* provkey, const OSSL_PARAM params[])
{
    return bign_signature_sign_init(vctx, provkey, params); // Reuse sign_init
}
const OSSL_DISPATCH ossl_bign_hbelt_signature_functions[] = {
   { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))bign_signature_newctx },
   { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))bign_signature_freectx },
   { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))bign_signature_sign_init },
   { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))bign_signature_sign },
   { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))bign_signature_verify_init },
   { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))bign_signature_verify },
   { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))bign_signature_digest_sign_init },
   { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))bign_signature_digest_verify_init },
   { 0, NULL }
};
