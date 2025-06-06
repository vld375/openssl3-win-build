/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

 /*
  * AES low level APIs are deprecated for public use, but still ok for internal
  * use where we're using them to implement the higher level EVP interface, as is
  * the case here.
  */
#include "internal/deprecated.h"


#include "cipher_belt.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include <lwocrypt/belt.h>
#include <stdio.h>



static OSSL_FUNC_cipher_newctx_fn belt_newctx;

struct belt_ctx_st {
    PROV_BELT_CTX* provctx;
    BELT_CTX belt_ctx;
};

static void* belt_newctx(void* vprovctx)
{
    struct belt_ctx_st* ctx = malloc(sizeof(*ctx));
    fprintf(stderr, "**** NEW CTX *****\n");
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = vprovctx;
    }
    return ctx;
}


static void belt_freectx(void* vctx)
{
    fprintf(stderr, "**** FREE CTX *****\n");
    struct belt_ctx_st* ctx = vctx;

    ctx->provctx = NULL;

    free(ctx);
}

static void* belt_dupctx(void* vctx)
{
    struct belt_ctx_st* src = vctx;
    struct belt_ctx_st* dst = NULL;
    fprintf(stderr, "**** DUP CTX *****\n");
    if (src == NULL
        || (dst = belt_newctx(NULL)) == NULL)

        dst->provctx = src->provctx;

    return dst;
}

static int belt_cbc256_encrypt_init(void* vctx,
    const unsigned char* key,
    size_t keyl,
    const unsigned char* iv,
    size_t iv_len,
    const OSSL_PARAM params[])
{
    fprintf(stderr, "**** ENC INIT *****\n");
    struct belt_ctx_st *ctx = vctx;
    BELT_cbc_init(&ctx->belt_ctx, key, iv);
    ctx->provctx->base.enc = 1;


    return 0;
}
static int belt_cbc256_decrypt_init(void* vctx,
    const unsigned char* key,
    size_t keyl,
    const unsigned char* iv,
    size_t iv_len,
    const OSSL_PARAM params[])
{
    fprintf(stderr, "**** DEC INIT *****\n");
      struct belt_ctx_st *ctx = vctx;
      BELT_cbc_init(&ctx->belt_ctx, key, iv);
      ctx->provctx->base.enc = 0;

    return 0;
}


static int belt_update(void* vctx,
    unsigned char* out, size_t* outl, size_t outsz,
    const unsigned char* in, size_t inl)
{
    fprintf(stderr, "**** UPDATE INIT *****\n");
    struct belt_ctx_st *ctx = vctx;

    if(ctx->provctx->base.enc == 1) {
        BELT_cbc_encrypt_update(&ctx->belt_ctx,in, inl, out);
    }else {
        BELT_cbc_decrypt_update(&ctx->belt_ctx,in, inl, out);
    }
    return 0;
}

static int belt_final(void* vctx,
    unsigned char* out, size_t* outl, size_t outsz)
{
    struct belt_ctx_st *ctx = vctx;
    fprintf(stderr, "**** FINAL INIT *****\n");
    if(ctx->provctx->base.enc == 1) {
        BELT_cbc_encrypt_final(&ctx->belt_ctx,out);
    }else {
        BELT_cbc_decrypt_final(&ctx->belt_ctx,out);
    }
    return 0;
}
