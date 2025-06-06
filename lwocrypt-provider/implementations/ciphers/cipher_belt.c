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
//#include "internal/deprecated.h"
//
//
//#include "cipher_belt.h"
//#include "prov/implementations.h"
//#include "prov/providercommon.h"
//#include <lwocrypt/belt.h>
//#include <stdio.h>


//const OSSL_DISPATCH ossl_belt256cbc_functions[] = {
//    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))belt_newctx },
//    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))belt_cbc256_encrypt_init },
//    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))belt_cbc256_decrypt_init },
//    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))belt_update },
//    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))belt_final },
//    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))belt_cipher},
//    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))belt_dupctx },
//    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))belt_freectx },
//    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))belt_get_params },
//    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))ossl_cipher_generic_gettable_params },
//    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))ossl_cipher_generic_get_ctx_params },
//    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))ossl_cipher_generic_gettable_ctx_params },
//    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))belt_set_ctx_params },
//    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))belt_settable_ctx_params },
//    { 0, NULL }
//};

/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

 /* Dispatch functions for ARIA cipher modes ecb, cbc, ofb, cfb, ctr */

#include  <lwocrypt-provider/cipher_belt.h>
#include <lwocrypt-provider/implementations.h>
#include <lwocrypt-provider/providercommon.h>


static OSSL_FUNC_cipher_freectx_fn belt_freectx;
static OSSL_FUNC_cipher_dupctx_fn belt_dupctx;

static void belt_freectx(void* vctx)
{
    PROV_BELT_CTX* ctx = (PROV_BELT_CTX*)vctx;

    ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX*)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void* belt_dupctx(void* ctx)
{
    fprintf(stderr, "**** LWOCrypt belt_dupctx called \n");
    PROV_BELT_CTX* in = (PROV_BELT_CTX*)ctx;
    PROV_BELT_CTX* ret;



    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->base.hw->copyctx(&ret->base, &in->base);

    return ret;
}

/* ossl_aria256ecb_functions */
IMPLEMENT_generic_cipher(belt, BELT, ecb, ECB, 0, 256, 128, 0, block)
/* ossl_aria192ecb_functions */
IMPLEMENT_generic_cipher(belt, BELT, ecb, ECB, 0, 192, 128, 0, block)
/* ossl_aria128ecb_functions */
IMPLEMENT_generic_cipher(belt, BELT, ecb, ECB, 0, 128, 128, 0, block)
/* ossl_aria256cbc_functions */
IMPLEMENT_generic_cipher(belt, BELT, cbc, CBC, 0, 256, 128, 128, block)
///* ossl_aria192cbc_functions */
IMPLEMENT_generic_cipher(belt, BELT, cbc, CBC, 0, 192, 128, 128, block)
/* ossl_aria128cbc_functions */
IMPLEMENT_generic_cipher(belt, BELT, cbc, CBC, 0, 128, 128, 128, block)
///* ossl_aria256ofb_functions */
//IMPLEMENT_generic_cipher(aria, ARIA, ofb, OFB, 0, 256, 8, 128, stream)
///* ossl_aria192ofb_functions */
//IMPLEMENT_generic_cipher(aria, ARIA, ofb, OFB, 0, 192, 8, 128, stream)
///* ossl_aria128ofb_functions */
//IMPLEMENT_generic_cipher(aria, ARIA, ofb, OFB, 0, 128, 8, 128, stream)
/* ossl_aria256cfb_functions */
IMPLEMENT_generic_cipher(belt, BELT, cfb, CFB, 0, 256, 8, 128, stream)
/* ossl_aria192cfb_functions */
IMPLEMENT_generic_cipher(belt, BELT, cfb, CFB, 0, 192, 8, 128, stream)
/* ossl_aria128cfb_functions */
IMPLEMENT_generic_cipher(belt, BELT, cfb, CFB, 0, 128, 8, 128, stream)
///* ossl_aria256cfb1_functions */
//IMPLEMENT_generic_cipher(belt, BELT, cfb1, CFB, 0, 256, 8, 128, stream)
///* ossl_aria192cfb1_functions */
//IMPLEMENT_generic_cipher(belt, BELT, cfb1, CFB, 0, 192, 8, 128, stream)
///* ossl_aria128cfb1_functions */
//IMPLEMENT_generic_cipher(belt, BELT, cfb1, CFB, 0, 128, 8, 128, stream)
///* ossl_aria256cfb8_functions */
//IMPLEMENT_generic_cipher(belt, BELT, cfb8, CFB, 0, 256, 8, 128, stream)
///* ossl_aria192cfb8_functions */
//IMPLEMENT_generic_cipher(belt, BELT, cfb8, CFB, 0, 192, 8, 128, stream)
///* ossl_aria128cfb8_functions */
//IMPLEMENT_generic_cipher(belt, BELT, cfb8, CFB, 0, 128, 8, 128, stream)
/* ossl_aria256ctr_functions */
IMPLEMENT_generic_cipher(belt, BELT, ctr, CTR, 0, 256, 8, 128, stream)
/* ossl_aria192ctr_functions */
IMPLEMENT_generic_cipher(belt, BELT, ctr, CTR, 0, 192, 8, 128, stream)
/* ossl_aria128ctr_functions */
IMPLEMENT_generic_cipher(belt, BELT, ctr, CTR, 0, 128, 8, 128, stream)
