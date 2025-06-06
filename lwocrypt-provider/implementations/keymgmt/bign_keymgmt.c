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

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core.h>

#include <lwocrypt-provider/implementations.h>
#include <lwocrypt-provider//providercommon.h>
#include <lwocrypt-provider/provider_ctx.h>
#include <lwocrypt-provider/kdfexchange.h>

static OSSL_FUNC_keymgmt_new_fn kdf_newdata;
static OSSL_FUNC_keymgmt_free_fn kdf_freedata;
static OSSL_FUNC_keymgmt_has_fn kdf_has;
static OSSL_FUNC_keymgmt_gen_init_fn bign_gen_init;
static OSSL_FUNC_keymgmt_gen_set_template_fn bign_gen_set_template;
static OSSL_FUNC_keymgmt_gen_set_params_fn bign_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn bign_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn bign_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn bign_gen_cleanup;
// ====================================================================================================
KDF_DATA *ossl_kdf_data_new(void *provctx)
{
    printf("<PROVIDER> KEYMGMT DATA NEW CALLED!!");
    KDF_DATA *kdfdata;

    if (!ossl_prov_is_running())
        return NULL;

    kdfdata = OPENSSL_zalloc(sizeof(*kdfdata));
    if (kdfdata == NULL)
        return NULL;

    //if (!CRYPTO_NEW_REF(&kdfdata->refcnt, 1)) {
    //    OPENSSL_free(kdfdata);
    //    return NULL;
    //}
    kdfdata->libctx = PROV_LIBCTX_OF(provctx);

    return kdfdata;
}
// ====================================================================================================
void ossl_kdf_data_free(KDF_DATA *kdfdata)
{
    printf("<PROVIDER> KEYMGMT DATA FREE CALLED!!");
    int ref = 0;

    if (kdfdata == NULL)
        return;

    //CRYPTO_DOWN_REF(&kdfdata->refcnt, &ref);
    if (ref > 0)
        return;

    //CRYPTO_FREE_REF(&kdfdata->refcnt);
    OPENSSL_free(kdfdata);
}
// ====================================================================================================
int ossl_kdf_data_up_ref(KDF_DATA *kdfdata)
{
    int ref = 0;
    printf("<PROVIDER> KEYMGMT DATA UP REF CALLED!!");
    /* This is effectively doing a new operation on the KDF_DATA and should be
     * adequately guarded again modules' error states.  However, both current
     * calls here are guarded properly in exchange/kdf_exch.c.  Thus, it
     * could be removed here.  The concern is that something in the future
     * might call this function without adequate guards.  It's a cheap call,
     * it seems best to leave it even though it is currently redundant.
     */
    if (!ossl_prov_is_running())
        return 0;

    //CRYPTO_UP_REF(&kdfdata->refcnt, &ref);
    return 1;
}
// ====================================================================================================
static void *kdf_newdata(void *provctx)
{
    return ossl_kdf_data_new(provctx);
}
// ====================================================================================================
static void kdf_freedata(void *kdfdata)
{
    ossl_kdf_data_free(kdfdata);
}
// ====================================================================================================
static int kdf_has(const void *keydata, int selection)
{
    printf("<PROVIDER> KEYMGMT HAS CALLED!!");
    return 1; /* nothing is missing */
}
// ====================================================================================================
// ====================================================================================================
static void* bign_gen_init(void* provctx, int selection, const OSSL_PARAM params[])
{
    OSSL_LIB_CTX* libctx = PROV_LIBCTX_OF(provctx);
    struct ec_gen_ctx* gctx = NULL;
    return gctx;
}
// ====================================================================================================
static int bign_gen_set_template(void* genctx, void* templ)
{
    
    return 1;
}
// ====================================================================================================
static int bign_gen_set_params(void* genctx, const OSSL_PARAM params[])
{
//   
    return 1;
}
// ====================================================================================================
static const OSSL_PARAM* bign_gen_settable_params(ossl_unused void* genctx,
    ossl_unused void* provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, NULL, 0),
        //OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}
// ====================================================================================================
static void* bign_gen(void* genctx, OSSL_CALLBACK* osslcb, void* cbarg)
{
    struct ec_gen_ctx* gctx = genctx;
    EC_KEY* ec = NULL;  
    return ec;
}
// ====================================================================================================
static void bign_gen_cleanup(void* genctx)
{ 
}
// ====================================================================================================
const OSSL_DISPATCH ossl_BIGN_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))kdf_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))kdf_freedata },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))kdf_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))bign_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
      (void (*)(void))bign_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))bign_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))bign_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))bign_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))bign_gen_cleanup },
    { 0, NULL }
};
// ====================================================================================================
