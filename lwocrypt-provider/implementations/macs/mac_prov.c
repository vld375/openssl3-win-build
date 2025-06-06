/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>

#include <openssl/crypto.h>
#include <lwocrypt-alg/belt.h>

#include <lwocrypt-provider/implementations.h>
#include <lwocrypt-provider/provider_ctx.h>
#include <lwocrypt-provider/provider_util.h>
#include <lwocrypt-provider/providercommon.h>


static OSSL_FUNC_mac_newctx_fn belt_mac_new;
static OSSL_FUNC_mac_dupctx_fn belt_mac_dup;
static OSSL_FUNC_mac_freectx_fn belt_mac_free;
static OSSL_FUNC_mac_gettable_ctx_params_fn belt_mac_gettable_ctx_params;
static OSSL_FUNC_mac_get_ctx_params_fn belt_mac_get_ctx_params;
static OSSL_FUNC_mac_settable_ctx_params_fn belt_mac_settable_ctx_params;
static OSSL_FUNC_mac_set_ctx_params_fn belt_mac_set_ctx_params;
static OSSL_FUNC_mac_init_fn belt_mac_init;
static OSSL_FUNC_mac_update_fn belt_mac_update;
static OSSL_FUNC_mac_final_fn belt_mac_final;

/* local BELT_MAC data */
struct belt_mac_data_st
{
    void *provctx;
    BELTmac_CTX ctx;
    size_t out_len;
};

static void *belt_mac_new(void *provctx)
{
    struct belt_mac_data_st *macctx;

    if (!ossl_prov_is_running())
        return NULL;

    if ((macctx = OPENSSL_zalloc(sizeof(*macctx))) == NULL)
    {
        OPENSSL_free(macctx);
        return NULL;
    }

    macctx->provctx = provctx;
    macctx->out_len = 8;

    return macctx;
}

static void belt_mac_free(void *vmacctx)
{
    struct belt_mac_data_st *macctx = vmacctx;

    if (macctx != NULL)
        OPENSSL_free(macctx);
}

static void *belt_mac_dup(void *vsrc)
{
    struct belt_mac_data_st *src = vsrc;
    struct belt_mac_data_st *dst;

    if (!ossl_prov_is_running())
        return NULL;

    dst = belt_mac_new(src->provctx);
    if (dst == NULL)
        return NULL;

    if (!memcpy(&dst->ctx, &src->ctx, sizeof(*src)))
    {
        belt_mac_free(dst);
        return NULL;
    }

    dst->out_len = src->out_len;

    return dst;
}

static size_t belt_mac_size(void *vmacctx)
{
    struct belt_mac_data_st *macctx = vmacctx;

    return sizeof(*macctx);
}

static int belt_mac_setkey(struct belt_mac_data_st *macctx, const unsigned char *key, size_t keylen)
{
    BELT_mac_Init(&macctx->ctx, key);
    return 1;
}

static int belt_mac_init(void *vmacctx, const unsigned char *key,
                         size_t keylen, const OSSL_PARAM params[])
{
    struct belt_mac_data_st *macctx = vmacctx;

    if (!ossl_prov_is_running() || !belt_mac_set_ctx_params(macctx, params))
        return 0;

    if (key != NULL)
        return belt_mac_setkey(macctx, key, keylen);

    return 1;
}

static int belt_mac_update(void *vmacctx, const unsigned char *data,
                           size_t datalen)
{
    struct belt_mac_data_st *macctx = vmacctx;

    return BELT_mac_Update(&macctx->ctx, data, datalen);
}

static int belt_mac_final(void *vmacctx, unsigned char *out, size_t *outl,
                          size_t outsize)
{
    struct belt_mac_data_st *macctx = vmacctx;

    if (!ossl_prov_is_running())
        return 0;

    *outl = macctx->out_len;

    return BELT_mac_Final(&macctx->ctx, out);
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END};
static const OSSL_PARAM *belt_mac_gettable_ctx_params(ossl_unused void *ctx,
                                                      ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static int belt_mac_get_ctx_params(void *vmacctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL && !OSSL_PARAM_set_size_t(p, belt_mac_size(vmacctx)))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL && !OSSL_PARAM_set_size_t(p, belt_mac_size(vmacctx)))
        return 0;

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_END};
static const OSSL_PARAM *belt_mac_settable_ctx_params(ossl_unused void *ctx,
                                                      ossl_unused void *provctx)
{
    return known_settable_ctx_params;
}

/*
 * ALL parameters should be set before init().
 */
static int belt_mac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[])
{
    struct belt_mac_data_st *macctx = vmacctx;
    OSSL_LIB_CTX *ctx = PROV_LIBCTX_OF(macctx->provctx);
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        return belt_mac_setkey(macctx, p->data, p->data_size);
    }
    return 1;
}

const OSSL_DISPATCH ossl_belt_mac_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))belt_mac_new},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))belt_mac_dup},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))belt_mac_free},
    {OSSL_FUNC_MAC_INIT, (void (*)(void))belt_mac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))belt_mac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))belt_mac_final},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
     (void (*)(void))belt_mac_gettable_ctx_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))belt_mac_get_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
     (void (*)(void))belt_mac_settable_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))belt_mac_set_ctx_params},
    {0, NULL}};
