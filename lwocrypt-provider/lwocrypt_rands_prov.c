
// lwocrypt_rands_prov.c
#include <stdio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/params.h>

#include <lwocrypt-provider/names.h>
#include <lwocrypt-provider/implementations.h>
#include <lwocrypt-provider/lwocrypt_prov_main.h>
#include <lwocrypt-provider/bign_keymgmt_prov.h>




#include <openssl/core_dispatch.h>
#include <openssl/rand.h>

typedef struct {
    LWOCRYPT_PROVIDER_CTX* provctx;
} BIGN_RAND_CTX;

static void* bign_rand_newctx(void* provctx, void* parent, const OSSL_DISPATCH* parent_calls) {
    BIGN_RAND_CTX* ctx = OPENSSL_zalloc(sizeof(BIGN_RAND_CTX));
    if (!ctx) return NULL;
    ctx->provctx = (LWOCRYPT_PROVIDER_CTX*)provctx;
    return ctx;
}

static void bign_rand_freectx(void* vctx) {
    BIGN_RAND_CTX* ctx = (BIGN_RAND_CTX*)vctx;
    OPENSSL_free(ctx);
}

static int bign_rand_generate(void* vctx, unsigned char* out, size_t outlen,
    unsigned int strength, int prediction_resistance,
    const unsigned char* addin, size_t addin_len) {
    BIGN_RAND_CTX* ctx = (BIGN_RAND_CTX*)vctx;
    if (!ctx || !ctx->provctx || !ctx->provctx->libctx) return 0;
    return RAND_bytes_ex(ctx->provctx->libctx, out, outlen, strength);
}

static const OSSL_PARAM* bign_rand_gettable_params(void* provctx) {
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };
    return params;
}

static int bign_rand_get_params(OSSL_PARAM params[]) {
    OSSL_PARAM* p;
    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH)) != NULL) {
        if (!OSSL_PARAM_set_uint(p, 256)) return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST)) != NULL) {
        if (!OSSL_PARAM_set_size_t(p, 4096)) return 0;
    }
    return 1;
}

static const OSSL_DISPATCH ossl_lwocrypt_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))bign_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))bign_rand_freectx },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))bign_rand_generate },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS, (void (*)(void))bign_rand_gettable_params },
    { OSSL_FUNC_RAND_GET_PARAMS, (void (*)(void))bign_rand_get_params },
    { 0, NULL }
};