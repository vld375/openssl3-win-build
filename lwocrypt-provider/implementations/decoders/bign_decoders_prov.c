// bign_decoders_prov.c

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include  <lwocrypt-provider/bign_keymgmt_prov.h>
#include <lwocrypt-provider/lwocrypt_prov_main.h>
#include <lwocrypt-provider/bign_decoders_prov.h>
#include <openssl/bn.h>


typedef struct {
    OSSL_LIB_CTX* libctx;
} BIGN_DECODER_CTX;

void* ossl_bign_decoder_newctx(void* provctx) {
    BIGN_DECODER_CTX* ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->libctx = ((LWOCRYPT_PROVIDER_CTX*)provctx)->libctx;
    return ctx;
}

void ossl_bign_decoder_freectx(void* vctx) {
    OPENSSL_free(vctx);
}

const OSSL_PARAM* ossl_bign_decoder_gettable_params(void* vctx) {
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("input-type", NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

int ossl_bign_decoder_get_params(OSSL_PARAM params[]) {
    OSSL_PARAM* p = OSSL_PARAM_locate(params, "input-type");
    if (p && !OSSL_PARAM_set_utf8_string(p, "PrivateKey"))
        return 0;
    return 1;
}

void* ossl_bign_decoder_decode(void* vctx, const unsigned char* in, size_t inlen,
    const OSSL_PARAM params[], int* ppkey_sel,
    EVP_PKEY** pk) {
    EVP_PKEY* pkey = NULL;

    // Проверяем тип входных данных
    const OSSL_PARAM* p = OSSL_PARAM_locate_const(params, "input-type");
    if (p && p->data_type == OSSL_PARAM_UTF8_STRING) {
        const char* input_type = p->data;
        if (strcmp(input_type, "PrivateKey") == 0) {
            // Декодируем DER-ключ
            const unsigned char* ptr = in;
            pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &ptr, inlen);
        }
    }
    else {
        // По умолчанию пробуем как DER
        const unsigned char* ptr = in;
        pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &ptr, inlen);
    }

    if (!pkey)
        return NULL;

    *pk = pkey;
    *ppkey_sel = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    return pkey;
}

int ossl_bign_decoder_does_selection(void* vctx, int selection) {
    return (selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY |
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
        OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS));
}
const OSSL_DISPATCH ossl_bign_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,             (void (*)(void))ossl_bign_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX,            (void (*)(void))ossl_bign_decoder_freectx },
    { OSSL_FUNC_DECODER_GET_PARAMS,         (void (*)(void))ossl_bign_decoder_get_params },
    { OSSL_FUNC_DECODER_GETTABLE_PARAMS,    (void (*)(void))ossl_bign_decoder_gettable_params },
   // { OSSL_FUNC_DECODER_SET_CTX_PARAMS,     (void (*)(void))ossl_bign_decoder_set_ctx_params },
   // { OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,(void (*)(void))ossl_bign_decoder_settable_ctx_params },
    { OSSL_FUNC_DECODER_DOES_SELECTION,     (void (*)(void))ossl_bign_decoder_does_selection },
    { OSSL_FUNC_DECODER_DECODE,             (void (*)(void))ossl_bign_decoder_decode },
  //  { OSSL_FUNC_DECODER_FREE_OBJECT,         (void (*)(void))ossl_bign_decoder_free_object },
    { 0, NULL }
};