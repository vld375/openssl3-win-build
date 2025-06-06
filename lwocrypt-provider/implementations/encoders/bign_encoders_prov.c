//bign_encoders_prov.c


#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <lwocrypt-provider/bign_keymgmt_prov.h>
#include <lwocrypt-provider/lwocrypt_prov_main.h>
#include <lwocrypt-provider/bign_encoders_prov.h>


// Helper function to create an EVP_PKEY from BIGN_KEYMGMT_KEY
// This encapsulates the common logic for both DER and PEM encoders
static EVP_PKEY* bign_keymgmt_to_evp_pkey(const BIGN_KEYMGMT_KEY* key, OSSL_LIB_CTX* libctx) {
    fprintf(stderr, "bign_keymgmt_to_evp_pkey: start \n");
    EVP_PKEY* encode_pkey = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    int ret = 0; // Failure by default

    if (!key || !key->group || !libctx) {
        fprintf(stderr, "bign_keymgmt_to_evp_pkey: key or key->group or libctx is NULL \n");
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY);
        return NULL;
    }

    encode_pkey = EVP_PKEY_new();
    if (!encode_pkey) {
        fprintf(stderr, "bign_keymgmt_to_evp_pkey: EVP_PKEY_new() error \n");
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    // Create a PKEY_CTX for EC parameters and initialize it
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, libctx);
    if (!pctx) {
        fprintf(stderr, "bign_keymgmt_to_evp_pkey: Failed to create EVP_PKEY_CTX\n");
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        fprintf(stderr, "bign_keymgmt_to_evp_pkey: EVP_PKEY_paramgen_init failed\n");
        ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
        goto err;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, key->nid) <= 0) {
        fprintf(stderr, "bign_keymgmt_to_evp_pkey: EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed for NID %d\n", key->nid);
        ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
        goto err;
    }
    if (EVP_PKEY_paramgen(pctx, &encode_pkey) <= 0) {
        fprintf(stderr, "bign_keymgmt_to_evp_pkey: EVP_PKEY_paramgen failed\n");
        ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
        goto err;
    }
    fprintf(stderr, "bign_keymgmt_to_evp_pkey: Successfully generated parameters for EVP_PKEY\n");








    // Set the private key (if present)
    if (key->priv_key) {
        fprintf(stderr, "bign_keymgmt_to_evp_pkey: Attempting to set private key...\n");
        OSSL_PARAM priv_param[] = {
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, key->priv_key, 0),
            OSSL_PARAM_END
        };
        if (EVP_PKEY_set_params(encode_pkey, priv_param) <= 0) {
            fprintf(stderr, "bign_keymgmt_to_evp_pkey: Failed to set private key params\n");
            ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
            goto err;
        }
        fprintf(stderr, "bign_keymgmt_to_evp_pkey: Private key params set successfully.\n");
    }

    // Set the public key (if present)
    if (key->pub_key) {
        unsigned char* pub_buf = NULL;
        size_t pub_len = 0;
        int pt_conversion = POINT_CONVERSION_UNCOMPRESSED;

        pub_len = EC_POINT_point2oct(key->group, key->pub_key, pt_conversion, NULL, 0, NULL);
        if (pub_len == 0) {
            ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
            goto err;
        }

        pub_buf = OPENSSL_malloc(pub_len);
        if (!pub_buf) {
            ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (EC_POINT_point2oct(key->group, key->pub_key, pt_conversion, pub_buf, pub_len, NULL) != pub_len) {
            ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
            OPENSSL_free(pub_buf);
            goto err;
        }

        OSSL_PARAM pub_param[] = {
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub_buf, pub_len),
            OSSL_PARAM_END
        };
        if (EVP_PKEY_set_params(encode_pkey, pub_param) <= 0) {
            ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
            OPENSSL_free(pub_buf);
            goto err;
        }
        OPENSSL_free(pub_buf);
    }

    ret = 1; // Success
err:
    EVP_PKEY_CTX_free(pctx);
    if (!ret) {
        EVP_PKEY_free(encode_pkey);
        encode_pkey = NULL;
    }
    fprintf(stderr, "bign_keymgmt_to_evp_pkey: end \n");
    return encode_pkey;
}




void* ossl_bign_encoder_newctx(void* provctx_arg) {
    fprintf(stderr, "ossl_bign_encoder_newctx: start\n");
    LWOCRYPT_PROVIDER_CTX* provctx = (LWOCRYPT_PROVIDER_CTX*)provctx_arg;
    BIGN_ENCODER_CTX* ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        fprintf(stderr, "ossl_bign_encoder_newctx: end\n");
        return NULL;
    }
    ctx->libctx = provctx->libctx;
    ctx->provctx = provctx; // Set the provctx
    return ctx;
}

void ossl_bign_encoder_freectx(void* vctx) {
    BIGN_ENCODER_CTX* ctx = (BIGN_ENCODER_CTX*)vctx;
    if (ctx) {
        OPENSSL_free(ctx->propq);
        OPENSSL_free(ctx);
    }
}

const OSSL_PARAM* ossl_bign_encoder_gettable_params(void* vctx) {
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("output-type", NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

int ossl_bign_encoder_get_params(OSSL_PARAM params[]) {
    OSSL_PARAM* p = OSSL_PARAM_locate(params, "output-type");
    if (p && !OSSL_PARAM_set_utf8_string(p, "PrivateKey")) return 0;
    return 1;
}

int ossl_bign_encoder_does_selection(void* vctx, int selection) {
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

int ossl_bign_encoder_der_encode(void* vctx, const void* obj_raw,
    int selection, OSSL_CORE_BIO* out,
    const OSSL_PARAM params[]) {
    fprintf(stderr, "ossl_bign_encoder_der_encode: start\n");
    BIGN_ENCODER_CTX* ctx = (BIGN_ENCODER_CTX*)vctx;
    const BIGN_KEYMGMT_KEY* key = (const BIGN_KEYMGMT_KEY*)obj_raw;
    EVP_PKEY* encode_pkey = NULL;
    unsigned char* der = NULL;
    int der_len = 0;
    BIO* bio = NULL;
    int ret = 0;

    // Check basic validity
    if (!ctx || !out || !key || !key->provctx || !key->libctx) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    // IMPORTANT: The encoder should only be asked to encode what it "does selection" for.
    // If it only does private key, then make sure private key is present.
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && key->priv_key == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY); // Corrected: Use EVP_R_INVALID_KEY
        return 0;
    }
    // Also ensure domain parameters are set if we're trying to encode a key
    if (key->group == NULL || key->nid == NID_undef) {
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET);
        return 0;
    }

    // Create a temporary EVP_PKEY from the BIGN_KEYMGMT_KEY
    encode_pkey = bign_keymgmt_to_evp_pkey(key, ctx->libctx);
    if (!encode_pkey) {
        return 0;
    }

    der_len = i2d_PrivateKey(encode_pkey, &der);
    if (der_len <= 0) {
        ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
        goto end;
    }

    bio = BIO_new_from_core_bio(ctx->libctx, out);
    if (!bio) {
        ERR_raise(ERR_LIB_EVP, ERR_R_BIO_LIB);
        goto end;
    }

    if (BIO_write(bio, der, der_len) == der_len) {
        ret = 1; // Success
    }
    else {
        ERR_raise(ERR_LIB_EVP, ERR_R_BIO_LIB);
    }

end:
    BIO_free(bio);
    OPENSSL_free(der);
    EVP_PKEY_free(encode_pkey);
    fprintf(stderr, "ossl_bign_encoder_der_encode: end\n");
    return ret;
}



int ossl_bign_encoder_pem_encode(void* vctx, const void* obj_raw,
    int selection, OSSL_CORE_BIO* out,
    const OSSL_PARAM params[]) {
    fprintf(stderr, "ossl_bign_encoder_pem_encode: start \n");
    BIGN_ENCODER_CTX* ctx = (BIGN_ENCODER_CTX*)vctx;
    const BIGN_KEYMGMT_KEY* key = (const BIGN_KEYMGMT_KEY*)obj_raw;
    EVP_PKEY* encode_pkey = NULL;
    BIO* bio = NULL;
    int ret = 0;

    // Check basic validity
    if (!ctx || !out || !key || !key->provctx || !key->libctx) {
        fprintf(stderr, "ossl_bign_encoder_pem_encode: Check basic validity error.\n");
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    // IMPORTANT: The encoder should only be asked to encode what it "does selection" for.
    // If it only does private key, then make sure private key is present.
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && key->priv_key == NULL) {
        fprintf(stderr, "ossl_bign_encoder_pem_encode: selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && key->priv_key error.\n");
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY); // Corrected: Use EVP_R_INVALID_KEY
        return 0;
    }
    // Also ensure domain parameters are set if we're trying to encode a key
    if (key->group == NULL || key->nid == NID_undef) {
        fprintf(stderr, "ossl_bign_encoder_pem_encode: key->group == NULL || key->nid == NID_undef error.\n");
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET);
        return 0;
    }

    // Create a temporary EVP_PKEY from the BIGN_KEYMGMT_KEY
    encode_pkey = bign_keymgmt_to_evp_pkey(key, ctx->libctx);
    if (!encode_pkey) {
        fprintf(stderr, "ossl_bign_encoder_pem_encode: bign_keymgmt_to_evp_pkey failed.\n");
        return 0;
    }
    fprintf(stderr, "ossl_bign_encoder_pem_encode: EVP_PKEY created successfully (addr: %p).\n", (void*)encode_pkey);


    bio = BIO_new_from_core_bio(ctx->libctx, out);
    if (!bio) {
        fprintf(stderr, "ossl_bign_encoder_pem_encode: BIO_new_from_core_bio failed.\n");
        ERR_raise(ERR_LIB_EVP, ERR_R_BIO_LIB);
        goto end;
    }
    fprintf(stderr, "ossl_bign_encoder_pem_encode: BIO created successfully (addr: %p).\n", (void*)bio);


    ret = PEM_write_bio_PrivateKey(bio, encode_pkey, NULL, NULL, 0, NULL, NULL);
    if (ret > 0) {
        fprintf(stderr, "ossl_bign_encoder_pem_encode: PEM_write_bio_PrivateKey succeeded with return %d.\n", ret);
        ret = 1;
    }
    else {
        fprintf(stderr, "ossl_bign_encoder_pem_encode: PEM_write_bio_PrivateKey FAILED with return %d.\n", ret);
        ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB); // Or check OpenSSL error stack for more specific error
    }

end:
    BIO_free(bio);
    EVP_PKEY_free(encode_pkey);
    fprintf(stderr, "ossl_bign_encoder_pem_encode: end \n");
    return ret;
}


const OSSL_PARAM* ossl_bign_encoder_settable_ctx_params(void* vctx) {
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

int ossl_bign_encoder_set_ctx_params(void* vctx, const OSSL_PARAM params[]) {
    BIGN_ENCODER_CTX* ctx = vctx;
    const OSSL_PARAM* p;

    p = OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_PROPERTIES);
    if (p != NULL && p->data_type == OSSL_PARAM_UTF8_STRING) {
        if (ctx->propq) {
            OPENSSL_free(ctx->propq);
            ctx->propq = NULL;
        }
        ctx->propq = OPENSSL_strdup(p->data);
        if (ctx->propq == NULL) return 0;
    }

    return 1;
}

void* ossl_bign_encoder_import_object(void* vctx, int selection, const OSSL_PARAM params[]) {
    BIGN_ENCODER_CTX* ctx = (BIGN_ENCODER_CTX*)vctx;
    if (!ctx || selection != OSSL_KEYMGMT_SELECT_PRIVATE_KEY || !ctx->provctx) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER); // Or more specific error
        return NULL;
    }

    // Pass the actual provctx to keymgmt_import
    return ossl_bign_keymgmt_import(ctx->provctx, selection, params);
}


void ossl_bign_encoder_free_object(void* obj) {
    ossl_bign_keymgmt_free(obj);
}

const OSSL_DISPATCH ossl_bign_encoder_der_privkey_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,             (void (*)(void))ossl_bign_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX,            (void (*)(void))ossl_bign_encoder_freectx },
    { OSSL_FUNC_ENCODER_GET_PARAMS,         (void (*)(void))ossl_bign_encoder_get_params },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS,    (void (*)(void))ossl_bign_encoder_gettable_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS,     (void (*)(void))ossl_bign_encoder_set_ctx_params },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,(void (*)(void))ossl_bign_encoder_settable_ctx_params },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,     (void (*)(void))ossl_bign_encoder_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,             (void (*)(void))ossl_bign_encoder_der_encode },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,      (void (*)(void))ossl_bign_encoder_import_object },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,        (void (*)(void))ossl_bign_encoder_free_object },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_bign_encoder_pem_privkey_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,             (void (*)(void))ossl_bign_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX,            (void (*)(void))ossl_bign_encoder_freectx },
    { OSSL_FUNC_ENCODER_GET_PARAMS,         (void (*)(void))ossl_bign_encoder_get_params },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS,    (void (*)(void))ossl_bign_encoder_gettable_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS,     (void (*)(void))ossl_bign_encoder_set_ctx_params },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,(void (*)(void))ossl_bign_encoder_settable_ctx_params },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,     (void (*)(void))ossl_bign_encoder_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,             (void (*)(void))ossl_bign_encoder_pem_encode },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,      (void (*)(void))ossl_bign_encoder_import_object },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,        (void (*)(void))ossl_bign_encoder_free_object },
    { 0, NULL }
};