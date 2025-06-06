// bign_keymgmt_prov.c

/*
 * Copyright 2019-2025 LWO Project Authors. All Rights Reserved.
 *
 * Key management functions for LWOCRYPT provider, supporting BIGN curves.
 */




#include <stdio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/crypto.h>
#include <openssl/core.h >
#include <openssl/evp.h> // For EVP_PKEY_xxx functions
#include <openssl/ec.h> // For EC_KEY and EC_GROUP
#include <openssl/bn.h> // For BIGNUM
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evperr.h>

#include <lwocrypt-provider/names.h>
#include <lwocrypt-provider/implementations.h>
#include <lwocrypt-provider/lwocrypt_prov_main.h>
#include <lwocrypt-provider/bign_keymgmt_prov.h>






// Определяем поддерживаемые параметры
static const OSSL_PARAM bign_keymgmt_gettable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM bign_gen_settable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM bign_keymgmt_settable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0), // To set the curve for an *existing* key, if allowed
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM bign_keymgmt_import_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};
// ----------------------------------------------------------------------
   


// Helper to create EVP_PKEY from BIGNUM private key and EC_POINT public key
// Now accepts LWOCRYPT_PROVIDER_CTX to access curve parameters directly
static EVP_PKEY* bign_pkey_new_from_components(LWOCRYPT_PROVIDER_CTX* provctx, int nid, BIGNUM* priv, EC_POINT* pub) {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    OSSL_PARAM_BLD* bld = NULL;
    OSSL_PARAM* params = NULL;
    const EC_GROUP* group = NULL;
    const char* curve_name = NULL;

    if (!provctx) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    // --- CRITICAL CHANGE HERE ---
    // Directly create the PKEY_CTX from your own key management functions.
    // This bypasses the problematic "fetch by name/properties" from within the provider.
    pctx = EVP_PKEY_CTX_new_from_core_keymgmt(provctx->libctx, ossl_bign_keymgmt_functions, NULL);
    if (!pctx) {
        // Use ERR_R_INTERNAL_ERROR as a general fallback for internal failures
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    // --- END CRITICAL CHANGE ---

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
        goto err;
    }

    bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    // Get curve name and group from provctx based on NID
    if (nid == provctx->nid_bign_curve256v1) {
        group = provctx->bign_curve256v1;
        curve_name = provctx->name_bign_curve256v1;
    }
    else if (nid == provctx->nid_bign_curve384v1) {
        group = provctx->bign_curve384v1;
        curve_name = provctx->name_bign_curve384v1;
    }
    else if (nid == provctx->nid_bign_curve512v1) {
        group = provctx->bign_curve512v1;
        curve_name = provctx->name_bign_curve512v1;
    }
    else {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEYLENGTH);
        goto err;
    }

    if (!curve_name || !group || !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_MISSING_PARAMETERS);
        goto err;
    }

    // Add private key if available
    if (priv) {
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv)) {
            ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY);
            goto err;
        }
    }

    // Add public key if available
    if (pub) {
        size_t pub_len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
        unsigned char* pub_buf = OPENSSL_malloc(pub_len);
        if (!pub_buf) {
            ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, pub_buf, pub_len, NULL) == 0) {
            OPENSSL_free(pub_buf);
            ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY);
            goto err;
        }

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_buf, pub_len)) {
            OPENSSL_free(pub_buf);
            ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY);
            goto err;
        }
        OPENSSL_free(pub_buf);
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        goto err;
    }

err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
int bign_generate_private_key(const EC_GROUP* group, BIGNUM* priv) {
    if (!group || !priv)
        return 0;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx)
        return 0;

    BIGNUM* order = BN_new();
    if (!order) {
        BN_CTX_free(ctx);
        return 0;
    }

    if (!EC_GROUP_get_order(group, order, ctx)) {
        BN_free(order);
        BN_CTX_free(ctx);
        return 0;
    }

    // Генерируем случайное число priv в [1, order-1]
    if (!BN_rand_range(priv, order)) {
        BN_free(order);
        BN_CTX_free(ctx);
        return 0;
    }
    if (BN_is_zero(priv)) {
        // если 0, делаем priv = 1
        if (!BN_one(priv)) {
            BN_free(order);
            BN_CTX_free(ctx);
            return 0;
        }
    }

    BN_free(order);
    BN_CTX_free(ctx);
    return 1;
}
int bign_compute_public_key(const EC_GROUP* group, const BIGNUM* priv, EC_POINT* pub) {
    if (!group || !priv || !pub)
        return 0;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx)
        return 0;

    // pub = priv * G
    int ret = EC_POINT_mul(group, pub, priv, NULL, NULL, ctx);

    BN_CTX_free(ctx);
    return ret;
}
static const EC_GROUP* get_bign_group_from_nid(LWOCRYPT_PROVIDER_CTX* provctx, int nid)
{
    if (nid == provctx->nid_bign_curve256v1)
        return provctx->bign_curve256v1;
    else if (nid == provctx->nid_bign_curve384v1)
        return provctx->bign_curve384v1;
    else if (nid == provctx->nid_bign_curve512v1)
        return provctx->bign_curve512v1;
    return NULL;
}



static int generate_ec_key(EVP_PKEY** pkey, LWOCRYPT_PROVIDER_CTX* provctx, BIGN_KEYMGMT_GEN_CTX* gen_ctx) { // Corrected type
    fprintf(stderr, "generate_ec_key: Generating key for NID=%d\n", gen_ctx->nid_to_gen);

    if (!provctx || !gen_ctx) { // No longer check provctx->bign_keymgmt
        fprintf(stderr, "generate_ec_key: Invalid provctx or gen_ctx\n");
        return 0;
    }

    // Select the appropriate EC_GROUP based on NID
    EC_GROUP* group = NULL;
    // We already have gen_ctx->group_to_gen from gen_set_params, use that directly
    // and avoid duplicating, as ownership is likely handled by the gen_ctx cleanup.
    group = gen_ctx->group_to_gen; // Use the group already stored in gen_ctx

    if (!group) {
        fprintf(stderr, "generate_ec_key: No matching group found for NID=%d\n", gen_ctx->nid_to_gen);
        return 0;
    }

    // --- CRITICAL CHANGE HERE ---
    // Create EVP_PKEY_CTX directly from your own keymgmt functions.
    // This is the correct way to get a PKEY_CTX from within your provider
    // for your own algorithm.
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_core_keymgmt(provctx->libctx, ossl_bign_keymgmt_functions, NULL);
    if (!pctx) {
        fprintf(stderr, "generate_ec_key: Failed to create EVP_PKEY_CTX from core keymgmt: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }
    // --- END CRITICAL CHANGE ---

    // Initialize key generation
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "generate_ec_key: Failed to initialize keygen: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    // Set the EC group via NID. Use nid_to_gen from gen_ctx.
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, gen_ctx->nid_to_gen) <= 0) {
        fprintf(stderr, "generate_ec_key: Failed to set curve NID=%d: %s\n", gen_ctx->nid_to_gen, ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    // Generate the key pair
    if (EVP_PKEY_generate(pctx, pkey) <= 0) {
        fprintf(stderr, "generate_ec_key: Failed to generate key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    // Validate the key - this might be redundant if EVP_PKEY_generate implies validation
    // but keeping it for robustness.
    if (EVP_PKEY_param_check(pctx) <= 0) {
        fprintf(stderr, "generate_ec_key: Key validation failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_free(*pkey); // Free the partially generated key
        *pkey = NULL;
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    // Cleanup
    EVP_PKEY_CTX_free(pctx);
    // Do NOT free 'group' here, it's owned by gen_ctx and will be freed in gen_cleanup

    fprintf(stderr, "generate_ec_key: Successfully generated key for NID=%d, pkey=%p\n", gen_ctx->nid_to_gen, *pkey);
    return 1;
}



void* ossl_bign_keymgmt_new(void* provctx_arg) {
    LWOCRYPT_PROVIDER_CTX* provctx = (LWOCRYPT_PROVIDER_CTX*)provctx_arg;

#if (lwodebug > 1)
    fprintf(stderr, "**** ossl_bign_keymgmt_new called with provctx=%p *****\n", provctx);
#endif
    if (provctx == NULL) {
        fprintf(stderr, "ossl_bign_keymgmt_new: provctx is NULL\n");
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    BIGN_KEYMGMT_KEY* key_ctx = OPENSSL_zalloc(sizeof(BIGN_KEYMGMT_KEY));
    if (key_ctx == NULL) {
        fprintf(stderr, "ossl_bign_keymgmt_new: Failed to allocate BIGN_KEYMGMT_KEY\n");
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    key_ctx->provctx = provctx;
    key_ctx->libctx = provctx->libctx; // Inherit libctx from provider context
    key_ctx->nid = NID_undef;
    key_ctx->group = NULL;
    key_ctx->priv_key = NULL;
    key_ctx->pub_key = NULL;

#if (lwodebug > 1)
    fprintf(stderr, "**** ossl_bign_keymgmt_new succeeded, returning ctx=%p *****\n", key_ctx);
#endif
    return key_ctx;
}
void ossl_bign_keymgmt_free(void* key_ctx_arg) {
#if (lwodebug > 1)
    fprintf(stderr, "ossl_bign_keymgmt_free: Freeing key context %p\n", key_ctx_arg);
#endif
    BIGN_KEYMGMT_KEY* key_ctx = (BIGN_KEYMGMT_KEY*)key_ctx_arg;
    if (key_ctx) {
        BN_free(key_ctx->priv_key);
        EC_POINT_free(key_ctx->pub_key);
        // If group was dup'd in gen/import, it must be freed here.
        // If it's merely a const pointer from provctx, do NOT free it.
        // Assuming it's dup'd for ownership:
        EC_GROUP_free(key_ctx->group); // Only if group is owned by key_ctx
        OPENSSL_free(key_ctx);
    }
}
// Получает параметры ключа (например, имя группы).
static int ossl_bign_keymgmt_get_params(void* keydata, OSSL_PARAM params[]) {
    BIGN_KEYMGMT_KEY* key = keydata;
    LWOCRYPT_PROVIDER_CTX* provctx;
    const char* curve_name = NULL;
    int ret = 1; // Assume success

    if (!key || !key->provctx || !params) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    provctx = key->provctx;

    // Determine curve name based on NID stored in key_ctx
    if (key->nid == provctx->nid_bign_curve256v1)
        curve_name = provctx->name_bign_curve256v1;
    else if (key->nid == provctx->nid_bign_curve384v1)
        curve_name = provctx->name_bign_curve384v1;
    else if (key->nid == provctx->nid_bign_curve512v1)
        curve_name = provctx->name_bign_curve512v1;
    else if (key->nid != NID_undef) // If NID is set but unknown
        curve_name = OBJ_nid2sn(key->nid); // Try standard OpenSSL names
    else
        curve_name = NULL; // No curve set

    for (OSSL_PARAM* p = params; p && p->key != NULL; p++) {
        if (strcmp(p->key, OSSL_PKEY_PARAM_GROUP_NAME) == 0) {
            if (curve_name == NULL) {
                ERR_raise(ERR_LIB_EVP, EVP_R_MISSING_PARAMETERS);
                ret = 0;
                break;
            }
            if (!OSSL_PARAM_set_utf8_string(p, curve_name)) {
                ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR); // Or more specific error
                ret = 0;
                break;
            }
        }
        // Add logic for OSSL_PKEY_PARAM_PUB_KEY and OSSL_PKEY_PARAM_PRIV_KEY if needed here
        // (Though usually export is preferred for full key material)
        // For example, if selection was OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        // if (strcmp(p->key, OSSL_PKEY_PARAM_PUB_KEY) == 0 && key->pub_key != NULL) {
        //     const EC_GROUP* group = get_bign_group_from_nid(provctx, key->nid);
        //     if (group && EC_POINT_point2oct(group, key->pub_key, POINT_CONVERSION_UNCOMPRESSED, (unsigned char*)p->data, p->data_size, NULL) > 0) {
        //         // Success
        //     } else {
        //         ERR_raise(...); ret = 0; break;
        //     }
        // }
    }

    return ret;
}
static const OSSL_PARAM* ossl_bign_keymgmt_gettable_params(void* provctx) {
#if (lwodebug > 1)
    fprintf(stderr, "ossl_bign_keymgmt_gettable_params:\n");
#endif
    return bign_keymgmt_gettable_params;
}
static int ossl_bign_keymgmt_set_params(void* key_ctx_arg, const OSSL_PARAM params[]) {
    BIGN_KEYMGMT_KEY* key_ctx = (BIGN_KEYMGMT_KEY*)key_ctx_arg;
    const OSSL_PARAM* p;
    const char* curve_name = NULL;
    int new_nid = NID_undef;
    const EC_GROUP* new_group_ref = NULL; // Reference to group from provctx

    if (!key_ctx) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    // You generally don't change the group of an *existing* key by setting parameters.
    // If a key exists, its group is immutable.
    // Setting parameters here usually implies setting properties *of* the key.
    // If an application tries to change the curve of an existing key,
    // they usually generate a *new* key, or this operation isn't supported.
    // I'm keeping the logic from your original code, which implies re-generation.
    // This is unusual for set_params, but if that's your design, then this is how it'd work.

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p) {
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &curve_name)) {
            ERR_raise(ERR_LIB_EVP, EVP_R_MISSING_PARAMETERS);
            return 0;
        }

        // Try to find the NID from the provided curve name
        if (strcmp(curve_name, SN_bign_curve256v1) == 0) new_nid = key_ctx->provctx->nid_bign_curve256v1;
        else if (strcmp(curve_name, SN_bign_curve384v1) == 0) new_nid = key_ctx->provctx->nid_bign_curve384v1;
        else if (strcmp(curve_name, SN_bign_curve512v1) == 0) new_nid = key_ctx->provctx->nid_bign_curve512v1;
        else {
            ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_ALGORITHM); // Or EVP_R_INVALID_PARAMETER
            return 0;
        }

        new_group_ref = get_bign_group_from_nid(key_ctx->provctx, new_nid);
        if (!new_group_ref) {
            ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_ALGORITHM); // Or EVP_R_INVALID_PARAMETER
            return 0;
        }

        // If the NID is different, it means we are changing the curve parameters.
        // This implicitly means re-generating a new key for this curve.
        if (key_ctx->nid != new_nid) {
            // Free old key components
            BN_free(key_ctx->priv_key);
            key_ctx->priv_key = NULL;
            EC_POINT_free(key_ctx->pub_key);
            key_ctx->pub_key = NULL;
            EC_GROUP_free(key_ctx->group); // Free old group if owned
            key_ctx->group = NULL;

            // Generate new key components for the new curve
            key_ctx->priv_key = BN_new();
            key_ctx->pub_key = EC_POINT_new(new_group_ref); // Create point for the new group
            if (!key_ctx->priv_key || !key_ctx->pub_key) {
                ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                return 0;
            }

            if (!bign_generate_private_key(new_group_ref, key_ctx->priv_key) ||
                !bign_compute_public_key(new_group_ref, key_ctx->priv_key, key_ctx->pub_key)) {
                ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB); // Or a more specific error
                return 0;
            }

            // Update key_ctx with new NID and group
            key_ctx->nid = new_nid;
            key_ctx->group = EC_GROUP_dup(new_group_ref); // Take ownership of the new group
            if (!key_ctx->group) {
                ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
    }

    return 1;
}
static const OSSL_PARAM* ossl_bign_keymgmt_settable_params(void* provctx) {
#if (lwodebug > 1)
    fprintf(stderr, "ossl_bign_keymgmt_settable_params:\n");
#endif
    return bign_keymgmt_settable_params;
}
int ossl_bign_keymgmt_has(const void* key_ctx_arg, int selection) {
    const BIGN_KEYMGMT_KEY* key_ctx = (const BIGN_KEYMGMT_KEY*)key_ctx_arg;

    if (!key_ctx) {
        fprintf(stderr, "ossl_bign_keymgmt_has: Invalid context\n");
        return 0;
    }

    int ret = 0;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (key_ctx->priv_key != NULL) {
            ret |= 1;
        }
    }
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (key_ctx->pub_key != NULL) {
            ret |= 1;
        }
    }
    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
        // A key has domain parameters if its NID is set and a group is associated
        if (key_ctx->nid != NID_undef && key_ctx->group != NULL) {
            ret |= 1;
        }
    }

    return ret;
}


static const char* ossl_bign_keymgmt_query_op_name(int operation_id) {
    if (operation_id == OSSL_OP_KEYMGMT) {
        return PROV_NAMES_BIGN; // Return the exact primary name used in OSSL_ALGORITHM
    }
    return NULL;
}

static void* ossl_bign_keymgmt_import(void* provctx_arg, int selection, const OSSL_PARAM params[]) {
    LWOCRYPT_PROVIDER_CTX* provctx = (LWOCRYPT_PROVIDER_CTX*)provctx_arg;
    const OSSL_PARAM* p;
    const char* group_name = NULL;
    int nid = NID_undef;
    BIGNUM* priv_temp = NULL; // Temporary for import, will be assigned to key_ctx->priv_key
    EC_POINT* pub_temp = NULL; // Temporary for import, will be assigned to key_ctx->pub_key
    const EC_GROUP* group_ref = NULL; // Reference to group from provctx

    BIGN_KEYMGMT_KEY* key = ossl_bign_keymgmt_new(provctx);
    if (!key)
        return NULL;

    // --- Parse Group Name ---
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (!p || !OSSL_PARAM_get_utf8_string_ptr(p, &group_name)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_MISSING_PARAMETERS);
        goto err;
    }

    if (strcmp(group_name, SN_bign_curve256v1) == 0) {
        nid = provctx->nid_bign_curve256v1;
    }
    else if (strcmp(group_name, SN_bign_curve384v1) == 0) {
        nid = provctx->nid_bign_curve384v1;
    }
    else if (strcmp(group_name, SN_bign_curve512v1) == 0) {
        nid = provctx->nid_bign_curve512v1;
    }
    else {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEYLENGTH); // Or EVP_R_UNSUPPORTED_ALGORITHM
        goto err;
    }

    group_ref = get_bign_group_from_nid(provctx, nid);
    if (!group_ref) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEYLENGTH);
        goto err;
    }

    key->nid = nid;
    key->group = EC_GROUP_dup(group_ref); // Take ownership of the group
    if (!key->group) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto err;
    }


    // --- Parse Private Key (if selected) ---
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            priv_temp = BN_new();
            if (!priv_temp || !OSSL_PARAM_get_BN(p, &priv_temp)) {
                ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
                goto err;
            }
            key->priv_key = priv_temp; // Assign directly to key_ctx
            priv_temp = NULL; // Clear temporary pointer
        }
    }

    // --- Parse Public Key (if selected) ---
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            size_t pub_len = p->data_size;
            unsigned char* pub_buf = OPENSSL_malloc(pub_len);
            if (!pub_buf) {
                ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (!OSSL_PARAM_get_octet_string(p, pub_buf, pub_len, &pub_len)) {
                OPENSSL_free(pub_buf);
                ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
                goto err;
            }

            pub_temp = EC_POINT_new(key->group); // Use key->group (which is now dup'd and owned)
            if (!pub_temp || !EC_POINT_oct2point(key->group, pub_temp, pub_buf, pub_len, NULL)) {
                EC_POINT_free(pub_temp);
                OPENSSL_free(pub_buf);
                ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY);
                goto err;
            }
            OPENSSL_free(pub_buf);
            key->pub_key = pub_temp; // Assign directly to key_ctx
            pub_temp = NULL; // Clear temporary pointer
        }
    }

    // Validate if a public key was provided or if we have a private key
    // and need to compute the public key from it for validation.
    if (key->priv_key && !key->pub_key) {
        key->pub_key = EC_POINT_new(key->group);
        if (!key->pub_key || !bign_compute_public_key(key->group, key->priv_key, key->pub_key)) {
            ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY);
            goto err;
        }
    }
    else if (!key->pub_key && !(selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) {
        // If no public key and no private key, and not just importing params, it's an error
        ERR_raise(ERR_LIB_EVP, EVP_R_MISSING_PARAMETERS);
        goto err;
    }


    return key;

err:
    BN_free(priv_temp);
    EC_POINT_free(pub_temp);
    ossl_bign_keymgmt_free(key); // Use your free function
    return NULL;
}

static const OSSL_PARAM* ossl_bign_keymgmt_import_types(int selection) {
    return bign_keymgmt_import_types;
}


static int ossl_bign_keymgmt_export(const void* keydata, int selection,
    OSSL_CALLBACK* cb, void* cbarg) {
    const BIGN_KEYMGMT_KEY* key = (const BIGN_KEYMGMT_KEY*)keydata;
    OSSL_PARAM params[4]; // Max possible params: group, pub, priv
    size_t param_n = 0;
    unsigned char pub_buf[132]; // Max 512-bit EC point (1 + 2*64 bytes for uncompressed)
    unsigned char priv_buf[66]; // Max 528 bits (66 bytes) for private key

    if (!key) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 && key->nid != NID_undef) {
        const char* curve_name = NULL;
        if (key->nid == key->provctx->nid_bign_curve256v1)
            curve_name = key->provctx->name_bign_curve256v1;
        else if (key->nid == key->provctx->nid_bign_curve384v1)
            curve_name = key->provctx->name_bign_curve384v1;
        else if (key->nid == key->provctx->nid_bign_curve512v1)
            curve_name = key->provctx->name_bign_curve512v1;
        else
            curve_name = OBJ_nid2sn(key->nid); // Fallback to standard NID name

        if (curve_name) {
            params[param_n++] = OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME,
                (char*)curve_name, 0); // OpenSSL will duplicate
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->pub_key != NULL && key->group != NULL) {
        size_t pub_len = EC_POINT_point2oct(key->group, key->pub_key, POINT_CONVERSION_UNCOMPRESSED,
            pub_buf, sizeof(pub_buf), NULL);
        if (pub_len == 0) {
            ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB); // Or specific error
            return 0;
        }

        params[param_n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, pub_buf, pub_len);
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->priv_key != NULL) {
        // Calculate the actual byte length of the private key BIGNUM
        size_t priv_key_actual_len = BN_num_bytes(key->priv_key);

        // Ensure priv_buf is large enough to hold the actual key.
        // Your priv_buf[66] is fine for 512-bit keys (max 64 bytes).
        // Use BN_bn2binpad to write the BIGNUM into the buffer.
        // The length argument to BN_bn2binpad is the target buffer size.
        // The return value is the number of bytes written, which should be priv_key_actual_len
        // or a padded length if priv_key_actual_len < sizeof(priv_buf)
        if (BN_bn2binpad(key->priv_key, priv_buf, priv_key_actual_len) <= 0) {
            ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
            return 0;
        }

        // Use OSSL_PARAM_construct_octet_string for the binary representation of the BIGNUM
        // The length should be the actual length of the BIGNUM data.
        params[param_n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, priv_buf, priv_key_actual_len);
    }

    params[param_n] = OSSL_PARAM_construct_end();
    return cb(params, cbarg);
}

static const OSSL_PARAM* ossl_bign_keymgmt_export_types(int selection) {
    return bign_keymgmt_import_types; // Often same as import types
}

static void* ossl_bign_keymgmt_dup(const void* key_ctx_arg, int selection) {
    const BIGN_KEYMGMT_KEY* src_key_ctx = (const BIGN_KEYMGMT_KEY*)key_ctx_arg;
    BIGN_KEYMGMT_KEY* dest_key_ctx = NULL;

    if (!src_key_ctx) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    dest_key_ctx = ossl_bign_keymgmt_new(src_key_ctx->provctx);
    if (!dest_key_ctx) return NULL;

    // Duplicate relevant members based on selection
    if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) { // Includes domain parameters
        dest_key_ctx->nid = src_key_ctx->nid;
        if (src_key_ctx->group) {
            dest_key_ctx->group = EC_GROUP_dup(src_key_ctx->group);
            if (!dest_key_ctx->group) goto err;
        }
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (src_key_ctx->priv_key) {
            dest_key_ctx->priv_key = BN_dup(src_key_ctx->priv_key);
            if (!dest_key_ctx->priv_key) goto err;
        }
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (src_key_ctx->pub_key && dest_key_ctx->group) { // pub_key depends on group being duplicated
            dest_key_ctx->pub_key = EC_POINT_dup(src_key_ctx->pub_key, dest_key_ctx->group);
            if (!dest_key_ctx->pub_key) goto err;
        }
        else if (src_key_ctx->pub_key && !dest_key_ctx->group) {
            // Should not happen if SELECT_ALL_PARAMETERS is used,
            // but if only public key is selected, we need the group to dup EC_POINT.
            // Consider duplicating group if only pub key selected, or error.
            ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR); // Cannot dup public key without group
            goto err;
        }
    }

    return dest_key_ctx;

err:
    ossl_bign_keymgmt_free(dest_key_ctx); // Use your free function
    return NULL;
}
static int ossl_bign_keymgmt_validate(void* key_ctx_arg, int selection, int checktype) {
    BIGN_KEYMGMT_KEY* key_ctx = (BIGN_KEYMGMT_KEY*)key_ctx_arg;
    int ret = 1; // Assume success

    if (!key_ctx) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (checktype == OSSL_KEYMGMT_VALIDATE_FULL_CHECK) {
        // Check domain parameters
        if (key_ctx->group == NULL || key_ctx->nid == NID_undef) {
            ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET); // This one should be valid.
            return 0;
        }

        // Check private key if selected
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            if (key_ctx->priv_key == NULL) {
                ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY); // Corrected: Use EVP_R_INVALID_KEY
                return 0;
            }
            // Add BIGN-specific private key range checks if necessary (e.g., 0 < priv < order)
            BIGNUM* order = BN_new();
            BN_CTX* ctx = BN_CTX_new();
            if (!order || !ctx) {
                ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                BN_free(order); BN_CTX_free(ctx);
                return 0;
            }
            if (!EC_GROUP_get_order(key_ctx->group, order, ctx)) {
                ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
                BN_free(order); BN_CTX_free(ctx);
                return 0;
            }
            // Check if priv_key is in the valid range [1, order-1]
            if (BN_is_zero(key_ctx->priv_key) || BN_cmp(key_ctx->priv_key, order) >= 0) {
                ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY);
                ret = 0;
            }
            BN_free(order);
            BN_CTX_free(ctx);
            if (!ret) return 0;
        }

        // Check public key if selected (and derive from private if only private is present)
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            EC_POINT* computed_pub = NULL;
            if (key_ctx->priv_key != NULL && key_ctx->pub_key != NULL) {
                // If both exist, compute and compare
                computed_pub = EC_POINT_new(key_ctx->group);
                if (!computed_pub) {
                    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                    return 0;
                }
                if (!bign_compute_public_key(key_ctx->group, key_ctx->priv_key, computed_pub)) {
                    ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY); // Corrected: Use EVP_R_INVALID_KEY
                    EC_POINT_free(computed_pub);
                    return 0;
                }
                if (EC_POINT_cmp(key_ctx->group, key_ctx->pub_key, computed_pub, NULL) != 0) {
                    ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY); // Corrected: Use EVP_R_INVALID_KEY
                    ret = 0;
                }
                EC_POINT_free(computed_pub);
            }
            else if (key_ctx->pub_key != NULL) {
                // Only public key exists, perform basic checks (e.g., if point is on curve)
                if (!EC_POINT_is_on_curve(key_ctx->group, key_ctx->pub_key, NULL)) {
                    ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY); // Corrected: Use EVP_R_INVALID_KEY
                    ret = 0;
                }
            }
            else if (key_ctx->priv_key != NULL) {
                // If only private key is present, and public key is selected for validation,
                // we should compute the public key to ensure it can be derived.
                key_ctx->pub_key = EC_POINT_new(key_ctx->group);
                if (!key_ctx->pub_key || !bign_compute_public_key(key_ctx->group, key_ctx->priv_key, key_ctx->pub_key)) {
                    ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY); // Corrected: Use EVP_R_INVALID_KEY
                    return 0;
                }
                // At this point, key_ctx->pub_key has been computed and validated
                // No need to free it here, it's part of the validated key_ctx.
            }
            else {
                // No public key to validate, and no private key to derive it from
                ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY); // Corrected: Use EVP_R_INVALID_KEY
                return 0;
            }
            if (!ret) return 0;
        }
    }

    return ret;
}
void* ossl_bign_keymgmt_gen_init(void* provctx_arg, int selection, const OSSL_PARAM params[]) {
#if (lwodebug > 1)
    fprintf(stderr, "ossl_bign_keymgmt_gen_init: start\n");
#endif
    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR)) {
        fprintf(stderr, "ossl_bign_keymgmt_gen_init: (selection & OSSL_KEYMGMT_SELECT_KEYPAIR error!\n");
        ERR_raise(ERR_LIB_EVP, EVP_R_CANNOT_GET_PARAMETERS); // Or more specific error
        return NULL;
    }

    BIGN_KEYMGMT_GEN_CTX* gen_ctx = OPENSSL_zalloc(sizeof(*gen_ctx));
    if (gen_ctx == NULL) {
        fprintf(stderr, "ossl_bign_keymgmt_gen_init: gen_ctx == NULL error!\n");
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    gen_ctx->provctx = (LWOCRYPT_PROVIDER_CTX*)provctx_arg;
    gen_ctx->nid_to_gen = NID_undef;
    gen_ctx->group_to_gen = NULL; // Will be set in gen_set_params and dup'd
    fprintf(stderr, "ossl_bign_keymgmt_gen_init: end\n");
    return gen_ctx;
}
int ossl_bign_keymgmt_gen_set_params(void* genctx_arg, const OSSL_PARAM params[]) {
    BIGN_KEYMGMT_GEN_CTX* gctx = (BIGN_KEYMGMT_GEN_CTX*)genctx_arg;
    const OSSL_PARAM* p;
    const char* curve_name = NULL;
    const EC_GROUP* temp_group_ref = NULL; // Reference to group from provctx

#if (lwodebug > 1)
    fprintf(stderr, "ossl_bign_keymgmt_gen_set_params:\n");
    for (const OSSL_PARAM* param = params; param && param->key != NULL; param++) {
        fprintf(stderr, "  param key: '%s'\n", param->key);
    }
#endif

    if (!gctx || !gctx->provctx) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p == NULL || !OSSL_PARAM_get_utf8_string_ptr(p, &curve_name)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_MISSING_PARAMETERS);
        return 0;
    }

    if (strcmp(curve_name, SN_bign_curve256v1) == 0) {
        gctx->nid_to_gen = gctx->provctx->nid_bign_curve256v1;
        temp_group_ref = gctx->provctx->bign_curve256v1;
    }
    else if (strcmp(curve_name, SN_bign_curve384v1) == 0) {
        gctx->nid_to_gen = gctx->provctx->nid_bign_curve384v1;
        temp_group_ref = gctx->provctx->bign_curve384v1;
    }
    else if (strcmp(curve_name, SN_bign_curve512v1) == 0) {
        gctx->nid_to_gen = gctx->provctx->nid_bign_curve512v1;
        temp_group_ref = gctx->provctx->bign_curve512v1;
    }
    else {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_ALGORITHM);
        return 0;
    }

    if (!temp_group_ref) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_ALGORITHM);
        return 0;
    }

    // Duplicate the group to be owned by the generation context
    // This ensures its lifetime is managed by gen_cleanup
    if (gctx->group_to_gen != NULL) { // Free old one if set again
        EC_GROUP_free(gctx->group_to_gen);
    }
    gctx->group_to_gen = EC_GROUP_dup(temp_group_ref);
    if (!gctx->group_to_gen) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return 1;
}
const OSSL_PARAM* ossl_bign_keymgmt_gen_settable_params(void* provctx) {
    (void)provctx; // Provider context not used in this function
    return bign_gen_settable_params;
}


void* ossl_bign_keymgmt_gen(void* gen_ctx_arg, OSSL_CALLBACK* osslcb, void* cbarg) {
    BIGN_KEYMGMT_GEN_CTX* gen_ctx = (BIGN_KEYMGMT_GEN_CTX*)gen_ctx_arg;
    BIGN_KEYMGMT_KEY* key_ctx = NULL;
    BN_CTX* bn_ctx = NULL;
    fprintf(stderr, "ossl_bign_keymgmt_gen: start\n");
    if (!gen_ctx || !gen_ctx->group_to_gen || !gen_ctx->provctx || !gen_ctx->provctx->libctx) {
        fprintf(stderr, "ossl_bign_keymgmt_gen: gen_ctx || !gen_ctx->group_to_gen || !gen_ctx->provctx || !gen_ctx->provctx->libctx error \n");
        ERR_raise(ERR_LIB_EVP, EVP_R_MISSING_PARAMETERS);
        return NULL;
    }

    // Create the key context that will hold the generated key material
    key_ctx = ossl_bign_keymgmt_new(gen_ctx->provctx);
    if (!key_ctx)
    {
        fprintf(stderr, "ossl_bign_keymgmt_gen: ossl_bign_keymgmt_new error \n");
        return NULL;
    }
    key_ctx->nid = gen_ctx->nid_to_gen;
    // Take ownership of the group from gen_ctx.
    // If gen_ctx->group_to_gen is guaranteed to be valid until gen_cleanup,
    // you can just assign and EC_GROUP_up_ref. If gen_ctx frees it, you need to dup.
    // Assuming gen_ctx owns and frees its group_to_gen, so we must dup here.
    key_ctx->group = EC_GROUP_dup(gen_ctx->group_to_gen);
    if (!key_ctx->group) {
        fprintf(stderr, "ossl_bign_keymgmt_gen: EC_GROUP_dup error \n");
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        goto err;

    key_ctx->priv_key = BN_new();
    key_ctx->pub_key = EC_POINT_new(key_ctx->group); // Use key_ctx->group for point creation
    if (!key_ctx->priv_key || !key_ctx->pub_key)
    {
        fprintf(stderr, "ossl_bign_keymgmt_gen: (!key_ctx->priv_key || !key_ctx->pub_key error \n");
        goto err;
    }
    // Generate private key (random in [1, order-1])
    if (!bign_generate_private_key(key_ctx->group, key_ctx->priv_key)) // Use key_ctx->group
    {
        fprintf(stderr, "ossl_bign_keymgmt_gen: bign_generate_private_key error \n");
        goto err;
    }


    // Compute public key: pub = priv * G
    if (!bign_compute_public_key(key_ctx->group, key_ctx->priv_key, key_ctx->pub_key)) // Use key_ctx->group
    {
        fprintf(stderr, "ossl_bign_keymgmt_gen: bign_compute_public_key error \n");
        goto err;
    }

    // The key_ctx is now fully populated with the generated key material.
    // No need to create an EVP_PKEY internally. OpenSSL will wrap this key_ctx.

    BN_CTX_free(bn_ctx);
    bn_ctx = NULL;

    if (osslcb) {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("operation", "keygen", 0);
        params[1] = OSSL_PARAM_construct_end();
        osslcb(params, cbarg);
    }
    char* hex_str;
    hex_str = BN_bn2hex(key_ctx->priv_key); if (hex_str) { printf("priv_key:  %s\n", hex_str); OPENSSL_free(hex_str); }
    
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();

    if (EC_POINT_get_affine_coordinates(key_ctx->group, key_ctx->pub_key, x, y, NULL)) {
        printf("pub_key_X: "); BN_print_fp(stdout, x);  putc('\n', stdout);
        printf("pub_key_Y: "); BN_print_fp(stdout, y);  putc('\n', stdout);
        
    }
    
    fprintf(stderr, "ossl_bign_keymgmt_gen: end\n");
    return key_ctx;

err:
    // Free only what was allocated within this function or assigned to key_ctx
    // and not yet freed by helper functions
    BN_CTX_free(bn_ctx);
    ossl_bign_keymgmt_free(key_ctx); // Use your free function to clean up key_ctx
    return NULL;
}

static void ossl_bign_keymgmt_gen_cleanup(void* gen_ctx_arg) {
    BIGN_KEYMGMT_GEN_CTX* gen_ctx = (BIGN_KEYMGMT_GEN_CTX*)gen_ctx_arg;
    if (gen_ctx) {
        // Free the EC_GROUP that was dup'd and stored in gen_ctx->group_to_gen
        EC_GROUP_free(gen_ctx->group_to_gen);
        OPENSSL_free(gen_ctx);
    }
}

// --- DISPATCH TABLE ---
const OSSL_DISPATCH ossl_bign_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ossl_bign_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ossl_bign_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))ossl_bign_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))ossl_bign_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))ossl_bign_keymgmt_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))ossl_bign_keymgmt_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ossl_bign_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))ossl_bign_keymgmt_query_op_name },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ossl_bign_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ossl_bign_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ossl_bign_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))ossl_bign_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ossl_bign_keymgmt_dup },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))ossl_bign_keymgmt_validate },

    /* Key generation */
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ossl_bign_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))ossl_bign_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))ossl_bign_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ossl_bign_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))ossl_bign_keymgmt_gen_cleanup },

    { 0, NULL }
};