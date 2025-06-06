// bign_keymgmt_prov.h
#ifndef LWOCRYPT_PROVIDER_BIGN_KEYMGMT_PROV_H
#define LWOCRYPT_PROVIDER_BIGN_KEYMGMT_PROV_H


#include <openssl/evp.h>
#include <openssl/ec.h> // Ensure EC_GROUP is known
#include <openssl/bn.h> // Ensure BIGNUM is known
#include <openssl/core_dispatch.h> // For OSSL_DISPATCH
#include <openssl/params.h> // For OSSL_PARAM
#include <lwocrypt-provider/lwocrypt_prov_main.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

/*
typedef struct {
    OSSL_LIB_CTX* libctx; // Store libctx for fetching later, if needed
    LWOCRYPT_PROVIDER_CTX* provctx;
    EC_GROUP* group;
    int nid;
    int selection;
    EVP_PKEY* pkey;
} BIGN_KEYMGMT_CTX;
*/

// Context for an instantiated BIGN key object (pkey->keymgmt_data)
typedef struct {
    OSSL_LIB_CTX* libctx;            // OpenSSL library context
    LWOCRYPT_PROVIDER_CTX* provctx;  // Pointer to your provider's global context
    int nid;                         // NID (Numeric ID) of the BIGN curve (e.g., NID_bign_curve256v1)
    EC_GROUP* group;                 // The EC_GROUP object for this curve (might be owned by provctx, or dup'd here)
    BIGNUM* priv_key;                // The BIGNUM representing the private key
    EC_POINT* pub_key;               // The EC_POINT representing the public key
} BIGN_KEYMGMT_KEY;

// Context for key generation parameters (genctx)
typedef struct {
    LWOCRYPT_PROVIDER_CTX* provctx;
    EC_GROUP* group_to_gen; // The EC_GROUP for key generation
    int nid_to_gen;         // NID of the curve to generate
} BIGN_KEYMGMT_GEN_CTX;



// --- Function Prototypes for functions called externally ---
// These are functions that are part of the OSSL_DISPATCH table or called by other provider components.

EXPORT void* ossl_bign_keymgmt_new(void* provctx_arg);
EXPORT void ossl_bign_keymgmt_free(void* key_ctx_arg);
EXPORT int ossl_bign_keymgmt_get_params(void* keydata, OSSL_PARAM params[]);
EXPORT const OSSL_PARAM* ossl_bign_keymgmt_gettable_params(void* provctx);
EXPORT int ossl_bign_keymgmt_set_params(void* key_ctx_arg, const OSSL_PARAM params[]);
EXPORT const OSSL_PARAM* ossl_bign_keymgmt_settable_params(void* provctx);
EXPORT int ossl_bign_keymgmt_has(const void* key_ctx_arg, int selection);
EXPORT const char* ossl_bign_keymgmt_query_op_name(int operation_id);
EXPORT void* ossl_bign_keymgmt_import(void* provctx, int selection, const OSSL_PARAM params[]);
EXPORT const OSSL_PARAM* ossl_bign_keymgmt_import_types(int selection);
EXPORT int ossl_bign_keymgmt_export(const void* keydata, int selection, OSSL_CALLBACK* cb, void* cbarg);
EXPORT const OSSL_PARAM* ossl_bign_keymgmt_export_types(int selection);
EXPORT void* ossl_bign_keymgmt_dup(const void* key_ctx_arg, int selection);
EXPORT int ossl_bign_keymgmt_validate(void* key_ctx_arg, int selection, int checktype);

// Key generation functions
EXPORT void* ossl_bign_keymgmt_gen_init(void* provctx_arg, int selection, const OSSL_PARAM params[]);
EXPORT int ossl_bign_keymgmt_gen_set_params(void* genctx, const OSSL_PARAM params[]);
EXPORT const OSSL_PARAM* ossl_bign_keymgmt_gen_settable_params(void* provctx);
EXPORT void* ossl_bign_keymgmt_gen(void* gen_ctx_arg, OSSL_CALLBACK* osslcb, void* cbarg);
EXPORT void ossl_bign_keymgmt_gen_cleanup(void* gen_ctx_arg);

// Also need the get_bign_group_from_nid if it's called from other files
// static const EC_GROUP* get_bign_group_from_nid(LWOCRYPT_PROVIDER_CTX* provctx, int nid);
// Note: If get_bign_group_from_nid is only used internally within bign_keymgmt_prov.c,
// you don't need to declare it in the .h file. Your current code shows it commented out.
// If ossl_bign_encoder_import_object is in *another* file, it will need a prototype for
// ossl_bign_keymgmt_import in a header file that it includes.

EXPORT extern const OSSL_DISPATCH ossl_bign_keymgmt_functions[];

#endif