
// lwocrypt_prov_main.h
#ifndef LWOCRYPT_PROVIDER_H
#define LWOCRYPT_PROVIDER_H
#ifdef __cplusplus
extern "C" {
#endif
#include <openssl/core.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#ifdef _WIN32
#ifdef LWOCRYPT_EXPORTS
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#endif
#else
#define EXPORT
#endif

    /* Контекст провайдера */
    typedef struct lwocrypt_provider_ctx_st {
        OSSL_LIB_CTX* libctx;            // Контекст библиотеки OpenSSL
        CRYPTO_RWLOCK* curve_lock;       // RW-блокировка для потокобезопасного доступа к кривым
        int nid_bign_curve256v1;
        EC_GROUP* bign_curve256v1;
        const char* name_bign_curve256v1;  // Добавлено: имя кривой

        int nid_bign_curve384v1;
        EC_GROUP* bign_curve384v1;
        const char* name_bign_curve384v1;  // Добавлено: имя кривой

        int nid_bign_curve512v1;
        EC_GROUP* bign_curve512v1;
        const char* name_bign_curve512v1;  // Добавлено: имя кривой

       // EVP_KEYMGMT* bign_keymgmt;       // Cached key management for BIGN
    } LWOCRYPT_PROVIDER_CTX;

    typedef struct {
        int nid;
        const char* name;
        const char* comment;
    } lwocrypt_curve;

    OPENSSL_EXPORT EC_GROUP* lwocrypt_get_bign_curve(void* provctx, int nid);
    EXPORT int lwocrypt_get_curves(lwocrypt_curve* curves, size_t* count);
    EXPORT int OSSL_provider_init(const OSSL_CORE_HANDLE* handle,
        const OSSL_DISPATCH* in,
        const OSSL_DISPATCH** out,
        void** provctx);
      void lwocrypt_prov_teardown(void* provctx);

#ifdef __cplusplus
}
#endif
#endif