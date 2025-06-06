//bign_encoders_prov.c


#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evperr.h>
#include <openssl/bio.h>
#include <lwocrypt-provider/bign_keymgmt_prov.h>
#include <lwocrypt-provider/lwocrypt_prov_main.h>
#include <lwocrypt-provider/bign_encoders_prov.h>
#include <openssl/objects.h> // Для OBJ_nid2sn (если используется в export)

// -- - Прототип вашей функции экспорта из bign_keymgmt_prov.c-- -
// Убедитесь, что этот прототип доступен (например, через bign_keymgmt_prov.h)
extern int ossl_bign_keymgmt_export(const void* keydata, int selection,
    OSSL_CALLBACK* cb, void* cbarg);


// -- - Вспомогательная функция для сбора параметров из ossl_bign_keymgmt_export-- -
// Используется как колбэк для OSSL_CALLBACK.
static int export_to_param_bld_cb(const OSSL_PARAM params[], void* arg) {
    OSSL_PARAM_BLD* bld = (OSSL_PARAM_BLD*)arg;

    if (!bld) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    for (const OSSL_PARAM* p = params; p->key != NULL; ++p) {
        int push_ok = 0;
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            // Assuming integer types are passed as int64_t for OSSL_PARAM_BLD_push_int64
            // You might need to adjust this based on the specific integer types your params use.
            // For instance, if you use OSSL_PARAM_uint32 in export, use OSSL_PARAM_BLD_push_uint32
            // For this example, I'll use int64/uint64 as common catch-alls
            if (p->data_size == sizeof(int32_t)) {
                push_ok = OSSL_PARAM_BLD_push_int32(bld, p->key, *(const int32_t*)p->data);
            }
            else if (p->data_size == sizeof(int64_t)) {
                push_ok = OSSL_PARAM_BLD_push_int64(bld, p->key, *(const int64_t*)p->data);
            }
            else {
                // Handle other integer sizes or raise error
                ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT);
                return 0;
            }
            break;
        case OSSL_PARAM_UNSIGNED_INTEGER:
            if (p->data_size == sizeof(uint32_t)) {
                push_ok = OSSL_PARAM_BLD_push_uint32(bld, p->key, *(const uint32_t*)p->data);
            }
            else if (p->data_size == sizeof(uint64_t)) {
                push_ok = OSSL_PARAM_BLD_push_uint64(bld, p->key, *(const uint64_t*)p->data);
            }
            else {
                // This case handles BIGNUM as an unsigned integer if it's not a direct BN pointer
                // If your private key or other BIGNUMs are exported as OSSL_PARAM_UNSIGNED_INTEGER
                // with raw bytes (like OSSL_PARAM_construct_BN does), this is the correct path.
                // However, it's safer to use OSSL_PARAM_BLD_push_octet_string for raw bytes
                // or OSSL_PARAM_BLD_push_BN if 'p->data' points to a BIGNUM*
                // Assuming your ossl_bign_keymgmt_export uses OSSL_PARAM_construct_BN which
                // makes it an OSSL_PARAM_UNSIGNED_INTEGER, but with data as unsigned char*.
                // This is where OSSL_PARAM_BLD_push_BN_pad or OSSL_PARAM_BLD_push_octet_string would be better.
                // For now, let's assume it's meant to be treated as raw bytes for the BN type.
                push_ok = OSSL_PARAM_BLD_push_octet_string(bld, p->key, p->data, p->data_size);
            }
            break;
        case OSSL_PARAM_UTF8_STRING:
            // Assuming p->data points to the string and p->data_size is its length
            // Use 0 for bsize to let OSSL_PARAM_BLD_push_utf8_string duplicate the string
            push_ok = OSSL_PARAM_BLD_push_utf8_string(bld, p->key, (const char*)p->data, 0);
            break;
        case OSSL_PARAM_OCTET_STRING:
            // p->data is the byte array, p->data_size is its length
            push_ok = OSSL_PARAM_BLD_push_octet_string(bld, p->key, p->data, p->data_size);
            break;
            // Add other OSSL_PARAM_BLD_push_ functions for other types if your export sends them
            // case OSSL_PARAM_REAL: // For doubles
            //     push_ok = OSSL_PARAM_BLD_push_double(bld, p->key, *(const double*)p->data);
            //     break;
        default:
            // Handle unsupported parameter types
            ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT); // Use a relevant error
            return 0;
        }

        if (!push_ok) {
            // Error pushing parameter (e.g., malloc failure)
            ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    return 1; // Success
}

// --- ФИНАЛЬНАЯ РЕАЛИЗАЦИЯ bign_keymgmt_to_evp_pkey ---
// Функция для создания стандартного EVP_PKEY из внутренней структуры BIGN_KEYMGMT_KEY.
static EVP_PKEY* bign_keymgmt_to_evp_pkey(const BIGN_KEYMGMT_KEY* key_ctx, OSSL_LIB_CTX* libctx) {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    OSSL_PARAM_BLD* bld = NULL;
    OSSL_PARAM* params = NULL;
    int ret = 0; // По умолчанию - неудача

    fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: Начинаю конвертацию BIGN_KEYMGMT_KEY в EVP_PKEY.\n");

    // Проверка входных параметров
    if (!key_ctx || !key_ctx->provctx || key_ctx->nid == NID_undef || !libctx) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: Некорректные параметры: key_ctx, provctx, NID или libctx NULL.\n");
        return NULL;
    }

    // 1. Создаем OSSL_PARAM_BLD для сбора экспортируемых параметров
    bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: OSSL_PARAM_BLD_new не удался.\n");
        goto err;
    }

    // 2. Вызываем вашу функцию экспорта для заполнения OSSL_PARAM_BLD
    // Мы хотим экспортировать параметры домена, публичный ключ и приватный ключ.
    // Если приватный ключ отсутствует, экспорт публичного все равно сработает.
    int selection = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS; // Включает domain, pub, priv
    if (!ossl_bign_keymgmt_export(key_ctx, selection, export_to_param_bld_cb, bld)) {
        fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: ossl_bign_keymgmt_export не удался.\n");
        // Ошибка уже должна быть поднята в ossl_bign_keymgmt_export
        goto err;
    }

    // 3. Конвертируем OSSL_PARAM_BLD в массив OSSL_PARAM
    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: OSSL_PARAM_BLD_to_param не удался.\n");
        goto err;
    }

#ifdef DEBUG_PRINT_PARAMS
    // Отладочный вывод параметров, используемых для fromdata
    fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: Параметры для EVP_PKEY_fromdata:\n");
    for (const OSSL_PARAM* p = params; p->key != NULL; ++p) {
        fprintf(stderr, "  - %s: type %d", p->key, p->data_type);
        if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            fprintf(stderr, ", Value: \"%s\"\n", (char*)p->data);
        }
        else if (p->data_type == OSSL_PARAM_OCTET_STRING) {
            fprintf(stderr, ", Value: (octet string, len %zu)\n", p->data_size);
        }
        else if (p->data_type == OSSL_PARAM_BN) {
            BIGNUM* bn_temp = BN_bin2bn((const unsigned char*)p->data, p->data_size, NULL);
            if (bn_temp) {
                char* hex_str = BN_bn2hex(bn_temp);
                fprintf(stderr, ", Value (hex): %s\n", hex_str);
                OPENSSL_free(hex_str);
                BN_free(bn_temp);
            }
            else {
                fprintf(stderr, ", Value: (BN, conversion failed)\n");
            }
        }
        else {
            fprintf(stderr, "\n");
        }
    }
#endif // DEBUG_PRINT_PARAMS

    // 4. Создаем EVP_PKEY_CTX для типа ключа EC.
    // Это указывает OpenSSL использовать реализацию управления ключами для стандартных EC-ключей
    // (это может быть ваша реализация, если вы зарегистрировали ваш провайдер для EVP_PKEY_EC,
    // или реализация EC по умолчанию от OpenSSL).
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, libctx);
    if (!pctx) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: Не удалось создать EVP_PKEY_CTX для EVP_PKEY_EC.\n");
        goto err;
    }
    fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: EVP_PKEY_CTX создан для EVP_PKEY_EC.\n");

    // 5. Инициализируем операцию fromdata
    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
        fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: EVP_PKEY_fromdata_init не удался.\n");
        goto err;
    }
    fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: EVP_PKEY_fromdata_init успешно завершен.\n");

    // 6. Создаем EVP_PKEY из собранных параметров.
    // EVP_PKEY_KEYPAIR означает, что мы создаем пару ключей (приватный + публичный).
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR); // Ошибка декодирования или построения ключа
        fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: EVP_PKEY_fromdata не удался: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto err;
    }
    fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: EVP_PKEY_fromdata успешно завершен, pkey=%p.\n", (void*)pkey);

    ret = 1; // Успех

err:
    // Очистка ресурсов
    OSSL_PARAM_free(params); // Освобождаем массив параметров
    OSSL_PARAM_BLD_free(bld); // Освобождаем строитель параметров
    EVP_PKEY_CTX_free(pctx); // Освобождаем контекст EVP_PKEY_CTX
    if (!ret) {
        // Если была ошибка, освобождаем EVP_PKEY, если он был выделен
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    fprintf(stderr, "DEBUG: bign_keymgmt_to_evp_pkey: Завершение. ret=%d\n", ret);
    return pkey;
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
    fprintf(stderr, "ossl_bign_encoder_newctx: end\n");
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