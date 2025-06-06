//

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif


#include <string.h>
#include <stdio.h>

#include <openssl/opensslconf.h>
#include <openssl/core.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>


#include <lwocrypt-provider/names.h>
#include <lwocrypt-provider/implementations.h>
#include <lwocrypt-provider/lwocrypt_prov_main.h>
#include <lwocrypt-provider/bign_keymgmt_prov.h>
#include <lwocrypt-provider/bign_encoders_prov.h>
#include <lwocrypt-provider/bign_decoders_prov.h>


// ======================================================================================= //
static  lwocrypt_curve lwocrypt_curves[] = {
	{ 0, "bign-curve256v1", "BIGN Curve 256v1 (STB 34.101.45)" },
	{ 0, "bign-curve384v1", "BIGN Curve 384v1 (STB 34.101.45)" },
	{ 0, "bign-curve512v1", "BIGN Curve 512v1 (STB 34.101.45)" }
};
// ------------------------------------------------------------------------------------------

// Получение списка кривых из переменной lwocrypt_curves
EXPORT int lwocrypt_get_curves(lwocrypt_curve* curves, size_t* count) {
	if (!count) {
		fprintf(stderr, "lwocrypt_get_curves: count is NULL\n");
		return 0;
	}
	size_t curve_count = sizeof(lwocrypt_curves) / sizeof(lwocrypt_curves[0]);
	size_t max_count = *count;
	*count = curve_count;

#if (lwodebug > 2)
	fprintf(stderr, "lwocrypt_get_curves: Returning %zu curves\n", curve_count);
	for (size_t i = 0; i < curve_count; i++) {
		fprintf(stderr, "Curve %zu: NID=%d, Name=%s, Comment=%s\n",
			i, lwocrypt_curves[i].nid, lwocrypt_curves[i].name, lwocrypt_curves[i].comment);
	}
#endif

	if (curves != NULL && max_count < curve_count) {
		fprintf(stderr, "lwocrypt_get_curves: Insufficient buffer size (%zu < %zu)\n",
			max_count, curve_count);
		return 0;
	}

	if (curves) {
		memcpy(curves, lwocrypt_curves, curve_count * sizeof(lwocrypt_curve));
	}

	// Проверка валидности NID
	for (size_t i = 0; i < curve_count; i++) {
		if (lwocrypt_curves[i].nid == NID_undef) {
			fprintf(stderr, "lwocrypt_get_curves: Curve %s has undefined NID\n",
				lwocrypt_curves[i].name);
			return 0;
		}
	}

	return 1;
}



// Получение EC_GROUP для кривой
OPENSSL_EXPORT EC_GROUP* lwocrypt_get_bign_curve(void* provctx, int nid) {
#if (lwodebug > 2)
	fprintf(stderr, "lwocrypt_get_bign_curve: Fetching curve for NID=%d\n", nid);
#endif
	if (provctx == NULL) {
		fprintf(stderr, "lwocrypt_get_bign_curve: Err: LWOCRYPT_PROVIDER_CTX is NULL");
		return NULL;
	}
LWOCRYPT_PROVIDER_CTX* lwocrypt_ctx = (LWOCRYPT_PROVIDER_CTX*)provctx;
	EC_GROUP* curve = NULL;
	CRYPTO_THREAD_read_lock(lwocrypt_ctx->curve_lock);
	if (nid == lwocrypt_ctx->nid_bign_curve256v1) {
		curve = EC_GROUP_dup(lwocrypt_ctx->bign_curve256v1);
#if (lwodebug > 2)
		fprintf(stderr, "lwocrypt_get_bign_curve: Found bign-curve256v1\n");
#endif
	}
	else if (nid == lwocrypt_ctx->nid_bign_curve384v1) {
		curve = EC_GROUP_dup(lwocrypt_ctx->bign_curve384v1);
#if (lwodebug > 2)
		fprintf(stderr, "lwocrypt_get_bign_curve: Found bign-curve384v1\n");
#endif
	}
	else if (nid == lwocrypt_ctx->nid_bign_curve512v1) {
		curve = EC_GROUP_dup(lwocrypt_ctx->bign_curve512v1);
#if (lwodebug > 2)
		fprintf(stderr, "lwocrypt_get_bign_curve: Found bign-curve512v1\n");
#endif
	}
	CRYPTO_THREAD_unlock(lwocrypt_ctx->curve_lock);

	if (!curve) {
		fprintf(stderr, "lwocrypt_get_bign_curve: Failed to duplicate curve for NID=%d\n", nid);
	}
	return curve;
}

 // Функция регистрации параметров кривой bign-curve256v1 = BIGN Curve 256v1, 1.2.112.0.2.0.34.101.45.3.1
 // вызываем при инициализации провайдера 
// параметр libctx OSSL_LIB_CTX* для соответствия контекстно-зависимому дизайну OpenSSL, 
// хотя в этой реализации он не используется (для будущей совместимости)
int register_bign_curve(OSSL_LIB_CTX* libctx, const char* curve_name, EC_GROUP** out_group) {
#if (lwodebug > 3)
	fprintf(stderr, "**** LWOCRYPT: register_bign_curve: %s begin called  -------\n", curve_name);
#endif

	int nid = OBJ_sn2nid(curve_name);
	if (nid != NID_undef) {
#if (lwodebug > 3)
		fprintf(stderr, "register_bign_curve: Reusing existing NID %d for %s\n", nid, curve_name);
#endif
	}
	else {
		const char* oid = NULL;
		if (strcmp(curve_name, "bign-curve256v1") == 0) {
			oid = "1.2.112.0.2.0.34.101.45.3.1";
		}
		else if (strcmp(curve_name, "bign-curve384v1") == 0) {
			oid = "1.2.112.0.2.0.34.101.45.3.2";
		}
		else if (strcmp(curve_name, "bign-curve512v1") == 0) {
			oid = "1.2.112.0.2.0.34.101.45.3.3";
		}
		else {
			fprintf(stderr, "register_bign_curve: Unknown curve: %s\n", curve_name);
			return NID_undef;
		}

		nid = OBJ_create(oid, curve_name, curve_name);
		if (nid == NID_undef) {
			fprintf(stderr, "register_bign_curve: Failed to create OID for %s: %s\n", curve_name, ERR_error_string(ERR_get_error(), NULL));
			return NID_undef;
		}
#if (lwodebug > 3)
		fprintf(stderr, "register_bign_curve: Created new NID %d for %s\n", nid, curve_name);
#endif
	}

	EC_GROUP* group = NULL;
	EC_POINT* generator = NULL;
	BIGNUM* p = NULL, * a = NULL, * b = NULL, * x = NULL, * y = NULL, * order = NULL;
	BN_CTX* ctx = BN_CTX_new();
	if (!ctx) goto err;

	p = BN_new(); a = BN_new(); b = BN_new(); x = BN_new(); y = BN_new(); order = BN_new();
	if (!p || !a || !b || !x || !y || !order) goto err;

	if (strcmp(curve_name, "bign-curve256v1") == 0) {
		if (!BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43") ||
			!BN_hex2bn(&a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40") ||
			!BN_hex2bn(&b, "77CE6C1515F3A8EDD2C13AABE4D8FBBE4CF55069978B9253B22E7D6BD69C03F1") ||
			!BN_hex2bn(&x, "0000000000000000000000000000000000000000000000000000000000000000") ||
			!BN_hex2bn(&y, "6BF7FC3CFB16D69F5CE4C9A351D6835D78913966C408F6521E29CF1804516A93") ||
			!BN_hex2bn(&order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD95C8ED60DFB4DFC7E5ABF99263D6607")) {
			goto err;
		}
	}
	else if (strcmp(curve_name, "bign-curve384v1") == 0) {
		if (!BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC3") ||
			!BN_hex2bn(&a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC0") ||
			!BN_hex2bn(&b, "3C75DFE1959CEF2033075AAB655D34D2712748BB0FFBB196A6216AF9E9712E3A14BDE2F0F3CEBD7CBCA7FC236873BF64") ||
			!BN_hex2bn(&x, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") ||
			!BN_hex2bn(&y, "5D438224A82E9E9E6330117E432DBF893A729A11DC86FFA00549E79E66B1D35584403E276B2A42F9EA5ECB31F733C451") ||
			!BN_hex2bn(&order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE6CCCC40373AF7BBB8046DAE7A6A4FF0A3DB7DC3FF30CA7B7")) {
			goto err;
		}
	}
	else if (strcmp(curve_name, "bign-curve512v1") == 0) {
		if (!BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7") ||
			!BN_hex2bn(&a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4") ||
			!BN_hex2bn(&b, "6CB45944933B8C43D88C5D6A60FD58895BC6A9EEDD5D255117CE13E3DAADB0882711DCB5C4245E952933008C87ACA243EA8622273A49A27A09346998D6139C90") ||
			!BN_hex2bn(&x, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") ||
			!BN_hex2bn(&y, "A826FF7AE4037681B182E6F7A0D18FABB0AB41B3B361BCE2D2EDF81B00CCCADA6973DDE20EFA6FD2FF777395EEE8226167AA83B9C94C0D04B792AE6FCEEFEDBD") ||
			!BN_hex2bn(&order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB2C0092C0198004EF26BEBB02E2113F4361BCAE59556DF32DCFFAD490D068EF1")) {
			goto err;
		}
	}

	// Выводим параметры кривой для проверки
#if (lwodebug > 3)
	{
		char* hex_str;
		hex_str = BN_bn2hex(p); if (hex_str) { printf("p: %s\n", hex_str); OPENSSL_free(hex_str); }
		hex_str = BN_bn2hex(a); if (hex_str) { printf("a: %s\n", hex_str); OPENSSL_free(hex_str); }
		hex_str = BN_bn2hex(b); if (hex_str) { printf("b: %s\n", hex_str); OPENSSL_free(hex_str); }
		hex_str = BN_bn2hex(x); if (hex_str) { printf("x: %s\n", hex_str); OPENSSL_free(hex_str); }
		hex_str = BN_bn2hex(y); if (hex_str) { printf("y: %s\n", hex_str); OPENSSL_free(hex_str); }
		hex_str = BN_bn2hex(order); if (hex_str) { printf("order: %s\n", hex_str); OPENSSL_free(hex_str); }
	}
#endif


	// Создаем группу
	group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
	if (!group) {
		fprintf(stderr, " Failed to create EC_GROUP: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}

	// Создаем генератор
	generator = EC_POINT_new(group);
	if (!generator) {
		fprintf(stderr, " Failed to create EC_POINT: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	// Устанавливаем координаты генератора
	if (!EC_POINT_set_affine_coordinates(group, generator, x, y, ctx)) {
		fprintf(stderr, "Failed to set generator coordinates: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	// Проверяем, что точка лежит на кривой
	if (!EC_POINT_is_on_curve(group, generator, ctx)) {
		fprintf(stderr, " Generator point is not on curve: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	// Устанавливаем генератор и порядок
	if (!EC_GROUP_set_generator(group, generator, order, BN_value_one())) {
		fprintf(stderr, " Failed to set generator: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}

	// Устанавливаем флаг именованной кривой
	EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
	// Устанавливаем форму представления точек
	EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);
	// Устанавливаем имя кривой в EC подсистеме 
	EC_GROUP_set_curve_name(group, nid);

	// Проверяем валидность кривой
		if (EC_GROUP_check(group, NULL) != 1) {
			fprintf(stderr, " Error EC_GROUP_check for NID: %d %s\n",nid,
				ERR_error_string(ERR_get_error(), NULL));
			goto err;
		} 
		

	/*

	// Проверяем возможность использования кривой через EVP API - EVP_PKEY_CTX для операций с ключами EC.
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!pctx) {
		fprintf(stderr, "Failed to create EVP_PKEY_CTX: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	if (EVP_PKEY_paramgen_init(pctx) <= 0 || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0) {
		fprintf(stderr, "Failed to set curve NID in EVP: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
	*/
	*out_group = group;
	group = NULL;
	// Освобождаем ресурсы
   // EVP_PKEY_CTX_free(pctx);
	EC_POINT_free(generator);
	BN_free(p); BN_free(a); BN_free(b); BN_free(x); BN_free(y); BN_free(order);
	BN_CTX_free(ctx);
	return nid;

err:
	// Освобождаем ресурсы
 //       if (pctx) {
 //           EVP_PKEY_CTX_free(pctx);
 //           pctx = NULL;
 //       }

	if (generator) {
		EC_POINT_free(generator);
		generator = NULL;
	}

	if (p) BN_free(p);
	if (a) BN_free(a);
	if (b) BN_free(b);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (order) BN_free(order);

	if (ctx) {
		BN_CTX_free(ctx);
		ctx = NULL;
	}
	return NID_undef;
}

//=========================================================================================================
// Массив OSSL_ALGORITHM, где указывается имя алгоритма, свойства, функции реализации и другие параметры.
static const OSSL_ALGORITHM lwocrypt_digests[] = {
	{ PROV_NAMES_BASH256, PROPERTY_NAME, ossl_bash256_functions},
	{ PROV_NAMES_BASH384, PROPERTY_NAME, ossl_bash384_functions },
	{ PROV_NAMES_BASH512, PROPERTY_NAME, ossl_bash512_functions },
	{ PROV_NAMES_BELT_HASH, PROPERTY_NAME, ossl_belthash_functions },
	{ NULL, NULL, NULL } };
static const OSSL_ALGORITHM lwocrypt_macs[] = {
	{ PROV_NAMES_BELT_MAC256, PROPERTY_NAME, ossl_belt_mac_functions },
	{ NULL, NULL, NULL } };
static const OSSL_ALGORITHM lwocrypt_ciphers[] = {
	{ PROV_NAMES_BELT_128_CBC, PROPERTY_NAME, ossl_belt128cbc_functions },
	{ PROV_NAMES_BELT_192_CBC, PROPERTY_NAME, ossl_belt192cbc_functions },
	{ PROV_NAMES_BELT_256_CBC, PROPERTY_NAME, ossl_belt256cbc_functions },
	{ PROV_NAMES_BELT_128_ECB, PROPERTY_NAME, ossl_belt128ecb_functions },
	{ PROV_NAMES_BELT_192_ECB, PROPERTY_NAME, ossl_belt192ecb_functions },
	{ PROV_NAMES_BELT_256_ECB, PROPERTY_NAME, ossl_belt256ecb_functions },
	{ PROV_NAMES_BELT_128_CTR, PROPERTY_NAME, ossl_belt128ctr_functions },
	{ PROV_NAMES_BELT_192_CTR, PROPERTY_NAME, ossl_belt192ctr_functions },
	{ PROV_NAMES_BELT_256_CTR, PROPERTY_NAME, ossl_belt256ctr_functions },
	{ PROV_NAMES_BELT_128_CFB, PROPERTY_NAME, ossl_belt128cfb_functions },
	{ PROV_NAMES_BELT_192_CFB, PROPERTY_NAME, ossl_belt192cfb_functions },
	{ PROV_NAMES_BELT_256_CFB, PROPERTY_NAME, ossl_belt256cfb_functions },
   // { PROV_NAMES_BELT_128_DWP, PROPERTY_NAME, ossl_belt128dwp_functions },
  //  { PROV_NAMES_BELT_192_DWP, PROPERTY_NAME, ossl_belt192dwp_functions },
   // { PROV_NAMES_BELT_256_DWP, PROPERTY_NAME, ossl_belt256dwp_functions },
   // { PROV_NAMES_BELT_128_KWP, PROPERTY_NAME, ossl_belt128kwp_functions },
   // { PROV_NAMES_BELT_192_KWP, PROPERTY_NAME, ossl_belt192kwp_functions },
   // { PROV_NAMES_BELT_256_KWP, PROPERTY_NAME, ossl_belt256kwp_functions },
	{ NULL, NULL, NULL } };
static const OSSL_ALGORITHM lwocrypt_kdfs[] = {
   // { PROV_NAMES_HKDF, PROPERTY_NAME, ossl_hkdf_functions },
	{ NULL, NULL, NULL }
};
static const OSSL_ALGORITHM lwocrypt_rands[] = {
  // { PROV_NAMES_CTR_DRBG, PROPERTY_NAME, ossl_lwocrypt_rand_functions },
	{ NULL, NULL, NULL }
};
static const OSSL_ALGORITHM lwocrypt_keymgmt[] = {
	 { "BIGN:bign:bign-curve256v1:bign-curve384v1:bign-curve512v1", "provider=lwocrypt", ossl_bign_keymgmt_functions },
	{ NULL, NULL, NULL  }
};
static const OSSL_ALGORITHM lwocrypt_keyexch[] = {
	//  { PROV_NAMES___, PROPERTY_NAME, ossl_keyexch_functions },
	  { NULL, NULL, NULL }
};
static const OSSL_ALGORITHM lwocrypt_signature[] = {
	{"BIGN","provider=lwocrypt",ossl_bign_hbelt_signature_functions},
	{ NULL, NULL, NULL } };
static const OSSL_ALGORITHM lwocrypt_asym_cipher[] = {
	//  { PROV_NAMES___, PROPERTY_NAME, ossl_asym_cipher_functions },
	  { NULL, NULL, NULL }
};
static const OSSL_ALGORITHM lwocrypt_kem[] = {
	//  { PROV_NAMES___, PROPERTY_NAME, ossl_kem_functions },
	  { NULL, NULL, NULL }
};
static const OSSL_ALGORITHM lwocrypt_encoders[] = {
	// For DER private key output
	{ "BIGN", "output=der", ossl_bign_encoder_der_privkey_functions },
	// For PEM private key output
	{ "BIGN", "output=pem", ossl_bign_encoder_pem_privkey_functions },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM lwocrypt_decoders[] = {
	// For PEM private key input
	{ "BIGN", "input=pem", ossl_bign_decoder_functions },
	// For DER private key input
	{ "BIGN", "input=der", ossl_bign_decoder_functions },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM lwocrypt_store[] = {
	//  { PROV_NAMES___, PROPERTY_NAME, ossl_store_functions },
	  { NULL, NULL, NULL }
};
/// =========================================================================================
/* lwocrypt_operation сопоставляет идентификаторы операций с таблицами алгоритмов. */
static const OSSL_ALGORITHM* lwocrypt_operation(void* provctx, int operation_id, int* no_cache) {
	//fprintf(stderr, "**** LWOCrypt lwocrypt_operation called operation_id: %d with provctx=%p *****\n", 
		//operation_id, provctx);
	*no_cache = 0;
	switch (operation_id) {
	case OSSL_OP_DIGEST:
		fprintf(stderr, "lwocrypt_operation: DIGEST  %p\n", (void*)lwocrypt_digests);
		return lwocrypt_digests;
	case OSSL_OP_CIPHER:
		fprintf(stderr, "lwocrypt_operation: CIPHER  %p\n", (void*)lwocrypt_ciphers);
		return lwocrypt_ciphers;
	case OSSL_OP_MAC:
		fprintf(stderr, "lwocrypt_operation: MAC   %p\n", (void*)lwocrypt_macs);
		return lwocrypt_macs;
	case OSSL_OP_KDF:
		fprintf(stderr, "lwocrypt_operation:  KDF   %p \n", (void*)lwocrypt_kdfs);
		return lwocrypt_kdfs;
	case OSSL_OP_RAND:
		fprintf(stderr, "lwocrypt_operation: RAND   %p\n", (void*)lwocrypt_rands);
		return lwocrypt_rands;
	case OSSL_OP_KEYMGMT:
		fprintf(stderr, "lwocrypt_operation:  KEYMGMT   %p\n", (void*)lwocrypt_keymgmt);
		return lwocrypt_keymgmt;
	case OSSL_OP_KEYEXCH:
		fprintf(stderr, "lwocrypt_operation:  KEYEXCH   %p\n", (void*)lwocrypt_keyexch);
		return lwocrypt_keyexch;
	case OSSL_OP_SIGNATURE:
		fprintf(stderr, "Returning SIGNATURE   %p\n", (void*)lwocrypt_signature);
		return lwocrypt_signature;
	case OSSL_OP_ASYM_CIPHER:
		fprintf(stderr, "Returning ASYM_CIPHER   %p\n", (void*)lwocrypt_asym_cipher);
		return lwocrypt_asym_cipher;
	case OSSL_OP_KEM:
		fprintf(stderr, "Returning _KEM   %p\n", (void*)lwocrypt_kem);
		return lwocrypt_kem;
	case OSSL_OP_ENCODER:
		fprintf(stderr, "Returning ENCODER   %p\n", (void*)lwocrypt_encoders);
		return lwocrypt_encoders;
	case OSSL_OP_DECODER:
		fprintf(stderr, "Returning DECODER   %p\n", (void*)lwocrypt_decoders);
		return lwocrypt_decoders;
	case OSSL_OP_STORE:
		fprintf(stderr, "Returning STORE   %p\n", (void*)lwocrypt_store);
		return lwocrypt_store;
	default:
		fprintf(stderr, "Unsupported operation id %d\n", operation_id);
		return NULL;
	}
}



// =========================================================================================
static int lwocrypt_prov_get_params(void* provctx, OSSL_PARAM params[])
{
	fprintf(stderr, "**** LWOCrypt lwocrypt_prov_get_params called  *****\n");
	OSSL_PARAM* p;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "LWOCRYPT Provider"))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "4.0.1"))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "LWOCrypt 4 12 Jun 2025"))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
	if (p != NULL && !OSSL_PARAM_set_int(p, 1))
		return 0;

	return 1;
}

static const OSSL_ALGORITHM* const* lwocrypt_get_encoder_types(void* provctx) {
	return &lwocrypt_encoders;
}

static const OSSL_ALGORITHM* const* lwocrypt_get_decoder_types(void* provctx) {
	return &lwocrypt_decoders;
}



// Таблица диспетчеризации
static const OSSL_DISPATCH provider_dispatch[] = {
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))lwocrypt_operation },
	{ OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))lwocrypt_prov_get_params },
	//{ OSSL_FUNC_PARAM_:GETTABLE, (void (*)(void))bign_param_gettable },
	//{ OSSL_FUNC_PARAM_GET, (void (*)(void))bign_param_get },
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))lwocrypt_prov_teardown },
	{ 0, NULL }

};
// =========================================================================================
 // Очистка провайдера
void lwocrypt_prov_teardown(void* provctx) {
	LWOCRYPT_PROVIDER_CTX* ctx = (LWOCRYPT_PROVIDER_CTX*)provctx;
#if (lwodebug > 1)
	fprintf(stderr, "**** LWOCRYPT lwocrypt_prov_teardown called *****\n");
#endif
	if (ctx->curve_lock)
		CRYPTO_THREAD_lock_free(ctx->curve_lock);
	if (ctx->bign_curve256v1)
		EC_GROUP_free(ctx->bign_curve256v1);
	if (ctx->bign_curve384v1)
		EC_GROUP_free(ctx->bign_curve384v1);
	if (ctx->bign_curve512v1)
		EC_GROUP_free(ctx->bign_curve512v1);
	if (ctx->libctx)
		OSSL_LIB_CTX_free(ctx->libctx);
}











// =========================================================================================
//  Инициализация провайдера (Регистрация всех необходимых алгоритмов (через OSSL_ALGORITHM).
LWOCRYPT_PROVIDER_API int OSSL_provider_init(const OSSL_CORE_HANDLE* handle,
	const OSSL_DISPATCH* in,  // Указатель на массив OSSL_DISPATCH , предоставляющий функции из ядра OpenSSL поставщику (например, распределение памяти, обработка ошибок)
	const OSSL_DISPATCH** out,  // указатель на массив OSSL_DISPATCH , в котором поставщик возвращает поддерживаемые им функции в OpenSSL.
	void** provctx) // указатель на контекст, специфичный для поставщика, который поставщик может использовать для хранения своего состояния.
{
	#if  (lwodebug > 1)
	fprintf(stderr, "**** LWOCRYPT OSSL_provider_init called  *****\n ");
	#endif
	//LWOCRYPT_PROVIDER_CTX* lwoprovctx = OPENSSL_zalloc(sizeof(*lwoprovctx));
	LWOCRYPT_PROVIDER_CTX* lwoprovctx = OPENSSL_zalloc(sizeof(LWOCRYPT_PROVIDER_CTX));
	if (!lwoprovctx) {
		fprintf(stderr, "OSSL_provider_init: Failed to allocate provider context\n");
		return 0;
	}
	lwoprovctx->libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
	
	if (lwoprovctx->libctx == NULL) {
		OPENSSL_free(lwoprovctx);
		return 0;
	}
	fprintf(stderr, "**** LWOCRYPT OSSL_provider_init lwoprovctx: %p lwoprovctx->libctx: %p\n", lwoprovctx, lwoprovctx->libctx);
	lwoprovctx->curve_lock = CRYPTO_THREAD_lock_new();
	if (!lwoprovctx->curve_lock) {
		fprintf(stderr, "OSSL_provider_init: Failed to create curve lock\n");
		OSSL_LIB_CTX_free(lwoprovctx->libctx);
		OPENSSL_free(lwoprovctx);
		return 0;
	}
	

	// Регистрация кривой bign-curve256v1
	lwoprovctx->nid_bign_curve256v1 = register_bign_curve(lwoprovctx->libctx, "bign-curve256v1", &lwoprovctx->bign_curve256v1);
	lwoprovctx->name_bign_curve256v1 = "bign-curve256v1";
	if (lwoprovctx->nid_bign_curve256v1 == NID_undef || !lwoprovctx->bign_curve256v1) {
		fprintf(stderr, "OSSL_provider_init: Failed to register bign-curve256v1: %s\n",
			ERR_error_string(ERR_get_error(), NULL));
		lwocrypt_prov_teardown(lwoprovctx);
		return 0;
	}
	lwocrypt_curves[0].nid = lwoprovctx->nid_bign_curve256v1;
	#if (lwodebug > 3)
	fprintf(stderr, "OSSL_provider_init: Curve bign-curve256v1 registered with NID: %d\n",
		lwoprovctx->nid_bign_curve256v1);
	#endif

	// Регистрация кривой bign-curve384v1
	lwoprovctx->nid_bign_curve384v1 = register_bign_curve(lwoprovctx->libctx, "bign-curve384v1", &lwoprovctx->bign_curve384v1);
	lwoprovctx->name_bign_curve384v1 = "bign-curve384v1";
	if (lwoprovctx->nid_bign_curve384v1 == NID_undef || !lwoprovctx->bign_curve384v1) {
		fprintf(stderr, "OSSL_provider_init: Failed to register bign-curve384v1: %s\n",
			ERR_error_string(ERR_get_error(), NULL));
		lwocrypt_prov_teardown(lwoprovctx);
		return 0;
	}
	lwocrypt_curves[1].nid = lwoprovctx->nid_bign_curve384v1;
#if (lwodebug > 3)
	fprintf(stderr, "OSSL_provider_init: Curve bign-curve384v1 registered with NID: %d\n",
		lwoprovctx->nid_bign_curve384v1);
#endif

	// Регистрация кривой bign-curve512v1
	lwoprovctx->nid_bign_curve512v1 = register_bign_curve(lwoprovctx->libctx, "bign-curve512v1", &lwoprovctx->bign_curve512v1);
	lwoprovctx->name_bign_curve512v1 = "bign-curve512v1";
	if (lwoprovctx->nid_bign_curve512v1 == NID_undef) {
		fprintf(stderr, "OSSL_provider_init: Failed to register bign-curve512v1: %s\n",
			ERR_error_string(ERR_get_error(), NULL));
		lwocrypt_prov_teardown(lwoprovctx);
		return 0;
	}
	lwocrypt_curves[2].nid = lwoprovctx->nid_bign_curve512v1;
#if (lwodebug > 3)
	fprintf(stderr, "OSSL_provider_init: Curve bign-curve512v1 registered with NID: %d\n",
		lwoprovctx->nid_bign_curve512v1);
#endif



	* out = provider_dispatch;
	*provctx = lwoprovctx;
	


#if (lwodebug > 1)
	fprintf(stderr, "**** LWOCRYPT OSSL_provider_init completed successfully!\n" );
#endif
	return 1;
}

//OSSL_PROVIDER* prov = OSSL_PROVIDER_load(libctx, "lwocrypt");
//if (!prov) {
//    fprintf(stderr, "Failed to load LWOCRYPT provider\n");
//    return NULL;
//}

/*

Получение LWOCRYPT_PROVIDER_CTX* из OSSL_LIB_CTX* где угодно :

LWOCRYPT_PROVIDER_CTX* lwoprovctx = OSSL_LIB_CTX_get_data(libctx, lwocrypt_ex_data_index);
if (!lwoprovctx) {
	fprintf(stderr, "LWOCRYPT context not found in libctx\n");
	return NULL;
}
*/