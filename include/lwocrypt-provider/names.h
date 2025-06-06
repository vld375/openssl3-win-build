
// names.h
#ifndef LWOCRYPT_NAMES_H
#define LWOCRYPT_NAMES_H

#ifdef __cplusplus
extern "C" {
#endif


#ifdef _WIN32
#ifdef LWOCRYPT_EXPORTS
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#endif
#else
#define EXPORT
#endif

#define lwodebug 3 
	// Уникальный идентификатор для провайдера LWOCRYPT в пределах приложения, чтобы избежать конфликтов с другими провайдерами или модулями
#define LWOCRYPT_PROVIDER_CONTEXT_ID 1001
/* Properties for algorithm selection */
#define PROPERTY_NAME "provider=lwocrypt"

#define LWOCRYPT_PROVIDER_API EXPORT


/* Symmetric ciphers */
#define PROV_NAMES_BELT_128_ECB "BELT-128-ECB:belt-ecb128:1.2.112.0.2.0.34.101.31.11"
#define PROV_NAMES_BELT_192_ECB "BELT-192-ECB:belt-ecb192:1.2.112.0.2.0.34.101.31.12"
#define PROV_NAMES_BELT_256_ECB "BELT-256-ECB:belt-ecb256:1.2.112.0.2.0.34.101.31.13"
#define PROV_NAMES_BELT_128_CBC "BELT-128-CBC:belt-cbc128:1.2.112.0.2.0.34.101.31.21"
#define PROV_NAMES_BELT_192_CBC "BELT-192-CBC:belt-cbc192:1.2.112.0.2.0.34.101.31.22"
#define PROV_NAMES_BELT_256_CBC "BELT-256-CBC:belt-cbc256:1.2.112.0.2.0.34.101.31.23"
#define PROV_NAMES_BELT_128_CFB "BELT-128-CFB:belt-cfb128:1.2.112.0.2.0.34.101.31.31"
#define PROV_NAMES_BELT_192_CFB "BELT-192-CFB:belt-cfb192:1.2.112.0.2.0.34.101.31.32"
#define PROV_NAMES_BELT_256_CFB "BELT-256-CFB:belt-cfb256:1.2.112.0.2.0.34.101.31.33"
#define PROV_NAMES_BELT_128_CTR "BELT-128-CTR:belt-ctr128:1.2.112.0.2.0.34.101.31.41"
#define PROV_NAMES_BELT_192_CTR "BELT-192-CTR:belt-ctr192:1.2.112.0.2.0.34.101.31.42"
#define PROV_NAMES_BELT_256_CTR "BELT-256-CTR:belt-ctr256:1.2.112.0.2.0.34.101.31.43"
#define PROV_NAMES_BELT_128_DWP "BELT-128-DWP:belt-dwp128:1.2.112.0.2.0.34.101.31.61"
#define PROV_NAMES_BELT_192_DWP "BELT-192-DWP:belt-dwp192:1.2.112.0.2.0.34.101.31.62"
#define PROV_NAMES_BELT_256_DWP "BELT-256-DWP:belt-dwp256:1.2.112.0.2.0.34.101.31.63"
#define PROV_NAMES_BELT_128_KWP "BELT-128-KWP:belt-kwp128:1.2.112.0.2.0.34.101.31.71"
#define PROV_NAMES_BELT_192_KWP "BELT-192-KWP:belt-kwp192:1.2.112.0.2.0.34.101.31.72"
#define PROV_NAMES_BELT_256_KWP "BELT-256-KWP:belt-kwp256:1.2.112.0.2.0.34.101.31.73"

/* Digests */
#define PROV_NAMES_BASH256 "BASH256:bash256:1.2.112.0.2.0.34.101.77.11"
#define PROV_NAMES_BASH384 "BASH384:bash384:1.2.112.0.2.0.34.101.77.12"
#define PROV_NAMES_BASH512 "BASH512:bash512:1.2.112.0.2.0.34.101.77.13"
#define PROV_NAMES_BELT_HASH "HBELT:BELT-HASH:hbelt:belt-hash:1.2.112.0.2.0.34.101.31.81"

/* KDFs / PRFs */
#define PROV_NAMES_HKDF "HKDF"

/* MACs */
#define PROV_NAMES_BELT_MAC128 "BELT-MAC128:1.2.112.0.2.0.34.101.31.51"
#define PROV_NAMES_BELT_MAC192 "BELT-MAC192:1.2.112.0.2.0.34.101.31.52"
#define PROV_NAMES_BELT_MAC256 "belt-mac:BELT-MAC256:1.2.112.0.2.0.34.101.31.53"

/* RANDs */
#define PROV_NAMES_CTR_DRBG "CTR-DRBG"

/* Asymmetric algorithms */
#define PROV_DESCS_EC "LWOCRYPT BIGN EC implementation"

/* Key generation #define PROV_NAMES_BIGN_KEYMGMT "BIGN:1.2.112.0.2.0.34.101.45.31"*/
#define PROV_NAMES_BIGN_KEYMGMT "BIGN"

/* Signature (BIGN with HBELT) */
#define PROV_NAMES_BIGN_HBELT "BIGN-HBELT:bign:bign-with-hbelt:1.2.112.0.2.0.34.101.45.12"
#define PROV_NAMES_BIGN "BIGN:bign:1.2.112.0.2.0.34.101.45.12"
/* Curve definitions */
#define SN_bign_curve256v1 "bign-curve256v1"
#define LN_bign_curve256v1 "BIGN Curve 256v1"
#define OBJ_bign_curve256v1 1,2,112,0,2,0,34,101,45,3,1

#define SN_bign_curve384v1 "bign-curve384v1"
#define LN_bign_curve384v1 "BIGN Curve 384v1"
#define OBJ_bign_curve384v1 1,2,112,0,2,0,34,101,45,3,2

#define SN_bign_curve512v1 "bign-curve512v1"
#define LN_bign_curve512v1 "BIGN Curve 512v1"
#define OBJ_bign_curve512v1 1,2,112,0,2,0,34,101,45,3,3



#ifdef __cplusplus
}
#endif

#endif