// implimentations.h



#include <openssl/core.h>
#include <openssl/types.h>
#include <openssl/core_dispatch.h> 
#include <openssl/core_names.h> 
#include <openssl/params.h> 
#include <openssl/crypto.h>
#include <openssl/evp.h> 
#include <openssl/ec.h> 
#include <openssl/err.h> 
#include <openssl/objects.h> 
#include <openssl/bn.h> 
#include <stdio.h> 
#include <string.h>

#include <lwocrypt-provider/names.h>




/* Digests */
extern const OSSL_DISPATCH ossl_bash256_functions[];
extern const OSSL_DISPATCH ossl_bash384_functions[];
extern const OSSL_DISPATCH ossl_bash512_functions[];
extern const OSSL_DISPATCH ossl_belthash_functions[];

/* Ciphers */
extern const OSSL_DISPATCH ossl_belt256ecb_functions[];
extern const OSSL_DISPATCH ossl_belt192ecb_functions[];
extern const OSSL_DISPATCH ossl_belt128ecb_functions[];

extern const OSSL_DISPATCH ossl_belt256cbc_functions[];
extern const OSSL_DISPATCH ossl_belt192cbc_functions[];
extern const OSSL_DISPATCH ossl_belt128cbc_functions[];

extern const OSSL_DISPATCH ossl_belt256cfb_functions[];
extern const OSSL_DISPATCH ossl_belt192cfb_functions[];
extern const OSSL_DISPATCH ossl_belt128cfb_functions[];

extern const OSSL_DISPATCH ossl_belt256ctr_functions[];
extern const OSSL_DISPATCH ossl_belt192ctr_functions[];
extern const OSSL_DISPATCH ossl_belt128ctr_functions[];

/* MACs */
extern const OSSL_DISPATCH ossl_belt_mac_functions[];

/* KDFs / PRFs */
//extern const OSSL_DISPATCH ossl_kdf_pbkdf1_functions[];

/* RNGs */
//EXPORT extern const OSSL_DISPATCH ossl_lwocrypt_rand_functions[];

/* Key management */
//EXPORT extern const OSSL_DISPATCH ossl_bign_keymgmt_functions[];
// in file bign_keymgmt_prov.h


/* Key Exchange */
//extern const OSSL_DISPATCH ossl_dh_keyexch_functions[];

/* Signature */
extern const OSSL_DISPATCH ossl_bign_hbelt_signature_functions[];

/* Asym Cipher */
//extern const OSSL_DISPATCH ossl_rsa_asym_cipher_functions[];

/* Asym Key encapsulation  */
//extern const OSSL_DISPATCH ossl_rsa_asym_kem_functions[];

/* Encoders */
//extern const OSSL_DISPATCH ossl_rsa_to_PKCS1_der_encoder_functions[];





/* Decoders */
//extern const OSSL_DISPATCH ossl_PrivateKeyInfo_der_to_dh_decoder_functions[];
