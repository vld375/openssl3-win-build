/*
 * Copyright 2020. All Rights Reserved.
 */

#include <stdlib.h>

#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#include <internal/refcount.h>

#include <lwocrypt-alg/bign.h>

# define CRYPTO_EX_INDEX_BIGN            18
typedef struct bign_key_st BIGN; // vld add



#ifdef __cplusplus
extern "C"
{
#endif





	int i2d_BIGNParameters(BIGN *bign, unsigned char **out);

	BIGN *d2i_BIGNParameters(BIGN **bign, const unsigned char **in, long len);

	int i2d_BIGNPrivateKey(BIGN *bign, unsigned char **out);

	BIGN *d2i_BIGNPrivatekey(BIGN **bign, const unsigned char **in, long len);

	int i2o_BIGNPublicKey(const BIGN *bign, unsigned char **out);

	BIGN *o2i_BIGNPublicKey(BIGN **bign, const unsigned char **in, long len);

	int bign_compute_key(const BIGN *bign, const EC_POINT *pubkey, unsigned char *out, size_t *out_len);

	int bign_check_pubkey_affine_coordinates(const BIGN *bign, BIGNUM *x, BIGNUM *y);

#ifdef __cplusplus
}
#endif