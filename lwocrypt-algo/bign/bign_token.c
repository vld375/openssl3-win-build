/*
 * Copyright 2023. All Rights Reserved.
 */
 //#include "crypto/bn.h"

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>

#include <lwocrypt-alg/belt.h>
#include <lwocrypt-alg/bignerr.h>
#include <lwocrypt-alg/bign_local.h>

unsigned int BIGN_create_token(
	BIGN *bign,
	const unsigned char *transport_key, size_t transport_key_len,
	const unsigned char header[16],
	unsigned char *out, size_t *out_len)
{
	BN_CTX *ctx = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	EC_POINT *R_point = NULL;
	unsigned char *theta = NULL, *pubkey = NULL, *kwp = NULL;
	size_t kwp_len = 0;
	unsigned int pubkey_len = 0;
	int ret = 1;
	BIGN *disp = NULL;

	int levelX2 = (EC_GROUP_order_bits(bign->group) + 7) / 8;

	if (!(ctx = BN_CTX_new()))
	{
		BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	disp = BIGN_new(NULL);
	disp->group = EC_GROUP_dup(bign->group);
	if (disp->group == NULL)
	{
		BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (BIGN_generate_key(disp))
	{
		BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (BIGN_get_pubkey(disp, pubkey, &pubkey_len) ||
		!(pubkey = OPENSSL_zalloc(pubkey_len)) ||
		BIGN_get_pubkey(disp, pubkey, &pubkey_len))
	{
		BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	BN_CTX_start(ctx);
	x_BN = BN_CTX_get(ctx);
	y_BN = BN_CTX_get(ctx);
	if (y_BN == NULL)
	{
		BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!(R_point = EC_POINT_new(bign->group)))
	{
		BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!EC_POINT_mul(bign->group, R_point, NULL, bign->pub_key, disp->priv_key, ctx))
	{
		BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!EC_POINT_get_affine_coordinates(bign->group, R_point, x_BN, y_BN, ctx))
	{
		BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!(theta = OPENSSL_zalloc((size_t)levelX2 << 1)))
	{
		BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!BN_bn2lebinpad(x_BN, theta, levelX2) ||
		!BN_bn2lebinpad(y_BN, theta + levelX2, levelX2))
	{
		BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	unsigned char our_header[16];
	memset(our_header, 0, 16);

	if (header)
		memcpy(our_header, header, 16);

	if (BELT_kwp_encrypt(transport_key, transport_key_len, our_header, theta, kwp, &kwp_len) ||
		!(kwp = OPENSSL_zalloc(kwp_len)) ||
		BELT_kwp_encrypt(transport_key, transport_key_len, our_header, theta, kwp, &kwp_len))
	{
		BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (out)
	{
		memcpy(out, pubkey, levelX2);
		memcpy(out + levelX2, kwp, kwp_len);
	}

	if (out_len)
		*out_len = levelX2 + kwp_len;

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	EC_POINT_free(R_point);

	BIGN_free(disp);
	OPENSSL_clear_free(pubkey, pubkey_len);
	OPENSSL_clear_free(theta, (size_t)levelX2 << 1);
	OPENSSL_clear_free(kwp, kwp_len);

	return ret;
}

unsigned int BIGN_decode_token(
	BIGN *bign,
	const unsigned char *token, size_t token_len,
	const unsigned char header[16],
	unsigned char *out, size_t *out_len)
{
	BN_CTX *ctx = NULL;
	EC_POINT *R_point = NULL, *Q_point = NULL;
	BIGNUM *p_BN = NULL, *x_BN = NULL, *y_BN = NULL;
	unsigned char *theta = NULL, *kwp = NULL;
	size_t kwp_len = 0;
	int ret = 1;

	int levelX2 = (EC_GROUP_order_bits(bign->group) + 7) / 8;

	if (!(ctx = BN_CTX_new()))
	{
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if ((size_t)levelX2 + 32 > token_len || (token_len << 3) % 8 != 0)
	{
		ret = 2;
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	BN_CTX_start(ctx);
	p_BN = BN_CTX_get(ctx);
	x_BN = BN_CTX_get(ctx);
	y_BN = BN_CTX_get(ctx);
	if (y_BN == NULL)
	{
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!BN_lebin2bn(token, levelX2, x_BN))
	{
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/*Step 4*/
	if (!EC_GROUP_get_curve(bign->group, p_BN, NULL, NULL, ctx))
	{
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (BN_cmp(x_BN, p_BN) >= 0)
	{
		ret = 2;
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!(R_point = EC_POINT_new(bign->group)) ||
		!(Q_point = EC_POINT_new(bign->group)))
	{
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/*Step 5-7*/
	if (!EC_POINT_set_compressed_coordinates(bign->group, Q_point, x_BN, 0, ctx))
	{
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	/*Step 8*/
	if (!EC_POINT_mul(bign->group, R_point, NULL, Q_point, bign->priv_key, ctx))
	{
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!EC_POINT_get_affine_coordinates(bign->group, R_point, x_BN, y_BN, ctx))
	{
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!(theta = OPENSSL_zalloc((size_t)levelX2 << 1)))
	{
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!BN_bn2lebinpad(x_BN, theta, levelX2) ||
		!BN_bn2lebinpad(y_BN, theta + levelX2, levelX2))
	{
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	unsigned char our_header[16];
	memset(our_header, 0, 16);

	if (header)
		memcpy(our_header, header, 16);

	if (BELT_kwp_decrypt(token + levelX2, token_len - levelX2, our_header, theta, kwp, &kwp_len) ||
		!(kwp = OPENSSL_zalloc(kwp_len)) ||
		BELT_kwp_decrypt(token + levelX2, token_len - levelX2, our_header, theta, kwp, &kwp_len))
	{
		BIGNerr(BIGN_F_DECODE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (out)
		memcpy(out, kwp, kwp_len);

	if (out_len)
		*out_len = kwp_len;

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	EC_POINT_free(R_point);
	EC_POINT_free(Q_point);

	OPENSSL_clear_free(theta, (size_t)levelX2 << 1);
	OPENSSL_clear_free(kwp, kwp_len);

	return ret;
}