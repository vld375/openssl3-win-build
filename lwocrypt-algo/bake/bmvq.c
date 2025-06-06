/*
 * Copyright 2022. All Rights Reserved.
 */

#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto/bn.h"
#include "../bign/bign_local.h"

#include <openssl/bake.h>
#include <openssl/belt.h>

int BAKE_bmvq_init(BMVQ_CTX *bmvq, EVP_PKEY *pkey,
				   const unsigned char *certID, int certID_len,
				   const unsigned char *helloA, size_t helloA_len,
				   const unsigned char *helloB, size_t helloB_len)
{
	int ret = 1;

	bmvq->main = (BIGN *)EVP_PKEY_get0_BIGN(pkey);

	bmvq->hello = NULL;
	bmvq->hello_len = 0;
	if (helloA || helloB)
	{
		bmvq->hello_len = helloA_len + helloB_len;
		if (!(bmvq->hello = OPENSSL_zalloc((helloA_len + helloB_len) + 1)))
			goto err;

		memcpy(bmvq->hello, helloA, helloA_len);
		memcpy(bmvq->hello + helloA_len, helloB, helloB_len);
	}

	if (!(bmvq->u_BN = BN_new()))
		goto err;

	bmvq->level = (EC_GROUP_order_bits(bmvq->main->group) + 15) / 16;

	if (!(bmvq->Va = EC_POINT_new(bmvq->main->group)))
		goto err;
	if (!(bmvq->Vb = EC_POINT_new(bmvq->main->group)))
		goto err;

	bmvq->certID = NULL;
	bmvq->certID_len = certID_len;
	if (!(bmvq->certID = OPENSSL_zalloc(bmvq->certID_len)))
		goto err;

	memcpy(bmvq->certID, certID, certID_len);

	ret = 0;

err:

	return ret;
}

int BAKE_bmvq_addHelloB(BMVQ_CTX *bmvq, const unsigned char *helloB, size_t helloB_len)
{
	int ret = 1;

	if (helloB)
	{
		bmvq->hello_len += helloB_len;
		OPENSSL_realloc(bmvq->hello, bmvq->hello_len);
		if (!(bmvq->hello))
			goto err;
		memcpy(bmvq->hello + (bmvq->hello_len - helloB_len), helloB, helloB_len);
	}

	ret = 0;

err:

	return ret;
}

void BAKE_bmvq_addSecondPublicKey(BMVQ_CTX *bmvq, EVP_PKEY *pkey)
{
	bmvq->secondary = (BIGN *)EVP_PKEY_get0_BIGN(pkey);
}

int BAKE_bmvq_step2(BMVQ_CTX *bmvq, unsigned char *out, unsigned int *out_len)
{
	BN_CTX *ctx = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	const BIGNUM *order = NULL;
	int ret = 1;

	if (out_len)
		*out_len = bmvq->level * 4 + bmvq->certID_len;

	if (out)
	{
		memcpy(out, bmvq->certID, bmvq->certID_len);
		out += bmvq->certID_len;

		if (!(ctx = BN_CTX_new()))
			goto err;

		BN_CTX_start(ctx);
		x_BN = BN_CTX_get(ctx);
		y_BN = BN_CTX_get(ctx);
		if (y_BN == NULL)
			goto err;

		/* 2 */
		order = EC_GROUP_get0_order(bmvq->main->group);
		if (order == NULL)
			goto err;

		do
			if (!BN_priv_rand_range(bmvq->u_BN, order))
				goto err;
		while (BN_is_zero(bmvq->u_BN));

		if (!EC_POINT_mul(bmvq->main->group, bmvq->Vb, bmvq->u_BN, NULL, NULL, ctx))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bmvq->main->group, bmvq->Vb, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, out, bmvq->level * 2) ||
			!BN_bn2lebinpad(y_BN, out + bmvq->level * 2, bmvq->level * 2))
			goto err;
	}

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return ret;
}

int BAKE_bmvq_step3(BMVQ_CTX *bmvq,
					const unsigned char *in, unsigned int in_len,
					unsigned char *out, unsigned int *out_len, unsigned char Ta[8])
{
	BN_CTX *ctx = NULL;
	EVP_MD_CTX *mctx = NULL;
	EC_POINT *K_point = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	BIGNUM *a_BN = NULL, *b_BN = NULL, *c_BN = NULL, *s_BN = NULL;
	const BIGNUM *order = NULL;
	unsigned char *t = NULL, *K = NULL, *R = NULL;
	int ret = 1;

	if (in_len < (unsigned int)bmvq->level * 4)
		goto err;

	if (out_len)
		*out_len = bmvq->level * 4 + bmvq->certID_len;

	if (out)
	{
		memcpy(out, bmvq->certID, bmvq->certID_len);
		out += bmvq->certID_len;

		if (!(ctx = BN_CTX_new()))
			goto err;

		BN_CTX_start(ctx);
		x_BN = BN_CTX_get(ctx);
		y_BN = BN_CTX_get(ctx);
		if (x_BN == NULL || y_BN == NULL)
			goto err;

		if (!(K_point = EC_POINT_new(bmvq->main->group)))
			goto err;

		order = EC_GROUP_get0_order(bmvq->main->group);
		if (order == NULL)
			goto err;

		int certIDB_len = in_len - (bmvq->level * 4);

		int R_len = bmvq->certID_len + certIDB_len + bmvq->hello_len;

		if (!(t = OPENSSL_zalloc(bmvq->level)) ||
			!(K = OPENSSL_zalloc(bmvq->level * 4)) ||
			!(R = OPENSSL_zalloc(R_len)))
			goto err;

		memcpy(R, bmvq->certID, bmvq->certID_len);
		memcpy(R + bmvq->certID_len, in, certIDB_len);
		memcpy(R + bmvq->certID_len + certIDB_len, bmvq->hello, bmvq->hello_len);

		in += certIDB_len;

		/* 3 */
		if (!BN_lebin2bn(in, bmvq->level * 2, x_BN) ||
			!BN_lebin2bn(in + bmvq->level * 2, bmvq->level * 2, y_BN))
			goto err;

		if (bign_check_pubkey_affine_coordinates(bmvq->main, x_BN, y_BN))
			goto err;

		if (!EC_POINT_set_affine_coordinates(bmvq->main->group, bmvq->Vb, x_BN, y_BN, ctx))
			goto err;

		/* 4 */
		do
			if (!BN_priv_rand_range(bmvq->u_BN, order))
				goto err;
		while (BN_is_zero(bmvq->u_BN));

		/* 5 */
		if (!EC_POINT_mul(bmvq->main->group, bmvq->Va, bmvq->u_BN, NULL, NULL, ctx))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bmvq->main->group, bmvq->Va, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, out, bmvq->level * 2) ||
			!BN_bn2lebinpad(y_BN, out + bmvq->level * 2, bmvq->level * 2))
			goto err;

		out += bmvq->level * 4;

		/* 6 */
		if (!(mctx = EVP_MD_CTX_new()))
			goto err;

		const EVP_MD *evpMD = EVP_belt_hash();
		if (!EVP_DigestInit_ex(mctx, evpMD, NULL))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bmvq->main->group, bmvq->Va, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, K, bmvq->level * 2) ||
			!BN_bn2lebinpad(y_BN, K + bmvq->level * 2, bmvq->level * 2))
			goto err;

		if (!EVP_DigestUpdate(mctx, K, bmvq->level * 2))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bmvq->main->group, bmvq->Vb, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, K, bmvq->level * 2) ||
			!BN_bn2lebinpad(y_BN, K + bmvq->level * 2, bmvq->level * 2))
			goto err;

		if (!EVP_DigestUpdate(mctx, K, bmvq->level * 2))
			goto err;

		if (!EVP_DigestFinal_ex(mctx, K, NULL))
			goto err;

		memcpy(t, K, bmvq->level);

		/* 7 */
		a_BN = BN_CTX_get(ctx);
		b_BN = BN_CTX_get(ctx);
		c_BN = BN_CTX_get(ctx);
		s_BN = BN_CTX_get(ctx);
		if (a_BN == NULL || b_BN == NULL || c_BN == NULL)
			goto err;

		if (!BN_lebin2bn(t, bmvq->level, a_BN))
			goto err;

		BN_one(b_BN);
		if (!BN_lshift(c_BN, b_BN, bmvq->level << 3))
			goto err;

		if (!BN_add(b_BN, a_BN, c_BN))
			goto err;

		if (!BN_mul(c_BN, bmvq->main->priv_key, b_BN, ctx))
			goto err;

		if (!BN_mod_sub(s_BN, bmvq->u_BN, c_BN, order, ctx))
			goto err;

		/* 8 */
		if (!EC_POINT_mul(bmvq->main->group, K_point, NULL, bmvq->secondary->pub_key, b_BN, ctx))
			goto err;

		if (!EC_POINT_invert(bmvq->main->group, K_point, ctx))
			goto err;

		if (!EC_POINT_add(bmvq->main->group, K_point, bmvq->Vb, K_point, ctx))
			goto err;

		if (!EC_POINT_mul(bmvq->main->group, K_point, NULL, K_point, s_BN, ctx))
			goto err;

		/* 9 */
		if (EC_POINT_is_at_infinity(bmvq->main->group, K_point))
			EC_POINT_copy(K_point, EC_GROUP_get0_generator(bmvq->main->group));

		if (!EC_POINT_get_affine_coordinates(bmvq->main->group, K_point, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, K, bmvq->level * 2) ||
			!BN_bn2lebinpad(y_BN, K + bmvq->level * 2, bmvq->level * 2))
			goto err;

		/* 10 */
		if (BAKE_kdf(K, bmvq->level * 2, R, R_len, 0, bmvq->K0))
			goto err;

		if (Ta)
		{
			/* 11 */
			if (BAKE_kdf(K, bmvq->level * 2, R, R_len, 1, bmvq->K1))
				goto err;

			/* 12 */
			unsigned char d[16] = {0};
			belt_mac(d, 16, bmvq->K1, Ta);
		}
	}

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	EVP_MD_CTX_free(mctx);

	OPENSSL_free(t);
	OPENSSL_free(K);
	OPENSSL_free(R);

	EC_POINT_free(K_point);

	return ret;
}

int BAKE_bmvq_step4(BMVQ_CTX *bmvq, const unsigned char *in, unsigned int in_len,
					const unsigned char Ta[8], unsigned char Tb[8])
{
	BN_CTX *ctx = NULL;
	EVP_MD_CTX *mctx = NULL;
	EC_POINT *K_point = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	BIGNUM *a_BN = NULL, *b_BN = NULL, *c_BN = NULL, *s_BN = NULL;
	const BIGNUM *order = NULL;
	unsigned char *t = NULL, *K = NULL, *R = NULL;
	int ret = 1;

	if (in_len < (unsigned int)bmvq->level * 4)
		goto err;

	if (!(ctx = BN_CTX_new()))
		goto err;

	BN_CTX_start(ctx);
	x_BN = BN_CTX_get(ctx);
	y_BN = BN_CTX_get(ctx);
	if (x_BN == NULL || y_BN == NULL)
		goto err;

	if (!(K_point = EC_POINT_new(bmvq->main->group)))
		goto err;

	order = EC_GROUP_get0_order(bmvq->main->group);
	if (order == NULL)
		goto err;

	int certIDB_len = in_len - (bmvq->level * 4);

	int R_len = certIDB_len + bmvq->certID_len + bmvq->hello_len;

	if (!(t = OPENSSL_zalloc(bmvq->level)) ||
		!(K = OPENSSL_zalloc(bmvq->level * 4)) ||
		!(R = OPENSSL_zalloc(R_len)))
		goto err;

	memcpy(R, in, certIDB_len);
	memcpy(R + certIDB_len, bmvq->certID, bmvq->certID_len);
	memcpy(R + certIDB_len + bmvq->certID_len, bmvq->hello, bmvq->hello_len);

	in += certIDB_len;

	/* 3 */
	if (!BN_lebin2bn(in, bmvq->level * 2, x_BN) ||
		!BN_lebin2bn(in + bmvq->level * 2, bmvq->level * 2, y_BN))
		goto err;

	if (bign_check_pubkey_affine_coordinates(bmvq->main, x_BN, y_BN))
		goto err;

	if (!EC_POINT_set_affine_coordinates(bmvq->main->group, bmvq->Va, x_BN, y_BN, ctx))
		goto err;

	/* 4 */
	if (!(mctx = EVP_MD_CTX_new()))
		goto err;

	const EVP_MD *evpMD = EVP_belt_hash();
	if (!EVP_DigestInit_ex(mctx, evpMD, NULL))
		goto err;

	if (!EC_POINT_get_affine_coordinates(bmvq->main->group, bmvq->Va, x_BN, y_BN, ctx))
		goto err;

	if (!BN_bn2lebinpad(x_BN, K, bmvq->level * 2) ||
		!BN_bn2lebinpad(y_BN, K + bmvq->level * 2, bmvq->level * 2))
		goto err;

	if (!EVP_DigestUpdate(mctx, K, bmvq->level * 2))
		goto err;

	if (!EC_POINT_get_affine_coordinates(bmvq->main->group, bmvq->Vb, x_BN, y_BN, ctx))
		goto err;

	if (!BN_bn2lebinpad(x_BN, K, bmvq->level * 2) ||
		!BN_bn2lebinpad(y_BN, K + bmvq->level * 2, bmvq->level * 2))
		goto err;

	if (!EVP_DigestUpdate(mctx, K, bmvq->level * 2))
		goto err;

	if (!EVP_DigestFinal_ex(mctx, K, NULL))
		goto err;

	memcpy(t, K, bmvq->level);

	/* 5 */
	a_BN = BN_CTX_get(ctx);
	b_BN = BN_CTX_get(ctx);
	c_BN = BN_CTX_get(ctx);
	s_BN = BN_CTX_get(ctx);
	if (a_BN == NULL || b_BN == NULL || c_BN == NULL)
		goto err;

	if (!BN_lebin2bn(t, bmvq->level, a_BN))
		goto err;

	BN_one(b_BN);
	if (!BN_lshift(c_BN, b_BN, bmvq->level << 3))
		goto err;

	if (!BN_add(b_BN, a_BN, c_BN))
		goto err;

	if (!BN_mul(c_BN, bmvq->main->priv_key, b_BN, ctx))
		goto err;

	if (!BN_mod_sub(s_BN, bmvq->u_BN, c_BN, order, ctx))
		goto err;

	/* 6 */
	if (!EC_POINT_mul(bmvq->main->group, K_point, NULL, bmvq->secondary->pub_key, b_BN, ctx))
		goto err;

	if (!EC_POINT_invert(bmvq->main->group, K_point, ctx))
		goto err;

	if (!EC_POINT_add(bmvq->main->group, K_point, bmvq->Va, K_point, ctx))
		goto err;

	if (!EC_POINT_mul(bmvq->main->group, K_point, NULL, K_point, s_BN, ctx))
		goto err;

	/* 7 */
	if (EC_POINT_is_at_infinity(bmvq->main->group, K_point))
		EC_POINT_copy(K_point, EC_GROUP_get0_generator(bmvq->main->group));

	if (!EC_POINT_get_affine_coordinates(bmvq->main->group, K_point, x_BN, y_BN, ctx))
		goto err;

	if (!BN_bn2lebinpad(x_BN, K, bmvq->level * 2) ||
		!BN_bn2lebinpad(y_BN, K + bmvq->level * 2, bmvq->level * 2))
		goto err;

	/* 8 */
	if (BAKE_kdf(K, bmvq->level * 2, R, R_len, 0, bmvq->K0))
		goto err;

	if (Ta && Tb)
	{
		/* 9 */
		if (BAKE_kdf(K, bmvq->level * 2, R, R_len, 1, bmvq->K1))
			goto err;

		/* 10 */
		unsigned char d[16] = {0}, tA[8] = {0};
		belt_mac(d, 16, bmvq->K1, tA);

		if (CRYPTO_memcmp(Ta, tA, 8))
			goto err;

		/* 11 */
		memset(d, 0xFF, 16);
		belt_mac(d, 16, bmvq->K1, Tb);
	}

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	EVP_MD_CTX_free(mctx);

	OPENSSL_free(t);
	OPENSSL_free(K);
	OPENSSL_free(R);

	EC_POINT_free(K_point);

	return ret;
}

int BAKE_bmvq_step5(BMVQ_CTX *bmvq, const unsigned char Tb[8])
{
	unsigned char d[16] = {0}, tB[8] = {0};
	memset(d, 0xFF, 16);

	belt_mac(d, 16, bmvq->K1, tB);

	if (CRYPTO_memcmp(Tb, tB, 8))
		return 1;

	return 0;
}

void BAKE_bmvq_final(BMVQ_CTX *bmvq, unsigned char out[32])
{
	if (bmvq->hello && bmvq->hello_len > 0)
		OPENSSL_clear_free(bmvq->hello, bmvq->hello_len);
	if (bmvq->certID && bmvq->certID_len > 0)
		OPENSSL_clear_free(bmvq->certID, bmvq->certID_len);

	BIGN_free(bmvq->main);
	BIGN_free(bmvq->secondary);

	EC_POINT_free(bmvq->Va);
	EC_POINT_free(bmvq->Vb);

	BN_free(bmvq->u_BN);

	if (out)
		memcpy(out, bmvq->K0, 32);

	memset(bmvq->K0, 0, 32);
	memset(bmvq->K1, 0, 32);
}