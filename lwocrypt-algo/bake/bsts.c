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

int BAKE_bsts_init(BSTS_CTX *bsts, EVP_PKEY *pkey,
				   const unsigned char *certID, int certID_len,
				   const unsigned char *helloA, size_t helloA_len,
				   const unsigned char *helloB, size_t helloB_len)
{
	int ret = 1;

	bsts->main = (BIGN *)EVP_PKEY_get0_BIGN(pkey);

	bsts->hello = NULL;
	bsts->hello_len = 0;
	if (helloA || helloB)
	{
		bsts->hello_len = helloA_len + helloB_len;
		if (!(bsts->hello = OPENSSL_zalloc((helloA_len + helloB_len) + 1)))
			goto err;

		memcpy(bsts->hello, helloA, helloA_len);
		memcpy(bsts->hello + helloA_len, helloB, helloB_len);
	}

	if (!(bsts->u_BN = BN_new()))
		goto err;

	bsts->level = (EC_GROUP_order_bits(bsts->main->group) + 15) / 16;

	if (!(bsts->Va = EC_POINT_new(bsts->main->group)))
		goto err;
	if (!(bsts->Vb = EC_POINT_new(bsts->main->group)))
		goto err;
	if (!(bsts->t = OPENSSL_zalloc(bsts->level)))
		goto err;

	bsts->certID = NULL;
	bsts->certID_len = bsts->level * 2 + certID_len;
	if (!(bsts->certID = OPENSSL_zalloc(bsts->certID_len)))
		goto err;

	memcpy(bsts->certID + bsts->level * 2, certID, certID_len);

	ret = 0;

err:

	return ret;
}

int BAKE_bsts_addHelloB(BSTS_CTX *bsts, const unsigned char *helloB, size_t helloB_len)
{
	int ret = 1;

	if (helloB)
	{
		bsts->hello_len += helloB_len;
		OPENSSL_realloc(bsts->hello, bsts->hello_len);
		if (!(bsts->hello))
			goto err;
		memcpy(bsts->hello + (bsts->hello_len - helloB_len), helloB, helloB_len);
	}

	ret = 0;

err:

	return ret;
}

void BAKE_bsts_addSecondPublicKey(BSTS_CTX *bsts, EVP_PKEY *pkey)
{
	bsts->secondary = (BIGN *)EVP_PKEY_get0_BIGN(pkey);
}

int BAKE_bsts_step2(BSTS_CTX *bsts, unsigned char *out, unsigned int *out_len)
{
	BN_CTX *ctx = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	const BIGNUM *order = NULL;
	int ret = 1;

	if (out_len)
		*out_len = bsts->level * 4;

	if (out)
	{
		if (!(ctx = BN_CTX_new()))
			goto err;

		BN_CTX_start(ctx);
		x_BN = BN_CTX_get(ctx);
		y_BN = BN_CTX_get(ctx);
		if (y_BN == NULL)
			goto err;

		order = EC_GROUP_get0_order(bsts->main->group);
		if (order == NULL)
			goto err;

		/* 2 */
		do
			if (!BN_priv_rand_range(bsts->u_BN, order))
				goto err;
		while (BN_is_zero(bsts->u_BN));

		if (!EC_POINT_mul(bsts->main->group, bsts->Vb, bsts->u_BN, NULL, NULL, ctx))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bsts->main->group, bsts->Vb, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, out, bsts->level * 2) ||
			!BN_bn2lebinpad(y_BN, out + bsts->level * 2, bsts->level * 2))
			goto err;
	}

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return ret;
}

int BAKE_bsts_step3(BSTS_CTX *bsts,
					const unsigned char *in, unsigned int in_len,
					unsigned char *out, unsigned int *out_len, unsigned char Ta[8])
{
	BN_CTX *ctx = NULL;
	EVP_MD_CTX *mctx = NULL;
	EC_POINT *K_point = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	BIGNUM *a_BN = NULL, *b_BN = NULL, *c_BN = NULL;
	const BIGNUM *order = NULL;
	unsigned char *K = NULL;
	int ret = 1;

	if (in_len != bsts->level * 4)
		goto err;

	if (out_len)
		*out_len = bsts->level * 4 + bsts->certID_len;

	if (out)
	{
		if (!(ctx = BN_CTX_new()))
			goto err;

		BN_CTX_start(ctx);
		x_BN = BN_CTX_get(ctx);
		y_BN = BN_CTX_get(ctx);
		if (x_BN == NULL || y_BN == NULL)
			goto err;

		if (!(K_point = EC_POINT_new(bsts->main->group)))
			goto err;

		order = EC_GROUP_get0_order(bsts->main->group);
		if (order == NULL)
			goto err;

		/* 2 */
		if (!BN_lebin2bn(in, bsts->level * 2, x_BN) ||
			!BN_lebin2bn(in + bsts->level * 2, bsts->level * 2, y_BN))
			goto err;

		if (bign_check_pubkey_affine_coordinates(bsts->main, x_BN, y_BN))
			goto err;

		if (!EC_POINT_set_affine_coordinates(bsts->main->group, bsts->Vb, x_BN, y_BN, ctx))
			goto err;

		/* 3 */
		do
			if (!BN_priv_rand_range(bsts->u_BN, order))
				goto err;
		while (BN_is_zero(bsts->u_BN));

		/* 4 */
		if (!EC_POINT_mul(bsts->main->group, bsts->Va, bsts->u_BN, NULL, NULL, ctx))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bsts->main->group, bsts->Va, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, out, bsts->level * 2) ||
			!BN_bn2lebinpad(y_BN, out + bsts->level * 2, bsts->level * 2))
			goto err;

		out += bsts->level * 4;

		/* 5 */
		if (!EC_POINT_mul(bsts->main->group, K_point, NULL, bsts->Vb, bsts->u_BN, ctx))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bsts->main->group, K_point, x_BN, y_BN, ctx))
			goto err;

		if (!(K = OPENSSL_zalloc(bsts->level * 4)))
			goto err;
		if (!BN_bn2lebinpad(x_BN, K, bsts->level * 2) ||
			!BN_bn2lebinpad(y_BN, K + bsts->level * 2, bsts->level * 2))
			goto err;

		/* 6 */
		if (BAKE_kdf(K, bsts->level * 2, bsts->hello, bsts->hello_len, 0, bsts->K0))
			goto err;

		/* 7 */
		if (BAKE_kdf(K, bsts->level * 2, bsts->hello, bsts->hello_len, 1, bsts->K1))
			goto err;

		/* 8 */
		if (BAKE_kdf(K, bsts->level * 2, bsts->hello, bsts->hello_len, 2, bsts->K2))
			goto err;

		/* 9 */
		if (!(mctx = EVP_MD_CTX_new()))
			goto err;

		const EVP_MD *evpMD = EVP_belt_hash();
		if (!EVP_DigestInit_ex(mctx, evpMD, NULL))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bsts->main->group, bsts->Va, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, K, bsts->level * 2) ||
			!BN_bn2lebinpad(y_BN, K + bsts->level * 2, bsts->level * 2))
			goto err;

		if (!EVP_DigestUpdate(mctx, K, bsts->level * 2))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bsts->main->group, bsts->Vb, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, K, bsts->level * 2) ||
			!BN_bn2lebinpad(y_BN, K + bsts->level * 2, bsts->level * 2))
			goto err;

		if (!EVP_DigestUpdate(mctx, K, bsts->level * 2))
			goto err;

		if (!EVP_DigestFinal_ex(mctx, K, NULL))
			goto err;

		memcpy(bsts->t, K, bsts->level);

		/* 10 */
		a_BN = BN_CTX_get(ctx);
		b_BN = BN_CTX_get(ctx);
		c_BN = BN_CTX_get(ctx);
		if (a_BN == NULL || b_BN == NULL || c_BN == NULL)
			goto err;

		if (!BN_lebin2bn(bsts->t, bsts->level, a_BN))
			goto err;

		BN_one(b_BN);
		if (!BN_lshift(c_BN, b_BN, bsts->level << 3))
			goto err;

		if (!BN_add(b_BN, a_BN, c_BN))
			goto err;

		if (!BN_mul(c_BN, bsts->main->priv_key, b_BN, ctx))
			goto err;

		if (!BN_mod_sub(a_BN, bsts->u_BN, c_BN, order, ctx))
			goto err;

		if (!BN_bn2lebinpad(a_BN, bsts->certID, bsts->level * 2))
			goto err;

		/* 11 */
		unsigned char sync[16] = {0};
		BELT_cfb_encrypt(bsts->certID, bsts->certID_len, bsts->K2, sync, out);

		/* 12 */
		unsigned char d[16] = {0};
		BELTmac_CTX c;

		BELT_mac_Init(&c, bsts->K1);
		BELT_mac_Update(&c, out, bsts->certID_len);
		BELT_mac_Update(&c, d, 16);
		BELT_mac_Final(&c, Ta);

		OPENSSL_cleanse(&c, sizeof(c));
	}

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	EVP_MD_CTX_free(mctx);

	OPENSSL_free(K);

	EC_POINT_free(K_point);

	return ret;
}

int BAKE_bsts_step4(BSTS_CTX *bsts,
					const unsigned char *in, unsigned int in_len, const unsigned char Ta[8],
					unsigned char *out, unsigned int *out_len, unsigned char Tb[8])
{
	BN_CTX *ctx = NULL;
	EVP_MD_CTX *mctx = NULL;
	EC_POINT *V_point = NULL, *K_point = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	BIGNUM *a_BN = NULL, *b_BN = NULL, *c_BN = NULL;
	const BIGNUM *order = NULL;
	unsigned char *K = NULL, *certIDa = NULL;
	int ret = 1;

	if (in_len < (unsigned int)bsts->level * 4)
		goto err;

	if (out_len)
		*out_len = bsts->certID_len;

	if (out)
	{
		if (!(ctx = BN_CTX_new()))
			goto err;

		BN_CTX_start(ctx);
		x_BN = BN_CTX_get(ctx);
		y_BN = BN_CTX_get(ctx);
		if (y_BN == NULL)
			goto err;

		if (!(V_point = EC_POINT_new(bsts->main->group)) ||
			!(K_point = EC_POINT_new(bsts->main->group)))
			goto err;

		order = EC_GROUP_get0_order(bsts->main->group);
		if (order == NULL)
			goto err;

		/* 2 */
		if (!BN_lebin2bn(in, bsts->level * 2, x_BN) ||
			!BN_lebin2bn(in + bsts->level * 2, bsts->level * 2, y_BN))
			goto err;

		if (bign_check_pubkey_affine_coordinates(bsts->main, x_BN, y_BN))
			goto err;

		in += bsts->level * 4;

		if (!EC_POINT_set_affine_coordinates(bsts->main->group, bsts->Va, x_BN, y_BN, ctx))
			goto err;

		/* 3 */
		if (!EC_POINT_mul(bsts->main->group, K_point, NULL, bsts->Va, bsts->u_BN, ctx))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bsts->main->group, K_point, x_BN, y_BN, ctx))
			goto err;

		if (!(K = OPENSSL_zalloc(bsts->level * 4)))
			goto err;
		if (!BN_bn2lebinpad(x_BN, K, bsts->level * 2) ||
			!BN_bn2lebinpad(y_BN, K + bsts->level * 2, bsts->level * 2))
			goto err;

		/* 4 */
		if (BAKE_kdf(K, bsts->level * 2, bsts->hello, bsts->hello_len, 0, bsts->K0))
			goto err;

		/* 5 */
		if (BAKE_kdf(K, bsts->level * 2, bsts->hello, bsts->hello_len, 1, bsts->K1))
			goto err;

		/* 6 */
		if (BAKE_kdf(K, bsts->level * 2, bsts->hello, bsts->hello_len, 2, bsts->K2))
			goto err;

		/* 7 */
		size_t certIDa_len = in_len - bsts->level * 4;
		if (!(certIDa = OPENSSL_zalloc(certIDa_len)))
			goto err;

		unsigned char d[16] = {0}, tA[8] = {0};
		BELTmac_CTX c;

		BELT_mac_Init(&c, bsts->K1);
		BELT_mac_Update(&c, in, certIDa_len);
		BELT_mac_Update(&c, d, 16);
		BELT_mac_Final(&c, tA);

		OPENSSL_cleanse(&c, sizeof(c));

		if (CRYPTO_memcmp(Ta, tA, 8))
			goto err;

		/* 11 */
		if (!(mctx = EVP_MD_CTX_new()))
			goto err;

		const EVP_MD *evpMD = EVP_belt_hash();
		if (!EVP_DigestInit_ex(mctx, evpMD, NULL))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bsts->main->group, bsts->Va, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, K, bsts->level * 2) ||
			!BN_bn2lebinpad(y_BN, K + bsts->level * 2, bsts->level * 2))
			goto err;

		if (!EVP_DigestUpdate(mctx, K, bsts->level * 2))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bsts->main->group, bsts->Vb, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, K, bsts->level * 2) ||
			!BN_bn2lebinpad(y_BN, K + bsts->level * 2, bsts->level * 2))
			goto err;

		if (!EVP_DigestUpdate(mctx, K, bsts->level * 2))
			goto err;

		if (!EVP_DigestFinal_ex(mctx, K, NULL))
			goto err;

		memcpy(bsts->t, K, bsts->level);

		/* 8 */
		unsigned char sync[16] = {0};
		BELT_cfb_decrypt(in, certIDa_len, bsts->K2, sync, certIDa);

		/* 9 */
		if (!BN_lebin2bn(certIDa, bsts->level * 2, x_BN))
			goto err;

		if (BN_cmp(x_BN, order) >= 0)
			goto err;

		/* 12 */
		a_BN = BN_CTX_get(ctx);
		b_BN = BN_CTX_get(ctx);
		c_BN = BN_CTX_get(ctx);
		if (a_BN == NULL || b_BN == NULL || c_BN == NULL)
			goto err;

		if (!BN_lebin2bn(bsts->t, bsts->level, a_BN))
			goto err;

		BN_one(b_BN);
		if (!BN_lshift(c_BN, b_BN, bsts->level << 3))
			goto err;

		if (!BN_add(b_BN, a_BN, c_BN))
			goto err;

		if (!EC_POINT_mul(bsts->main->group, V_point, x_BN, bsts->secondary->pub_key, b_BN, ctx))
			goto err;

		if (EC_POINT_cmp(bsts->main->group, bsts->Va, V_point, ctx))
			goto err;

		/* 13 */
		if (!BN_mul(c_BN, bsts->main->priv_key, b_BN, ctx))
			goto err;

		if (!BN_mod_sub(a_BN, bsts->u_BN, c_BN, order, ctx))
			goto err;

		if (!BN_bn2lebinpad(a_BN, bsts->certID, bsts->level * 2))
			goto err;

		/* 14 */
		memset(sync, 0xFF, 16);
		BELT_cfb_encrypt(bsts->certID, bsts->certID_len, bsts->K2, sync, out);

		/* 15 */
		memset(d, 0xFF, 16);
		BELT_mac_Init(&c, bsts->K1);
		BELT_mac_Update(&c, out, bsts->certID_len);
		BELT_mac_Update(&c, d, 16);
		BELT_mac_Final(&c, Tb);

		OPENSSL_cleanse(&c, sizeof(c));
	}

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	EVP_MD_CTX_free(mctx);

	OPENSSL_free(K);
	OPENSSL_free(certIDa);

	EC_POINT_free(V_point);
	EC_POINT_free(K_point);

	return ret;
}

int BAKE_bsts_step5(BSTS_CTX *bsts, const unsigned char *in, unsigned int in_len, const unsigned char Tb[8])
{
	BN_CTX *ctx = NULL;
	EC_POINT *V_point = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	BIGNUM *a_BN = NULL, *b_BN = NULL, *c_BN = NULL;
	const BIGNUM *order = NULL;
	unsigned char *certIDa = NULL;
	int ret = 1;

	if (!(ctx = BN_CTX_new()))
		goto err;

	BN_CTX_start(ctx);
	x_BN = BN_CTX_get(ctx);
	y_BN = BN_CTX_get(ctx);
	if (y_BN == NULL)
		goto err;

	if (!(V_point = EC_POINT_new(bsts->main->group)))
		goto err;

	order = EC_GROUP_get0_order(bsts->main->group);
	if (order == NULL)
		goto err;

	/* 2 */
	size_t certIDa_len = in_len;
	if (!(certIDa = OPENSSL_zalloc(certIDa_len)))
		goto err;

	unsigned char d[16] = {0}, tB[8] = {0};
	memset(d, 0xFF, 16);
	BELTmac_CTX c;

	BELT_mac_Init(&c, bsts->K1);
	BELT_mac_Update(&c, in, in_len);
	BELT_mac_Update(&c, d, 16);
	BELT_mac_Final(&c, tB);

	OPENSSL_cleanse(&c, sizeof(c));

	if (CRYPTO_memcmp(Tb, tB, 8))
		goto err;

	/* 3 */
	unsigned char sync[16] = {0};
	memset(sync, 0xFF, 16);
	BELT_cfb_decrypt(in, certIDa_len, bsts->K2, sync, certIDa);

	/* 4 */
	if (!BN_lebin2bn(certIDa, bsts->level * 2, x_BN))
		goto err;

	if (BN_cmp(x_BN, order) >= 0)
		goto err;

	/* 6 */
	a_BN = BN_CTX_get(ctx);
	b_BN = BN_CTX_get(ctx);
	c_BN = BN_CTX_get(ctx);
	if (a_BN == NULL || b_BN == NULL || c_BN == NULL)
		goto err;

	if (!BN_lebin2bn(bsts->t, bsts->level, a_BN))
		goto err;

	BN_one(b_BN);
	if (!BN_lshift(c_BN, b_BN, bsts->level << 3))
		goto err;

	if (!BN_add(b_BN, a_BN, c_BN))
		goto err;

	if (!EC_POINT_mul(bsts->main->group, V_point, x_BN, bsts->secondary->pub_key, b_BN, ctx))
		goto err;

	if (EC_POINT_cmp(bsts->main->group, bsts->Vb, V_point, ctx))
		goto err;

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	OPENSSL_free(certIDa);

	EC_POINT_free(V_point);

	return ret;
}

void BAKE_bsts_final(BSTS_CTX *bsts, unsigned char out[32])
{
	OPENSSL_clear_free(bsts->t, bsts->level);

	if (bsts->hello && bsts->hello_len > 0)
		OPENSSL_clear_free(bsts->hello, bsts->hello_len);
	if (bsts->certID && bsts->certID_len > 0)
		OPENSSL_clear_free(bsts->certID, bsts->certID_len);

	BIGN_free(bsts->main);
	BIGN_free(bsts->secondary);

	EC_POINT_free(bsts->Va);
	EC_POINT_free(bsts->Vb);

	BN_free(bsts->u_BN);

	if (out)
		memcpy(out, bsts->K0, 32);

	memset(bsts->K0, 0, 32);
	memset(bsts->K1, 0, 32);
	memset(bsts->K2, 0, 32);
}