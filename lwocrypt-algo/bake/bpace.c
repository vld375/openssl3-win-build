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
#include "bake_local.h"

#include <openssl/bake.h>
#include <openssl/belt.h>
#include <openssl/brng.h>

int BAKE_bpace_init(BPACE_CTX *bpace, int level, const unsigned char *P, size_t P_len,
					const unsigned char *helloA, size_t helloA_len,
					const unsigned char *helloB, size_t helloB_len)
{
	EVP_MD_CTX *mctx = NULL;

	int ret = 1;

	if (!(mctx = EVP_MD_CTX_new()))
		goto err;

	switch (level)
	{
	case 128:
		bpace->bign = BIGN_new("bign-curve256v1");
		break;
	case 192:
		bpace->bign = BIGN_new("bign-curve384v1");
		break;
	case 256:
		bpace->bign = BIGN_new("bign-curve512v1");
		break;
	default:
		goto err;
	}

	bpace->helloA = NULL;
	bpace->helloA_len = 0;
	if (helloA)
	{
		bpace->helloA_len = helloA_len;
		if (!(bpace->helloA = OPENSSL_zalloc(bpace->helloA_len + 1)))
			goto err;
		memcpy(bpace->helloA, helloA, bpace->helloA_len);
	}

	bpace->helloB = NULL;
	bpace->helloB_len = 0;
	if (helloB)
	{
		bpace->helloB_len = helloB_len;
		if (!(bpace->helloB = OPENSSL_zalloc(bpace->helloB_len + 1)))
			goto err;
		memcpy(bpace->helloB, helloB, bpace->helloB_len);
	}

	if (!(bpace->u_BN = BN_new()))
		goto err;

	bpace->level = (EC_GROUP_order_bits(bpace->bign->group) + 15) / 16;
	bpace->R = NULL;

	const EVP_MD *evpMD = EVP_belt_hash();
	if (!EVP_DigestInit_ex(mctx, evpMD, NULL))
		goto err;
	if (!EVP_DigestUpdate(mctx, P, P_len))
		goto err;
	if (!EVP_DigestFinal_ex(mctx, bpace->K2, NULL))
		goto err;

	ret = 0;

err:
	EVP_MD_CTX_free(mctx);

	return ret;
}

int BAKE_bpace_addHelloB(BPACE_CTX *bpace, const unsigned char *helloB, size_t helloB_len)
{
	int ret = 1;

	if (helloB)
	{
		bpace->helloB_len = helloB_len;
		if (!(bpace->helloB = OPENSSL_zalloc(bpace->helloB_len + 1)))
			goto err;
		memcpy(bpace->helloB, helloB, bpace->helloB_len);
	}

	ret = 0;

err:

	return ret;
}

int BAKE_bpace_step2(BPACE_CTX* bpace, unsigned char* out, unsigned int* out_len)
{
	int ret = 1;

	if (out_len)
		*out_len = bpace->level;

	if (out)
	{
		unsigned char Rb[32] = { 0 };
		unsigned char random[96] = { 0 };
		if (RAND_priv_bytes(random, 96) <= 0)
			goto err;

		brng_ctr_hbelt(1, random, random + 32, random + 64, Rb);

		if (!(bpace->R = OPENSSL_zalloc(bpace->level * 4 + (bpace->helloA_len + bpace->helloB_len))))
			goto err;

		memcpy(bpace->R + bpace->level, Rb, bpace->level);

		if (BELT_ecb_encrypt(Rb, bpace->level, bpace->K2, out))
			goto err;
	}

	ret = 0;

err:

	return ret;
}

int BAKE_bpace_step3(BPACE_CTX *bpace, const unsigned char *in, unsigned int in_len,
					 unsigned char *out, unsigned int *out_len)
{
	BN_CTX *ctx = NULL;
	EC_POINT *Va_point = NULL, *W_point = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	const BIGNUM *order = NULL;
	int ret = 1;

	if (in_len != bpace->level)
		goto err;

	if (out_len)
		*out_len = bpace->level * 5;

	if (out)
	{
		if (!(ctx = BN_CTX_new()))
			goto err;

		BN_CTX_start(ctx);
		x_BN = BN_CTX_get(ctx);
		y_BN = BN_CTX_get(ctx);
		if (y_BN == NULL)
			goto err;

		if (!(bpace->R = OPENSSL_zalloc(bpace->level * 4 + (bpace->helloA_len + bpace->helloB_len))))
			goto err;

		/* 4 */
		if (BELT_ecb_decrypt(in, bpace->level, bpace->K2, bpace->R + bpace->level))
			goto err;

		/* 5 */
		unsigned char Ra[32] = {0};
		unsigned char random[96] = {0};
		if (RAND_priv_bytes(random, 96) <= 0)
			goto err;

		brng_ctr_hbelt(1, random, random + 32, random + 64, Ra);
		memcpy(bpace->R, Ra, bpace->level);

		/* 6 */
		if (BELT_ecb_encrypt(Ra, bpace->level, bpace->K2, out))
			goto err;

		out += bpace->level;

		/* 7 */
		if (!(Va_point = EC_POINT_new(bpace->bign->group)) ||
			!(W_point = EC_POINT_new(bpace->bign->group)))
			goto err;

		if (bake_swu(bpace->bign, bpace->R, W_point))
			goto err;

		/* 8 */
		order = EC_GROUP_get0_order(bpace->bign->group);
		if (order == NULL)
			goto err;

		do
			if (!BN_priv_rand_range(bpace->u_BN, order))
				goto err;
		while (BN_is_zero(bpace->u_BN));

		/* 9 */
		if (!EC_POINT_mul(bpace->bign->group, Va_point, NULL, W_point, bpace->u_BN, ctx))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bpace->bign->group, Va_point, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, out, bpace->level * 2) ||
			!BN_bn2lebinpad(y_BN, out + bpace->level * 2, bpace->level * 2))
			goto err;

		/* save Vax */
		memcpy(bpace->R, out, bpace->level * 2);
	}

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	EC_POINT_free(Va_point);
	EC_POINT_free(W_point);

	return ret;
}

int BAKE_bpace_step4(BPACE_CTX *bpace, const unsigned char *in, unsigned int in_len,
					 unsigned char *out, unsigned int *out_len, unsigned char Tb[8])
{
	BN_CTX *ctx = NULL;
	EC_POINT *Va_point = NULL, *Vb_point = NULL, *W_point = NULL, *K_point = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	const BIGNUM *order = NULL;
	unsigned char *K = NULL;
	int ret = 1;

	if (in_len != bpace->level * 5)
		goto err;

	if (out_len)
		*out_len = bpace->level * 4;

	if (out)
	{
		if (!(W_point = EC_POINT_new(bpace->bign->group)))
			goto err;

		/* 4 */
		if (BELT_ecb_decrypt(in, bpace->level, bpace->K2, bpace->R))
			goto err;

		/* 5 */
		if (bake_swu(bpace->bign, bpace->R, W_point))
			goto err;

		in += bpace->level;

		if (!(ctx = BN_CTX_new()))
			goto err;

		BN_CTX_start(ctx);
		x_BN = BN_CTX_get(ctx);
		y_BN = BN_CTX_get(ctx);
		if (y_BN == NULL)
			goto err;

		/* 2 */
		if (!BN_lebin2bn(in, bpace->level * 2, x_BN) ||
			!BN_lebin2bn(in + bpace->level * 2, bpace->level * 2, y_BN))
			goto err;

		if (bign_check_pubkey_affine_coordinates(bpace->bign, x_BN, y_BN))
			goto err;

		/* save Vax */
		memcpy(bpace->R, in, bpace->level * 2);

		if (!(Va_point = EC_POINT_new(bpace->bign->group)) ||
			!(Vb_point = EC_POINT_new(bpace->bign->group)) ||
			!(K_point = EC_POINT_new(bpace->bign->group)))
			goto err;

		if (!EC_POINT_set_affine_coordinates(bpace->bign->group, Va_point, x_BN, y_BN, ctx))
			goto err;

		/* 6 */
		order = EC_GROUP_get0_order(bpace->bign->group);
		if (order == NULL)
			goto err;

		do
			if (!BN_priv_rand_range(bpace->u_BN, order))
				goto err;
		while (BN_is_zero(bpace->u_BN));

		/* 7 */
		if (!EC_POINT_mul(bpace->bign->group, Vb_point, NULL, W_point, bpace->u_BN, ctx))
			goto err;
		if (!EC_POINT_get_affine_coordinates(bpace->bign->group, Vb_point, x_BN, y_BN, ctx))
			goto err;

		if (!BN_bn2lebinpad(x_BN, out, bpace->level * 2) ||
			!BN_bn2lebinpad(y_BN, out + bpace->level * 2, bpace->level * 2))
			goto err;

		/* save Vbx */
		memcpy(bpace->R + (bpace->level * 2), out, bpace->level * 2);

		/* 8 */
		if (!EC_POINT_mul(bpace->bign->group, K_point, NULL, Va_point, bpace->u_BN, ctx))
			goto err;

		if (!EC_POINT_get_affine_coordinates(bpace->bign->group, K_point, x_BN, y_BN, ctx))
			goto err;

		if (!(K = OPENSSL_zalloc(bpace->level * 2)))
			goto err;
		if (!BN_bn2lebinpad(x_BN, K, bpace->level * 2))
			goto err;

		/* add helloA */
		if (bpace->helloA)
			memcpy(bpace->R + (bpace->level * 4), bpace->helloA, bpace->helloA_len);
		if (bpace->helloB)
			memcpy(bpace->R + (bpace->level * 4) + bpace->helloA_len, bpace->helloB, bpace->helloB_len);

		/* 9 */
		if (BAKE_kdf(K, bpace->level * 2, bpace->R, bpace->level * 4 + bpace->helloA_len + bpace->helloB_len, 0, bpace->K0))
			goto err;

		if (Tb)
		{
			/* 10 */
			if (BAKE_kdf(K, bpace->level * 2, bpace->R, bpace->level * 4 + bpace->helloA_len + bpace->helloB_len, 1, bpace->K1))
				goto err;

			/* 11 */
			unsigned char d[16] = {0};

			memset(d, 0xFF, 16);
			belt_mac(d, 16, bpace->K1, Tb);
		}
	}

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	OPENSSL_free(K);

	EC_POINT_free(Va_point);
	EC_POINT_free(Vb_point);
	EC_POINT_free(W_point);
	EC_POINT_free(K_point);

	return ret;
}

int BAKE_bpace_step5(BPACE_CTX *bpace, const unsigned char *in, unsigned int in_len, const unsigned char Tb[8], unsigned char Ta[8])
{
	BN_CTX *ctx = NULL;
	EC_POINT *Vb_point = NULL, *K_point = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	unsigned char *K = NULL;
	int ret = 1;

	if (in_len != bpace->level * 4)
		goto err;

	if (!(ctx = BN_CTX_new()))
		goto err;

	BN_CTX_start(ctx);
	x_BN = BN_CTX_get(ctx);
	y_BN = BN_CTX_get(ctx);
	if (y_BN == NULL)
		goto err;

	/* 2 */
	if (!BN_lebin2bn(in, bpace->level * 2, x_BN) ||
		!BN_lebin2bn(in + bpace->level * 2, bpace->level * 2, y_BN))
		goto err;

	if (bign_check_pubkey_affine_coordinates(bpace->bign, x_BN, y_BN))
		goto err;

	/* save Vbx */
	memcpy(bpace->R + (bpace->level * 2), in, bpace->level * 2);

	if (!(Vb_point = EC_POINT_new(bpace->bign->group)) ||
		!(K_point = EC_POINT_new(bpace->bign->group)))
		goto err;

	if (!EC_POINT_set_affine_coordinates(bpace->bign->group, Vb_point, x_BN, y_BN, ctx))
		goto err;

	/* 3 */
	if (!EC_POINT_mul(bpace->bign->group, K_point, NULL, Vb_point, bpace->u_BN, ctx))
		goto err;

	/* 4 */
	if (!EC_POINT_get_affine_coordinates(bpace->bign->group, K_point, x_BN, y_BN, ctx))
		goto err;

	if (!(K = OPENSSL_zalloc(bpace->level * 2)))
		goto err;

	if (!BN_bn2lebinpad(x_BN, K, bpace->level * 2))
		goto err;

	/* add helloA */
	if (bpace->helloA)
		memcpy(bpace->R + (bpace->level * 4), bpace->helloA, bpace->helloA_len);
	if (bpace->helloB)
		memcpy(bpace->R + (bpace->level * 4) + bpace->helloA_len, bpace->helloB, bpace->helloB_len);

	if (BAKE_kdf(K, bpace->level * 2, bpace->R, bpace->level * 4 + bpace->helloA_len + bpace->helloB_len, 0, bpace->K0))
		goto err;

	if (Tb && Ta)
	{
		/* 5 */
		if (BAKE_kdf(K, bpace->level * 2, bpace->R, bpace->level * 4 + bpace->helloA_len + bpace->helloB_len, 1, bpace->K1))
			goto err;

		/* 5 */
		unsigned char d[16] = {0}, tB[8] = {0};
		memset(d, 0xFF, 16);
		belt_mac(d, 16, bpace->K1, tB);

		if (CRYPTO_memcmp(Tb, tB, 8))
			goto err;

		/* 7 */
		memset(d, 0x00, 16);
		belt_mac(d, 16, bpace->K1, Ta);
	}

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	OPENSSL_free(K);

	EC_POINT_free(Vb_point);
	EC_POINT_free(K_point);

	return ret;
}

int BAKE_bpace_step6(BPACE_CTX *bpace, const unsigned char Ta[8])
{
	unsigned char d[16] = {0}, tA[8] = {0};

	belt_mac(d, 16, bpace->K1, tA);

	if (CRYPTO_memcmp(Ta, tA, 8))
		return 1;

	return 0;
}

void BAKE_bpace_final(BPACE_CTX *bpace, unsigned char out[32])
{
	OPENSSL_clear_free(bpace->R, bpace->level * 4 + (bpace->helloA_len + bpace->helloB_len));

	if (bpace->helloA && bpace->helloA_len > 0)
		OPENSSL_clear_free(bpace->helloA, bpace->helloA_len);
	if (bpace->helloB && bpace->helloB_len > 0)
		OPENSSL_clear_free(bpace->helloB, bpace->helloB_len);

	BIGN_free(bpace->bign);
	BN_free(bpace->u_BN);

	if (out)
		memcpy(out, bpace->K0, 32);

	memset(bpace->K0, 0, 32);
	memset(bpace->K1, 0, 32);
	memset(bpace->K2, 0, 32);
}