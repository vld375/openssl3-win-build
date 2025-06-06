/*
 * Copyright 2023. All Rights Reserved.
 */
 //#include "crypto/bn.h"
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <lwocrypt-alg/belt.h>
#include <lwocrypt-alg/bignerr.h>
#include <lwocrypt-alg/bign_local.h>

static ossl_inline void xor (unsigned char *out, unsigned char *a, unsigned char *b, size_t count)
{
	size_t it;

	for (it = 0; it < count; it++)
		*(out + it) = *(a + it) ^ *(b + it);
}

int BIGN_genk(BIGN *bign, const unsigned char *md, unsigned int md_len, const unsigned char *oid, unsigned int oid_len, const unsigned char *t, size_t t_len, unsigned char *key)
{
	EVP_MD_CTX *mctx = NULL;
	BIGNUM *r_BN = NULL;
	unsigned char *r = NULL, *s = NULL, *theta = NULL, *privkey = NULL;
	unsigned char temp16[16];
	unsigned int key_len = 0;
	int ret = 1, repeat = 0;

	const BIGNUM *order;
	order = EC_GROUP_get0_order(bign->group);
	int levelX2 = (EC_GROUP_order_bits(bign->group) + 7) / 8;

	if (md_len != levelX2)
	{
		BIGNerr(BIGN_F_BIGN_GENK, BIGN_R_INVALID_DIGEST_LENGTH);
		goto err;
	}

	if (BIGN_get_privkey(bign, privkey, &key_len) ||
		!(privkey = OPENSSL_zalloc(key_len)) ||
		BIGN_get_privkey(bign, privkey, &key_len))
	{
		BIGNerr(BIGN_F_BIGN_GENK, ERR_R_BIGN_LIB);
		goto err;
	}

	int n = levelX2 >> 4;

	if (!(r_BN = BN_new()) || !(theta = OPENSSL_zalloc(EVP_MAX_MD_SIZE)))
	{
		BIGNerr(BIGN_F_BIGN_GENK, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!(mctx = EVP_MD_CTX_new()))
	{
		BIGNerr(BIGN_F_BIGN_GENK, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/*Step 2*/
	EVP_MD *evpMD = NULL;
	if ((evpMD = EVP_MD_fetch(NULL, "hbelt", "")) == NULL ||
		!EVP_DigestInit_ex(mctx, evpMD, NULL) ||
		!EVP_DigestUpdate(mctx, oid, oid_len) ||
		!EVP_DigestUpdate(mctx, privkey, key_len) ||
		!EVP_DigestUpdate(mctx, t, t_len) ||
		!EVP_DigestFinal_ex(mctx, theta, NULL))
		goto err;

	/*Step 3*/
	if (!(r = OPENSSL_zalloc(levelX2)) || !(s = OPENSSL_zalloc(16)))
	{
		BIGNerr(BIGN_F_BIGN_GENK, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	memcpy(r, md, md_len);

	/*Step 4*/
	do
	{
		repeat++;
		/*Substep 1*/
		if (n == 2)
			memcpy(s, r, 16);
		/*Substep 2*/
		else if (n == 3)
		{
			xor(s, r, r + 16, 16);
			memcpy(r, r + 16, 16);
		}
		/*Substep 3*/
		else if (n == 4)
		{
			xor(temp16, r, r + 16, 16);
			xor(s, temp16, r + 32, 16);
			memcpy(r, r + 16, 16);
			memcpy(r + 16, r + 32, 16);
		}

		/*Substep 4*/
		BELT_block_encrypt(s, temp16, theta);
		xor(r + levelX2 - 32, temp16, r + levelX2 - 16, 16);

		memset(temp16, 0, 16);
		*((unsigned int *)(temp16)) = repeat;

		xor(r + levelX2 - 32, r + levelX2 - 32, temp16, 16);

		/*Substep 5*/
		memcpy(r + levelX2 - 16, s, 16);

		/*Substep 6*/
		if (repeat % (2 * n) == 0)
		{
			if (!BN_lebin2bn(r, levelX2, r_BN))
			{
				BIGNerr(BIGN_F_BIGN_GENK, ERR_R_BIGN_LIB);
				goto err;
			}

			if (BN_cmp(order, r_BN) > 0)
				repeat = 0;
		}
	} while (repeat);

	/*Step 5*/
	memcpy(key, r, levelX2);

	ret = 0;

err:
	BN_free(r_BN);
	EVP_MD_CTX_free(mctx);

	OPENSSL_clear_free(theta, EVP_MAX_MD_SIZE);
	OPENSSL_clear_free(s, 16);
	OPENSSL_clear_free(r, levelX2);
	OPENSSL_clear_free(privkey, key_len);

	return ret;
}

int BIGN_sign(
	BIGN *bign,
	const unsigned char *md, unsigned int md_len,
	const unsigned char *oid, unsigned int oid_len,
	const unsigned char *t, size_t t_len,
	unsigned char *sign, unsigned int *siglen)
{
	BN_CTX *ctx = NULL;
	EVP_MD_CTX *mctx = NULL;
	BIGNUM *a_BN, *b_BN, *c_BN, *k_BN, *x_BN, *y_BN;
	EC_POINT *R_point = NULL;
	unsigned char *k = NULL, *R = NULL;
	int ret = 1;

	const BIGNUM *order;
	order = EC_GROUP_get0_order(bign->group);
	int levelX2 = (EC_GROUP_order_bits(bign->group) + 7) / 8;

	if (md_len != levelX2)
	{
		BIGNerr(BIGN_F_BIGN_SIGN, BIGN_R_INVALID_DIGEST_LENGTH);
		goto err;
	}

	if (siglen)
		*siglen = levelX2 + (levelX2 >> 1);

	if (!sign)
		return 0;

	if (!(ctx = BN_CTX_new()) || !(mctx = EVP_MD_CTX_new()))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	BN_CTX_start(ctx);
	k_BN = BN_CTX_get(ctx);
	x_BN = BN_CTX_get(ctx);
	y_BN = BN_CTX_get(ctx);
	if (y_BN == NULL)
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!(k = OPENSSL_zalloc(levelX2)))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (BIGN_genk(bign, md, md_len, oid, oid_len, t, t_len, k))
	{
		OPENSSL_clear_free(k, levelX2);
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!BN_lebin2bn(k, levelX2, k_BN))
	{
		OPENSSL_clear_free(k, levelX2);
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	OPENSSL_clear_free(k, levelX2);

	if (!(R_point = EC_POINT_new(bign->group)))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!EC_POINT_mul(bign->group, R_point, k_BN, NULL, NULL, ctx))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!EC_POINT_get_affine_coordinates(bign->group, R_point, x_BN, y_BN, ctx))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!(R = OPENSSL_zalloc(levelX2 << 1)))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!BN_bn2lebinpad(x_BN, R, levelX2) ||
		!BN_bn2lebinpad(y_BN, R + levelX2, levelX2))
	{
		OPENSSL_free(R);
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	EVP_MD *evpMD = NULL;
	if ((evpMD = EVP_MD_fetch(NULL, "hbelt", "")) == NULL ||
		!EVP_DigestInit_ex(mctx, evpMD, NULL) ||
		!EVP_DigestUpdate(mctx, oid, oid_len) ||
		!EVP_DigestUpdate(mctx, R, levelX2) ||
		!EVP_DigestUpdate(mctx, md, md_len) ||
		!EVP_DigestFinal_ex(mctx, sign, NULL))
	{
		OPENSSL_free(R);
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	OPENSSL_free(R);

	a_BN = BN_CTX_get(ctx);
	b_BN = BN_CTX_get(ctx);
	c_BN = BN_CTX_get(ctx);
	if (c_BN == NULL)
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!BN_lebin2bn(sign, levelX2 >> 1, a_BN))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	BN_one(b_BN);
	if (!BN_lshift(c_BN, b_BN, levelX2 << 2))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!BN_add(b_BN, a_BN, c_BN))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!BN_mul(c_BN, bign->priv_key, b_BN, ctx))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!BN_lebin2bn(md, levelX2, b_BN))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!BN_sub(a_BN, k_BN, b_BN))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!BN_mod_sub(b_BN, a_BN, c_BN, order, ctx))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!BN_bn2lebinpad(b_BN, sign + (levelX2 >> 1), levelX2))
	{
		BIGNerr(BIGN_F_BIGN_SIGN, ERR_R_BIGN_LIB);
		goto err;
	}

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EVP_MD_CTX_free(mctx);

	EC_POINT_free(R_point);

	return ret;
}

int BIGN_verify(
	BIGN *bign,
	const unsigned char *sign, unsigned int sign_len,
	const unsigned char *md, unsigned int md_len,
	const unsigned char *oid, unsigned int oid_len)
{
	BN_CTX *ctx = NULL;
	EVP_MD_CTX *mctx = NULL;
	BIGNUM *a_BN = NULL, *b_BN = NULL, *c_BN = NULL, *d_BN = NULL, *x_BN = NULL, *y_BN = NULL;
	EC_POINT *R_point = NULL;
	unsigned char *R = NULL, *t = NULL;
	int ret = 1;

	const BIGNUM *order;
	order = EC_GROUP_get0_order(bign->group);
	int levelX2 = (EC_GROUP_order_bits(bign->group) + 7) / 8;

	if (sign_len != levelX2 + (levelX2 >> 1))
	{
		ret = 2;
		BIGNerr(BIGN_F_BIGN_VERIFY, BIGN_R_INVALID_SIGN_LENGTH);
		goto err;
	}

	if (md_len != levelX2)
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, BIGN_R_INVALID_DIGEST_LENGTH);
		goto err;
	}

	if (!(ctx = BN_CTX_new()) || !(mctx = EVP_MD_CTX_new()))
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	BN_CTX_start(ctx);
	a_BN = BN_CTX_get(ctx);
	b_BN = BN_CTX_get(ctx);
	c_BN = BN_CTX_get(ctx);
	d_BN = BN_CTX_get(ctx);
	if (d_BN == NULL)
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!BN_lebin2bn(sign + (levelX2 >> 1), levelX2, a_BN))
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_BIGN_LIB);
		goto err;
	}

	if (BN_cmp(a_BN, order) >= 0)
	{
		ret = 2;
		BIGNerr(BIGN_F_BIGN_VERIFY, BIGN_R_BIGN_VERIFY_FAIL);
		goto err;
	}

	if (!BN_lebin2bn(md, md_len, b_BN))
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!BN_mod_add(d_BN, a_BN, b_BN, order, ctx))
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!BN_lebin2bn(sign, (levelX2 >> 1), a_BN))
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_BIGN_LIB);
		goto err;
	}

	BN_one(b_BN);
	if (!BN_lshift(c_BN, b_BN, levelX2 << 2))
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!BN_add(b_BN, a_BN, c_BN))
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!(R_point = EC_POINT_new(bign->group)))
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!EC_POINT_mul(bign->group, R_point, d_BN, bign->pub_key, b_BN, ctx))
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_BIGN_LIB);
		goto err;
	}

	x_BN = BN_CTX_get(ctx);
	y_BN = BN_CTX_get(ctx);
	if (y_BN == NULL)
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!EC_POINT_get_affine_coordinates(bign->group, R_point, x_BN, y_BN, ctx))
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!(R = OPENSSL_zalloc(levelX2 << 1)))
	{
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!BN_bn2lebinpad(x_BN, R, levelX2) ||
		!BN_bn2lebinpad(y_BN, R + levelX2, levelX2))
	{
		OPENSSL_free(R);
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_BIGN_LIB);
		goto err;
	}

	if (!(t = OPENSSL_zalloc(levelX2)))
	{
		OPENSSL_free(R);
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	EVP_MD *evpMD = NULL;
	if ((evpMD = EVP_MD_fetch(NULL, "hbelt", "")) == NULL ||
		!EVP_DigestInit_ex(mctx, evpMD, NULL) ||
		!EVP_DigestUpdate(mctx, oid, oid_len) ||
		!EVP_DigestUpdate(mctx, R, levelX2) ||
		!EVP_DigestUpdate(mctx, md, md_len) ||
		!EVP_DigestFinal_ex(mctx, t, NULL))
	{
		OPENSSL_free(R);
		OPENSSL_free(t);
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_BIGN_LIB);
		goto err;
	}

	OPENSSL_free(R);

	if (!BN_lebin2bn(t, levelX2 >> 1, b_BN))
	{
		OPENSSL_free(t);
		BIGNerr(BIGN_F_BIGN_VERIFY, ERR_R_BIGN_LIB);
		goto err;
	}

	OPENSSL_free(t);

	if (BN_cmp(b_BN, a_BN) != 0)
	{
		ret = 2;
		BIGNerr(BIGN_F_BIGN_VERIFY, BIGN_R_BIGN_VERIFY_FAIL);
		goto err;
	}

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EVP_MD_CTX_free(mctx);

	EC_POINT_free(R_point);

	return ret;
}