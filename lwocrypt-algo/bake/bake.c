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

#include <openssl/belt.h>

int BAKE_dh(
	const BIGN *bign,
	const unsigned char *public_key, unsigned int public_key_len,
	unsigned char *out, size_t *out_len)
{
	BN_CTX *ctx = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	EC_POINT *tmp = NULL;
	int ret = 1;

	int levelX2 = (EC_GROUP_order_bits(bign->group) + 7) / 8;

	*out_len = levelX2 << 1;
	if (!out)
		return 0;

	if (!(ctx = BN_CTX_new()))
		goto err;

	BN_CTX_start(ctx);
	x_BN = BN_CTX_get(ctx);
	y_BN = BN_CTX_get(ctx);
	if (y_BN == NULL)
		goto err;

	if (!BN_lebin2bn(public_key, levelX2, x_BN) ||
		!BN_lebin2bn(public_key + levelX2, levelX2, y_BN))
		goto err;

	if (!(tmp = EC_POINT_new(bign->group)))
		goto err;

	if (bign_check_pubkey_affine_coordinates(bign, x_BN, y_BN))
		goto err;

	if (!EC_POINT_set_affine_coordinates(bign->group, tmp, x_BN, y_BN, ctx))
		goto err;

	ret = bign_compute_key(bign, tmp, out, out_len);

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	EC_POINT_free(tmp);

	return ret;
}

int BAKE_kdf(const unsigned char *x, size_t x_len,
			 const unsigned char *s, size_t s_len,
			 size_t number, unsigned char out[32])
{
	EVP_MD_CTX *mctx = NULL;
	unsigned char *theta = NULL;
	unsigned char d[12] = {0}, i[16] = {0};
	unsigned int mdlen;
	int ret = 1;

	if (!(theta = OPENSSL_zalloc(EVP_MAX_MD_SIZE)))
		goto err;

	if (!(mctx = EVP_MD_CTX_new()))
		goto err;

	/*Step 1*/
	const EVP_MD *evpMD = EVP_belt_hash();
	if (!EVP_DigestInit_ex(mctx, evpMD, NULL))
		goto err;
	if (!EVP_DigestUpdate(mctx, x, x_len))
		goto err;
	if (!EVP_DigestUpdate(mctx, s, s_len))
		goto err;
	if (!EVP_DigestFinal_ex(mctx, theta, &mdlen))
		goto err;

	memset(d, 0xFF, 12);
	memcpy(i, &number, sizeof(size_t));

	ret = BELT_keyrep(theta, mdlen, d, i, 32, out);

err:
	EVP_MD_CTX_free(mctx);

	OPENSSL_clear_free(theta, EVP_MAX_MD_SIZE);

	return ret;
}

int bake_swu(const BIGN *bign, const unsigned char x[], EC_POINT *W)
{
	BN_CTX *ctx = NULL;
	BIGNUM *p_BN = NULL, *a_BN = NULL, *b_BN = NULL;
	BIGNUM *s_BN = NULL, *t_BN = NULL, *x1_BN = NULL, *x2_BN = NULL, *y_BN = NULL;
	BIGNUM *temp1_BN = NULL, *temp2_BN = NULL, *temp3_BN = NULL;
	unsigned char header[16] = {0}, key[32] = {0};
	unsigned char *kwp = NULL;
	size_t kwp_len = 0;
	int ret = 1;

	int levelX2 = (EC_GROUP_order_bits(bign->group) + 7) / 8;

	if (!(ctx = BN_CTX_new()))
		goto err;

	if (BELT_kwp_encrypt(x, levelX2, header, key, kwp, &kwp_len) ||
		!(kwp = OPENSSL_zalloc(kwp_len)) ||
		BELT_kwp_encrypt(x, levelX2, header, key, kwp, &kwp_len))
		goto err;

	BN_CTX_start(ctx);
	p_BN = BN_CTX_get(ctx);
	a_BN = BN_CTX_get(ctx);
	b_BN = BN_CTX_get(ctx);
	s_BN = BN_CTX_get(ctx);
	t_BN = BN_CTX_get(ctx);
	temp1_BN = BN_CTX_get(ctx);
	temp2_BN = BN_CTX_get(ctx);
	temp3_BN = BN_CTX_get(ctx);
	x1_BN = BN_CTX_get(ctx);
	x2_BN = BN_CTX_get(ctx);
	y_BN = BN_CTX_get(ctx);
	if (y_BN == NULL)
		goto err;

	if (!EC_GROUP_get_curve(bign->group, p_BN, a_BN, b_BN, ctx))
		goto err;

	if (!BN_lebin2bn(kwp, kwp_len, s_BN))
		goto err;

	/* step2 */
	if (!BN_mod(s_BN, s_BN, p_BN, ctx))
		goto err;

	/* step3 */
	if (!BN_mod_sqr(temp1_BN, s_BN, p_BN, ctx))
		goto err;

	BN_set_negative(temp1_BN, 1);
	if (!BN_mod(t_BN, temp1_BN, p_BN, ctx))
		goto err;

	/* step4 */
	BN_set_word(temp1_BN, 2);
	BN_sub(temp1_BN, p_BN, temp1_BN);

	if (!BN_mod_sqr(temp2_BN, t_BN, p_BN, ctx))
		goto err;

	/* temp2 = t^2 + t */
	if (!BN_mod_add(temp2_BN, temp2_BN, t_BN, p_BN, ctx))
		goto err;

	/* temp3 = a(t^2 + t) */
	if (!BN_mod_mul(temp3_BN, a_BN, temp2_BN, p_BN, ctx))
		goto err;

	/* temp1 = (a(t^2 + t))^(p-2) */
	if (!BN_mod_exp(temp1_BN, temp3_BN, temp1_BN, p_BN, ctx))
		goto err;

	/* temp2 = b(t^2 + t) */
	if (!BN_mod_mul(temp2_BN, b_BN, temp2_BN, p_BN, ctx))
		goto err;

	/* temp2 = b(t^2 + t) + b */
	if (!BN_mod_add(temp2_BN, temp2_BN, b_BN, p_BN, ctx))
		goto err;

	/* temp2 = -b (t^2 + t + 1) */
	BN_set_negative(temp2_BN, 1);

	/* x1 = -b (t^2 + t + 1)(a(t^2 + t))^(p-2) mod p */
	if (!BN_mod_mul(x1_BN, temp2_BN, temp1_BN, p_BN, ctx))
		goto err;

	/* step5 */
	if (!BN_mod_mul(x2_BN, t_BN, x1_BN, p_BN, ctx))
		goto err;

	/* step6 */
	BN_set_word(temp3_BN, 3);
	/* temp1 = x1^3 */
	if (!BN_mod_exp(temp1_BN, x1_BN, temp3_BN, p_BN, ctx))
		goto err;
	/* temp2 = a * x1 */
	if (!BN_mod_mul(temp2_BN, x1_BN, a_BN, p_BN, ctx))
		goto err;
	/* temp2 = a * x1 + b */
	if (!BN_mod_add(temp2_BN, temp2_BN, b_BN, p_BN, ctx))
		goto err;
	/* y = (x1^3 + a * x1 + b) mod p */
	if (!BN_mod_add(y_BN, temp1_BN, temp2_BN, p_BN, ctx))
		goto err;

	/* step7 */
	/* temp1 = s^3 */
	if (!BN_mod_exp(temp1_BN, s_BN, temp3_BN, p_BN, ctx))
		goto err;
	/* s = (s^3 * y) mod p */
	if (!BN_mod_mul(s_BN, temp1_BN, y_BN, p_BN, ctx))
		goto err;

	/* step8 */
	BN_copy(temp1_BN, p_BN);
	/* temp2 = p + 1 */
	BN_add_word(temp1_BN, 1);
	/* temp2 = (p + 1) / 4 */
	BN_div_word(temp1_BN, 4);
	/* temp2 = 1 + (p + 1) / 4 */
	BN_add_word(temp1_BN, 1);
	/* temp3 = p - 1 - (p + 1) / 4 */
	if (!BN_sub(temp2_BN, p_BN, temp1_BN))
		goto err;
	/* t = y^(p - 1 - (p + 1) / 4) mod p */
	if (!BN_mod_exp(t_BN, y_BN, temp2_BN, p_BN, ctx))
		goto err;

	/* step9 */
	if (!BN_sqr(temp1_BN, t_BN, ctx))
		goto err;
	if (!BN_mod_mul(temp2_BN, temp1_BN, y_BN, p_BN, ctx))
		goto err;

	BN_set_word(temp1_BN, 1);
	if (BN_cmp(temp2_BN, temp1_BN) == 0)
	{
		if (!BN_copy(temp1_BN, x1_BN))
			goto err;
		if (!BN_mod_mul(temp2_BN, t_BN, y_BN, p_BN, ctx))
			goto err;
	}
	else
	{
		if (!BN_copy(temp1_BN, x2_BN))
			goto err;
		if (!BN_mod_mul(temp2_BN, s_BN, t_BN, p_BN, ctx))
			goto err;
	}

	if (!EC_POINT_set_affine_coordinates(bign->group, W, temp1_BN, temp2_BN, ctx))
		goto err;

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	OPENSSL_clear_free(kwp, kwp_len);

	return ret;
}

int BAKE_swu(const BIGN *bign, const unsigned char x[], unsigned char point[])
{
	BN_CTX *ctx = NULL;
	BIGNUM *x_BN = NULL, *y_BN = NULL;
	EC_POINT *W_point = NULL;
	int ret = 1;

	int levelX2 = (EC_GROUP_order_bits(bign->group) + 7) / 8;

	if (!(ctx = BN_CTX_new()))
		goto err;

	BN_CTX_start(ctx);
	x_BN = BN_CTX_get(ctx);
	y_BN = BN_CTX_get(ctx);
	if (y_BN == NULL)
		goto err;

	if (!(W_point = EC_POINT_new(bign->group)))
		goto err;

	if (bake_swu(bign, x, W_point))
		goto err;

	if (!EC_POINT_get_affine_coordinates(bign->group, W_point, x_BN, y_BN, ctx))
		goto err;

	if (!BN_bn2lebinpad(x_BN, point, levelX2) ||
		!BN_bn2lebinpad(y_BN, point + levelX2, levelX2))
		goto err;

	ret = 0;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	EC_POINT_free(W_point);

	return ret;
}