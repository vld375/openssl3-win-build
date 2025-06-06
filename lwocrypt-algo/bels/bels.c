/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <crypto/bn.h>
#include <crypto/evp.h>

#include <lwocrypt/bels.h>
#include "bels_local.h"

#include "../bn/bn_local.h"

int minBit(const BIGNUM *a)
{
	int i, j;
	BN_ULONG mask;

	if (BN_is_zero(a))
		return 0;

	for (i = 0; i < a->top - 1; i++)
	{
		if (!a->d[i])
			continue;
		mask = 1;
		for (j = 0; j < BN_BITS2; j++)
		{
			if (a->d[i] & mask)
			{
				return BN_BITS2 * i + j;
			}
			mask <<= 1;
		}
	}
	return 0;
}

int customMIN(int a, int b)
{
	return a < b ? a : b;
}

int BN_check_bit(const BIGNUM *a, int bit)
{
	return a->d[bit / BN_BITS2] & (1 << (bit % BN_BITS2));
}

int BN_GF2m_mod_full(BIGNUM *r, const BIGNUM *a, const BIGNUM *p)
{
	int ret = 1;

	BN_CTX *ctx = NULL;
	BIGNUM *A = NULL, *P = NULL;

	int res = BN_cmp(a, p);
	if (res == 0)
	{
		BN_zero(r);
		return 0;
	}
	else if (res < 0)
	{
		BN_copy(r, a);
		return 0;
	}

	if (!(ctx = BN_CTX_new()))
		goto err;

	BN_CTX_start(ctx);

	A = BN_CTX_get(ctx);
	P = BN_CTX_get(ctx);

	BN_copy(A, a);

	res = BN_num_bits(p);
	while (BN_cmp(A, p) > 0)
	{

		int bitsA = BN_num_bits(A);

		BN_lshift(P, p, bitsA - res);
		BN_GF2m_add(A, A, P);
	}

	BN_copy(r, A);
	ret = 0;
err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return ret;
}

int BELS_ExGCD(const BIGNUM *a, const BIGNUM *b, BIGNUM *d, BIGNUM *da, BIGNUM *db)
{
	BN_CTX *ctx = NULL;
	BIGNUM *A = NULL, *B = NULL, *da0 = NULL, *db0 = NULL;
	BIGNUM *mod = NULL, *temp = NULL;
	BIGNUM *U = NULL, *V = NULL;
	int ret = 1;

	if (!(ctx = BN_CTX_new()))
		goto err;

	BN_CTX_start(ctx);
	da0 = BN_CTX_get(ctx);
	db0 = BN_CTX_get(ctx);
	A = BN_CTX_get(ctx);
	B = BN_CTX_get(ctx);

	mod = BN_CTX_get(ctx);
	temp = BN_CTX_get(ctx);

	U = BN_CTX_get(ctx);
	V = BN_CTX_get(ctx);

	BN_set_bit(mod, 2048);
	int s = customMIN(minBit(a), minBit(b));

	BN_set_word(da, 0);
	BN_set_word(db, 1);
	BN_set_word(da0, 1);
	BN_set_word(db0, 0);

	BN_rshift(A, a, s);
	BN_rshift(B, b, s);

	BN_copy(U, A);
	BN_copy(V, B);

	while (!BN_is_zero(U))
	{
		for (; !BN_check_bit(U, 0); BN_rshift(U, U, 1))
		{
			if (!BN_check_bit(da0, 0))
			{
				BN_rshift(da0, da0, 1);
				BN_rshift(db0, db0, 1);
			}
			else
			{
				BN_GF2m_add(da0, da0, B);
				BN_rshift(da0, da0, 1);
				BN_GF2m_add(db0, db0, A);
				BN_rshift(db0, db0, 1);
			}
		}

		for (; !BN_check_bit(V, 0); BN_rshift(V, V, 1))
		{
			if (!BN_check_bit(da, 0))
			{
				BN_rshift(da, da, 1);
				BN_rshift(db, db, 1);
			}
			else
			{
				BN_GF2m_add(da, da, B);
				BN_rshift(da, da, 1);
				BN_GF2m_add(db, db, A);
				BN_rshift(db, db, 1);
			}
		}

		if (BN_cmp(U, V) >= 0)
		{
			BN_GF2m_add(U, U, V);
			BN_GF2m_add(da0, da0, da);
			BN_GF2m_add(db0, db0, db);
		}
		else
		{
			BN_GF2m_add(V, U, V);
			BN_GF2m_add(da, da0, da);
			BN_GF2m_add(db, db0, db);
		}
	}
	BN_copy(d, V);
	BN_set_bit(temp, s);
	BN_GF2m_mod_mul(d, d, temp, mod, ctx);
	ret = 0;
err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return ret;
}

int bels2PKEY(EVP_PKEY *pkey, const BIGNUM *si, const BIGNUM *mi, int i)
{
	int ret = 1;
	int s_len = (BN_num_bits(si) + 7) / 8;

	BELS_KEY *bkey = NULL;
	if ((bkey = (BELS_KEY *)OPENSSL_zalloc(sizeof(BELS_KEY))) == NULL)
		goto err;

	switch (s_len)
	{
	case 16:
		bkey->nid = NID_bels_m0128v1;
		bkey->m0 = &m_128[0];
		break;
	case 24:
		bkey->nid = NID_bels_m0192v1;
		bkey->m0 = &m_192[0];
		break;
	case 32:
		bkey->nid = NID_bels_m0256v1;
		bkey->m0 = &m_256[0];
		break;
	default:
		goto err;
	}

	bkey->len = s_len;
	bkey->num = i;

	BN_bn2lebinpad(si, bkey->secret, s_len);
	BN_bn2lebinpad(mi, bkey->m, s_len);

	EVP_PKEY_assign(pkey, EVP_PKEY_BELS, bkey);
	ret = 0;

err:
	return ret;
}

void BELS_free(BELS_CTX *bels)
{
	int i;

	if (bels == NULL)
		return;

	for (i = 0; i < bels->n; i++)
		if (bels->pkeys[i])
			EVP_PKEY_free(bels->pkeys[i]);

	OPENSSL_free(bels->pkeys);
	OPENSSL_clear_free((void *)bels, sizeof(BELS_CTX));
}

BELS_CTX *BELS_share(int n, int t, const unsigned char *secret, int secret_len)
{
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL, *C = NULL, *secr = NULL;
	BIGNUM *m0 = NULL, *xl = NULL, *temp = NULL;
	BIGNUM *mi = NULL, *mod_i = NULL, *si = NULL;
	int i;

	BELS_CTX *ret = OPENSSL_zalloc(sizeof(*ret));
	if (ret == NULL)
		return NULL;

	const unsigned char *M = (secret_len == 16 ? &m_128[0] : secret_len == 24 ? &m_192[0]
														 : secret_len == 32	  ? &m_256[0]
																			  : NULL);
	if (!M || n > 16 || t < 2 || t > n)
		goto err;

	if ((ret->pkeys = (EVP_PKEY **)OPENSSL_zalloc(sizeof(EVP_PKEY *) * n)) == NULL)
		goto err;

	ret->n = n;
	for (i = 0; i < ret->n; i++)
		if ((ret->pkeys[i] = EVP_PKEY_new()) == NULL)
			goto err;

	if (!(ctx = BN_CTX_new()))
		goto err;

	BN_CTX_start(ctx);
	k = BN_CTX_get(ctx);
	C = BN_CTX_get(ctx);
	m0 = BN_CTX_get(ctx);
	xl = BN_CTX_get(ctx);
	mi = BN_CTX_get(ctx);
	secr = BN_CTX_get(ctx);
	mod_i = BN_CTX_get(ctx);
	si = BN_CTX_get(ctx);
	temp = BN_CTX_get(ctx);

	/* k = {0,1}^((t - 1) * l) */
	BN_set_bit(temp, (t - 1) * (secret_len << 3));
	if (!BN_priv_rand_range(k, temp))
		goto err;

	/* C(x) = (x^l + M0(x)) * k(x) + S(x) */
	if (!BN_lebin2bn(M, secret_len, m0))
		goto err;

	if (!BN_lebin2bn(secret, secret_len, secr))
		goto err;

	BN_set_bit(xl, (secret_len << 3));
	BN_set_bit(mod_i, 1024);

	BN_GF2m_add(C, xl, m0);

	BN_GF2m_mod_mul(temp, C, k, mod_i, ctx);
	BN_GF2m_add(C, temp, secr);

	/* Si(x) = C(x) mod (x^l + Mi(x)) */
	for (i = 1; i <= n; i++)
	{
		if (!BN_lebin2bn(M + (i * secret_len), secret_len, mi))
			goto err;

		BN_GF2m_add(mod_i, xl, mi);
		BN_GF2m_mod_full(si, C, mod_i);

		bels2PKEY(ret->pkeys[i - 1], si, mi, i);
	}

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return ret;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	BELS_free(ret);

	return NULL;
}

int BELS_recov(BELS_CTX *bels, unsigned char *out, int *out_len)
{
	BN_CTX *ctx = NULL;
	BIGNUM *C = NULL, *secr = NULL, *xl = NULL;
	BIGNUM *mi = NULL, *s_i = NULL;
	BIGNUM *g = NULL, *d = NULL, *u = NULL, *v = NULL;
	BIGNUM *sum = NULL, *mod = NULL, *temp = NULL;
	int i, ret = 1;

	if (!(ctx = BN_CTX_new()))
		goto err;

	BN_CTX_start(ctx);

	mi = BN_CTX_get(ctx);
	s_i = BN_CTX_get(ctx);
	C = BN_CTX_get(ctx);
	xl = BN_CTX_get(ctx);

	g = BN_CTX_get(ctx);
	d = BN_CTX_get(ctx);
	u = BN_CTX_get(ctx);
	v = BN_CTX_get(ctx);

	sum = BN_CTX_get(ctx);
	mod = BN_CTX_get(ctx);
	temp = BN_CTX_get(ctx);
	secr = BN_CTX_get(ctx);

	BELS_KEY *bkey = (BELS_KEY *)EVP_PKEY_get0(bels->pkeys[0]);

	if (!BN_lebin2bn(bkey->secret, bkey->len, C))
		goto err;

	if (!BN_lebin2bn(bkey->m, bkey->len, mi))
		goto err;

	BN_set_bit(mod, 2048);
	BN_set_bit(xl, (bkey->len << 3));
	BN_GF2m_add(g, xl, mi);

	for (i = 1; i < bels->n; i++)
	{
		bkey = (BELS_KEY *)EVP_PKEY_get0(bels->pkeys[i]);

		if (!BN_lebin2bn(bkey->m, bkey->len, mi))
			goto err;

		BN_GF2m_add(sum, xl, mi);

		// НОД (x^l + Mi(x), g(x))
		if (BELS_ExGCD(sum, g, d, u, v) || !BN_is_one(d))
			goto err;

		if (!BN_lebin2bn(bkey->secret, bkey->len, s_i))
			goto err;

		// C(x) = u(x)(x^l + Mi(x))C(x) + v(x)g(x)Si(x)
		BN_GF2m_mod_mul(temp, u, C, mod, ctx);
		BN_GF2m_mod_mul(C, temp, sum, mod, ctx);

		BN_GF2m_mod_mul(temp, v, g, mod, ctx);
		BN_GF2m_mod_mul(temp, temp, s_i, mod, ctx);

		BN_GF2m_add(C, C, temp);

		// g(x) = (x^l + Mi(x))g(x)
		BN_GF2m_mod_mul(g, g, sum, mod, ctx);

		// C(x) = C(x) mod g(x)
		BN_GF2m_mod_full(C, C, g);
	}

	if (!BN_lebin2bn(bkey->m0, bkey->len, mi))
		goto err;

	// S(x) = C(x) mod (x^l + M0(x))
	BN_GF2m_add(sum, xl, mi);
	BN_GF2m_mod_full(secr, C, sum);

	if (out_len)
		*out_len = bkey->len;

	if (out)
		BN_bn2lebinpad(secr, out, bkey->len);

	ret = 0;
err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return ret;
}