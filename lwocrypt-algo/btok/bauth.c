/*
 * Copyright 2022. All Rights Reserved.
 */

#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto/bn.h"
#include "../bake/bake_local.h"
#include "../bign/bign_local.h"

#include <lwocrypt/bake.h>
#include <lwocrypt/brng.h>
#include <lwocrypt/btok.h>

int BTOK_bauth_init(BAUTH_CTX *bauth, EVP_PKEY *pkey,
					const unsigned char *helloA, size_t helloA_len,
					const unsigned char *helloB, size_t helloB_len,
					int twoWayAuth)
{
	int ret = 1;

	bauth->auth = twoWayAuth;

	bauth->bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);

	bauth->disp = BIGN_new(NULL);
	bauth->disp->group = EC_GROUP_dup(bauth->bign->group);

	bauth->level = (EC_GROUP_order_bits(bauth->bign->group) + 15) / 16;
	if (!(bauth->Rb = OPENSSL_zalloc(bauth->level + 1)))
		goto err;

	bauth->R_len = (helloA_len + helloB_len);
	bauth->R_len += bauth->auth ? 16 : 0;
	if (!(bauth->R = OPENSSL_zalloc(bauth->R_len + 1)))
		goto err;

	memcpy(bauth->R + (bauth->R_len - (helloA_len + helloB_len)), helloA, helloA_len);
	memcpy(bauth->R + (bauth->R_len - helloB_len), helloB, helloB_len);

	ret = 0;

err:

	return ret;
}

int BTOK_bauth_step2(BAUTH_CTX *bauth,
					 const unsigned char *public_key, unsigned int public_key_len,
					 unsigned char *out, unsigned int *out_len)
{
	unsigned char *K = NULL, *kwp = NULL;
	size_t K_len = 0, kwp_len = 0;

	int ret = 1;

	if (out_len)
		*out_len = (bauth->level * 4) + (bauth->level + 16);

	if (out)
	{
		unsigned char random[96] = {0}, Rb[32] = {0}, header[16] = {0};

		/* Step 3 */
		if (RAND_priv_bytes(random, 96) <= 0)
			goto err;

		brng_ctr_hbelt(1, random, random + 32, random + 64, Rb);
		memcpy(bauth->Rb, Rb, bauth->level);

		/* Step 4 */
		if (BIGN_generate_key(bauth->disp))
			goto err;

		/* Step 5 */
		if (BAKE_dh(bauth->disp, public_key, public_key_len, K, &K_len) ||
			!(K = OPENSSL_zalloc(K_len + 1)) ||
			BAKE_dh(bauth->disp, public_key, public_key_len, K, &K_len))
			goto err;

		/* Step 6 */
		if (BELT_kwp_encrypt(bauth->Rb, bauth->level, header, K, kwp, &kwp_len) ||
			!(kwp = OPENSSL_zalloc(kwp_len + 1)) ||
			BELT_kwp_encrypt(bauth->Rb, bauth->level, header, K, kwp, &kwp_len))
		{
			BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_BIGN_LIB);
			goto err;
		}

		unsigned int publen = 0;
		if (BIGN_get_pubkey(bauth->disp, out, &publen))
			goto err;

		memcpy(out + publen, kwp, kwp_len);
	}

	ret = 0;

err:
	OPENSSL_clear_free(K, K_len);
	OPENSSL_clear_free(kwp, kwp_len);

	return ret;
}

int BTOK_bauth_step3(BAUTH_CTX *bauth, const unsigned char *in, unsigned int in_len,
					 unsigned char out[8], unsigned char Ra[16])
{
	unsigned char *K = NULL;
	size_t K_len = 0;

	int ret = 1;
	unsigned int publen = bauth->level << 2;
	unsigned char header[16] = {0};

	/* Step 2 */
	if (BIGN_check_pubkey(bauth->disp, in, publen))
		goto err;

	/* Step 3 */
	if (BAKE_dh(bauth->bign, in, publen, K, &K_len) ||
		!(K = OPENSSL_zalloc(K_len)) ||
		BAKE_dh(bauth->bign, in, publen, K, &K_len))
		goto err;

	/* Step 4 */
	if (BELT_kwp_decrypt(in + publen, in_len - publen, header, K, bauth->Rb, NULL))
	{
		BIGNerr(BIGN_F_CREATE_TOKEN, ERR_R_BIGN_LIB);
		goto err;
	}

	/* Step 5 */
	if (bauth->auth)
	{
		unsigned char random[96] = {0}, temp[32] = {0};
		if (RAND_priv_bytes(random, 96) <= 0)
			goto err;

		brng_ctr_hbelt(1, random, random + 32, random + 64, temp);
		memcpy(bauth->R, temp, 16);
		memcpy(Ra, temp, 16);
	}

	/* Step 6 */
	if (BAKE_kdf(bauth->Rb, bauth->level, bauth->R, bauth->R_len, 0, bauth->K0))
		goto err;

	/* Step 7 */
	if (BAKE_kdf(bauth->Rb, bauth->level, bauth->R, bauth->R_len, 1, bauth->K1))
		goto err;

	/* Step 8 */
	if (bauth->auth)
		if (BAKE_kdf(bauth->Rb, bauth->level, bauth->R, bauth->R_len, 2, bauth->K2))
			goto err;

	/* Step 9 */
	unsigned char d[16] = {0};
	belt_mac(d, 16, bauth->K1, out);

	ret = 0;
err:

	OPENSSL_clear_free(K, K_len);
	return ret;
}

int BTOK_bauth_step4(BAUTH_CTX *bauth, const unsigned char *in, unsigned int in_len,
					 unsigned char *out, unsigned int *out_len)
{
	EVP_MD_CTX *mctx = NULL;
	int ret = 1;

	if (bauth->auth && in_len > 8)
		memcpy(bauth->R, in + 8, 16);

	/* Step 2 */
	if (BAKE_kdf(bauth->Rb, bauth->level, bauth->R, bauth->R_len, 0, bauth->K0))
		goto err;

	/* Step 3 */
	if (BAKE_kdf(bauth->Rb, bauth->level, bauth->R, bauth->R_len, 1, bauth->K1))
		goto err;

	/* Step 4 */
	unsigned char d[16] = {0}, T[8] = {0};
	belt_mac(d, 16, bauth->K1, T);

	if (CRYPTO_memcmp(in, T, 8))
		goto err;

	/* Step 5 */
	if (bauth->auth)
	{
		if (BAKE_kdf(bauth->Rb, bauth->level, bauth->R, bauth->R_len, 2, bauth->K2))
			goto err;

		/* Step 6 */
		unsigned char pubkey[64] = {0}, t[32];
		unsigned int publen = 0;
		if (BIGN_get_pubkey(bauth->disp, pubkey, &publen))
			goto err;

		if (!(mctx = EVP_MD_CTX_new()))
			goto err;

		const EVP_MD *evpMD = EVP_belt_hash();
		if (!EVP_DigestInit_ex(mctx, evpMD, NULL))
			goto err;
		if (!EVP_DigestUpdate(mctx, pubkey, bauth->level << 1) ||
			EVP_DigestUpdate(mctx, bauth->R, 16))
			goto err;
		if (!EVP_DigestFinal_ex(mctx, t, NULL))
			goto err;
	}

	ret = 0;

err:
	EVP_MD_CTX_free(mctx);

	return ret;
}

int BTOK_bauth_step5(BAUTH_CTX *bauth, const unsigned char *in, unsigned int in_len)
{
	return 0;
}

void BTOK_bauth_final(BAUTH_CTX *bauth, unsigned char out[32])
{
	OPENSSL_clear_free(bauth->R, bauth->R_len);
	OPENSSL_clear_free(bauth->Rb, bauth->level);

	BIGN_free(bauth->bign);
	BIGN_free(bauth->disp);

	if (out)
		memcpy(out, bauth->K0, 32);

	memset(bauth->K0, 0, 32);
	memset(bauth->K1, 0, 32);
	memset(bauth->K2, 0, 32);
}