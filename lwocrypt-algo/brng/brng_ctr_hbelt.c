/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>

#include <lwocrypt-alg/belt.h>
#include <lwocrypt-alg/brng.h>
#include "brng_local.h"

static void brng_add_one_mod256(unsigned char dest[32])
{
	unsigned long long *s_words = (unsigned long long *)dest;

	s_words[0] += 1;
	if (s_words[0] == 0)
	{
		s_words[1] += 1;
		if (s_words[1] == 0)
		{
			s_words[2] += 1;
			if (s_words[2] == 0)
			{
				s_words[3] += 1;
			}
		}
	}
}

void BRNG_ctr_hbelt_Init(BRNGctr_hbelt_CTX *ctx, const unsigned char key[32], const unsigned char s[32])
{
	memcpy(ctx->theta, key, 32);

	/*Step 1*/
	memcpy(ctx->temp_s, s, 32);

	/*Step 2*/
	memset(ctx->temp_r, 0xFF, 32);

	BRNG_CHUNK256_XOREQ(ctx->temp_r, ctx->temp_s);
}

void BRNG_ctr_hbelt_Update(BRNGctr_hbelt_CTX *ctx, const unsigned char *buf, size_t buf_len, unsigned char *out)
{
	unsigned char temp128[128];
	size_t it = 0;

	for (it = 0; it < buf_len; it += 32)
	{
		/*Substep 1*/
		memcpy(temp128, ctx->theta, 32);
		memcpy(temp128 + 32, ctx->temp_s, 32);
		memcpy(temp128 + 64, buf + it, 32);
		memcpy(temp128 + 96, ctx->temp_r, 32);

		belt_hash(temp128, 128, out + it);

		/*Substep 2*/
		brng_add_one_mod256(ctx->temp_s);

		/*Substep 3*/
		BRNG_CHUNK256_XOREQ(ctx->temp_r, out + it);
	}
}

void brng_ctr_hbelt(
	unsigned int n,
	const unsigned char key[32], const unsigned char s[32],
	const unsigned char *bytes, unsigned char *out)
{
	size_t msg_len = 32 * n;

	BRNGctr_hbelt_CTX state;

	BRNG_ctr_hbelt_Init(&state, key, s);
	BRNG_ctr_hbelt_Update(&state, bytes, msg_len, out);

	OPENSSL_cleanse(&state, sizeof(state));
}

void brng_hmac_hbelt(
	int n,
	const unsigned char *theta, size_t theta_len,
	const unsigned char *s, size_t s_len,
	unsigned char *out)
{
	size_t it, temp_len;
	unsigned char temp_r[32];

	unsigned char *x = (unsigned char *)OPENSSL_malloc(32 + s_len);

	/*Step 1*/
	hmac_hbelt(s, s_len, theta, theta_len, temp_r);

	memcpy(x + 32, s, s_len);

	/*Step 2*/
	temp_len = n * 32;
	for (it = 0; it < temp_len; it += 32)
	{
		/*Substep 1*/
		memcpy(x, temp_r, 32);
		hmac_hbelt(x, 32 + s_len, theta, theta_len, out + it);

		/*Substep 2*/
		hmac_hbelt(temp_r, 32, theta, theta_len, temp_r);
	}

	OPENSSL_free(x);
}