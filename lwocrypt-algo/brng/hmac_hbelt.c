/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>

#include <lwocrypt-alg/brng.h>
#include "brng_local.h"

void BRNG_hmac_Init(BRNGhmac_CTX *st, const void *theta, size_t theta_len)
{
	size_t it = 0;

	BELT_hash_Init(&st->hash_state);

	for (it = 0; it < 32; it++)
		*(st->ipad + it) = 0x36;

	for (it = 0; it < 32; it++)
		*(st->opad + it) = 0x5C;

	/*Step 1*/
	if (theta_len <= 32)
	{
		memcpy(st->k, theta, theta_len);

		for (it = theta_len; it < 32; it++)
			*(st->k + it) = 0;
	}
	else
		belt_hash(theta, theta_len, st->k);

	BRNG_CHUNK256_XOR(st->temp32, st->k, st->ipad);
	BELT_hash_Update(&st->hash_state, st->temp32, 32);
}

void BRNG_hmac_Update(BRNGhmac_CTX *st, const unsigned char *buf, size_t buf_len)
{
	BELT_hash_Update(&st->hash_state, buf, buf_len);
}

void BRNG_hmac_Final(BRNGhmac_CTX *st, unsigned char *out)
{
	BELT_hash_Final(st->temp32, &st->hash_state);

	unsigned char temp64[64];
	int temp_len = 32 + 32;

	/*Step 3*/
	BRNG_CHUNK256_XOR(temp64, st->k, st->opad);
	memcpy(temp64 + 32, st->temp32, 32);
	belt_hash(temp64, temp_len, st->temp32);

	/*Step 4*/
	memcpy(out, st->temp32, 32);
}

unsigned char *hmac_hbelt(
	const unsigned char *bytes, size_t bytes_count,
	const unsigned char *theta, size_t theta_len,
	unsigned char *md)
{
	BRNGhmac_CTX state;
	static unsigned char m[32];

	if (md == NULL)
		md = m;

	BRNG_hmac_Init(&state, theta, theta_len);
	BRNG_hmac_Update(&state, bytes, bytes_count);
	BRNG_hmac_Final(&state, md);

	OPENSSL_cleanse(&state, sizeof(state));

	return md;
}