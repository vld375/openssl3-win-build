/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <lwocrypt-alg/belt.h>
#include "belt_local.h"

void BELT_kwp_init(BELT_CTX *ctx, const unsigned char header[16], const unsigned char key[32])
{
	OPENSSL_cleanse(ctx, sizeof(*ctx));

	memcpy(ctx->iv, header, 16);
	memcpy(ctx->key, key, 32);
}

int BELT_kwp_encrypt_update(BELT_CTX *ctx, const unsigned char *x, size_t x_len, unsigned char *out, size_t *out_len)
{
	if (x_len < 16)
		return 1;

	if (out_len)
		*out_len = x_len + 16;

	if (out)
	{
		unsigned char *Y;
		Y = (unsigned char *)OPENSSL_malloc(x_len + 16);

		memcpy(Y, x, x_len);
		memcpy(Y + x_len, ctx->iv, 16);

		BELT_wblock_encrypt(Y, x_len + 16, out, ctx->key);

		OPENSSL_free(Y);
	}

	return 0;
}

int BELT_kwp_decrypt_update(BELT_CTX *ctx, const unsigned char *x, size_t x_len, unsigned char *out, size_t *out_len)
{
	if (((x_len << 3) & 0x7) || (x_len < 32))
		return 1;

	if (out_len)
		*out_len = x_len - 16;

	if (out)
	{
		unsigned char *Y;
		Y = (unsigned char *)OPENSSL_malloc(x_len);

		BELT_wblock_decrypt(x, x_len, Y, ctx->key);

		if (memcmp(Y + x_len - 16, ctx->iv, 16) != 0)
		{
			OPENSSL_free(Y);
			return 1;
		}

		memcpy(out, Y, x_len - 16);
		OPENSSL_free(Y);
	}

	return 0;
}

int BELT_kwp_encrypt(const unsigned char *x, size_t x_len, const unsigned char header[16], const unsigned char key[32], unsigned char *out, size_t *out_len)
{
	int result;

	BELT_CTX state;

	BELT_kwp_init(&state, header, key);
	result = BELT_kwp_encrypt_update(&state, x, x_len, out, out_len);

	OPENSSL_cleanse(&state, sizeof(state));

	return result;
}

int BELT_kwp_decrypt(const unsigned char *x, size_t x_len, const unsigned char header[16], const unsigned char key[32], unsigned char *out, size_t *out_len)
{
	int result;

	BELT_CTX state;

	BELT_kwp_init(&state, header, key);
	result = BELT_kwp_decrypt_update(&state, x, x_len, out, out_len);

	OPENSSL_cleanse(&state, sizeof(state));

	return result;
}