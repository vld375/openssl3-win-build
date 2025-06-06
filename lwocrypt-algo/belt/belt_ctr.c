/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <lwocrypt-alg/belt.h>
#include "belt_local.h"

void BELT_ctr_init(BELT_CTX *ctx, const unsigned char key[32], const unsigned char s[16])
{
	OPENSSL_cleanse(ctx, sizeof(*ctx));

	ctx->quotas_current = (unsigned long long)0;

	memcpy(ctx->key, key, 32);
	memcpy(ctx->iv, s, 16);

	BELT_block_encrypt(ctx->iv, ctx->iv, ctx->key);
}

void belt_ctr_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	size_t n = ctx->buf_len;

	while (n && in_len)
	{
		*(out++) = *(in++) ^ ctx->buf[n];
		--in_len;
		n = (n + 1) % 16;
	}

	while (in_len >= 16)
	{
		belt_ctr128_inc(ctx->iv);
		BELT_block_encrypt(ctx->iv, ctx->buf, ctx->key);
		BELT_CHUNK128_XOR(out, in, ctx->buf);
		in_len -= 16;
		out += 16;
		in += 16;
	}

	if (in_len)
	{
		belt_ctr128_inc(ctx->iv);
		BELT_block_encrypt(ctx->iv, ctx->buf, ctx->key);
		while (in_len--)
		{
			out[n] = in[n] ^ ctx->buf[n];
			++n;
		}
	}
	ctx->buf_len = (int)n;
}

void BELT_ctr_encrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	ctx->quotas_current += (unsigned long long)in_len;
	belt_ctr_update(ctx, in, in_len, out);
}

void BELT_ctr_decrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	belt_ctr_update(ctx, in, in_len, out);
}

void BELT_ctr_encrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out)
{
	BELT_CTX state;

	BELT_ctr_init(&state, key, s);
	BELT_ctr_encrypt_update(&state, in, in_len, out);

	OPENSSL_cleanse(&state, sizeof(state));
}

void BELT_ctr_decrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out)
{
	BELT_CTX state;

	BELT_ctr_init(&state, key, s);
	BELT_ctr_decrypt_update(&state, in, in_len, out);

	OPENSSL_cleanse(&state, sizeof(state));
}