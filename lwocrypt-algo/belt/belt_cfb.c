/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/modes.h>

#include <lwocrypt-alg/belt.h>
#include "belt_local.h"

void BELT_cfb_init(BELT_CTX *ctx, const unsigned char key[32], const unsigned char s[16])
{
	OPENSSL_cleanse(ctx, sizeof(*ctx));

	ctx->quotas_current = (unsigned long long)0;

	memcpy(ctx->key, key, 32);
	memcpy(ctx->iv, s, 16);
}

void BELT_cfb_encrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	int num = ctx->buf_len;
	ctx->quotas_current += (unsigned long long)in_len;
	CRYPTO_cfb128_encrypt(in, out, in_len, ctx->key, ctx->iv, &num, 1, (block128_f)BELT_block_encrypt);
	ctx->buf_len = num;
}

void BELT_cfb_decrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	int num = ctx->buf_len;
	CRYPTO_cfb128_encrypt(in, out, in_len, ctx->key, ctx->iv, &num, 0, (block128_f)BELT_block_encrypt);
	ctx->buf_len = num;
}

void BELT_cfb_encrypt(const unsigned char *bytes, size_t bytes_count, const unsigned char key[32], const unsigned char s[16], unsigned char *out)
{
	BELT_CTX state;

	BELT_cfb_init(&state, key, s);
	BELT_cfb_encrypt_update(&state, bytes, bytes_count, out);

	OPENSSL_cleanse(&state, sizeof(state));
}

void BELT_cfb_decrypt(const unsigned char *bytes, size_t bytes_count, const unsigned char key[32], const unsigned char s[16], unsigned char *out)
{
	BELT_CTX state;

	BELT_cfb_init(&state, key, s);
	BELT_cfb_decrypt_update(&state, bytes, bytes_count, out);

	OPENSSL_cleanse(&state, sizeof(state));
}