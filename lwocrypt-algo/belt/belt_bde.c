/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <lwocrypt-alg/belt.h>
#include "belt_local.h"

typedef void (*block_f)(const unsigned char *, unsigned char *, const unsigned char *, unsigned char *);

static ossl_inline void belt_bde_e_block(const unsigned char *in, unsigned char *out, const unsigned char *key, unsigned char *iv)
{
	BELT_CHUNK128_XOR(out, in, iv);
	BELT_block_encrypt(out, out, key);
	BELT_CHUNK128_XOREQ(out, iv);
}

static ossl_inline void belt_bde_d_block(const unsigned char *in, unsigned char *out, const unsigned char *key, unsigned char *iv)
{
	BELT_CHUNK128_XOR(out, in, iv);
	BELT_block_decrypt(out, out, key);
	BELT_CHUNK128_XOREQ(out, iv);
}

void belt_bde_do_step(BELT_CTX *ctx, unsigned char *out, const unsigned char *in, size_t in_len, block_f blk)
{
	unsigned char tempC[16] = {0};
	tempC[0] = 0x02;

	if (ctx->buf_len)
	{
		memcpy(ctx->buf + ctx->buf_len, in, 16 - ctx->buf_len);
		in_len -= 16 - ctx->buf_len;
		in = (const unsigned char *)in + (16 - ctx->buf_len);

		belt_gmul((unsigned int *)ctx->iv, (unsigned int *)ctx->iv, (unsigned int *)tempC);
		blk(in, out, ctx->key, ctx->iv);

		ctx->buf_len = 0;
	}

	while (in_len >= 16)
	{
		belt_gmul((unsigned int *)ctx->iv, (unsigned int *)ctx->iv, (unsigned int *)tempC);
		blk(in, out, ctx->key, ctx->iv);

		in = (const unsigned char *)in + 16;
		in_len -= 16;
		out += 16;
	}

	if (in_len)
		memcpy(ctx->buf, in, ctx->buf_len = (int)in_len);
}

void BELT_bde_init(BELT_CTX *ctx, const unsigned char key[32], const unsigned char s[16])
{
	OPENSSL_cleanse(ctx, sizeof(*ctx));

	memcpy(ctx->key, key, 32);
	memcpy(ctx->iv, s, 16);

	BELT_block_encrypt(ctx->iv, ctx->iv, ctx->key);
}

void BELT_bde_encrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	belt_bde_do_step(ctx, out, in, in_len, belt_bde_e_block);
}

void BELT_bde_decrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	belt_bde_do_step(ctx, out, in, in_len, belt_bde_d_block);
}

void BELT_bde_encrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out)
{
	BELT_CTX state;

	BELT_bde_init(&state, key, s);
	BELT_bde_encrypt_update(&state, in, in_len, out);

	OPENSSL_cleanse(&state, sizeof(state));
}

void BELT_bde_decrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out)
{
	BELT_CTX state;

	BELT_bde_init(&state, key, s);
	BELT_bde_decrypt_update(&state, in, in_len, out);

	OPENSSL_cleanse(&state, sizeof(state));
}