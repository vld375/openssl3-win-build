/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <lwocrypt-alg/belt.h>
#include "belt_local.h"

typedef void (*block_f)(const unsigned char *, unsigned char *, const unsigned char *, unsigned char *);

static ossl_inline void belt_cbc_e_block(const unsigned char *in, unsigned char *out, const unsigned char *key, unsigned char *iv)
{
	BELT_CHUNK128_XOR(out, in, iv);
	BELT_block_encrypt(out, out, key);
	memcpy(iv, out, 16);
}

static ossl_inline void belt_cbc_d_block(const unsigned char *in, unsigned char *out, const unsigned char *key, unsigned char *iv)
{
	BELT_block_decrypt(in, out, key);
	BELT_CHUNK128_XOR(out, out, iv);
	memcpy(iv, in, 16);
}

static int belt_cbc_do_step(BELT_CTX *ctx, unsigned char *out, const unsigned char *in, size_t in_len, block_f blk)
{
	int copy_len = 0;
	int rv = 0;

	if ((ctx->buf_len + in_len) < 32)
	{
		memcpy(ctx->buf + ctx->buf_len, in, in_len);
		ctx->buf_len += (int)in_len;
		goto out;
	}

	if (ctx->buf_len < 32)
	{
		copy_len = 32 - ctx->buf_len;
		memcpy(ctx->buf + ctx->buf_len, in, copy_len);
		ctx->buf_len += copy_len;
		in += copy_len;
		in_len -= copy_len;
	}

	while (ctx->buf_len == 32)
	{
		blk(ctx->buf, out, ctx->key, ctx->iv);
		ctx->buf_len -= 16;
		out += 16;
		rv += 16;
		memcpy(ctx->buf, ctx->buf + 16, 16);

		copy_len = in_len < 16 ? (int)in_len : 16;
		memcpy(ctx->buf + 16, in, copy_len);
		in += copy_len;
		in_len -= copy_len;
		ctx->buf_len += copy_len;
	}
	memset(ctx->buf + ctx->buf_len, 0, 32 - (int)ctx->buf_len);

out:
	return rv;
}

static int belt_cbc_e_final(BELT_CTX *ctx, unsigned char *out)
{
	int rv = -1;

	if (ctx->buf_len < 16)
		goto out;

	rv = ctx->buf_len;

	if (out)
	{
		if (rv == 16)
			belt_cbc_e_block(ctx->buf, out, ctx->key, ctx->iv);
		else
		{
			unsigned char tmp[32];
			BELT_CHUNK128_XOR(tmp + 16, ctx->buf, ctx->iv);
			BELT_block_encrypt(tmp + 16, tmp + 16, ctx->key);
			BELT_CHUNK128_XOR(tmp, tmp + 16, ctx->buf + 16);
			BELT_block_encrypt(tmp, tmp, ctx->key);
			memcpy(out, tmp, rv);
			memset(tmp, 0, sizeof(tmp));
		}
	}

out:
	return rv;
}

static int belt_cbc_d_final(BELT_CTX *ctx, unsigned char *out)
{
	int rv = -1;

	if (ctx->buf_len < 16)
		goto out;

	rv = ctx->buf_len;

	if (out)
	{
		if (rv == 16)
			belt_cbc_d_block(ctx->buf, out, ctx->key, ctx->iv);
		else
		{
			unsigned char tmp[32];
			memset(tmp, 0, sizeof(tmp));
			BELT_block_decrypt(ctx->buf, tmp + 16, ctx->key);
			BELT_CHUNK128_XOR(tmp + 16, tmp + 16, ctx->buf + 16);
			memcpy(ctx->buf + rv, tmp + rv, (size_t)32 - rv);
			BELT_block_decrypt(ctx->buf + 16, tmp, ctx->key);
			BELT_CHUNK128_XOR(tmp, tmp, ctx->iv);
			memcpy(out, tmp, rv);
			memset(tmp, 0, sizeof(tmp));
		}
	}

out:
	return rv;
}

void BELT_cbc_init(BELT_CTX *ctx, const unsigned char key[32], const unsigned char s[16])
{
	OPENSSL_cleanse(ctx, sizeof(*ctx));

	ctx->quotas_current = (unsigned long long)0;

	memcpy(ctx->key, key, 32);
	memcpy(ctx->iv, s, 16);
}

int BELT_cbc_encrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	ctx->quotas_current += (unsigned long long)in_len;
	return belt_cbc_do_step(ctx, out, in, in_len, belt_cbc_e_block);
}

int BELT_cbc_decrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	return belt_cbc_do_step(ctx, out, in, in_len, belt_cbc_d_block);
}

int BELT_cbc_encrypt_final(BELT_CTX *ctx, unsigned char *out)
{
	return belt_cbc_e_final(ctx, out);
}

int BELT_cbc_decrypt_final(BELT_CTX *ctx, unsigned char *out)
{
	return belt_cbc_d_final(ctx, out);
}

int BELT_cbc_encrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out)
{
	BELT_CTX ctx;
	int result = 0;

	BELT_cbc_init(&ctx, key, s);
	result = BELT_cbc_encrypt_update(&ctx, in, in_len, out);
	result = BELT_cbc_encrypt_final(&ctx, out + result);

	OPENSSL_cleanse(&ctx, sizeof(ctx));

	result = result ? 0 : 1;

	return result;
}

int BELT_cbc_decrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out)
{
	BELT_CTX ctx;
	int result = 0;

	BELT_cbc_init(&ctx, key, s);
	result = BELT_cbc_decrypt_update(&ctx, in, in_len, out);
	result = BELT_cbc_decrypt_final(&ctx, out + result);

	OPENSSL_cleanse(&ctx, sizeof(ctx));

	result = result ? 0 : 1;

	return result;
}