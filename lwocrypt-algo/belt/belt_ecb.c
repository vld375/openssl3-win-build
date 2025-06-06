/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/modes.h>

#include <lwocrypt-alg/belt.h>
#include "belt_local.h"

static int belt_ecb_do_step(BELT_CTX *ctx, unsigned char *out, const unsigned char *in, size_t in_len, block128_f blk)
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
		blk(ctx->buf, out, ctx->key);
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
	memset(ctx->buf + ctx->buf_len, 0, 32 - ctx->buf_len);

out:
	return rv;
}

static int belt_ecb_do_final(BELT_CTX *ctx, unsigned char *out, block128_f blk)
{
	int rv = -1;

	if (ctx->buf_len < 16)
		goto out;

	rv = ctx->buf_len;

	if (out)
	{
		if (rv == 16)
		{
			blk(ctx->buf, out, ctx->key);
		}
		else
		{
			unsigned char tmp[32];
			memset(tmp, 0, sizeof(tmp));
			blk(ctx->buf, tmp + 16, ctx->key);
			memcpy(ctx->buf + rv, tmp + rv, (size_t)32 - rv);
			blk(ctx->buf + 16, tmp, ctx->key);
			memcpy(out, tmp, rv);
			memset(tmp, 0, sizeof(tmp));
		}
	}

out:
	return rv;
}

void BELT_ecb_init(BELT_CTX *ctx, const unsigned char key[32])
{
	OPENSSL_cleanse(ctx, sizeof(*ctx));

	memcpy(ctx->key, key, 32);
}

int BELT_ecb_encrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	return belt_ecb_do_step(ctx, out, in, in_len, (block128_f)BELT_block_encrypt);
}

int BELT_ecb_decrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	return belt_ecb_do_step(ctx, out, in, in_len, (block128_f)BELT_block_decrypt);
}

int BELT_ecb_encrypt_final(BELT_CTX *ctx, unsigned char *out)
{
	return belt_ecb_do_final(ctx, out, (block128_f)BELT_block_encrypt);
}

int BELT_ecb_decrypt_final(BELT_CTX *ctx, unsigned char *out)
{
	return belt_ecb_do_final(ctx, out, (block128_f)BELT_block_decrypt);
}

int BELT_ecb_encrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], unsigned char *out)
{
	BELT_CTX ctx;
	int result = 0;

	BELT_ecb_init(&ctx, key);
	result = BELT_ecb_encrypt_update(&ctx, in, in_len, out);
	result = BELT_ecb_encrypt_final(&ctx, out + result);

	OPENSSL_cleanse(&ctx, sizeof(ctx));

	result = result ? 0 : 1;

	return result;
}

int BELT_ecb_decrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], unsigned char *out)
{
	BELT_CTX ctx;
	int result = 0;

	OPENSSL_cleanse(&ctx, sizeof(ctx));

	BELT_ecb_init(&ctx, key);
	result = BELT_ecb_decrypt_update(&ctx, in, in_len, out);
	result = BELT_ecb_decrypt_final(&ctx, out + result);

	OPENSSL_cleanse(&ctx, sizeof(ctx));

	result = result ? 0 : 1;

	return result;
}