/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <lwocrypt-alg/belt.h>
#include "belt_local.h"

static void belt_dwp_do_step(BELT_CTX *ctx, const unsigned char *in)
{
	BELT_CHUNK128_XOREQ(ctx->temp_s, in);
	belt_gmul((unsigned int *)ctx->temp_s, (unsigned int *)ctx->temp_s, (unsigned int *)ctx->temp_r);
}

static void belt_dwp_step(BELT_CTX *ctx, const unsigned char *in)
{
	belt_dwp_do_step(ctx, in);
	ctx->len.u[1] += (unsigned long long)16 << 3;
}

void BELT_dwp_init(BELT_CTX *ctx, const unsigned char key[32], const unsigned char s[16])
{
	OPENSSL_cleanse(ctx, sizeof(*ctx));

	ctx->quotas_current = (unsigned long long)0;

	memcpy(ctx->key, key, 32);
	memcpy(ctx->iv, s, 16);

	/*Step 1*/
	BELT_block_encrypt(ctx->iv, ctx->iv, ctx->key);
}

void BELT_dwp_set_aad(BELT_CTX *ctx, const unsigned char *aad, size_t aad_len)
{
	/*Step 3*/
	BELT_block_encrypt(ctx->iv, ctx->temp_r, ctx->key);
	memcpy(ctx->temp_s, BELT_H, 16);

	ctx->len.u[0] = (unsigned long long)aad_len << 3;
	ctx->len.u[1] = (unsigned long long)0;

	while (aad_len >= 16)
	{
		belt_dwp_do_step(ctx, aad);
		aad += 16;
		aad_len -= 16;
	}
	if (aad_len)
	{
		unsigned char tmp[16];
		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp, aad, aad_len);
		belt_dwp_do_step(ctx, tmp);
		memset(tmp, 0, sizeof(tmp));
	}
}

void BELT_dwp_encrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	size_t n = ctx->buf_len;
	ctx->quotas_current += (unsigned long long)in_len;

	while (n && in_len)
	{
		*(out++) = (ctx->buf[n] ^= *(in++));
		--in_len;
		++n;
		if (n == 16)
		{
			belt_dwp_step(ctx, ctx->buf);
			n = 0;
		}
	}

	while (in_len >= 16)
	{
		belt_ctr128_inc(ctx->iv);
		BELT_block_encrypt(ctx->iv, ctx->buf, ctx->key);
		BELT_CHUNK128_XOR(out, in, ctx->buf);
		belt_dwp_step(ctx, out);
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
			out[n] = (ctx->buf[n] ^= in[n]);
			++n;
		}
	}
	ctx->buf_len = (int)n;
}

void BELT_dwp_decrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	size_t n = ctx->buf_len;
	unsigned char tmp;

	while (n && in_len)
	{
		tmp = *in;
		*(out++) = *(in++) ^ ctx->buf[n];
		ctx->buf[n] = tmp;
		--in_len;
		++n;
		if (n == 16)
		{
			belt_dwp_step(ctx, ctx->buf);
			n = 0;
		}
	}

	while (in_len >= 16)
	{
		belt_ctr128_inc(ctx->iv);
		BELT_block_encrypt(ctx->iv, ctx->buf, ctx->key);
		belt_dwp_step(ctx, in);
		BELT_CHUNK128_XOR(out, in, ctx->buf);
		in_len -= 16;
		out += 16;
		in += 16;
		n = 0;
	}

	if (in_len)
	{
		belt_ctr128_inc(ctx->iv);
		BELT_block_encrypt(ctx->iv, ctx->buf, ctx->key);
		while (in_len--)
		{
			tmp = in[n];
			out[n] = in[n] ^ ctx->buf[n];
			ctx->buf[n] = tmp;
			++n;
		}
	}
	ctx->buf_len = (int)n;
}

void BELT_dwp_get_tag(BELT_CTX *ctx, unsigned char *tag, size_t tag_len)
{
	unsigned char tmp[16];

	if (ctx->buf_len)
	{
		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp, ctx->buf, ctx->buf_len);
		belt_dwp_do_step(ctx, tmp);
		ctx->len.u[1] += (unsigned long long)ctx->buf_len << 3;
	}

	belt_dwp_do_step(ctx, ctx->len.c);
	BELT_block_encrypt(ctx->temp_s, tmp, ctx->key);

	tag_len = tag_len < 8 ? tag_len : 8;

	memcpy(tag, tmp, tag_len);
	memset(tmp, 0, sizeof(tmp));
}

void BELT_dwp_encrypt(
	const unsigned char *in, size_t in_len,
	const unsigned char *i, size_t i_len,
	const unsigned char key[32], const unsigned char s[16],
	unsigned char *out, unsigned char t[8])
{
	BELT_CTX state;

	BELT_dwp_init(&state, key, s);
	BELT_dwp_set_aad(&state, i, i_len);
	BELT_dwp_encrypt_update(&state, in, in_len, out);
	BELT_dwp_get_tag(&state, t, 8);

	OPENSSL_cleanse(&state, sizeof(state));
}

int BELT_dwp_decrypt(
	const unsigned char *in, size_t in_len,
	const unsigned char *i, size_t i_len,
	const unsigned char t[8],
	const unsigned char key[32], const unsigned char s[16],
	unsigned char *out)
{
	BELT_CTX state;
	unsigned char ttag[8];
	int result = 1;

	BELT_dwp_init(&state, key, s);
	BELT_dwp_set_aad(&state, i, i_len);
	BELT_dwp_decrypt_update(&state, in, in_len, out);
	BELT_dwp_get_tag(&state, ttag, 8);

	if (memcmp(t, ttag, 8) == 0)
		result = 0;

	OPENSSL_cleanse(&state, sizeof(state));

	return result;
}