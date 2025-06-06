/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <lwocrypt-alg/belt.h>
#include "belt_local.h"

static void belt_phi1(unsigned char src[16], unsigned char dest[16])
{
	unsigned int u[4];
	unsigned int temp;

	PACK_U32(src, &u[0]);
	PACK_U32(src + 4, &u[1]);
	PACK_U32(src + 8, &u[2]);
	PACK_U32(src + 12, &u[3]);

	temp = u[0] ^ u[1];

	UNPACK_U32(u[1], dest);
	UNPACK_U32(u[2], dest + 4);
	UNPACK_U32(u[3], dest + 8);
	UNPACK_U32(temp, dest + 12);
}

static void belt_phi2(unsigned char src[16], unsigned char dest[16])
{
	unsigned int u[4];
	unsigned int temp;

	PACK_U32(src, &u[0]);
	PACK_U32(src + 4, &u[1]);
	PACK_U32(src + 8, &u[2]);
	PACK_U32(src + 12, &u[3]);

	temp = u[0] ^ u[3];

	UNPACK_U32(temp, dest);
	UNPACK_U32(u[0], dest + 4);
	UNPACK_U32(u[1], dest + 8);
	UNPACK_U32(u[2], dest + 12);
}

static void belt_psi(unsigned char *bytes, size_t bytes_count, unsigned char dest[16])
{
	size_t zeros_to_write = 0;
	size_t it = 0;
	size_t it2 = 0;

	zeros_to_write = 15 - bytes_count;

	for (it = 0; it < bytes_count; it++)
		dest[it] = bytes[it];

	dest[it++] = 0x80;

	for (it2 = 0; it2 < zeros_to_write; it2++)
		dest[it + it2] = 0x00;
}

void BELT_mac_Init(BELTmac_CTX *ctx, const unsigned char key[32])
{
	OPENSSL_cleanse(ctx, sizeof(*ctx));

	memcpy(ctx->theta, key, 32);

	BELT_block_encrypt(ctx->s, ctx->r, ctx->theta);
}

int BELT_mac_Update(BELTmac_CTX *ctx, const unsigned char *in, size_t in_len)
{
	int copy_len = 0;

	if ((ctx->buf_len + in_len) <= 16)
	{
		memcpy(ctx->buf + ctx->buf_len, in, in_len);
		ctx->buf_len += (int)in_len;
		return 1;
	}

	if (ctx->buf_len < 16)
	{
		copy_len = 16 - ctx->buf_len;
		memcpy(ctx->buf + ctx->buf_len, in, copy_len);
		ctx->buf_len += copy_len;
		in += copy_len;
		in_len -= copy_len;
	}

	do
	{
		BELT_CHUNK128_XOR(ctx->s, ctx->buf, ctx->s);
		BELT_block_encrypt(ctx->s, ctx->s, ctx->theta);
		ctx->buf_len -= 16;

		copy_len = in_len < 16 ? (int)in_len : 16;
		memcpy(ctx->buf, in, copy_len);
		in += copy_len;
		in_len -= copy_len;
		ctx->buf_len += copy_len;
	} while (in_len > 0);

	return 1;
}

int BELT_mac_Final(BELTmac_CTX *ctx, unsigned char *out)
{
	unsigned char tmp[32];

	if (ctx->buf_len == 16)
	{
		belt_phi1(ctx->r, tmp);
		BELT_CHUNK128_XOREQ(tmp, ctx->buf);
		BELT_CHUNK128_XOREQ(tmp, ctx->s);
	}
	else
	{
		belt_phi2(ctx->r, tmp);
		belt_psi(ctx->buf, ctx->buf_len, tmp + 16);
		BELT_CHUNK128_XOREQ(tmp, tmp + 16);
		BELT_CHUNK128_XOREQ(tmp, ctx->s);
	}

	BELT_block_encrypt(tmp, tmp, ctx->theta);
	memcpy(out, tmp, 8);

	return 1;
}

unsigned char *belt_mac(const unsigned char *in, size_t in_len, const unsigned char key[32], unsigned char *md)
{
	BELTmac_CTX c;
	static unsigned char m[8];

	if (md == NULL)
		md = m;
	BELT_mac_Init(&c, key);
	BELT_mac_Update(&c, in, in_len);
	BELT_mac_Final(&c, md);
	OPENSSL_cleanse(&c, sizeof(c));
	return md;
}