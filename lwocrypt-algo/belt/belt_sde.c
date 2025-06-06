/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <lwocrypt-alg/belt.h>
#include "belt_local.h"

void BELT_sde_init(BELT_CTX *ctx, const unsigned char key[32], const unsigned char s[16])
{
	OPENSSL_cleanse(ctx, sizeof(*ctx));

	memcpy(ctx->key, key, 32);
	memcpy(ctx->iv, s, 16);

	BELT_block_encrypt(ctx->iv, ctx->iv, ctx->key);
}

void BELT_sde_encrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	memcpy(out, in, in_len);
	BELT_CHUNK128_XOREQ(out, ctx->iv);
	BELT_wblock_encrypt(out, in_len, out, ctx->key);
	BELT_CHUNK128_XOREQ(out, ctx->iv);
}

void BELT_sde_decrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out)
{
	memcpy(out, in, in_len);
	BELT_CHUNK128_XOREQ(out, ctx->iv);
	BELT_wblock_decrypt(out, in_len, out, ctx->key);
	BELT_CHUNK128_XOREQ(out, ctx->iv);
}

void BELT_sde_encrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out)
{
	BELT_CTX state;

	BELT_sde_init(&state, key, s);
	BELT_sde_encrypt_update(&state, in, in_len, out);

	OPENSSL_cleanse(&state, sizeof(state));
}

void BELT_sde_decrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out)
{
	BELT_CTX state;

	BELT_sde_init(&state, key, s);
	BELT_sde_decrypt_update(&state, in, in_len, out);

	OPENSSL_cleanse(&state, sizeof(state));
}