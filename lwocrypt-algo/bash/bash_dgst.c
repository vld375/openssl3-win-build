/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <lwocrypt-alg/bash.h>

/*64 bit macro*/
#define BASH_CHUNK64_COPY(dest, src) *((unsigned long long *)(dest)) = *((unsigned long long *)(src));

#define ROTLEFT64(word, amount) \
	(((word) << (amount)) | ((word) >> (64 - (amount))))

#define BASH_S(w0, w1, w2, m1, n1, m2, n2, t0, t1, t2) \
	t0 = ROTLEFT64(w0, m1);                            \
	w0 = w0 ^ w1 ^ w2;                                 \
	t1 = w1 ^ ROTLEFT64(w0, n1);                       \
	w1 = t0 ^ t1;                                      \
	w2 = w2 ^ ROTLEFT64(w2, m2) ^ ROTLEFT64(t1, n2);   \
	t0 = ~w2;                                          \
	t1 = w0 | w2;                                      \
	t2 = w0 & w1;                                      \
	t0 = t0 | w1;                                      \
	w0 = w0 ^ t0;                                      \
	w1 = w1 ^ t1;                                      \
	w2 = w2 ^ t2;

static void bash_f(unsigned char bytes[192])
{
	unsigned long long c;
	int it = 0;
	int j = 0;

	unsigned char temp[192] = {0};

	c = 0x3BF5080AC8BA94B1;

	for (it = 0; it < 24; it++)
	{
		int m1 = 8;
		int n1 = 53;
		int m2 = 14;
		int n2 = 1;

		unsigned long long *w0p;
		unsigned long long *w1p;
		unsigned long long *w2p;

		w0p = (unsigned long long *)(bytes);
		w1p = (unsigned long long *)(bytes + 64);
		w2p = (unsigned long long *)(bytes + 128);

		for (j = 0; j < 8; j++)
		{
			unsigned long long t0, t1, t2;

			BASH_S(*w0p, *w1p, *w2p, m1, n1, m2, n2, t0, t1, t2);

			w0p++;
			w1p++;
			w2p++;

			m1 = (7 * m1) & 63;
			n1 = (7 * n1) & 63;
			m2 = (7 * m2) & 63;
			n2 = (7 * n2) & 63;
		}

		BASH_CHUNK64_COPY(temp + 0, bytes + 120);
		BASH_CHUNK64_COPY(temp + 8, bytes + 80);
		BASH_CHUNK64_COPY(temp + 16, bytes + 72);
		BASH_CHUNK64_COPY(temp + 24, bytes + 96);
		BASH_CHUNK64_COPY(temp + 32, bytes + 88);
		BASH_CHUNK64_COPY(temp + 40, bytes + 112);
		BASH_CHUNK64_COPY(temp + 48, bytes + 104);
		BASH_CHUNK64_COPY(temp + 56, bytes + 64);
		BASH_CHUNK64_COPY(temp + 64, bytes + 136);
		BASH_CHUNK64_COPY(temp + 72, bytes + 128);
		BASH_CHUNK64_COPY(temp + 80, bytes + 152);
		BASH_CHUNK64_COPY(temp + 88, bytes + 144);
		BASH_CHUNK64_COPY(temp + 96, bytes + 168);
		BASH_CHUNK64_COPY(temp + 104, bytes + 160);
		BASH_CHUNK64_COPY(temp + 112, bytes + 184);
		BASH_CHUNK64_COPY(temp + 120, bytes + 176);
		BASH_CHUNK64_COPY(temp + 128, bytes + 48);
		BASH_CHUNK64_COPY(temp + 136, bytes + 24);
		BASH_CHUNK64_COPY(temp + 144, bytes);
		BASH_CHUNK64_COPY(temp + 152, bytes + 40);
		BASH_CHUNK64_COPY(temp + 160, bytes + 16);
		BASH_CHUNK64_COPY(temp + 168, bytes + 56);
		BASH_CHUNK64_COPY(temp + 176, bytes + 32);
		BASH_CHUNK64_COPY(temp + 184, bytes + 8);

		memcpy(bytes, temp, 192);

		*((unsigned long long *)(bytes + 184)) = *((unsigned long long *)(bytes + 184)) ^ c;

		if ((unsigned long long)(c & 1) == 0)
			c = c >> 1;
		else
			c = (c >> 1) ^ 0xDC2BE1997FE0D8AE;
	}
}

int BASH_Init(BASH_CTX *ctx, unsigned int l)
{
	OPENSSL_cleanse(ctx, sizeof(*ctx));

	ctx->md_size = l >> 2;
	ctx->block_size = (1536 - 4 * l) >> 3;

	*(unsigned long long *)(ctx->s + 184) = (unsigned long long)(ctx->md_size);

	return 1;
}

int BASH_Update(BASH_CTX *ctx, const void *_data, size_t in_len)
{
	int copy_len = 0;
	const unsigned char *data = (const unsigned char *)_data;

	if ((ctx->buf_len + in_len) < ctx->block_size)
	{
		memcpy(ctx->s + ctx->buf_len, data, in_len);
		ctx->buf_len += (int)in_len;
		return 1;
	}

	if (ctx->buf_len < ctx->block_size)
	{
		copy_len = ctx->block_size - ctx->buf_len;
		memcpy(ctx->s + ctx->buf_len, data, copy_len);
		ctx->buf_len += copy_len;
		data += copy_len;
		in_len -= copy_len;
	}

	while (ctx->buf_len == ctx->block_size)
	{
		bash_f(ctx->s);
		ctx->buf_len -= ctx->block_size;

		copy_len = in_len < ctx->block_size ? (int)in_len : ctx->block_size;
		memcpy(ctx->s, data, copy_len);
		data += copy_len;
		in_len -= copy_len;
		ctx->buf_len += copy_len;
	}

	return 1;
}

int BASH_Final(unsigned char *md, BASH_CTX *ctx)
{
	memset(ctx->s + ctx->buf_len, 0, ctx->block_size - ctx->buf_len);
	ctx->s[ctx->buf_len] = 0x40;
	bash_f(ctx->s);

	memcpy(md, ctx->s, ctx->md_size);

	return 1;
}