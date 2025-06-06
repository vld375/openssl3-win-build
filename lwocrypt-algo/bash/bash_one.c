/*
 * Copyright 2023. All Rights Reserved.
 */
#include <openssl/crypto.h>
#include <lwocrypt-alg/bash.h>

unsigned char *BASH256(const unsigned char *in, size_t in_len, unsigned char *md)
{
	BASH_CTX c;
	static unsigned char m[32];

	if (md == NULL)
		md = m;
	BASH_Init(&c, 128);
	BASH_Update(&c, in, in_len);
	BASH_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));
	return md;
}

unsigned char *BASH384(const unsigned char *in, size_t in_len, unsigned char *md)
{
	BASH_CTX c;
	static unsigned char m[48];

	if (md == NULL)
		md = m;
	BASH_Init(&c, 192);
	BASH_Update(&c, in, in_len);
	BASH_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));
	return md;
}

unsigned char *BASH512(const unsigned char *in, size_t in_len, unsigned char *md)
{
	BASH_CTX c;
	static unsigned char m[64];

	if (md == NULL)
		md = m;
	BASH_Init(&c, 256);
	BASH_Update(&c, in, in_len);
	BASH_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));
	return md;
}
