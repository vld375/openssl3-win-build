/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/objects.h>

#include <lwocrypt-alg/belt.h>
#include <lwocrypt-alg/brng.h>
//===================================================================================== 

int BIGN_oid2der(const char *oid, unsigned char *out, unsigned int *out_len)
{
	ASN1_OBJECT *obj = NULL;
	int len;
	int rv = 1;

	obj = OBJ_txt2obj(oid, 1);

	if (!obj || (len = i2d_ASN1_OBJECT(obj, NULL)) < 0)
		goto err;

	if (out)
		i2d_ASN1_OBJECT(obj, &out);

	if (out_len)
		*out_len = len;

	rv = 0;

err:
	if (obj)
		ASN1_OBJECT_free(obj);

	return rv;
}

void BIGN_build_key_on_password(
	const unsigned char *pass, size_t pass_len,
	unsigned int c,
	const unsigned char *iv, size_t iv_len,
	unsigned char theta[32])
{
	unsigned char *s_one;
	size_t s_one_size;
	unsigned int i;

	s_one_size = iv_len + 4;
	s_one = (unsigned char *)OPENSSL_zalloc(s_one_size);

	memcpy(s_one, iv, iv_len);
	s_one[s_one_size - 1] = 1;

	hmac_hbelt(s_one, s_one_size, pass, pass_len, theta);
	free(s_one);

	for (i = 0; i < c; i++)
		hmac_hbelt(theta, 32, pass, pass_len, theta);
}

int BIGN_password_protect(
	const unsigned char *pass, size_t pass_len,
	const unsigned char *iv, size_t iv_len,
	const unsigned char *key, size_t key_len,
	const unsigned char header[16],
	unsigned int c,
	unsigned char *out, size_t *out_len)
{
	unsigned char password_key[32];
	BIGN_build_key_on_password(pass, pass_len, c, iv, iv_len, password_key);

	unsigned char our_header[16];
	memset(our_header, 0, 16);

	if (header)
		memcpy(our_header, header, 16);

	return BELT_kwp_encrypt(key, key_len, our_header, password_key, out, out_len);
}


int BIGN_password_unprotect(
	const unsigned char *pass, size_t pass_len,
	const unsigned char *iv, size_t iv_len,
	const unsigned char *protected_key, size_t protected_key_len,
	const unsigned char header[16],
	unsigned int c,
	unsigned char *out, size_t *out_len)
{
	unsigned char password_key[32];
	BIGN_build_key_on_password(pass, pass_len, c, iv, iv_len, password_key);

	unsigned char our_header[16];
	memset(our_header, 0, 16);

	if (header)
		memcpy(our_header, header, 16);

	return BELT_kwp_decrypt(protected_key, protected_key_len, our_header, password_key, out, out_len);
}
