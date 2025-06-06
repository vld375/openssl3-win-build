/*
 * Copyright 2021. All Rights Reserved.
 */

#include "internal/cryptlib.h"
#include <stdio.h>
#include <openssl/err.h>

#include <openssl/obj_mac.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"

#include <openssl/bels.h>
#include "bels_local.h"

int bels_secret_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
	unsigned char *s;
	int ptype = V_ASN1_UNDEF;
	void *pval = NULL;

	BELS_KEY *bkey = (BELS_KEY *)EVP_PKEY_get0(pkey);

	ASN1_OBJECT *asn1obj = OBJ_nid2obj(bkey->nid);

	if (asn1obj == NULL || OBJ_length(asn1obj) == 0)
	{
		ASN1_OBJECT_free(asn1obj);
		return 0;
	}
	pval = asn1obj;
	ptype = V_ASN1_OBJECT;

	if ((s = (unsigned char *)malloc(bkey->len + 1)) == NULL)
		return 0;

	s[0] = bkey->num;
	memcpy(&s[1], bkey->secret, bkey->len);

	if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey->ameth->pkey_id), 0, ptype, pval, s, bkey->len + 1))
		return 0;

	return 1;
}

static int bels_secret_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8inf)
{
	const unsigned char *secret = NULL;
	const void *pval = NULL;
	int secretLen = 0, ptype = V_ASN1_UNDEF;
	const X509_ALGOR *palg = NULL;

	BELS_KEY *bkey = (BELS_KEY *)malloc(sizeof(BELS_KEY));

	if (!PKCS8_pkey_get0(NULL, &secret, &secretLen, &palg, p8inf))
		return 0;
	X509_ALGOR_get0(NULL, &ptype, (const void **)&pval, palg);

	if (ptype == V_ASN1_OBJECT)
	{
		const ASN1_OBJECT *poid = pval;

		char obj_tmp[80];
		i2t_ASN1_OBJECT(obj_tmp, sizeof(obj_tmp), poid);
		bkey->nid = OBJ_ln2nid(obj_tmp);
	}

	switch (bkey->nid)
	{
	case NID_bels_m0128v1:
		bkey->m0 = &m_128[0];
		break;
	case NID_bels_m0192v1:
		bkey->m0 = &m_192[0];
		break;
	case NID_bels_m0256v1:
		bkey->m0 = &m_256[0];
		break;
	default:
		return 0;
	}

	bkey->len = secretLen - 1;
	bkey->num = secret[0];

	memcpy(bkey->secret, secret + 1, bkey->len);
	memcpy(bkey->m, bkey->m0 + (bkey->len * bkey->num), bkey->len);

	EVP_PKEY_assign(pkey, EVP_PKEY_BELS, bkey);

	return 1;
}

static int bels_secret_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)
{
	int ret = 0;

	BELS_KEY *bkey = (BELS_KEY *)EVP_PKEY_get0(pkey);

	const char *bels_str = "Secret";

	if (!BIO_indent(out, indent, 128))
		goto err;

	if (BIO_printf(out, "%s: (%d bit)\n", bels_str, bkey->len * 8) <= 0)
		goto err;

	if (bkey->secret != NULL)
	{
		if (ASN1_buf_print(out, bkey->secret, bkey->len, indent + 4) == 0)
			goto err;
	}

	bels_str = "BELS-Parameters";
	if (BIO_printf(out, "%s: (%d bit)\n", bels_str, bkey->len * 8) <= 0)
		goto err;

	if (BIO_printf(out, "M0 name: %s\n", OBJ_nid2ln(bkey->nid)) <= 0)
		goto err;

	if (bkey->m != NULL)
	{
		if (BIO_printf(out, "M: (%d bit)\n", bkey->len * 8) <= 0)
			goto err;
		if (ASN1_buf_print(out, bkey->m, bkey->len, indent + 4) == 0)
			goto err;
	}

	ret = 1;
err:
	return ret;
}

static int bels_size(const EVP_PKEY *pkey)
{
	BELS_KEY *bkey = (BELS_KEY *)EVP_PKEY_get0(pkey);
	return bkey->len;
}

static int bels_bits(const EVP_PKEY *pkey)
{
	BELS_KEY *bkey = (BELS_KEY *)EVP_PKEY_get0(pkey);
	return bkey->len * 8;
}

static void bels_free(EVP_PKEY *pkey)
{
	BELS_KEY *bels = (BELS_KEY *)EVP_PKEY_get0(pkey);
	OPENSSL_free(bels);
}

const EVP_PKEY_ASN1_METHOD bels_asn1_meth = {
	EVP_PKEY_BELS,
	EVP_PKEY_BELS,
	ASN1_PKEY_SIGPARAM_NULL,

	"BELS",
	"OpenSSL BELS method",

	0,
	0,
	0,
	0,

	bels_secret_decode,
	bels_secret_encode,
	bels_secret_print,

	bels_size,
	bels_bits,
	0, //bels_security_bits,

	0, //bels_param_decode,
	0, //bels_param_encode,
	0, //bels_param_missing,
	0, //bels_param_copy,
	0, //bels_param_cmp,
	0, //bels_param_print,

	0,

	bels_free,
	0,

	0, 0, 0, 0};