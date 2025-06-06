/*
 * Copyright 2020. All Rights Reserved.
 */

#include <stdio.h>
#include "internal/cryptlib.h"

#include <openssl/x509.h>
#include <openssl/bign.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/asn1t.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"

#include "bign_local.h"

static int bign_param2type(int *pptype, void **ppval, const BIGN *bign)
{
	int nid;
	if (bign == NULL)
	{
		BIGNerr(BIGN_F_PARAM2TYPE, BIGN_R_MISSING_PARAMETERS);
		return 0;
	}

	if (EC_GROUP_get_asn1_flag(bign->group) && (nid = EC_GROUP_get_curve_name(bign->group)))
	{
		ASN1_OBJECT *asn1obj = OBJ_nid2obj(nid);

		if (asn1obj == NULL || OBJ_length(asn1obj) == 0)
		{
			ASN1_OBJECT_free(asn1obj);
			BIGNerr(BIGN_F_PARAM2TYPE, BIGN_R_MISSING_OID);
			return 0;
		}
		*ppval = asn1obj;
		*pptype = V_ASN1_OBJECT;
	}

	return 1;
}

static int bign_pub_encode(X509_PUBKEY *pub, const EVP_PKEY *pkey)
{
	BIGN *bign = (BIGN *)EVP_PKEY_get0(pkey);
	void *pval = NULL;
	int ptype = V_ASN1_UNDEF;
	unsigned char *pubKey = NULL;
	int pubKeyLen = 0;

	if (!bign_param2type(&ptype, &pval, bign))
	{
		BIGNerr(BIGN_F_PUB_ENCODE, ERR_R_BIGN_LIB);
		return 0;
	}

	pubKeyLen = i2o_BIGNPublicKey(bign, &pubKey);
	if (pubKeyLen <= 0)
		goto err;

	if (X509_PUBKEY_set0_param(pub, OBJ_nid2obj(EVP_PKEY_base_id(pkey)),
							   ptype, pval, pubKey, pubKeyLen))
		return 1;

err:
	if (ptype == V_ASN1_OBJECT)
		ASN1_OBJECT_free(pval);
	else
		ASN1_STRING_free(pval);
	OPENSSL_free(pubKey);
	return 0;
}

BIGN *bign_type2param(int ptype, const void *pval)
{
	BIGN *bign = NULL;

	if (ptype == V_ASN1_OBJECT)
	{
		const ASN1_OBJECT *poid = pval;

		char obj_tmp[80];
		i2t_ASN1_OBJECT(obj_tmp, sizeof(obj_tmp), poid);

		if ((bign = BIGN_new(obj_tmp)) == NULL)
		{
			BIGNerr(BIGN_F_TYPE2PARAM, ERR_R_MALLOC_FAILURE);
			goto err;
		}

		EC_GROUP_set_asn1_flag(bign->group, OPENSSL_EC_NAMED_CURVE);
	}
	else
	{
		BIGNerr(BIGN_F_TYPE2PARAM, BIGN_R_DECODE_ERROR);
		goto err;
	}

	return bign;

err:
	BIGN_free(bign);
	return NULL;
}

static int bign_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *x509_pubkey)
{
	const unsigned char *pubKey = NULL;
	int pubKeyLen = 0;
	X509_ALGOR *palg = NULL;
	BIGN *bign = NULL;
	int ptype = V_ASN1_UNDEF;
	const void *pval = NULL;

	if (!X509_PUBKEY_get0_param(NULL, &pubKey, &pubKeyLen, &palg, x509_pubkey))
		return 0;
	X509_ALGOR_get0(NULL, &ptype, &pval, palg);

	bign = bign_type2param(ptype, pval);
	if (!bign)
	{
		BIGNerr(BIGN_F_PUB_DECODE, BIGN_R_DECODE_ERROR);
		return 0;
	}

	if (!o2i_BIGNPublicKey(&bign, &pubKey, pubKeyLen))
	{
		BIGNerr(BIGN_F_PUB_DECODE, ERR_R_BIGN_LIB);
		goto err;
	}

	EVP_PKEY_assign_BIGN(pkey, bign);
	return 1;

err:
	BIGN_free(bign);
	return 0;
}

static int bign_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
	int r;

	BIGN *bign_a = (BIGN *)EVP_PKEY_get0_BIGN(a);
	BIGN *bign_b = (BIGN *)EVP_PKEY_get0_BIGN(b);

	if (bign_a == NULL || bign_b == NULL ||
		bign_a->group == NULL ||
		bign_a->pub_key == NULL || bign_b->pub_key == NULL)
		return -2;
	r = EC_POINT_cmp(bign_a->group, bign_a->pub_key, bign_b->pub_key, NULL);
	if (r == 0)
		return 1;
	if (r == 1)
		return 0;
	return -2;
}

static int bign_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);
	void *pval = NULL;
	int ptype = V_ASN1_UNDEF;
	unsigned char *privKey = NULL;
	int privKeyLen = 0;

	if (!bign_param2type(&ptype, &pval, bign))
	{
		BIGNerr(BIGN_F_PRIV_ENCODE, BIGN_R_DECODE_ERROR);
		return 0;
	}

	privKeyLen = i2d_BIGNPrivateKey(bign, &privKey);
	if (privKeyLen <= 0)
	{
		BIGNerr(BIGN_F_PRIV_ENCODE, ERR_R_BIGN_LIB);
		return 0;
	}

	if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey->ameth->pkey_id), 0,
						 ptype, pval, privKey, privKeyLen))
	{
		OPENSSL_free(privKey);
		return 0;
	}

	return 1;
}

static int bign_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8inf)
{
	const unsigned char *privKey = NULL;
	const void *pval = NULL;
	int privKeyLen = 0, ptype = V_ASN1_UNDEF;
	const X509_ALGOR *palg = NULL;
	BIGN *bign = NULL;

	if (!PKCS8_pkey_get0(NULL, &privKey, &privKeyLen, &palg, p8inf))
		return 0;
	X509_ALGOR_get0(NULL, &ptype, (const void **)&pval, palg);

	bign = bign_type2param(ptype, pval);
	if (!bign)
	{
		BIGNerr(BIGN_F_PRIV_DECODE, BIGN_R_DECODE_ERROR);
		return 0;
	}

	if (!d2i_BIGNPrivatekey(&bign, &privKey, privKeyLen))
	{
		BIGNerr(BIGN_F_PRIV_DECODE, ERR_R_BIGN_LIB);
		return 0;
	}

	EVP_PKEY_assign_BIGN(pkey, bign);

	return 1;
}

static int bign_size(const EVP_PKEY *pkey)
{
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);
	int levelX2 = (EC_GROUP_order_bits(bign->group) + 7) / 8;

	int ret = levelX2 + (levelX2 >> 1);

	return ret;
}

static int bign_bits(const EVP_PKEY *pkey)
{
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);
	return EC_GROUP_order_bits(bign->group);
}

static int bign_security_bits(const EVP_PKEY *pkey)
{
	int bignbits = bign_bits(pkey);
	return bignbits / 2;
}

static int bign_param_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen)
{
	BIGN *bign;

	if ((bign = d2i_BIGNParameters(NULL, pder, derlen)) == NULL)
	{
		BIGNerr(BIGN_F_PARAM_DECODE, ERR_R_BIGN_LIB);
		return 0;
	}
	EVP_PKEY_assign_BIGN(pkey, bign);
	return 1;
}

static int bign_param_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
	return i2d_BIGNParameters((BIGN *)EVP_PKEY_get0_BIGN(pkey), pder);
}

static int bign_param_missing(const EVP_PKEY *pkey)
{
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);

	if (bign == NULL || bign->group == NULL)
		return 1;
	return 0;
}

static int bign_param_copy(EVP_PKEY *to, const EVP_PKEY *from)
{
	BIGN *efrom = (BIGN *)EVP_PKEY_get0_BIGN(from);

	EC_GROUP *group = EC_GROUP_dup(efrom->group);
	if (group == NULL)
		return 0;

	if (to->pkey.ptr == NULL)
	{
		to->pkey.ptr = BIGN_new(NULL);
		if (to->pkey.ptr == NULL)
			goto err;
	}

	BIGN *eto = (BIGN *)EVP_PKEY_get0_BIGN(to);

	EC_GROUP_free(eto->group);
	eto->group = EC_GROUP_dup(group);
	if (eto->group == NULL)
	{
		goto err;
	}

	EC_GROUP_free(group);
	return 1;
err:
	EC_GROUP_free(group);
	return 0;
}

static int bign_param_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
	BIGN *data_a = (BIGN *)EVP_PKEY_get0_BIGN(a);
	BIGN *data_b = (BIGN *)EVP_PKEY_get0_BIGN(b);

	if (data_a->group == NULL || data_b->group == NULL)
		return -2;

	if (EC_GROUP_cmp(data_a->group, data_b->group, NULL))
		return 0;
	else
		return 1;
}

typedef enum
{
	BIGN_PRINT_PRIVATE,
	BIGN_PRINT_PUBLIC,
	BIGN_PRINT_PARAM
} bign_print;

static int do_BIGN_print(BIO *out, const BIGN *bign, int indent, ASN1_PCTX *pctx, bign_print ktype)
{
	const char *bignstr;
	unsigned char *priv = NULL, *pub = NULL;
	unsigned int privlen = 0, publen = 0;
	int ret = 0;

	if (bign == NULL || (bign->group) == NULL)
	{
		BIGNerr(BIGN_F_DO_BIGN_PRINT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (ktype != BIGN_PRINT_PARAM)
	{
		if (BIGN_get_pubkey(bign, pub, &publen) ||
			!(pub = OPENSSL_zalloc(publen)) ||
			BIGN_get_pubkey(bign, pub, &publen))
			goto err;
	}

	if (ktype == BIGN_PRINT_PRIVATE)
	{
		if (BIGN_get_privkey(bign, priv, &privlen) ||
			!(priv = OPENSSL_zalloc(privlen)) ||
			BIGN_get_privkey(bign, priv, &privlen))
			goto err;
	}

	if (ktype == BIGN_PRINT_PRIVATE)
		bignstr = "Private-Key";
	else if (ktype == BIGN_PRINT_PUBLIC)
		bignstr = "Public-Key";
	else
		bignstr = "BIGN-Parameters";

	if (!BIO_indent(out, indent, 128))
		goto err;
	if (BIO_printf(out, "%s: (%d bit)\n", bignstr, EC_GROUP_order_bits(bign->group)) <= 0)
		goto err;

	if (privlen != 0)
	{
		if (ASN1_buf_print(out, priv, privlen, indent + 4) == 0)
			goto err;
	}

	if (publen != 0)
	{
		if (ASN1_buf_print(out, pub, publen, indent + 4) == 0)
			goto err;
	}

	if (!ECPKParameters_print(out, bign->group, indent))
		goto err;

	ret = 1;

err:
	if (!ret)
		BIGNerr(BIGN_F_DO_BIGN_PRINT, ERR_R_BIGN_LIB);
	OPENSSL_clear_free(priv, privlen);
	OPENSSL_clear_free(pub, publen);
	return ret;
}

static int bign_param_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)
{
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);
	return do_BIGN_print(out, bign, indent, pctx, BIGN_PRINT_PARAM);
}

static int bign_pub_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)
{
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);
	return do_BIGN_print(out, bign, indent, pctx, BIGN_PRINT_PUBLIC);
}

static int bign_priv_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)
{
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);
	return do_BIGN_print(out, bign, indent, pctx, BIGN_PRINT_PRIVATE);
}

static void bign_free(EVP_PKEY *pkey)
{
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);
	BIGN_free(bign);
}

static int bign_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);

	switch (op)
	{
	case ASN1_PKEY_CTRL_PKCS7_SIGN:
		if (arg1 == 0)
		{
			int snid, hnid;
			X509_ALGOR *alg1 = NULL, *alg2 = NULL;
			PKCS7_SIGNER_INFO_get0_algs(arg2, NULL, &alg1, &alg2);
			if (alg1 == NULL || alg1->algorithm == NULL)
				return -1;
			hnid = OBJ_obj2nid(alg1->algorithm);
			if (hnid == NID_undef)
				return -1;
			if (!OBJ_find_sigid_by_algs(&snid, hnid, EVP_PKEY_id(pkey)))
				return -1;
			X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0);
		}
		return 1;
#ifndef OPENSSL_NO_CMS
	case ASN1_PKEY_CTRL_CMS_SIGN:
		if (arg1 == 0)
		{
			int snid, hnid;
			X509_ALGOR *alg1 = NULL, *alg2 = NULL;
			CMS_SignerInfo_get0_algs(arg2, NULL, NULL, &alg1, &alg2);
			if (alg1 == NULL || alg1->algorithm == NULL)
				return -1;
			hnid = OBJ_obj2nid(alg1->algorithm);
			if (hnid == NID_undef)
				return -1;
			if (!OBJ_find_sigid_by_algs(&snid, hnid, EVP_PKEY_id(pkey)))
				return -1;
			X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0);
		}
		return 1;
#endif
	case ASN1_PKEY_CTRL_PKCS7_ENCRYPT:
		if (arg1 == 0)
		{
			X509_ALGOR *alg1 = NULL;
			void *pval = NULL;
			int ptype = V_ASN1_UNDEF;

			if (!bign_param2type(&ptype, &pval, bign))
				return -1;

			PKCS7_RECIP_INFO_get0_alg((PKCS7_RECIP_INFO *)arg2, &alg1);
			X509_ALGOR_set0(alg1, OBJ_nid2obj(EVP_PKEY_id(pkey)), ptype, pval);
		}
		return 1;
#ifndef OPENSSL_NO_CMS
	case ASN1_PKEY_CTRL_CMS_ENVELOPE:
		if (arg1 == 0)
		{
			X509_ALGOR *alg1;

			if (CMS_RecipientInfo_ktri_get0_algs((CMS_RecipientInfo *)arg2, NULL, NULL, &alg1) <= 0)
				return 0;

			X509_ALGOR_set0(alg1, OBJ_nid2obj(NID_bign_keytransport), V_ASN1_NULL, 0);
		}
		else if (arg1 == 1)
		{
			EVP_PKEY_CTX *pkctx;
			X509_ALGOR *cmsalg;

			pkctx = CMS_RecipientInfo_get0_pkey_ctx((CMS_RecipientInfo *)arg2);
			if (pkctx == NULL)
				return 0;
			if (!CMS_RecipientInfo_ktri_get0_algs((CMS_RecipientInfo *)arg2, NULL, NULL, &cmsalg))
				return -1;
		}
		return 1;
#endif
	case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
		*(int *)arg2 = NID_belt_hash;
		return 2;
	case ASN1_PKEY_CTRL_SET1_TLS_ENCPT:
		return BIGN_set_pubkey(bign, arg2, arg1) ? 0 : 1;
	case ASN1_PKEY_CTRL_GET1_TLS_ENCPT:
		return i2o_BIGNPublicKey(bign, arg2);
	}

	return -2;
}

const EVP_PKEY_ASN1_METHOD bign_asn1_meth = {
	EVP_PKEY_BIGN,
	EVP_PKEY_BIGN,
	ASN1_PKEY_SIGPARAM_NULL,

	"BIGN",
	"OpenSSL BIGN method",

	bign_pub_decode,
	bign_pub_encode,
	bign_pub_cmp,
	bign_pub_print,

	bign_priv_decode,
	bign_priv_encode,
	bign_priv_print,

	bign_size,
	bign_bits,
	bign_security_bits,

	bign_param_decode,
	bign_param_encode,
	bign_param_missing,
	bign_param_copy,
	bign_param_cmp,
	bign_param_print,

	0,

	bign_free,
	bign_ctrl,

	0, 0, 0, 0};