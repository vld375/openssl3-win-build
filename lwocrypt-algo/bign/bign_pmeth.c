/*
 * Copyright 2020. All Rights Reserved.
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "crypto/ctype.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto/evp.h"

#include <openssl/brng.h>
#include "bign_local.h"

/* BIGN pkey context structure */
typedef struct bign_pmeth_st
{
	/* Key and paramgen group */
	EC_GROUP *group;

	const EVP_MD *md;

	unsigned char header[16];
} BIGN_PKEY_CTX;

/******************** Инициализация, копирование и очистка для всех алгоритмов ********************/
static int pkey_bign_init(EVP_PKEY_CTX *ctx)
{
	BIGN_PKEY_CTX *dctx;

	if ((dctx = OPENSSL_zalloc(sizeof(*dctx))) == NULL)
	{
		ERR_raise(ERR_LIB_BIGN, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	dctx->md = NULL;

	memset((void *)dctx->header, 0x00, 16);

	EVP_PKEY_CTX_set_data(ctx, dctx);

	return 1;
}

static int pkey_bign_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
{
	BIGN_PKEY_CTX *dctx, *sctx;

	if (!pkey_bign_init(dst))
		return 0;

	sctx = EVP_PKEY_CTX_get_data(src);
	dctx = EVP_PKEY_CTX_get_data(dst);

	if (sctx->group)
	{
		dctx->group = EC_GROUP_dup(sctx->group);
		if (!dctx->group)
			return 0;
	}

	dctx->md = sctx->md;

	memcpy(dctx->header, sctx->header, sizeof(dctx->header));

	return 1;
}

static void pkey_bign_cleanup(EVP_PKEY_CTX *ctx)
{
	BIGN_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	if (dctx != NULL)
	{
		EC_GROUP_free(dctx->group);
		OPENSSL_cleanse(dctx, sizeof(*dctx));
		OPENSSL_free(dctx);
		ctx->data = NULL;
	}
}

static int pkey_bign_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	BIGN *bign = NULL;
	BIGN_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	int ret;

	if (dctx->group == NULL)
	{
		ERR_raise(ERR_LIB_BIGN, BIGN_R_NO_PARAMETERS_SET);
		return 0;
	}

	bign = BIGN_new(NULL);
	if (bign == NULL)
		return 0;

	EC_GROUP_free(bign->group);
	bign->group = EC_GROUP_dup(dctx->group);
	if (bign->group == NULL)
	{
		ERR_raise(ERR_LIB_BIGN, ERR_R_MALLOC_FAILURE);
		BIGN_free(bign);
		return 0;
	}

	if (!ossl_assert(ret = EVP_PKEY_assign_BIGN(pkey, bign)))
		BIGN_free(bign);
	return ret;
}

static int pkey_bign_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	BIGN *bign = NULL;
	BIGN_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	int ret;

	if (ctx->pkey == NULL && dctx->group == NULL)
	{
		EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_BIGN,
						  EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
						  EVP_PKEY_CTRL_BIGN_PARAMGEN_CURVE_NID, NID_bign_curve256v1, NULL);
	}

	bign = BIGN_new(NULL);
	if (bign == NULL)
		return 0;

	if (!ossl_assert(ret = EVP_PKEY_assign_BIGN(pkey, bign)))
	{
		BIGN_free(bign);
		return 0;
	}

	if (ctx->pkey != NULL)
		ret = EVP_PKEY_copy_parameters(pkey, ctx->pkey);
	else
	{
		bign->group = EC_GROUP_dup(dctx->group);
		if (bign->group == NULL)
		{
			ERR_raise(ERR_LIB_BIGN, ERR_R_MALLOC_FAILURE);
			BIGN_free(bign);
			return 0;
		}
		ret = 1;
	}

	ret = ret ? BIGN_generate_key(bign) : 1;

	return ret ? 0 : 1;
}

static int pkey_bign_sign(EVP_PKEY_CTX *ctx,
						  unsigned char *sig, size_t *siglen,
						  const unsigned char *tbs, size_t tbslen)
{
	BIGN_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);

	ASN1_OBJECT *obj = NULL;
	unsigned char *oid = NULL, *t = NULL, *ptr = NULL;
	int type, rv = 0, oidlen = 0;
	unsigned int sltmp;

	if (tbslen != (size_t)EVP_MD_size(dctx->md))
	{
		ERR_raise(ERR_LIB_BIGN, BIGN_R_INVALID_DIGEST_LENGTH);
		return -1;
	}

	type = dctx->md ? EVP_MD_type(dctx->md) : NID_belt_hash;
	obj = OBJ_nid2obj(type);
	if (!obj || (oidlen = i2d_ASN1_OBJECT(obj, NULL)) < 0 || !(ptr = oid = OPENSSL_malloc(oidlen)))
		goto err;
	i2d_ASN1_OBJECT(obj, &ptr);

	t = (unsigned char *)OPENSSL_malloc(tbslen);
	if (t == NULL || RAND_bytes(t, tbslen) <= 0)
		goto err;

	if (BIGN_sign(bign, tbs, tbslen, oid, oidlen, t, tbslen, sig, &sltmp))
		goto err;

	*siglen = sltmp;

	rv = 1;

err:
	if (t)
	{
		OPENSSL_cleanse(t, tbslen);
		OPENSSL_free(t);
	}
	if (oid)
	{
		OPENSSL_cleanse(oid, oidlen);
		OPENSSL_free(oid);
	}
	if (obj)
		ASN1_OBJECT_free(obj);
	return rv;
}

static int pkey_bign_verify(EVP_PKEY_CTX *ctx,
							const unsigned char *sig, size_t siglen,
							const unsigned char *tbs, size_t tbslen)
{
	BIGN_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);
	ASN1_OBJECT *obj = NULL;
	unsigned char *oid = NULL, *ptr;
	int type, rv = 0, oidlen = 0;

	if (!bign)
		goto err;

	type = dctx->md ? EVP_MD_type(dctx->md) : NID_belt_hash;
	obj = OBJ_nid2obj(type);
	if (!obj || (oidlen = i2d_ASN1_OBJECT(obj, NULL)) < 0 || !(ptr = oid = OPENSSL_malloc(oidlen)))
		goto err;
	i2d_ASN1_OBJECT(obj, &ptr);

	if (BIGN_verify(bign, sig, siglen, tbs, tbslen, oid, oidlen))
		goto err;

	rv = 1;
err:
	if (oid)
	{
		OPENSSL_cleanse(oid, oidlen);
		OPENSSL_free(oid);
	}
	if (obj)
		ASN1_OBJECT_free(obj);

	return rv;
}

static int pkey_bign_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
	BIGN_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);

	int levelX2 = (EC_GROUP_order_bits(bign->group) + 7) / 8;
	*outlen = inlen + ((size_t)levelX2 + 16);
	if (!out)
		return 1;

	if (BIGN_create_token(bign, in, inlen, dctx->header, out, outlen))
		return 0;

	return 1;
}

static int pkey_bign_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
	BIGN_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	BIGN *bign = (BIGN *)EVP_PKEY_get0_BIGN(pkey);

	int levelX2 = (EC_GROUP_order_bits(bign->group) + 7) / 8;
	*outlen = inlen - ((size_t)levelX2 + 16);
	if (!out)
		return 1;

	if (BIGN_decode_token(bign, in, inlen, dctx->header, out, outlen))
		return 0;

	return 1;
}

static int pkey_bign_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
	const BIGN *pkey, *peerkey;

	if (!ctx->pkey || !ctx->peerkey)
	{
		ERR_raise(ERR_LIB_BIGN, BIGN_R_KEYS_NOT_SET);
		return 0;
	}

	pkey = (BIGN *)EVP_PKEY_get0_BIGN(ctx->pkey);
	peerkey = (BIGN *)EVP_PKEY_get0_BIGN(ctx->peerkey);

	if (pkey == NULL || pkey->priv_key == NULL)
	{
		ERR_raise(ERR_LIB_BIGN, BIGN_R_INVALID_PRIVATE_KEY);
		return 0;
	}
	if (peerkey == NULL || peerkey->pub_key == NULL)
	{
		ERR_raise(ERR_LIB_BIGN, BIGN_R_INVALID_PEER_KEY);
		return 0;
	}

	if (!key)
	{
		int levelX2 = (EC_GROUP_order_bits(pkey->group) + 7) / 8;
		*keylen = (size_t)levelX2 << 1;
		return 1;
	}

	if (bign_compute_key(pkey, peerkey->pub_key, key, keylen))
		return 0;

	return 1;
}

static int pkey_bign_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	BIGN_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	EC_GROUP *group;
	switch (type)
	{
	case EVP_PKEY_CTRL_BIGN_PARAMGEN_CURVE_NID:
		group = EC_GROUP_new_by_curve_name(p1);
		if (group == NULL)
		{
			ERR_raise(ERR_LIB_BIGN, BIGN_R_INVALID_CURVE);
			return 0;
		}
		EC_GROUP_free(dctx->group);
		dctx->group = group;
		return 1;
	case EVP_PKEY_CTRL_MD:
		dctx->md = (EVP_MD *)p2;
		return 1;

	case EVP_PKEY_CTRL_GET_MD:
		*(const EVP_MD **)p2 = dctx->md;
		return 1;

	case EVP_PKEY_CTRL_SET_IV:
	case EVP_PKEY_CTRL_PEER_KEY:
	case EVP_PKEY_CTRL_DIGESTINIT:
	case EVP_PKEY_CTRL_PKCS7_SIGN:
	case EVP_PKEY_CTRL_CMS_SIGN:
		return 1;

	case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
	case EVP_PKEY_CTRL_PKCS7_DECRYPT:
#ifndef OPENSSL_NO_CMS
	case EVP_PKEY_CTRL_CMS_ENCRYPT:
	case EVP_PKEY_CTRL_CMS_DECRYPT:
#endif
		memset(dctx->header, 0, sizeof(dctx->header));
		return 1;

	default:
		return -2;
	}
}

static int pkey_bign_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
	if (!value)
		return 0;

	if (strcmp(type, "paramgen_curve") == 0)
	{
		int nid = OBJ_sn2nid(value);
		if (nid == NID_undef)
			nid = OBJ_ln2nid(value);
		if (nid == NID_undef)
		{
			ERR_raise(ERR_LIB_BIGN, BIGN_R_INVALID_CURVE);
			return 0;
		}
		return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_BIGN,
								 EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
								 EVP_PKEY_CTRL_BIGN_PARAMGEN_CURVE_NID, nid, NULL);
	}

	return -2;
}

static const EVP_PKEY_METHOD bign_pkey_meth = {
	EVP_PKEY_BIGN,
	EVP_PKEY_FLAG_AUTOARGLEN,

	pkey_bign_init,
	pkey_bign_copy,
	pkey_bign_cleanup,

	0,
	pkey_bign_paramgen,

	0,
	pkey_bign_keygen,

	0,
	pkey_bign_sign,

	0,
	pkey_bign_verify,

	0, 0, 0, 0, 0, 0,

	0,
	pkey_bign_encrypt,

	0,
	pkey_bign_decrypt,

	0,
	pkey_bign_derive,

	pkey_bign_ctrl,
	pkey_bign_ctrl_str
};

const EVP_PKEY_METHOD *ossl_bign_pkey_method(void)
{
    return &bign_pkey_meth;
}
