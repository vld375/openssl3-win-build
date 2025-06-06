/*
 * Copyright 2023. All Rights Reserved.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

#include <lwocrypt-alg/bignerr.h>
#include <lwocrypt-alg/bign_local.h>

int i2d_BIGNParameters(BIGN *bign, unsigned char **out)
{
	if (bign == NULL)
	{
		BIGNerr(BIGN_F_I2D_BIGNPARAMETERS, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	return i2d_ECPKParameters(bign->group, out);
}

BIGN *d2i_BIGNParameters(BIGN **bign, const unsigned char **in, long len)
{
	BIGN *ret;

	if (in == NULL || *in == NULL)
	{
		BIGNerr(BIGN_F_D2I_BIGNPARAMETERS, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	if (bign == NULL || *bign == NULL)
	{
		if ((ret = BIGN_new(NULL)) == NULL)
		{
			BIGNerr(BIGN_F_D2I_BIGNPARAMETERS, ERR_R_MALLOC_FAILURE);
			return NULL;
		}
	}
	else
		ret = *bign;

	if (!d2i_ECPKParameters(&ret->group, in, len))
	{
		BIGNerr(BIGN_F_D2I_BIGNPARAMETERS, ERR_R_BIGN_LIB);
		if (bign == NULL || *bign != ret)
			BIGN_free(ret);
		return NULL;
	}

	if (bign)
		*bign = ret;

	return ret;
}

/*
*******************************************************************************
Кодирование и декодирование открытого ключа, вложенных в структуру bign_key

\remark Открытый ключ задается типом PublicKey ::= BIT STRING
*******************************************************************************
*/
int i2o_BIGNPublicKey(const BIGN *bign, unsigned char **out)
{
	unsigned int len = 0;
	int new_buffer = 0;

	if (bign == NULL)
	{
		//BIGNerr(BIGN_F_I2O_BIGNPUBLICKEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (BIGN_get_pubkey(bign, NULL, &len))
	{
		//BIGNerr(BIGN_F_I2O_BIGNPUBLICKEY, ERR_R_BIGN_LIB);
		return 0;
	}

	if (out == NULL || len == 0)
		/* out == NULL => just return the length of the octet string */
		return len;

	if (*out == NULL)
	{
		if ((*out = OPENSSL_malloc(len)) == NULL)
		{
			//BIGNerr(BIGN_F_I2O_BIGNPUBLICKEY, ERR_R_MALLOC_FAILURE);
			return 0;
		}
		new_buffer = 1;
	}

	if (BIGN_get_pubkey(bign, *out, &len))
	{
		//BIGNerr(BIGN_F_I2O_BIGNPUBLICKEY, ERR_R_BIGN_LIB);
		if (new_buffer)
		{
			OPENSSL_free(*out);
			*out = NULL;
		}
		return 0;
	}

	if (!new_buffer)
		*out += len;

	return len;
}

BIGN *o2i_BIGNPublicKey(BIGN **bign, const unsigned char **in, long len)
{
	BIGN *ret = NULL;

	if (bign == NULL || (*bign) == NULL || (*bign)->group == NULL)
	{
		/*
		 * sorry, but a EC_GROUP-structure is necessary to set the public key
		 */
		//BIGNerr(BIGN_F_O2I_BIGNPUBLICKEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	ret = *bign;
	if (BIGN_set_pubkey(ret, *in, len))
	{
		//BIGNerr(BIGN_F_O2I_BIGNPUBLICKEY, ERR_R_BIGN_LIB);
		return 0;
	}

	return ret;
}

/*
*******************************************************************************
Кодирование и декодирование личного ключа, вложенных в структуру bign_key

\remark Открытый ключ задается типом PrivateKey ::= BIT STRING
*******************************************************************************
*/
int i2d_BIGNPrivateKey(BIGN *bign, unsigned char **out)
{
	unsigned int len = 0;
	int new_buffer = 0;

	if (bign == NULL)
	{
		//BIGNerr(BIGN_F_I2D_BIGNPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (BIGN_get_privkey(bign, NULL, &len))
	{
		//BIGNerr(BIGN_F_I2D_BIGNPRIVATEKEY, ERR_R_BIGN_LIB);
		return 0;
	}

	if (out == NULL || len == 0)
		/* out == NULL => just return the length of the octet string */
		return len;

	if (*out == NULL)
	{
		if ((*out = OPENSSL_malloc(len)) == NULL)
		{
			//BIGNerr(BIGN_F_I2D_BIGNPRIVATEKEY, ERR_R_MALLOC_FAILURE);
			return 0;
		}
		new_buffer = 1;
	}

	if (BIGN_get_privkey(bign, *out, &len))
	{
		//BIGNerr(BIGN_F_I2D_BIGNPRIVATEKEY, ERR_R_BIGN_LIB);
		if (new_buffer)
		{
			OPENSSL_free(*out);
			*out = NULL;
		}
		return 0;
	}

	if (!new_buffer)
		*out += len;

	return len;
}

BIGN *d2i_BIGNPrivatekey(BIGN **bign, const unsigned char **in, long len)
{
	BIGN *ret = NULL;

	if (bign == NULL || (*bign) == NULL || (*bign)->group == NULL)
	{
		/*
		 * sorry, but a EC_GROUP-structure is necessary to set the public key
		 */
		//BIGNerr(BIGN_F_D2I_BIGNPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	ret = *bign;

	if (BIGN_set_privkey(ret, *in, len))
	{
		//BIGNerr(BIGN_F_D2I_BIGNPRIVATEKEY, ERR_R_BIGN_LIB);
		return 0;
	}

	return ret;
}