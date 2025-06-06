/*
 * Copyright 2020. All Rights Reserved.
 */

#include <stdlib.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include "internal/refcount.h"
#include <openssl/bign.h>

#ifdef __cplusplus
extern "C"
{
#endif

	int bake_swu(const BIGN *bign, const unsigned char x[], EC_POINT *W);

#ifdef __cplusplus
}
#endif