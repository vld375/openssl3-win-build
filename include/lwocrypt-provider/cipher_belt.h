
/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <lwocrypt-alg/belt.h>
#include <lwocrypt-provider/ciphercommon.h>

#include "crypto/aria.h"

typedef struct prov_belt_ctx_st {
    PROV_CIPHER_CTX base;      /* Must be first */
    union {
        OSSL_UNION_ALIGN;
        ARIA_KEY ks;
    } ks;
} PROV_BELT_CTX;


//#define ossl_prov_cipher_hw_belt_ofb ossl_prov_cipher_hw_belt_ofb128
//#define ossl_prov_cipher_hw_belt_cfb ossl_prov_cipher_hw_belt_cfb128
//const PROV_CIPHER_HW* ossl_prov_cipher_hw_belt_ecb(size_t keybits);
const PROV_CIPHER_HW* ossl_prov_cipher_hw_belt_cbc(size_t keybits);
//const PROV_CIPHER_HW* ossl_prov_cipher_hw_belt_ofb128(size_t keybits);
const PROV_CIPHER_HW* ossl_prov_cipher_hw_belt_cfb(size_t keybits);
//const PROV_CIPHER_HW* ossl_prov_cipher_hw_belt_cfb1(size_t keybits);
//const PROV_CIPHER_HW* ossl_prov_cipher_hw_belt_cfb8(size_t keybits);
const PROV_CIPHER_HW* ossl_prov_cipher_hw_belt_ctr(size_t keybits);
