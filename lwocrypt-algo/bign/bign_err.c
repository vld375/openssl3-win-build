/*
 * Copyright 2020. All Rights Reserved.
 */

#include <openssl/err.h>
#include <lwocrypt-alg/bignerr.h>

static const ERR_STRING_DATA BIGN_str_reasons[] = {
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_I2D_BIGNPARAMETERS, 0), "i2d_BIGNParameters"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_D2I_BIGNPARAMETERS, 0), "d2i_BIGNParameters"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_I2O_BIGNPUBLICKEY, 0), "i2o_BIGNPublicKey"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_O2I_BIGNPUBLICKEY, 0), "o2i_BIGNPublicKey"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_I2D_BIGNPRIVATEKEY, 0), "i2d_BIGNPrivateKey"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_D2I_BIGNPRIVATEKEY, 0), "d2i_BIGNPrivatekey"},

    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PARAM2TYPE, 0), "bign_param2type"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PUB_ENCODE, 0), "bign_pub_encode"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_TYPE2PARAM, 0), "bign_type2param"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PUB_DECODE, 0), "bign_pub_decode"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PRIV_ENCODE, 0), "bign_priv_encode"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PRIV_DECODE, 0), "bign_priv_decode"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PARAM_DECODE, 0), "bign_param_decode"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_DO_BIGN_PRINT, 0), "do_BIGN_print"},

    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PKEY_BIGN_INIT, 0), "pkey_bign_init"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PKEY_BIGN_PARAMGEN, 0), "pkey_bign_paramgen"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PKEY_BIGN_KEYGEN, 0), "pkey_bign_keygen"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PKEY_BIGN_SIGN, 0), "pkey_bign_sign"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PKEY_BIGN_DERIVE, 0), "peky_bign_derive"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PKEY_BIGN_CTRL, 0), "pkey_bign_ctrl"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_PKEY_BIGN_CTRL_STR, 0), "pkey_bign_ctrl_str"},

    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_BIGN_NEW, 0), "BIGN_new"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_BIGN_GENERATE_KEY, 0), "BIGN_generate_key"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_BIGN_GET_PRIVKEY, 0), "BIGN_get_privkey"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_BIGN_GET_PUBKEY, 0), "BIGN_get_pubkey"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_BIGN_SET_PRIVKEY, 0), "BIGN_set_privkey"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_BIGN_CHECK_PUBKEY, 0), "BIGN_check_pubkey"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_BIGN_SET_PUBKEY, 0), "BIGN_set_pubkey"},

    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_BIGN_GENK, 0), "BIGN_genk"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_BIGN_SIGN, 0), "BIGN_sign"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_BIGN_VERIFY, 0), "BIGN_verify"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_CREATE_TOKEN, 0), "BIGN_create_token"},
    {ERR_PACK(ERR_LIB_BIGN, BIGN_F_DECODE_TOKEN, 0), "BIGN_decode_token"},
    {ERR_PACK(ERR_LIB_BIGN, 0, BIGN_R_MISSING_PARAMETERS), "missing parameters BIGN"},
    {ERR_PACK(ERR_LIB_BIGN, 0, BIGN_R_MISSING_OID), "missing OID"},
    {ERR_PACK(ERR_LIB_BIGN, 0, BIGN_R_DECODE_ERROR), "key decode error"},
    {ERR_PACK(ERR_LIB_BIGN, 0, BIGN_R_NO_PARAMETERS_SET), "no parameters set"},
    {ERR_PACK(ERR_LIB_BIGN, 0, BIGN_R_INVALID_DIGEST_LENGTH), "invalid digest length"},
    {ERR_PACK(ERR_LIB_BIGN, 0, BIGN_R_INVALID_PRIVATE_KEY), "invalid private key"},
    {ERR_PACK(ERR_LIB_BIGN, 0, BIGN_R_INVALID_PUBLIC_KEY), "invalid public key"},
    {ERR_PACK(ERR_LIB_BIGN, 0, BIGN_R_INVALID_PEER_KEY), "invalid peer key"},
    {ERR_PACK(ERR_LIB_BIGN, 0, BIGN_R_INVALID_CURVE), "invalid curve name"},
    {ERR_PACK(ERR_LIB_BIGN, 0, BIGN_R_INVALID_SIGN_LENGTH), "invalid sign length"},
    {ERR_PACK(ERR_LIB_BIGN, 0, BIGN_R_BIGN_VERIFY_FAIL), "bign verify error"},
    {ERR_PACK(ERR_LIB_BIGN, 0, BIGN_R_KEYS_NOT_SET), "keys not set"},

    {0, NULL}};


int ERR_load_BIGN_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_reason_error_string(BIGN_str_reasons[0].error) == NULL)
        ERR_load_strings_const(BIGN_str_reasons);
#endif
    return 1;
}
