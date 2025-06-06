/*
 * Copyright 2001-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/proverr.h>
#include <lwocrypt-provider/cipher_belt.h>


char* bytes_to_hex(const unsigned char* bytes, size_t size) {
    const char hex_chars[] = "0123456789ABCDEF";
    char* hex_str = (char*)malloc(size * 2 + 1); // каждый байт превращается в два символа, плюс 1 для нулевого символа
    if (hex_str == NULL) {
        return NULL; // Ошибка выделения памяти
    }
    for (size_t i = 0; i < size; i++) {
        hex_str[i * 2] = hex_chars[(bytes[i] >> 4) & 0xF]; // получаем старшую тетраду
        hex_str[i * 2 + 1] = hex_chars[bytes[i] & 0xF]; // получаем младшую тетраду
    }
    hex_str[size * 2] = '\0'; // завершаем строку нулевым символом
    return hex_str;
}

void belt_cbc_crypt(const unsigned char* in, unsigned char* out, size_t len, const void* key, unsigned char ivec[16], int enc) {
    if (enc) {
        BELT_cbc_encrypt(in, len, key, ivec, out);
        fprintf(stderr, "**** cbc ENC: key:%s \n in:%s\nout: %s*****\n", bytes_to_hex(key, 32), bytes_to_hex(in,48), bytes_to_hex(out, 48));
    }
    else {
        BELT_cbc_decrypt(in, len, key, ivec, out);
        fprintf(stderr, "**** cbc DEC: *****\n");
    }
}

void belt_ecb_crypt(const unsigned char* in, unsigned char* out, size_t len, const void* key, int enc) {
    //len = 47;
    
    fprintf(stderr, "**** ecb len: %zd %d*****\n", len, strlen(in));
    if (enc) {
        
        int res = BELT_ecb_encrypt(in, len, key, out);
        fprintf(stderr, "**** ecb ENC: key:%s \n in:%s\nout: %s*****\n", bytes_to_hex(key, 32), bytes_to_hex(in, len), bytes_to_hex(out, len));
    }
    else {
        BELT_ecb_decrypt(in, len, key, out);
        fprintf(stderr, "**** ecb DEC: *****\n");
    }
}

void belt_cfb_crypt(const unsigned char* in, unsigned char* out, size_t len, const void* key, unsigned char ivec[16], int enc) {
    //len = 47;

    fprintf(stderr, "**** ecb len: %zd %d*****\n", len, strlen(in));
    if (enc) {
        
        BELT_cfb_encrypt(in, len, key, ivec, out);
        fprintf(stderr, "**** ecb ENC: key:%s \n in:%s\nout: %s*****\n", bytes_to_hex(key, 32), bytes_to_hex(in, len), bytes_to_hex(out, len));
    }
    else {
        BELT_cfb_decrypt(in, len, key, ivec, out);
        fprintf(stderr, "**** ecb DEC: *****\n");
    }
}

void belt_ctr_encrypt(const unsigned char* in, unsigned char* out, size_t blocks, const void* key, const unsigned char ivec[16]) {
    BELT_ctr_encrypt(in, blocks, key, ivec, out);
    fprintf(stderr, "blocks: %zd\n", blocks);
    fprintf(stderr, "**** ctr ENC: key:%s \n in:%s\nout: %s*****\n", bytes_to_hex(key, 32), bytes_to_hex(in, 50), bytes_to_hex(out, 8));
}
void belt_ctr_decrypt(const unsigned char* in, unsigned char* out, size_t blocks, const void* key, const unsigned char ivec[16]) {
    BELT_ctr_decrypt(in, blocks, key, ivec, out);
}

static int cipher_hw_belt_initkey(PROV_CIPHER_CTX* dat,
    const unsigned char* key, size_t keylen)
{
    int mode = dat->mode;
    PROV_BELT_CTX* adat = (PROV_BELT_CTX*)dat;

    dat->ks = key;
    
    fprintf(stderr, "**** KEYs: %d  *****\n", mode);

    return 1;
}

IMPLEMENT_CIPHER_HW_COPYCTX(cipher_hw_belt_copyctx, PROV_BELT_CTX)

 int belt_cipher_cbc(PROV_CIPHER_CTX* ctx, unsigned char* out, const unsigned char* in, size_t inl) {
    unsigned char* key = ctx->ks;
    unsigned char* iv = ctx->iv;
    int enc = ctx->enc;
    //inl = 36;
    if (enc) {
        BELT_cbc_encrypt(in, inl, key, iv, out);
        fprintf(stderr, "**** cbc ENC: key:%s \n in:%s\nout: %s*****\n", bytes_to_hex(key, 32), bytes_to_hex(in, 48), bytes_to_hex(out, 48));
    }
    else {
        BELT_cbc_decrypt(in, inl, key, iv, out);
        fprintf(stderr, "**** cbc DEC: *****\n");
    }
    fprintf(stderr, "**** cbc ENC:\n len: %zd\n key:%s \n in:%s\nout: %s*****\n", inl,bytes_to_hex(ctx->ks, 32), bytes_to_hex(in, inl), bytes_to_hex(out, inl));
    return 1;
}

int belt_cipher_ctr(PROV_CIPHER_CTX* ctx, unsigned char* out, const unsigned char* in, size_t inl) {
    unsigned char* key = ctx->ks;
    unsigned char* iv = ctx->iv;
    int enc = ctx->enc;
    fprintf(stderr, "**** ctr ENC:\n len: %zd\n key:%s \n in:%s\nout: %s*****\n", inl, bytes_to_hex(ctx->ks, 32), bytes_to_hex(in, inl), bytes_to_hex(out, inl));
    if (enc) {
        BELT_ctr_encrypt(in, inl, key, iv, out);
        fprintf(stderr, "**** ctr ENC: key:%s \n in:%s\nout: %s*****\n", bytes_to_hex(key, 32), bytes_to_hex(in, 48), bytes_to_hex(out, 48));
    }
    else {
        BELT_ctr_decrypt(in, inl, key, iv, out);
        fprintf(stderr, "**** ctr DEC: *****\n");
    }
    fprintf(stderr, "**** ctr ENC:\n len: %zd\n key:%s \n in:%s\nout: %s*****\n", inl, bytes_to_hex(ctx->ks, 32), bytes_to_hex(in, inl), bytes_to_hex(out, inl));
    return 1;
}

int belt_cipher_ecb(PROV_CIPHER_CTX* ctx, unsigned char* out, const unsigned char* in, size_t inl) {
    unsigned char* key = ctx->ks;
    unsigned char* iv = ctx->iv;
    int enc = ctx->enc;
    fprintf(stderr, "**** ecb ENC:\n len: %zd\n key:%s \n in:%s\nout: %s*****\n", inl, bytes_to_hex(ctx->ks, 32), bytes_to_hex(in, inl), bytes_to_hex(out, inl));
    if (enc) {
        BELT_ecb_encrypt(in, inl, key, out);
        fprintf(stderr, "**** ecb ENC: key:%s \n in:%s\nout: %s*****\n", bytes_to_hex(key, 32), bytes_to_hex(in, 48), bytes_to_hex(out, 48));
    }
    else {
        BELT_ecb_decrypt(in, inl, key, out);
        fprintf(stderr, "**** ecb DEC: *****\n");
    }
    fprintf(stderr, "**** ecb ENC:\n len: %zd\n key:%s \n in:%s\nout: %s*****\n", inl, bytes_to_hex(ctx->ks, 32), bytes_to_hex(in, inl), bytes_to_hex(out, inl));
    return 1;
}

int belt_cipher_cfb(PROV_CIPHER_CTX* ctx, unsigned char* out, const unsigned char* in, size_t inl) {
    unsigned char* key = ctx->ks;
    unsigned char* iv = ctx->iv;
    int enc = ctx->enc;
    fprintf(stderr, "**** cfb:\n iv:%s  \n len: %zd\n key:%s \n in:%s*****\n", bytes_to_hex(iv, 16), inl, bytes_to_hex(ctx->ks, 32), bytes_to_hex(in, inl));
    if (enc) {
        BELT_cfb_encrypt(in, inl, key, iv, out);
        fprintf(stderr, "**** cfb ENC:*****\n");
    }
    else {
        BELT_cfb_decrypt(in, inl, key, iv, out);
        fprintf(stderr, "**** cfb DEC: *****\n");
    }
    fprintf(stderr, "**** cfb out: %s*****\n", bytes_to_hex(out, inl));
    return 1;
}

# define PROV_CIPHER_HW_belt_mode(mode)                                        \
static const PROV_CIPHER_HW belt_##mode = {                                    \
    cipher_hw_belt_initkey,                                                    \
    belt_cipher_##mode,                                             \
    cipher_hw_belt_copyctx                                                     \
};                                                                             \
const PROV_CIPHER_HW *ossl_prov_cipher_hw_belt_##mode(size_t keybits)          \
{                                                                              \
    return &belt_##mode;                                                       \
}
PROV_CIPHER_HW_belt_mode(cbc)
PROV_CIPHER_HW_belt_mode(ecb)
PROV_CIPHER_HW_belt_mode(cfb)
PROV_CIPHER_HW_belt_mode(ctr)
