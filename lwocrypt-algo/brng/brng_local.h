#ifndef OSSL_CRYPTO_BRNG_LOCAL_H
#define OSSL_CRYPTO_BRNG_LOCAL_H

#define BRNG_CHUNK256_XOR(dest, src1, src2)                                                  \
	((unsigned int *)(dest))[0] = ((unsigned int *)(src1))[0] ^ ((unsigned int *)(src2))[0]; \
	((unsigned int *)(dest))[1] = ((unsigned int *)(src1))[1] ^ ((unsigned int *)(src2))[1]; \
	((unsigned int *)(dest))[2] = ((unsigned int *)(src1))[2] ^ ((unsigned int *)(src2))[2]; \
	((unsigned int *)(dest))[3] = ((unsigned int *)(src1))[3] ^ ((unsigned int *)(src2))[3]; \
	((unsigned int *)(dest))[4] = ((unsigned int *)(src1))[4] ^ ((unsigned int *)(src2))[4]; \
	((unsigned int *)(dest))[5] = ((unsigned int *)(src1))[5] ^ ((unsigned int *)(src2))[5]; \
	((unsigned int *)(dest))[6] = ((unsigned int *)(src1))[6] ^ ((unsigned int *)(src2))[6]; \
	((unsigned int *)(dest))[7] = ((unsigned int *)(src1))[7] ^ ((unsigned int *)(src2))[7];

#define BRNG_CHUNK256_XOREQ(dest, src)                         \
	((unsigned int *)(dest))[0] ^= ((unsigned int *)(src))[0]; \
	((unsigned int *)(dest))[1] ^= ((unsigned int *)(src))[1]; \
	((unsigned int *)(dest))[2] ^= ((unsigned int *)(src))[2]; \
	((unsigned int *)(dest))[3] ^= ((unsigned int *)(src))[3]; \
	((unsigned int *)(dest))[4] ^= ((unsigned int *)(src))[4]; \
	((unsigned int *)(dest))[5] ^= ((unsigned int *)(src))[5]; \
	((unsigned int *)(dest))[6] ^= ((unsigned int *)(src))[6]; \
	((unsigned int *)(dest))[7] ^= ((unsigned int *)(src))[7];

#endif
