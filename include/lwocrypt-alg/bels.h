#ifndef HEADER_BELS_H
#define HEADER_BELS_H

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_BELS
#include <openssl/x509.h>
#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct BELSstate
	{
		EVP_PKEY **pkeys;
		int n;

	} BELS_CTX;

	/*
		Функция: BELS_free;
		Параметры:
			BELS *ctx - указатель на структуру, куда будут записаны открытые ключи и частичные секреты;
*/
	void BELS_free(BELS_CTX *ctx);

	/*
		Функция: BELS_share;
		Описание: СТБ 34.101.60-2014 П. 7.3 Алгоритм разделения секрета;
		Параметры:
			n - число пользователей;
			t - пороговое число;
			secret - указатель на массив байт, содержащий секрет;
			secret_len - длина секрета [16, 24, 32];
*/
	BELS_CTX *BELS_share(int n, int t, const unsigned char *secret, int secret_len);

	/*
		Функция: BELS_recov;
		Описание: СТБ 34.101.60-2014 П. 7.4 Алгоритм восстановления секрета;
		Параметры:
			ctx - указатель на структуру, где записаны частичные секреты;
			out - указатель на массив байт, куда будет записан восстановленный секрет;
			out_len - размер восстановленного секрета, в байтах [16, 24, 32]);

		Коды возврата:
			0x0000 - успех
			0x0001 - ошибка
*/
	int BELS_recov(BELS_CTX *ctx, unsigned char *out, int *out_len);

#ifdef __cplusplus
}
#endif
#endif

#endif