#ifndef HEADER_BTOK_H
#define HEADER_BTOK_H

#include <openssl/opensslconf.h>
#include <openssl/ec.h>
#include <openssl/bign.h>

#ifndef OPENSSL_NO_BTOK
#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct BAUTH_st
	{
		int auth;
		int level;
		unsigned char *Rb; /*!< Одноразовый секретный ключ */

		unsigned char *R; /* Rt + helloA + helloB */
		size_t R_len;	  /*!< длина R в октетах */

		unsigned char K0[32];
		unsigned char K1[32];
		unsigned char K2[32];

		BIGN *bign;
		BIGN *disp;
	} BAUTH_CTX;

	/*
	Функция: BTOK_bauth_init;
	Описание: Инициализация стуктуры контекста протокола BAUTH;
	Параметры:
		ctx - указатель на структуру контекста;
		pkey - указатель на структуру личного ключа;
		helloA - указатель на массив байт, содержащий приветственнное сообщение стороны А;
		helloA_len - размер приветственнного сообщения стороны А;
		helloB - указатель на массив байт, содержащий приветственнное сообщение стороны B;
		helloB_len - размер приветственнного сообщения стороны B;
		twoWayAuth - используемый режим аутентификации
			0 - односторонняя аутентификация;
			1 - двусторонняяя аутентификация;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BTOK_bauth_init(BAUTH_CTX *bauth, EVP_PKEY *pkey,
					const unsigned char *helloA, size_t helloA_len,
					const unsigned char *helloB, size_t helloB_len,
					int twoWayAuth);

	/*
		Функция: BTOK_bauth_step2;
		Описание: Выполнение стороной B первого шага;
		Параметры:
			ctx - указатель на структуру контекста;
			public_key - указатель на массив байт, содержащий открытый ключ стороны А;
			public_key_len - размер открытого ключа;
			out - указатель на массив байт, куда будет записано сообщение m1 (результат);
			out_len - будет записан размер сообщения m1 в байтах (результат);

		Коды возврата:
			0x0000 - успех
			0x0001 - ошибка
*/
	int BTOK_bauth_step2(BAUTH_CTX *ctx,
						 const unsigned char *public_key, unsigned int public_key_len,
						 unsigned char *out, unsigned int *out_len);

	/*
		Функция: BTOK_bauth_step3;
		Описание: Выполнение стороной A первого шага;
		Параметры:
			ctx - указатель на структуру контекста;
			in - указатель на массив байт, содержащий сообщение m1;
			in_len - размер сообщения m1 в байтах;
			out - указатель на массив байт, куда будет записано сообщение m2 (результат);
			Ra - указатель на массив байт, куда будет синхропосылка при двусторонней аутентификации;

		Коды возврата:
			0x0000 - успех
			0x0001 - ошибка
*/
	int BTOK_bauth_step3(BAUTH_CTX *ctx, const unsigned char *in, unsigned int in_len,
						 unsigned char out[8], unsigned char Ra[16]);

	/*
		Функция: BTOK_bauth_step4;
		Описание: Выполнение стороной B второго шага;
		Параметры:
			ctx - указатель на структуру контекста;
			in - указатель на массив байт, содержащий сообщение m2;
			in_len - размер сообщения m2 в байтах;
			out - указатель на массив байт, куда будет записано сообщение m3 (результат);
			out_len - будет записан размер сообщения m2 в байтах (результат);

		Коды возврата:
			0x0000 - успех
			0x0001 - ошибка
*/
	int BTOK_bauth_step4(BAUTH_CTX *ctx, const unsigned char *in, unsigned int in_len,
						 unsigned char *out, unsigned int *out_len);

	/*
		Функция: BTOK_bauth_step5;
		Описание: Выполнение стороной A второго шага. Не выполняется при односторонней аутентификации;
		Параметры:
			ctx - указатель на структуру контекста;
			in - указатель на массив байт, содержащий сообщение m2;
			in_len - размер сообщения m2 в байтах;

		Коды возврата:
			0x0000 - успех
			0x0001 - ошибка
*/
	int BTOK_bauth_step5(BAUTH_CTX *ctx, const unsigned char *in, unsigned int in_len);

	/*
		Функция: BTOK_bauth_final;
		Описание: Выполнение очистки структуры;
		Параметры:
			ctx - указатель на структуру контекста;
			out - выработаннный общий ключ [32 байта];

		Коды возврата:
			0x0000 - успех
			0x0001 - ошибка
*/
	void BTOK_bauth_final(BAUTH_CTX *ctx, unsigned char out[32]);

#ifdef __cplusplus
}
#endif
#endif

#endif