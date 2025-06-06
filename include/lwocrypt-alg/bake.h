#ifndef HEADER_BAKE_H
#define HEADER_BAKE_H

#include <openssl/opensslconf.h>
#include <openssl/ec.h>
#include <lwocrypt/bign.h>

#ifndef OPENSSL_NO_BAKE
#ifdef __cplusplus
extern "C"
{
#endif

	/*
	Функция: BAKE_dh;
	Описание: СТБ 34.101.66-2014 Приложение A. Вычисление общего ключа по алгоритму Диффи-Хеллмана;
	Параметры:
		bign - указатель на структуру;
		public_key - указатель на массив байт, содержащий открытый ключ;
		public_key_len - размер открытого ключа;
		out - указатель на массив байт, куда будет записан общий ключ;
		out_len - размер общего ключа;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_dh(
		const BIGN *bign,
		const unsigned char *public_key, unsigned int public_key_len,
		unsigned char *out, size_t *out_len);

	/*
	Функция: BAKE_kdf;
	Описание: СТБ 34.101.66-2014 П 6.1 Алгоритм построения ключа
	Параметры:
		x - указатель на массив байт, содержащий секретное слово;
		x_len - размер секретного слова;
		s - указатель на массив байт, содержащий дополнительное слово;
		s_len - размер дополительного слова;
		number - номер ключа, неотрицательное целое число;
		out - указатель на массив байт, куда будет записан ключ (32 байта);

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_kdf(const unsigned char *x, size_t x_len,
				 const unsigned char *s, size_t s_len,
				 size_t number, unsigned char out[32]);

	/*
	Функция: BAKE_swu;
	Описание: СТБ 34.101.66-2014 П 6.2 Алгоритм построения точки эллиптической кривой;
	Параметры:
		bign - указатель на проинициализированную структуру;
		x - указатель на массив байт, содержащий входное слово,
			размером l / 4 (32, 48 или 64 байта);
		point - указатель на массив байт, куда будет записана точка,
			размером l / 2 (64, 96 или 128 байта);

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_swu(const BIGN *bign, const unsigned char x[], unsigned char point[]);

	//===============================================================================================================================================
	typedef struct BPACE_st
	{
		unsigned char *helloA; /*!< приветственное сообщение стороны A */
		size_t helloA_len;	   /*!< длина helloA в октетах */
		unsigned char *helloB; /*!< приветственное сообщение стороны B */
		size_t helloB_len;	   /*!< длина helloB в октетах */

		unsigned char *R;
		BIGNUM *u_BN;

		int level;

		unsigned char K0[32];
		unsigned char K1[32];
		unsigned char K2[32];

		BIGN *bign;
	} BPACE_CTX;

	/*
	Функция: BAKE_bpace_init;
	Описание: Инициализация стуктуры контекста протокола BPACE;
	Параметры:
		ctx - указатель на структуру контекста;
		level - уровень стойкости [128, 192, 256];
		P - указатель на массив байт, содержащий общий пароль протокола BPACE;
		P_len - размер общего пароля в байтах;
		helloA - указатель на массив байт, содержащий приветственнное сообщение стороны А;
		helloA_len - размер приветственнного сообщения стороны А;
		helloB - указатель на массив байт, содержащий приветственнное сообщение стороны B;
		helloB_len - размер приветственнного сообщения стороны B;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bpace_init(BPACE_CTX *ctx, int level, const unsigned char *P, size_t P_len,
						const unsigned char *helloA, size_t helloA_len,
						const unsigned char *helloB, size_t helloB_len);

	/*
	Функция: BAKE_bpace_addHelloB;
	Описание: Выполнение стороной A добавления приветственного сообщения;
	Параметры:
		ctx - указатель на структуру контекста;
		helloB - указатель на массив байт, содержащий приветственнное сообщение стороны B;
		helloB_len - размер приветственнного сообщения стороны B;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bpace_addHelloB(BPACE_CTX *bpace, const unsigned char *helloB, size_t helloB_len);

	/*
	Функция: BAKE_bpace_step2;
	Описание: Выполнение стороной B первого шага;
	Параметры:
		ctx - указатель на структуру контекста;
		out - указатель на массив байт, куда будет записано сообщение m1 (результат);
		out_len - будет записан размер сообщения m1 в байтах (результат) [16, 24, 32];

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bpace_step2(BPACE_CTX *ctx, unsigned char *out, unsigned int *out_len);

	/*
	Функция: BAKE_bpace_step3;
	Описание: Выполнение стороной A первого шага;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на массив байт, содержащий сообщение m1;
		in_len - размер сообщения m1 в байтах;
		out - указатель на массив байт, куда будет записано сообщение m2 (результат);
		out_len - будет записан размер сообщения m2 в байтах (результат) [80, 120, 160];

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bpace_step3(BPACE_CTX *ctx,
						 const unsigned char *in, unsigned int in_len,
						 unsigned char *out, unsigned int *out_len);

	/*
	Функция: BAKE_bpace_step4;
	Описание: Выполнение стороной B второго шага. Выходное ообщение m3 = out[||Tb];
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на массив байт, содержащий сообщение m2;
		in_len - размер сообщения m2 в байтах;
		out - указатель на массив байт, куда будет записано часть сообщения m3 (результат);
		out_len - будет записан размер части сообщения m3 в байтах (результат) [80, 120, 160];
		Tb - синхропосылка стороны B[8 байт], если необходима аутентификация перед второй стороной (результат);

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bpace_step4(BPACE_CTX *ctx,
						 const unsigned char *in, unsigned int in_len,
						 unsigned char *out, unsigned int *out_len, unsigned char Tb[8]);

	/*
	Функция: BAKE_bpace_step5;
	Описание: Выполнение стороной A второго шага. Выходное ообщение m4 = [||Ta];
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на массив байт, содержащий сообщение m3;
		in_len - размер сообщения m3 в байтах;
		Tb - синхропосылка стороны B[8 байт], если необходима аутентификация перед второй стороной;
		Ta - синхропосылка стороны A[8 байт], если необходима аутентификация перед второй стороной (результат);

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bpace_step5(BPACE_CTX *ctx, const unsigned char *in, unsigned int in_len, const unsigned char Tb[8], unsigned char Ta[8]);

	/*
	Функция: BAKE_bpace_step6;
	Описание: Выполнение стороной B последнего шага;
	Параметры:
		ctx - указатель на структуру контекста;
		Ta - синхропосылка стороны A[8 байт], если необходима аутентификация перед второй стороной;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bpace_step6(BPACE_CTX *ctx, const unsigned char Ta[8]);

	/*
	Функция: BAKE_bpace_final;
	Описание: Выполнение очистки структуры;
	Параметры:
		ctx - указатель на структуру контекста;
		out - выработаннный общий ключ [32 байта];

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	void BAKE_bpace_final(BPACE_CTX *ctx, unsigned char out[32]);

	//===============================================================================================================================================
	typedef struct BSTS_st
	{
		unsigned char *hello; /*!< приветственные сообщения сторон */
		size_t hello_len;	  /*!< длина hello в октетах */

		unsigned char *certID; /*!< сертификат обрабатывающей стороны */
		size_t certID_len;	   /*!< длина certID в октетах */

		unsigned char *t;

		EC_POINT *Va;
		EC_POINT *Vb;

		int level;
		BIGNUM *u_BN;

		unsigned char K0[32];
		unsigned char K1[32];
		unsigned char K2[32];

		BIGN *main;
		BIGN *secondary;
	} BSTS_CTX;

	/*
	Функция: BAKE_bsts_init;
	Описание: Инициализация стуктуры контекста протокола BSTS;
	Параметры:
		ctx - указатель на структуру контекста;
		pkey - указатель на структуру личного ключа;
		helloA - указатель на массив байт, содержащий приветственнное сообщение стороны А;
		helloA_len - размер приветственнного сообщения стороны А;
		helloB - указатель на массив байт, содержащий приветственнное сообщение стороны B;
		helloB_len - размер приветственнного сообщения стороны B;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bsts_init(BSTS_CTX *ctx, EVP_PKEY *pkey,
					   const unsigned char *certID, int certID_len,
					   const unsigned char *helloA, size_t helloA_len,
					   const unsigned char *helloB, size_t helloB_len);

	/*
	Функция: BAKE_bsts_addHelloB;
	Описание: Выполнение стороной A добавления приветственного сообщения;
	Параметры:
		ctx - указатель на структуру контекста;
		helloB - указатель на массив байт, содержащий приветственнное сообщение стороны B;
		helloB_len - размер приветственнного сообщения стороны B;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bsts_addHelloB(BSTS_CTX *ctx, const unsigned char *helloB, size_t helloB_len);

	/*
	Функция: BAKE_bsts_addSecondPublicKey;
	Описание: Выполнение сторонами добавления открытого ключа второй стороны;
	Параметры:
		ctx - указатель на структуру контекста;
		pkey - указатель на структуру открытого ключа;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	void BAKE_bsts_addSecondPublicKey(BSTS_CTX *bsts, EVP_PKEY *pkey);

	/*
	Функция: BAKE_bsts_step2;
	Описание: Выполнение стороной B первого шага;
	Параметры:
		ctx - указатель на структуру контекста;
		out - указатель на массив байт, куда будет записано сообщение m1 (результат);
		out_len - будет записан размер сообщения m1 в байтах (результат) [16, 24, 32];

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bsts_step2(BSTS_CTX *ctx, unsigned char *out, unsigned int *out_len);

	/*
	Функция: BAKE_bsts_step3;
	Описание: Выполнение стороной A первого шага;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на массив байт, содержащий сообщение m1;
		in_len - размер сообщения m1 в байтах;
		out - указатель на массив байт, куда будет записано сообщение m2 (результат);
		out_len - будет записан размер сообщения m2 в байтах (результат);
		Ta - синхропосылка стороны A[8 байт], если необходима аутентификация перед второй стороной (результат);

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bsts_step3(BSTS_CTX *ctx,
						const unsigned char *in, unsigned int in_len,
						unsigned char *out, unsigned int *out_len, unsigned char Ta[8]);

	/*
	Функция: BAKE_bsts_step4;
	Описание: Выполнение стороной B второго шага;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на массив байт, содержащий сообщение m2;
		in_len - размер сообщения m2 в байтах;
		Ta - синхропосылка стороны A[8 байт], если необходима аутентификация перед второй стороной;
		out - указатель на массив байт, куда будет записано часть сообщения m3 (результат);
		out_len - будет записан размер части сообщения m3 в байтах (результат);
		Tb - синхропосылка стороны B[8 байт] (результат);

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bsts_step4(BSTS_CTX *bsts,
						const unsigned char *in, unsigned int in_len, const unsigned char Ta[8],
						unsigned char *out, unsigned int *out_len, unsigned char Tb[8]);

	/*
	Функция: BAKE_bsts_step5;
	Описание: Выполнение стороной A третьего шага;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на массив байт, содержащий сообщение m3;
		in_len - размер сообщения m1 в байтах;
		Tb - синхропосылка стороны A[8 байт];

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bsts_step5(BSTS_CTX *bsts, const unsigned char *in, unsigned int in_len, const unsigned char Tb[8]);

	/*
	Функция: BAKE_bsts_final;
	Описание: Выполнение очистки структуры и возврат общего ключа;
	Параметры:
		ctx - указатель на структуру контекста;
		out - выработаннный общий ключ [32 байта];

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	void BAKE_bsts_final(BSTS_CTX *ctx, unsigned char out[32]);

	//===============================================================================================================================================
	typedef struct BMVQ_st
	{
		unsigned char *hello; /*!< приветственные сообщения сторон */
		size_t hello_len;	  /*!< длина hello в октетах */

		unsigned char *certID; /*!< сертификат обрабатывающей стороны */
		size_t certID_len;	   /*!< длина certID в октетах */

		EC_POINT *Va;
		EC_POINT *Vb;

		int level;
		BIGNUM *u_BN;

		unsigned char K0[32];
		unsigned char K1[32];

		BIGN *main;
		BIGN *secondary;
	} BMVQ_CTX;

	/*
	Функция: BAKE_bmvq_init;
	Описание: Инициализация стуктуры контекста протокола BMVQ;
	Параметры:
		ctx - указатель на структуру контекста;
		pkey - указатель на структуру личного ключа;
		helloA - указатель на массив байт, содержащий приветственнное сообщение стороны А;
		helloA_len - размер приветственнного сообщения стороны А;
		helloB - указатель на массив байт, содержащий приветственнное сообщение стороны B;
		helloB_len - размер приветственнного сообщения стороны B;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bmvq_init(BMVQ_CTX *ctx, EVP_PKEY *pkey,
					   const unsigned char *certID, int certID_len,
					   const unsigned char *helloA, size_t helloA_len,
					   const unsigned char *helloB, size_t helloB_len);

	/*
	Функция: BAKE_bmvq_addHelloB;
	Описание: Выполнение стороной A добавления приветственного сообщения;
	Параметры:
		ctx - указатель на структуру контекста;
		helloB - указатель на массив байт, содержащий приветственнное сообщение стороны B;
		helloB_len - размер приветственнного сообщения стороны B;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bmvq_addHelloB(BMVQ_CTX *ctx, const unsigned char *helloB, size_t helloB_len);

	/*
	Функция: BAKE_bmvq_addSecondPublicKey;
	Описание: Выполнение сторонами добавления открытого ключа второй стороны;
	Параметры:
		ctx - указатель на структуру контекста;
		pkey - указатель на структуру открытого ключа;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	void BAKE_bmvq_addSecondPublicKey(BMVQ_CTX *ctx, EVP_PKEY *pkey);

	/*
	Функция: BAKE_bmvq_step2;
	Описание: Выполнение стороной B первого шага;
	Параметры:
		ctx - указатель на структуру контекста;
		out - указатель на массив байт, куда будет записано сообщение m1 (результат);
		out_len - будет записан размер сообщения m1 в байтах (результат);

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bmvq_step2(BMVQ_CTX *ctx, unsigned char *out, unsigned int *out_len);

	/*
	Функция: BAKE_bmvq_step3;
	Описание: Выполнение стороной A первого шага;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на массив байт, содержащий сообщение m1;
		in_len - размер сообщения m1 в байтах;
		out - указатель на массив байт, куда будет записано сообщение m2 (результат);
		out_len - будет записан размер сообщения m2 в байтах (результат);
		Ta - синхропосылка стороны A[8 байт], если необходима аутентификация перед второй стороной (результат);

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bmvq_step3(BMVQ_CTX *ctx,
						const unsigned char *in, unsigned int in_len,
						unsigned char *out, unsigned int *out_len, unsigned char Ta[8]);

	/*
	Функция: BAKE_bmvq_step4;
	Описание: Выполнение стороной B второго шага;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на массив байт, содержащий сообщение m2;
		in_len - размер сообщения m2 в байтах;
		Ta - синхропосылка стороны A[8 байт], если необходима аутентификация перед второй стороной;
		Tb - синхропосылка стороны B[8 байт], если необходима аутентификация перед второй стороной (результат);

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bmvq_step4(BMVQ_CTX *bmvq, const unsigned char *in, unsigned int in_len,
						const unsigned char Ta[8], unsigned char Tb[8]);

	/*
	Функция: BAKE_bmvq_step5;
	Описание: Выполнение стороной A третьего шага;
	Параметры:
		ctx - указатель на структуру контекста;
		Tb - синхропосылка стороны B[8 байт], если необходима аутентификация перед второй стороной;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BAKE_bmvq_step5(BMVQ_CTX *ctx, const unsigned char Tb[8]);

	/*
	Функция: BAKE_bmvq_final;
	Описание: Выполнение очистки структуры и возврат общего ключа;
	Параметры:
		ctx - указатель на структуру контекста;
		out - выработаннный общий ключ [32 байта];

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	void BAKE_bmvq_final(BMVQ_CTX *ctx, unsigned char out[32]);

#ifdef __cplusplus
}
#endif
#endif

#endif