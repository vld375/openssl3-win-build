#ifndef HEADER_BRNG_H
#define HEADER_BRNG_H

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_BRNG
#include <lwocrypt-alg/belt.h>
#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct BRNGhmac_st
	{
		unsigned char ipad[32];
		unsigned char opad[32];
		unsigned char k[32];
		unsigned char temp32[32];

		BELThash_CTX hash_state;
	} BRNGhmac_CTX;

	/*
	Функция: BRNG_hmac_Init;
	Описание: СТБ 34.101.47-2017 П 6.1 Алгоритм выработки имитовставкии в режиме НМАС. Инициализирует структуру контекста;
	Параметры:
		st - указатель на структуру контекста;
		theta - указатель на массив байт, содержащий ключ;
		theta_len - размер ключа в байтах;
*/
	void BRNG_hmac_Init(BRNGhmac_CTX *st, const void *theta, size_t theta_len);

	/*
	Функция: BRNG_hmac_Update;
	Описание: СТБ 34.101.47-2017 П 6.1 Алгоритм выработки имитовставкии в режиме НМАС. Производит вычисления над блоком данных;
	Параметры:
		st - указатель на структуру контекста;
		buf - указатель на блок данных, представляющих собой массив байт;
		buf_len - размер блока данных в байтах;
*/
	void BRNG_hmac_Update(BRNGhmac_CTX *st, const unsigned char *buf, size_t buf_len);

	/*
	Функция: BRNG_hmac_Final;
	Описание: СТБ 34.101.47-2017 П 6.1 Алгоритм выработки имитовставкии в режиме НМАС. Завершить вычисления и вывести результат;
	Параметры:
		state - указатель на структуру контекста;
		dest - указатель на массив байт, куда будет записан результат;
*/
	void BRNG_hmac_Final(BRNGhmac_CTX *st, unsigned char *dest);

	/*
	Функция: hmac_hbelt;
	Описание: СТБ 34.101.47-2017 П 6.1  Алгоритм выработки имитовставкии в режиме НМАС. Атомарная функция вычисления имитовставки;
	Параметры:
		bytes - указатель на массив байт, содержащих входное сообщение;
		bytes_count - размер входного сообщения в байтах;
		theta - указатель на массив байт, содержащих ключ;
		theta_len - размер ключа в байтах;
		dest - указатель на массив байт, куда будет записан результат;

*/
	unsigned char *hmac_hbelt(
		const unsigned char *bytes, size_t bytes_count,
		const unsigned char *theta, size_t theta_len,
		unsigned char *md);

	//===================================================================================================
	typedef struct BRNGctr_hbelt_st
	{
		unsigned char temp_s[32];
		unsigned char temp_r[32];
		unsigned char theta[32];
	} BRNGctr_hbelt_CTX;

	/*
	Функция: BRNG_ctr_hbelt_Init;
	Описание: СТБ 34.101.47-2017 П 6.2 Генерация псевдослучайных чисел в режиме счетчика. Инициализация структуры контекста;
	Параметры:
		ctx - указатель на структуру контекста;
		key - ключ;
		s - синхропосылка;
*/
	void BRNG_ctr_hbelt_Init(BRNGctr_hbelt_CTX *ctx, const unsigned char key[32], const unsigned char s[32]);

	/*
	Функция: BRNG_ctr_hbelt_Update;
	Описание: СТБ 34.101.47-2017 П 6.2 Генерация псевдослучайных чисел в режиме счетчика. Производит вычисления над блоком данных и записывает результат;
	Параметры:
		ctx - указатель на структуру контекста;
		buf - указатель на массив байт, представляющий собой данные;
		buf_len - размер данных в байтах;
		out - указатель на массив байт, куда будет записан результат;
*/
	void BRNG_ctr_hbelt_Update(BRNGctr_hbelt_CTX *ctx, const unsigned char *buf, size_t buf_len, unsigned char *out);

	/*
	Функция: brng_ctr_hbelt;
	Описание: СТБ 34.101.47-2017 П 6.2 Генерация псевдослучайных чисел в режиме счетчика. Атомарная функция генерации псевдослучайных чисел в режиме счетчика;
	Параметры:
		n - число, представляющее собой количество 32 байтовых слов, которые будут сгенерированы;
		key - указатель на массив байт, содержащий ключ [32 байта];
		s - указатель на массив байт, содержащий синхропосылку [32 байта];
		bytes - указатель на массив байт, содержащий дополнительное входное слово [n * 32];
		out - указатель на массив байт, куда будет записан результат [n * 32] байт;
*/

	void brng_ctr_hbelt(
		unsigned int n,
		const unsigned char key[32], const unsigned char s[32],
		const unsigned char *bytes, unsigned char *out);

	//===================================================================================================
	/*
	Функция: brng_hmac_hbelt;
	Описание: СТБ 34.101.47-2017 6.3 Генерация псевдослучайных чисел в режиме НМАС. Атомарная функция генерации псевдослучайных чисел в режиме hmac;
	Параметры:
		n - число, представляющее собой количество 32 байтовых слов, которые будут сгенерированы;
		theta - указатель на массив байт, содержащий ключ;
		theta_len - размер ключа в байтах;
		s - указатель на массив байт, содержащий синхропосылку;
		s_len - размер синхропосылки;
		out - указатель на массив байт, куда будет записан результат [n * 32] байт;
*/

	void brng_hmac_hbelt(
		int n,
		const unsigned char *theta, size_t theta_len,
		const unsigned char *s, size_t s_len,
		unsigned char *out);

#ifdef __cplusplus
}
#endif
#endif

#endif