#ifndef HEADER_BELT_H
#define HEADER_BELT_H

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_BELT
#include <stddef.h>
#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct BELThashstate_st
	{
		unsigned long long bytes_count;

		unsigned char s[16];
		unsigned char hash[32];

		unsigned char buf[32];
		unsigned int buf_len;

	} BELThash_CTX;

	/*
	Функция:	BELT_hash_Init;
	Описание:	СТБ 34.101.31-2020 П 7.8.3 Алгоритм хэширования. Инициализирует структуру контекста алгоритма хеширования;
	Параметры:
		ctx - указатель на структуру контекста;
	Коды возврата:
		1 - Успешное завершение;
*/
	int BELT_hash_Init(BELThash_CTX *ctx);

	/*
	Функция:	BELT_hash_Update;
	Описание:	СТБ 34.101.31-2020 П 7.8.3 Алгоритм хэширования. Производит вычисления над следующим блоком данных, результат записывает в структуру контекста;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на блок данных;
		in_len - размер блока данных в байтах;
	Коды возврата:
		1 - Успешное завершение;
*/
	int BELT_hash_Update(BELThash_CTX *ctx, const void *in, size_t in_len);

	/*
	Функция:	BELT_hash_Final;
	Описание:	СТБ 34.101.31-2020 П 7.8.3 Алгоритм хэширования. Завершает вычисления и заполняет результирующее значение;
	Параметры:
		ctx - указатель на структуру контекста;
		md - указатель на массив байт, куда будут записаны результирующие данные;
	Коды возврата:
		1 - Успешное завершение;
*/
	int BELT_hash_Final(unsigned char *md, BELThash_CTX *ctx);

	/*
	Функция:	belt_hash;
	Описание: 	СТБ 34.101.31-2020 П 7.8.3 Алгоритм хэширования. Атомарная функция;
	Параметры:
		in - входное сообщение;
		in_len - размер входного сообщения;
		md - указатель на массив байт, куда будут записаны результирующие данные;
	Коды возврата:
		1 - Успешное завершение;
*/
	unsigned char *belt_hash(const unsigned char *in, size_t in_len, unsigned char *md);

	//===============================================================================================================================================
	typedef struct BELTmacstate_st
	{
		unsigned char theta[32];
		unsigned char s[16];
		unsigned char r[16];

		unsigned char buf[32];
		unsigned int buf_len;
	} BELTmac_CTX;

	/*
	Функция: BELT_mac_Init;
	Описание: СТБ 34.101.31-2020 П 7.5.3 Алгоритм выработки имитовставки. Инициализация структуры контекста;
	Параметры:
		ctx - указатель на структуру контекста;
		key - ключ;
*/
	void BELT_mac_Init(BELTmac_CTX *ctx, const unsigned char key[32]);

	/*
	Функция: BELT_mac_Update;
	Описание: СТБ 34.101.31-2020 П 7.5.3 Алгоритм выработки имитовставки. Производит вычисления над очередным блоком данных;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на блок данных;
		in_len - размер блока данных в байтах;
	Коды возврата:
		1 - Успешное завершение;
*/
	int BELT_mac_Update(BELTmac_CTX *ctx, const unsigned char *in, size_t in_len);

	/*
	Функция: BELT_mac_Final;
	Описание: СТБ 34.101.31-2020 П 7.5.3 Алгоритм выработки имитовставки. Завершает вычисления и сохраняет результат в результирующий буффер;
	Параметры:
		ctx - указатель на структуру контекста;
		out - указатель на массив байт, куда будут записаны результирующие данные;
	Коды возврата:
		1 - Успешное завершение;
*/
	int BELT_mac_Final(BELTmac_CTX *ctx, unsigned char *out);

	/*
	Функция: belt_mac;
	Описание: СТБ 34.101.31-2020 П 7.5.3 Алгоритм выработки имитовставки. Атомарная функция;
	Параметры:
		in - указатель на данные, с которых будет высчитываться имитовставка;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		md - указатель на массив байт, куда будут записаны результирующие данные;
	Коды возврата:
		- нет	 
*/
	unsigned char *belt_mac(const unsigned char *in, size_t in_len, const unsigned char key[32], unsigned char *md);

	//===============================================================================================================================================
	typedef struct BELTstate
	{
		unsigned char key[32];
		unsigned char iv[16];

		unsigned char buf[32];
		unsigned int buf_len;

		union
		{
			unsigned long long u[2];
			unsigned char c[16];
		} len;

		union
		{
			unsigned int u[2];
			unsigned long long limit;
		} quotas;
		unsigned long long quotas_current;

		unsigned char temp_r[16];
		unsigned char temp_s[16];

	} BELT_CTX;

	/*
	Функция: BELT_block_encrypt;
	Описание: СТБ 34.101.31-2020 П 6.1.3 Алгоритм зашифрования блока.
	Параметры:
		in - блок входных данных 16 байт;
		out - результат зашифрования 16 байт;
		key - ключ 32 байта;
*/
	void BELT_block_encrypt(const void *in, unsigned char *out, const unsigned char key[32]);

	/*
	Функция: BELT_block_decrypt;
	Описание: СТБ 34.101.31-2020 П 6.1.4 Алгоритм расшифрования блока.
	Параметры:
		in - блок входных данных 16 байт;
		out - результат расшифрования 16 байт;
		key - ключ 32 байта;
*/
	void BELT_block_decrypt(const void *in, unsigned char *out, const unsigned char key[32]);

	/*
	Функция: BELT_wblock_encrypt;
	Описание: СТБ 34.101.31-2020 П 6.2.3 Алгоритм зашифрования широкого блока.
	Параметры:
		in - блок входных данных;
		in_len - размер блок входных данных в байтах;
		out - результат зашифрования;
		key - ключ 32 байта;
*/
	void BELT_wblock_encrypt(const void *in, size_t in_len, unsigned char *out, const unsigned char key[32]);

	/*
	Функция: BELT_wblock_decrypt;
	Описание: СТБ 34.101.31-2020 П 6.2.4 Алгоритм расшифрования широкого блока.
	Параметры:
		in - блок входных данных;
		in_len - размер блок входных данных в байтах;
		out - результат расшифрования;
		key - ключ 32 байта;
*/
	void BELT_wblock_decrypt(const void *in, size_t in_len, unsigned char *out, const unsigned char key[32]);

	/*
	Функция: BELT_compress;
	Описание: СТБ 34.101.31-2020 П 6.3.2 Алгоритм сжатия.
	Параметры:
		in - блок входных данных 64 байта;
		S - промежуточный результат сжатия 16 байт;
		key - окончательный результат сжатия 32 байта;
*/
	void BELT_compress(const unsigned char in[64], unsigned char S[16], unsigned char Y[32]);

	/*
	Функция: BELT_ecb_init;
	Описание: СТБ 34.101.31-2020 П 7.1 Шифрование в режиме простой замены. Инициализирует структуру контекста;
	Параметры:
		ctx - указатель на структуру контекста;
		key - ключ 32 байта;
*/
	void BELT_ecb_init(BELT_CTX *ctx, const unsigned char key[32]);

	/*
	Функция: BELT_ecb_encrypt_update;
	Описание: СТБ 34.101.31-2020 П 7.1 Шифрование в режиме простой замены. Зашифрование блока данных;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на блок данных для зашифрование;
		in_len - размер блока данных для зашифрования в байтах;
		out - указатель на массив байт куда будет записано результирующее зашифрованное сообщение;
*/
	int BELT_ecb_encrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out);

	/*
	Функция: BELT_ecb_decrypt_update;
	Описание: СТБ 34.101.31-2020 П 7.1 Шифрование в режиме простой замены. Расшифрование блока данных;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на блок данных для расшифрования;
		in_len - размер блока данных для расшифрования в байтах;
		out - указатель на массив байт, куда будет записано результирующее расшифрованное сообщение;
*/
	int BELT_ecb_decrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out);

	/*
	Функция: BELT_ecb_encrypt_final;
	Описание: СТБ 34.101.31-2020 П 6.2 Шифрование в режиме простой замены. Результирующий блок зашифрованных данных;
	Параметры:
		ctx - указатель на структуру контекста;
		out - указатель на массив байт, куда будет записано результирующее расшифрованное сообщение;
*/
	int BELT_ecb_encrypt_final(BELT_CTX *ctx, unsigned char *out);

	/*
	Функция: BELT_ecb_decrypt_final;
	Описание: СТБ 34.101.31-2020 П 6.2 Шифрование в режиме простой замены. Результирующий блок расшифрованных данных;
	Параметры:
		ctx - указатель на структуру контекста;
		out - указатель на массив байт, куда будет записано результирующее расшифрованное сообщение;
*/
	int BELT_ecb_decrypt_final(BELT_CTX *ctx, unsigned char *out);

	/*
	Функция : BELT_ecb_encrypt;
	Описание : СТБ 34.101.31-2020 П 6.2 Шифрование в режиме простой замены. Атомарная функция зашифрования;
	Параметры :
		in - данные, которые необходимо зашифровать;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		out - указатель на массив, куда будут записаны результирующие зашифрованные данные;

*/
	int BELT_ecb_encrypt(const unsigned char *in, size_t in_ken, const unsigned char key[32], unsigned char *out);

	/*
	Функция: BELT_ecb_decrypt;
	Описание: СТБ 34.101.31-2020 П 6.2 Шифрование в режиме простой замены. Атомарная функция расшифрования;
	Параметры:
		in - данные, которые необходимо расшифровать;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		out - указатель на массив, куда будут записаны результирующие расшифрованные данные;

*/
	int BELT_ecb_decrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], unsigned char *out);

	//===============================================================================================================================================
	/*
	Функция: BELT_cbc_init;
	Описание:СТБ 34.101.31-2020 П 7.2 Шифрование в режиме сцепления блоков. Инициализировать структуру контекста;
	Параметры:
		ctx - указатель на структуру контекста;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
*/
	void BELT_cbc_init(BELT_CTX *ctx, const unsigned char key[32], const unsigned char s[16]);

	/*
	Функция: BELT_cbc_encrypt_update;
	Описание:СТБ 34.101.31-2020 П 7.2 Шифрование в режиме сцепления блоков. Зашифрование блока данных;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на блок данных для зашифрования;
		in_len - размер блока данных для зашифрования;
		out - указатель на массив байт, куда будут записаны результирующие данные;
*/
	int BELT_cbc_encrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out);

	/*
	Функция: BELT_cbc_decrypt_update;
	Описание:СТБ 34.101.31-2020 П 7.2 Шифрование в режиме сцепления блоков. Расшифрование блока данных;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на блок данных для расшифрования;
		in_len - размер блока данных для расшифрования;
		out - указатель на массив байт, куда будут записаны результирующие данные;
*/
	int BELT_cbc_decrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out);

	/*
	Функция: BELT_cbc_encrypt_final;
	Описание:СТБ 34.101.31-2020 П 7.2 Шифрование в режиме сцепления блоков. Результирующий блок зашифрованных данных;
	Параметры:
		ctx - указатель на структуру контекста;
		out - указатель на массив байт, куда будут записаны результирующие данные;
*/
	int BELT_cbc_encrypt_final(BELT_CTX *ctx, unsigned char *out);

	/*
	Функция: BELT_cbc_decrypt_final;
	Описание:СТБ 34.101.31-2020 П 7.2 Расшифрование в режиме сцепления блоков. Результирующий блок расшифрованных данных;
	Параметры:
		ctx - указатель на структуру контекста;
		out - указатель на массив байт, куда будут записаны результирующие данные;
*/
	int BELT_cbc_decrypt_final(BELT_CTX *ctx, unsigned char *out);

	/*
	Функция: BELT_cbc_encrypt;
	Описание: СТБ 34.101.31-2020 П 7.2 Шифрование в режиме сцепления блоков. Атомарная функция зашифрования;
	Параметры:
		in - данные, которые необходимо зашифровать;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
		out - указатель на массив байт, куда будут записаны результирующие данные;
*/
	int BELT_cbc_encrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out);

	/*
	Функция: BELT_cbc_decrypt;
	Описание: СТБ 34.101.31-2020 П 7.2 Шифрование в режиме сцепления блоков. Атомарная функция расшифрования;
	Параметры:
		in - данные, которые необходимо расшифровать;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
		out - указатель на массив байт, куда будут записаны результирующие данные;
	*/
	int BELT_cbc_decrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out);

	//===============================================================================================================================================
	/*
	Функция: BELT_cfb_init;
	Описание: СТБ 34.101.31-2020 П 7.3 Шифрование в режиме гаммирования с обратной связью. Инициализировать структуру контекста;
	Параметры:
		ctx - указатель на структуру контекста;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
*/
	void BELT_cfb_init(BELT_CTX *ctx, const unsigned char key[32], const unsigned char s[16]);

	/*
	Функция: BELT_cfb_encrypt_update;
	Описание: СТБ 34.101.31-2020 П 7.3 Шифрование в режиме гаммирования с обратной связью. Зашифрование блока данных;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на блок данных для зашифрования;
		in_len - размер блока данных для зашифрования;
		out - указатель на массив байт куда будут записаны результирующие данные;
*/
	void BELT_cfb_encrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out);

	/*
	Функция: BELT_cfb_decrypt_update;
	Описание: СТБ 34.101.31-2020 П 7.3 Шифрование в режиме гаммирования с обратной связью. Расшифрование блока данных;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на блок данных для расшифрования;
		in_len - размер блока данных для расшифрования;
		out - указатель на массив байт куда будут записан результирующие данные;
*/
	void BELT_cfb_decrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out);

	/*
	Функция: BELT_cfb_encrypt;
	Описание: СТБ 34.101.31-2020 П 7.3 Шифрование в режиме гаммирования с обратной связью. Атомарная функция зашифрования;
	Параметры:
		in - указатель на данные, которые необходимо зашифровать;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
		out - указатель на массив байт, куда будут записаны результирующие данные;
*/
	void BELT_cfb_encrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out);

	/*
	Функция: BELT_cfb_decrypt;
	Описание: СТБ 34.101.31-2020 П 7.3 Шифрование в режиме гаммирования с обратной связью. Атомарная функция расшифрования; 
	Параметры:
		in - указатель на данные, которые необходимо расшифровать;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
		out - указатель на массив байт, куда будут записаны результирующие данные;
*/
	void BELT_cfb_decrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out);

	//===============================================================================================================================================
	/*
	Функция: BELT_ctr_init;
	Описание: СТБ 34.101.31-2020 П 7.4 Шифрование в режиме счетчика. Инициализирует структуру контекста;
	Параметры:
		ctx - указатель на структуру контекста;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
*/
	void BELT_ctr_init(BELT_CTX *ctx, const unsigned char key[32], const unsigned char s[16]);

	/*
	Функция: BELT_ctr_encrypt_update;
	Описание: СТБ 34.101.31-2020 П 7.4 Шифрование в режиме счетчика. Зашифрование блока данных;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на блок данных;
		in_len - размер блока данных;
		out - указатель на массив байт, куда будут записаны результирующие данные;
*/
	void BELT_ctr_encrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out);

	/*
	Функция: BELT_ctr_decrypt_update;
	Описание: СТБ 34.101.31-2020 П 7.4 Шифрование в режиме счетчика. Расшифрование блока данных;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на блок данных;
		in_len - размер блока данных;
		out - указатель на массив байт, куда будут записаны результирующие данные;
*/
	void BELT_ctr_decrypt_update(BELT_CTX* ctx, const unsigned char* in, size_t in_len, unsigned char* out);

	/*
	Функция: BELT_ctr_encrypt;
	Описание: СТБ 34.101.31-2020 П 7.4 Шифрование в режиме счетчика. Атомарная функция зашифрования;
	Параметры:
		in - указатель на данные, которые необходимо зашифровать;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
		out - указатель на массив байт, куда будут записаны результирующие данные;
*/
	void BELT_ctr_encrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out);

	/*
	Функция: BELT_ctr_decrypt;
	Описание: СТБ 34.101.31-2020 П 7.4 Шифрование в режиме счетчика. Атомарная функция расшифрования;
	Параметры:
		in - указатель на данные, которые необходимо расшифровать;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
		out - указатель на массив байт, куда будут записаны результирующие данные;
*/
	void BELT_ctr_decrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out);

	//===============================================================================================================================================
	/*
	Функция: BELT_kwp_init;
	Описание: СТБ 34.101.31-2020 П 7.7 Алгоритм одновременного шифрования и имитозащиты ключа. Инициализация структуры контекста;
	Параметры:
		ctx - указатель на структуру контекста;
		header - заголовок 16 байт;
		key - ключ защиты 32 байта;
*/
	void BELT_kwp_init(BELT_CTX *ctx, const unsigned char header[16], const unsigned char key[32]);

	/*
	Функция: BELT_kwp_encrypt_update;
	Описание: СТБ 34.101.31-2020 П 7.7 Алгоритм одновременного шифрования и имитозащиты ключа. Алгоритм установки защиты ключа;
	Параметры:
		ctx - указатель на структуру контекста;
		x - указатель на массив байт, которые содержат ключ, на который необходимо установить защиту;
		x_len - размер защищаемого ключа;
		out - указатель на массив байт, куда будет записано результирующее значение;
		out_len - размер массива, куда будет записано результирующее значение, в байтах;

	Код возврата:
		0x0000 - ошибка;
		0x0001 - успех;
*/
	int BELT_kwp_encrypt_update(BELT_CTX *ctx, const unsigned char *x, size_t x_len, unsigned char *out, size_t *out_len);

	/*
	Функция: BELT_kwp_decrypt_update;
	Описание: СТБ 34.101.31-2020 П 7.7 Алгоритм одновременного шифрования и имитозащиты ключа. Снятие защиты с защищенного ключа;
	Параметры:
		ctx - указатель на структуру контекста;
		x - указатель на массив байт, содержащий ключ, с которого необходимо снять защиту;
		x_len - размер ключа, с которого необходимо снять защиту в байтах;
		out - указатель на массив байт, куда будет записано результирующее значение;
		out_len - размер массива, куда будет записано результирующее значение, в байтах;

	Код возврата:
		0x0000 - успех;
		0x0001 - ошибка;
*/
	int BELT_kwp_decrypt_update(BELT_CTX *ctx, const unsigned char *x, size_t x_len, unsigned char *out, size_t *out_len);

	/*
	Функция: BELT_kwp_encrypt;
	Описание: СТБ 34.101.31-2020 П 7.7 Алгоритм одновременного шифрования и имитозащиты ключа. Алгоритм установки защиты ключа;
	Параметры:
		x - указатель на массив байт, которые содержат ключ, на который необходимо установить защиту;
		x_len - размер защищаемого ключа;
		header - заголовок 16 байт;
		key - ключ 32 байта;
		out - указатель на массив байт, куда будет записано результирующее значение;
		out_len - размер массива, куда будет записано результирующее значение, в байтах;

	Код возврата:
		0x0000 - успех;
		0x0001 - ошибка;
*/
	int BELT_kwp_encrypt(const unsigned char *x, size_t x_len, const unsigned char header[16], const unsigned char key[32], unsigned char *out, size_t *out_len);

	/*
	Функция: BELT_kwp_decrypt;
	Описание: СТБ 34.101.31-2020 П 7.7 Алгоритм одновременного шифрования и имитозащиты ключа. Снятие защиты с защищенного ключа;
	Параметры:
		x - указатель на массив байт, содержащий ключ, с которого необходимо снять защиту;
		x_len - размер ключа, с которого необходимо снять защиту в байтах;
		header - заголовок 16 байт;
		key - ключ защиты 32 байта;
		out - указатель на массив байт, куда будет записано результирующее значение;
		out_len - размер массива, куда будет записано результирующее значение, в байтах;

	Код возврата:
		0x0000 - ошибка;
		0x0001 - успех;
*/
	int BELT_kwp_decrypt(const unsigned char *x, size_t x_len, const unsigned char header[16], const unsigned char key[32], unsigned char *out, size_t *out_len);

	//==================================================================================================================================================
	/*
	Функция: BELT_dwp_init;
	Описание: СТБ 34.101.31-2020 П 7.6 Шифрование и имитозащита данных. Инициализация;
	Параметры:
		ctx - указатель на структуру контекста;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
*/
	void BELT_dwp_init(BELT_CTX *ctx, const unsigned char key[32], const unsigned char s[16]);

	/*
	Функция: BELT_dwp_set_aad;
	Описание: СТБ 34.101.31-2020 П 7.6 Добавление открытого сообщения;
	Параметры:
		ctx - указатель на структуру контекста;
		aad - открытое сообщение;
		aad_len - размер открытого сообщения;
*/
	void BELT_dwp_set_aad(BELT_CTX *ctx, const unsigned char *aad, size_t aad_len);

	/*
	Функция: BELT_dwp_encrypt_update;
	Описание: СТБ 34.101.31-2020 П 7.6 Шифрование и имитозащита данных. Зашифровать блок данных;
	Параметры:
		ctx - указатель на структуру контекста;
		in - указатель на данные, которые необходимо зашифровать;
		in_len - размер данных в байтах;
		out - указатель на массив байт, куда будет записано результирующее значение;

*/
	void BELT_dwp_encrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out);

	/*
		Функция: BELT_dwp_decrypt_update;
		Описание: СТБ 34.101.31-2020 П 7.6 Шифрование и имитозащита данных. Расшифровать блок данных;
		Параметры:
			ctx - указатель на структуру контекста;
			in - указатель на данные, которые необходимо зашифровать;
			in_len - размер данных в байтах;
			out - указатель на массив байт, куда будет записано результирующее значение;

*/
	void BELT_dwp_decrypt_update(BELT_CTX *ctx, const unsigned char *in, size_t in_len, unsigned char *out);

	/*
	Функция: BELT_dwp_get_tag;
	Описание: СТБ 34.101.31-2020 П 7.6 Шифрование и имитозащита данных. Расшифровать блок данных;
	Параметры:
		ctx - указатель на структуру контекста;
		tag - указатель на массив байт, куда будет записана имитовставка;
		tag_len - размер данных в байтах;

*/
	void BELT_dwp_get_tag(BELT_CTX *ctx, unsigned char *tag, size_t tag_len);

	/*
	Функция: BELT_dwp_encrypt;
	Описание: СТБ 34.101.31-2020 П 7.6 Шифрование и имитозащита данных. Вычислить имитовставку и зашифровать данные;
	Параметры:
		in - указатель на данные, которые необходимо зашифровать;
		in_len - размер данных в байтах;
		i - открытое сообщение;
		i_len - размер открытого сообщения в байтах;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
		out - указатель на массив байт, куда будет записано результирующее значение;
		t - указатель на массив байт, куда будет записана имитовставка
*/
	void BELT_dwp_encrypt(
		const unsigned char *in, size_t in_len,
		const unsigned char *i, size_t i_len,
		const unsigned char theta[32], const unsigned char s[16],
		unsigned char *out, unsigned char t[8]);

	/*
	Функция: BELT_dwp_decrypt;
	Описание: СТБ 34.101.31-2020 П 7.6 Шифрование и имитозащита данных. Расшифровать сообщение и проверить имитовставку;
	Параметры:
		x - указатель на массив байт, содержащий данные, которые необходимо расшифровать;
		x_len - размер данных в байтах;
		i - открытое сообщение;
		i_len - размер открытого сообщения в байтах;
		t - указатель на массив байт, содержащиий имитовставку;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
		out - указатель на массив байт, куда будет записано результирующее сообщение;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BELT_dwp_decrypt(
		const unsigned char *x, size_t x_len,
		const unsigned char *i, size_t i_len,
		const unsigned char t[8],
		const unsigned char key[32], const unsigned char s[16],
		unsigned char *out);

	//===============================================================================================================================================
	/*
	Функция: BELT_bde_encrypt;
	Описание: СТБ 34.101.31-2020 П 7.9 Дисковое шифрование. Атомарная функция блокового зашифрования;
	Параметры:
		in - указатель на данные, которые необходимо зашифровать;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
		out - указатель на массив байт, куда будет записано результирующее сообщение;
*/
	void BELT_bde_encrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out);

	/*
	Функция: BELT_bde_decrypt;
	Описание: СТБ 34.101.31-2020 П 7.9 Дисковое шифрование. Атомарная функция блокового расшифрования;
	Параметры:
		in - указатель на данные, которые необходимо расшифровать;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
		out - указатель на массив байт, куда будет записано результирующее сообщение;
*/
	void BELT_bde_decrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out);

	//===============================================================================================================================================
	/*
	Функция: BELT_sde_encrypt;
	Описание: СТБ 34.101.31-2020 П 7.9 Дисковое шифрование. Атомарная функция секторного зашифрования;
	Параметры:
		in - указатель на данные, которые необходимо зашифровать;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
		out - указатель на массив байт, куда будет записано результирующее сообщение;
*/
	void BELT_sde_encrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out);

	/*
	Функция: BELT_sde_decrypt;
	Описание: СТБ 34.101.31-2020 П 7.9 Дисковое шифрование. Атомарная функция секторного расшифрования;
	Параметры:
		in - указатель на данные, которые необходимо расшифровать;
		in_len - размер данных в байтах;
		key - ключ 32 байта;
		s - синхропосылка 16 байт;
		out - указатель на массив байт, куда будет записано результирующее сообщение;
*/
	void BELT_sde_decrypt(const unsigned char *in, size_t in_len, const unsigned char key[32], const unsigned char s[16], unsigned char *out);

	//===============================================================================================================================================
	/*
	Функция: BELT_keyexpand;
	Описание: СТБ 34.101.31-2020 П 8.1 Служебные алгоритмы. Расширение ключа;
	Параметры:
		key - указатель на массив байт, куда будет записан результат;
		theta - ключ;
		len - размер ключа в байтах;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BELT_keyexpand(unsigned char key[32], const unsigned char *theta, int len);

	/*
	Функция: BELT_keyrep;
	Описание: Справка: СТБ 34.101.31-2020 П 8.2 Служебные алгоритмы. Преобразование ключа;
	Параметры:
		key - указатель на массив байт, содержащий ключ, который необходимо преобразовать;
		n - размер ключа в байтах (16, 24, 32);
		d - глубина ключа;
		i - заголовок;
		m - размер нового ключа в байтах (16, 24, 32);
		out - указатель на массив байт, куда будет записан результат;

	Коды возврата:
		0x0000 - успех
		0x0001 - ошибка
*/
	int BELT_keyrep(const unsigned char *key, int n, const unsigned char d[12], const unsigned char i[16], int m, unsigned char *out);

#ifdef __cplusplus
}
#endif
#endif

#endif