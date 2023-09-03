#ifndef _AES_H_
#define _AES_H_

#include <stdio.h>
#include <stdlib.h>


#ifdef _WIN32
#include <Windows.h>
#else // linux
#include <fcntl.h>
#include <unistd.h>
#endif


#define AES_128 0
#define AES_192 1
#define AES_256 2

#define KEY_AES_128 16
#define KEY_AES_192 24
#define KEY_AES_256 32

#define ROUND_AES_128 10
#define ROUND_AES_192 12
#define ROUND_AES_256 14

#define AES_ECB 0
#define AES_CBC 1

#define AES_BLOCK_SIZE 16

#define IV_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char byte;

typedef struct {
    size_t dataSize;
    byte* data;
}CryptData;

/**
 * Генерирует истинно случайный ключ.
 */
int keyGeneration(byte* key, int keySize);

/**
 * Функция для шифрования данных алгоритмом AES.
 *
 * @param key возвращает ключ шифрования.
 * @param versionAES устанавливает AES_128, AES_192 или AES_256.
 * @param mode устанавливает режим шифрования.
 * @return возвращает зашифрованные данные.
 */
CryptData encryptAES(byte* data, size_t dataSize, int versionAES, int modeAES, byte* key);

/**
 * Функция для шифрования данных алгоритмом AES в режиме ECB.
 *
 * @param key возвращает ключ шифрования.
 * @param versionAES устанавливает AES_128, AES_192 или AES_256.
 * @return возвращает зашифрованные данные.
 */
CryptData encryptAES_ECB(byte** dataBlock, size_t blockCount, int versionAES, byte* key);

/**
 * Функция дополняет данные, если они не кратны нужному
 * кол-ву байт используя PKCS7 Padding.
 *
 * Возвращает новый размер данных с учетом PKCS7 Padding.
 */
size_t addPadding(byte *blockData, size_t blockDataSize, const int blockSize);

/**
 * Функция удаляет PKCS7 Padding.
 *
 * Возвращает новый размер данных с учетом удаленного PKCS7 Padding.
 */
size_t delPadding(byte* data, size_t dataSize);

/**
 * Функция которая разбивает данные на нужное кол-во блоков.
 */
byte **splitDataInBlock(byte *data, size_t dataSize, const int blockSize, size_t *blockCount);

/**
 * XOR одного блока с другим
 * @return возвращает новый блок данных выделенный динамически (malloc()),
 * его размер будет зависить от наибольшего переданного блока
 */
byte* dataXOR(const byte* data1, const byte* data2, size_t dataSize1, size_t dataSize2);

/**
 * SubBytes используя таблицу S-box.
 */
void subBytes(byte* data, size_t dataSize);



#ifdef __cplusplus
}
#endif

#endif //_AES_H_
