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

typedef enum {
    AES_128,
    AES_192,
    AES_256
} VersionAES;

typedef enum {
    AES_ECB,
    AES_CBC
} ModeAES;

#define KEY_AES_128 16
#define KEY_AES_192 24
#define KEY_AES_256 32

#define ROUND_AES_128 10
#define ROUND_AES_192 12
#define ROUND_AES_256 14

#define ROUND_KEY_AES_128 44
#define ROUND_KEY_AES_192 52
#define ROUND_KEY_AES_256 60

#define AES_BLOCK_SIZE 16

#define IV_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char byte;
typedef unsigned long word;

typedef struct {
    size_t dataSize;
    byte *data;
} CryptData;

/**
 * Генерирует истинно случайный ключ.
 */
int keyGeneration(byte *key, int keySize);

/**
 * Функция для шифрования данных алгоритмом AES.
 *
 * @param key возвращает ключ шифрования.
 * @param version устанавливает AES_128, AES_192 или AES_256.
 * @param mode устанавливает режим шифрования.
 * @return возвращает зашифрованные данные.
 */
CryptData encryptAES(byte *data, size_t dataSize, VersionAES version, ModeAES mode, byte *key);

/**
 * Функция для шифрования данных алгоритмом AES в режиме ECB.
 *
 * @param key возвращает ключ шифрования.
 * @param version устанавливает AES_128, AES_192 или AES_256.
 * @param data приниемает данные и защифровывает их. *
 */
void encryptAES_ECB(byte **data, size_t blockCount, VersionAES version, byte *key);

/**
 * Функция дополняет данные, если они не кратны нужному
 * кол-ву байт используя PKCS7 Padding.
 *
 * Возвращает новый размер данных с учетом PKCS7 Padding.
 */
size_t addPadding(byte *blockData, size_t blockDataSize);

/**
 * Функция удаляет PKCS7 Padding.
 *
 * Возвращает новый размер данных с учетом удаленного PKCS7 Padding.
 */
size_t delPadding(byte *data, size_t dataSize);

/**
 * Функция которая разбивает данные на нужное кол-во блоков.
 */
byte **splitDataInBlock(byte *data, size_t dataSize, size_t *blockCount);

/**
 * Обьеденяет блоки в один поток данных.
 */
byte *mergerBlockInData(byte** blockData, size_t blockCount);

/**
 * Set the block values, for the block: \n
 * a0,0 a0,1 a0,2 a0,3\n
 * a1,0 a1,1 a1,2 a1,3\n
 * a2,0 a2,1 a2,2 a2,3\n
 * a3,0 a3,1 a3,2 a3,3\n
 * the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
 */
byte* expandBlock(byte *data);

/**
 * Return the block to its original state.
 */
byte* backExpandBlock(byte *data);

/**
 * XOR одного блока с другим.
 * @return возвращает новый блок данных выделенный динамически (malloc()),
 * его размер будет зависить от наибольшего переданного блока.
 */
byte *dataXOR(const byte *data1, const byte *data2, size_t dataSize1, size_t dataSize2);

/**
 * SubBytes используя таблицу S-box.
 */
void subBytes(byte *data, size_t dataSize);

/**
 * Adding a Round Key to a Data Block.
 */
void addRoundKey(byte *data, word *roundKey);

/**
 * Rotates the string to the left.
 * The amount of blending depends on the row number.
 */
void shiftRows(byte *data);

/**
 * Функция берёт все столбцы State и смешивает их данные
 * (независимо друг от друга), чтобы получить новые столбцы.
 */
void mixColumns(byte* data);

/**
 * Function inverse of MixColumns.
 */
void invMixColumns(byte *data);

/**
 * Key expansion для создание раундового ключа.
 * Размер ключа зависит от версии AES:
 * 128 - 44 байта
 * 192 - 52 байта
 * 256 - 60 байт
 */
void keyExpansion(const byte *key, word *roundKey, VersionAES versionAES);

/**
 * SubWord импользуя таблицу S-box.
 */
word subWord(word keyWord);

/**
 * Функция для выполнения циклического сдвига 32-битного слова влево на один байт.
 */
word rotWord(word keyWord);


#ifdef __cplusplus
}
#endif

#endif //_AES_H_
