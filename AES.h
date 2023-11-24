/*
 * AES crypter
 *
 * This library allows you to encrypt and decrypt various data.
 * There is support for AES-128, AES-192, and AES-256 in ECB and CBC modes.
 *
 * PKCS7 Padding is used to supplement blocks, it complements only if the block is not complete,
 * but if the block is complete, another augmented block will not be created.
 *
 * It is also possible to generate a truly random key, but only on Windows, on Linux this function will not work
 * in the library. In order for this function to work, you need to connect bcrypt.dll and add define _GEN_RAND_KEY.
 *
 * Most functions have prototypes in "AES.h" in order to be able to use them separately for their needs
 *
 * To receive progress messages, define _DEBUGE
 */
#ifndef _AES_H_
#define _AES_H_

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#endif // _WIN32

//#define _DEBUG

#ifdef _DEBUG
#define _print(msg, ...) printf(msg, ## __VA_ARGS__)
#define _forprint(msg, doI, j, data) for(size_t i = 1; i < doI + 1; ++i){   \
                                        _print(msg, data[i - 1]);           \
                                        if (i % j == 0)                     \
                                            _print("\n");                   \
                                     }                                      \
                                     printf("\n");
#else // _DEBUG
#define _print(msg, ...)
#define _forprint(msg, doI, j, ...)
#endif


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

typedef enum {
    AES_128,
    AES_192,
    AES_256
} VersionAES;

typedef enum {
    AES_ECB,
    AES_CBC
} ModeAES;

typedef unsigned char byte;
typedef unsigned long word;
typedef const char* lpcstr;

typedef struct {
    long long dataSize;
    byte *data;
} CryptData;

//static lpcstr errMsg = "NULL";
//
///**
// * Function to get error information.
// */
//lpcstr getErrMsg();
//
///**
// * Function to set error information.
// */
//void setErrMsg(lpcstr msg);


#if defined(_WIN32) && defined(_GEN_RAND_KEY)
#pragma comment(lib, "bcrypt.lib");
/**
 * Generates a truly random key.
 */
int keyGeneration(byte *key, int keySize);
#endif // defined(_WIN32) && defined(_RAND_KEY_)

/**
 * A function for decrypting data with the AES algorithm.
 *
 * @param key accepts the encryption key.
 * @param iv accepts an initialization vector, if you use the mode without its support, then use NULL.
 * @param version sets AES_128, AES_192 or AES_256.
 * @param mode sets the encryption mode.
 * @return returns decrypted data.
 * @return returns structures with empty data if the transmitted encrypted data is not a multiple of 16 bytes or there is no IV when using CBC mode.
 */
CryptData* decryptAES(byte *data, size_t dataSize, VersionAES version, ModeAES mode, byte *key, byte* iv);

/**
 * A function to decrypt data with the AES algorithm in ECB mode.
 *
 * @param key returns the encryption key.
 * @param version sets AES_128, AES_192 or AES_256.
 * @param data takes data and decrypts it.
 */
void decryptAES_ECB(byte **data, size_t blockCount, VersionAES version, byte *key);

/**
 * A function for decrypting data with the AES algorithm in CBC mode.
 *
 * @param key returns the encryption key.
 * @param version sets AES_128, AES_192 or AES_256.
 * @param data takes data and decrypts it.
 */
void decryptAES_CBC(byte **data, size_t blockCount, VersionAES version, byte *key, byte *iv);

/**
 * A function to encrypt data with the AES algorithm.
 *
 * @param key takes the encryption key.
 * @param iv accepts initialization vector if using mode
 * without its support, then use NULL.
 * @param version sets AES_128, AES_192 or AES_256.
 * @param mode sets the encryption mode.
 * @return returns encrypted data.
 */
CryptData encryptAES(byte *data, size_t dataSize, VersionAES version, ModeAES mode, byte *key, byte *iv);

/**
 * Function to encrypt data with AES algorithm in ECB mode.
 *
 * @param key returns the encryption key.
 * @param version sets AES_128, AES_192 or AES_256.
 * @param data takes data and encrypts it.
 */
void encryptAES_ECB(byte **data, size_t blockCount, VersionAES version, byte *key);

/**
 * Function to encrypt data with AES algorithm in CBC mode.
 *
 * @param key returns the encryption key.
 * @param version sets AES_128, AES_192 or AES_256.
 * @param data takes data and encrypts it.
 */
void encryptAES_CBC(byte **data, size_t blockCount, VersionAES version, byte *key, byte *iv);

/**
 * The function completes the data if it is not a multiple of the required one.
 * number of bytes using PKCS7 Padding.
 *
 * Returns the new data size with PKCS7 Padding.
 */
byte* addPadding(byte *blockData, size_t* blockDataSize);

/**
 * The function removes PKCS7 Padding.
 *
 * Returns the new data size given the removed PKCS7 Padding.
 */
size_t delPadding(byte *data, size_t dataSize);

/**
 * A function that splits the data into the desired number of blocks.
 */
byte **splitDataInBlock(byte *data, size_t dataSize, size_t *blockCount);

/**
 * combinesBlocksIntoOneDataStream
 */
byte *mergerBlockInData(byte **blockData, size_t blockCount);

/**
 * Set the block values, for the block: \n
 * a0,0 a0,1 a0,2 a0,3\n
 * a1,0 a1,1 a1,2 a1,3\n
 * a2,0 a2,1 a2,2 a2,3\n
 * a3,0 a3,1 a3,2 a3,3\n
 * the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
 */
byte *expandBlock(byte *data);

/**
 * Return the block to its original state.
 */
byte *backExpandBlock(byte *data);

/**
 * XOR one block with another.
 * @return returns a new block of data allocated dynamically (malloc()),
 * its size will depend on the largest transmitted block.
 */
byte *dataXOR(const byte *data1, const byte *data2, size_t dataSize1, size_t dataSize2);

/**
 * SubBytes using table S-box.
 */
void subBytes(byte *data, size_t dataSize);

/**
 * InvSubBytes используя таблицу InvS-box.
 */
void invSubBytes(byte *data, size_t dataSize);

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
 * Rotates the string to the left.
 * The amount of blending depends on the row number.
 */
void invShiftRows(byte *data);

/**
 * The function takes all the State columns and mixes their data
 * (independently of each other) to get new columns.
 */
void mixColumns(byte *data);

/**
 * Function inverse of MixColumns.
 */
void invMixColumns(byte *data);

/**
 * Key expansion to create a round key.
 * Key size depends on AES version:
 * 128 - 44 байта
 * 192 - 52 байта
 * 256 - 60 байт
 */
void keyExpansion(const byte *key, word *roundKey, VersionAES versionAES);

/**
 * SubWord using table S-box.
 */
word subWord(word keyWord);

/**
 * A function to rotate a 32-bit word left by one byte.
 */
word rotWord(word keyWord);


#ifdef __cplusplus
}
#endif

#endif //_AES_H_
