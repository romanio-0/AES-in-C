#include "AES.h"

// the number of 32-bit words that make up the encryption key,
// for AES Nk = 4, 6, or 8
#define NK_128 4
#define NK_192 6
#define NK_256 8

#define NB 4

// number of rounds, which is a function of Nk and Nb. For AES Nr = 10, 12, 14
#define NR_128 ROUND_AES_128
#define NR_192 ROUND_AES_192
#define NR_256 ROUND_AES_256

static const int NkAES[] = {
        NK_128,
        NK_192,
        NK_256
};

static const int keySizeAES[] = {
        KEY_AES_128,
        KEY_AES_192,
        KEY_AES_256
};

static const int NrAES[] = {
        NR_128,
        NR_192,
        NR_256
};

static const byte Sbox[] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const word Rcon[] = {0x00, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                            0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

#ifdef _WIN32

int keyGeneration(byte *key, int keySize) {
    if (CryptAcquireContext(NULL, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptGenRandom(0, keySize, key)) {
            // key generated
            return 1; //true
        }
    }

    // key generation error
    return 0; //false
}

#else // linux
int keyGeneration(byte* key, int keySize){
    int randomFile = open("/dev/urandom", O_RDONLY);
    if (randomFile < 0) {
        //failed open file
        return 0; //false
    }

    if (read(randomFile, key, keySize) != keySize) {
        // key generation error
        close(randomFile);
        return 0; //false
    }

    // key generated
    close(randomFile);
    return 1; //true
}
#endif

CryptData encryptAES(byte *data, size_t dataSize, VersionAES versionAES, ModeAES mode, byte *key) {
    size_t blockCount = 0;
    int keySize = keySizeAES[versionAES];

    dataSize = addPadding(data, dataSize, AES_BLOCK_SIZE);

    byte **blockData = splitDataInBlock(data, dataSize, AES_BLOCK_SIZE, &blockCount);

    if (!keyGeneration(key, keySize)) {
        return (CryptData) {0, NULL};
    }


}


CryptData encryptAES_ECB(byte **dataBlock, size_t blockCount, VersionAES version, byte *key) {

}


size_t addPadding(byte *blockData, size_t blockDataSize) {
    if (blockDataSize % AES_BLOCK_SIZE == 0) {
        // if padding is not needed
        return blockDataSize;
    }
    byte valuePadding = AES_BLOCK_SIZE - (blockDataSize % AES_BLOCK_SIZE);
    for (size_t i = 0; i < valuePadding; ++i) {
        blockData[blockDataSize + i] = valuePadding;
    }

    return blockDataSize + valuePadding;
}


size_t delPadding(byte *data, size_t dataSize) {
    byte valuePadding = data[dataSize - 1];
    for (size_t i = dataSize - valuePadding; i < dataSize; ++i) {
        if (data[i] != valuePadding) {
            // invalid padding
            return dataSize;
        }
    }
    for (size_t i = dataSize - valuePadding; i < dataSize; ++i) {
        data[i] = 0;
    }

    return dataSize - valuePadding;
}


byte **splitDataInBlock(byte *data, size_t dataSize, size_t *blockCount) {
    // if the data is not a multiple of the block size, then it will be padded
    *blockCount = dataSize / AES_BLOCK_SIZE;
    byte **blockData = malloc(sizeof(void *) * (*blockCount));
    for (size_t i = 0; i < *blockCount; ++i) {
        blockData[i] = malloc(AES_BLOCK_SIZE);
        for (int j = 0; j < AES_BLOCK_SIZE; ++j) {
            blockData[i][j] = data[(AES_BLOCK_SIZE * i) + j];
        }
    }

    return blockData;
}


byte *dataXOR(const byte *data1, const byte *data2, size_t dataSize1, size_t dataSize2) {
    size_t maxSize = dataSize1 > dataSize2 ? dataSize1 : dataSize2;
    byte *dataNew = malloc(maxSize);

    if (dataSize1 > dataSize2) {
        for (size_t i = 0; i < dataSize2; ++i) {
            dataNew[i] = data1[i] ^ data2[i];
        }
        for (size_t i = dataSize2; i < maxSize; ++i) {
            dataNew[i] = data1[i];
        }
    } else {
        for (size_t i = 0; i < dataSize1; ++i) {
            dataNew[i] = data1[i] ^ data2[i];
        }
        for (size_t i = dataSize1; i < maxSize; ++i) {
            dataNew[i] = data2[i];
        }
    }

    return dataNew;
}


void subBytes(byte *data, size_t dataSize) {
    for (int i = 0; i < dataSize; ++i) {
        data[i] = Sbox[data[i]];
    }
}


void addRoundKey(byte *data, word *roundKey) {
    byte byteRoundKey[AES_BLOCK_SIZE] = {0};
    for (int i = 0; i < NB; ++i) {
        byteRoundKey[i * 4 + 0] = ((byte) (roundKey[i] >> 24));
        byteRoundKey[i * 4 + 1] = ((byte) (roundKey[i] >> 16));
        byteRoundKey[i * 4 + 2] = ((byte) (roundKey[i] >> 8));
        byteRoundKey[i * 4 + 3] = ((byte) (roundKey[i]));
    }
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        data[i] ^= byteRoundKey[i];
    }
}


void shiftRows(byte *data) {
    for (int rows = 0; rows < NB; ++rows) {
        byte tmp;
        for (int i = 0; i < rows; ++i) {
            for (int j = 0; j < NB - 1; ++j) {
                tmp = data[rows * NB + j];
                data[rows * NB + j] = data[rows * NB + j + 1];
                data[rows * NB + j + 1] = tmp;
            }
        }
    }
}


byte multiplyAES(byte a, byte b) {
    byte result = 0;
    byte carry;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }
        carry = a & 0x80;
        a <<= 1;
        if (carry) {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    return result;
}

/**
 * a function that mixes the data of one column for the mixColumns/invMixColumns function
 */
void mixColumn(byte *data, byte *mixMatrix) {
    byte dataCpy[4];
    for (int i = 0; i < 4; i++) {
        dataCpy[i] = data[i];
    }
    data[0] = multiplyAES(dataCpy[0], mixMatrix[0]) ^
              multiplyAES(dataCpy[3], mixMatrix[1]) ^
              multiplyAES(dataCpy[2], mixMatrix[2]) ^
              multiplyAES(dataCpy[1], mixMatrix[3]);

    data[1] = multiplyAES(dataCpy[1], mixMatrix[4]) ^
              multiplyAES(dataCpy[0], mixMatrix[5]) ^
              multiplyAES(dataCpy[3], mixMatrix[6]) ^
              multiplyAES(dataCpy[2], mixMatrix[7]);

    data[2] = multiplyAES(dataCpy[2], mixMatrix[8]) ^
              multiplyAES(dataCpy[1], mixMatrix[9]) ^
              multiplyAES(dataCpy[0], mixMatrix[10]) ^
              multiplyAES(dataCpy[3], mixMatrix[11]);

    data[3] = multiplyAES(dataCpy[3], mixMatrix[12]) ^
              multiplyAES(dataCpy[2], mixMatrix[13]) ^
              multiplyAES(dataCpy[1], mixMatrix[14]) ^
              multiplyAES(dataCpy[0], mixMatrix[15]);
}


void mixColumns(byte *data) {
    byte mixMatrix[] = {0x02, 0x03, 0x01, 0x01, 0x01, 0x02, 0x03, 0x01,
                        0x01, 0x01, 0x02, 0x03, 0x03, 0x01, 0x01, 0x02};

    byte dataCol[NB];

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j){
            dataCol[j] = data[j * 4 + i];
        }

        // apply the MixColumn on one column
        mixColumn(dataCol, mixMatrix);

        for (int j = 0; j < 4; ++j){
            data[j * 4 + i] = dataCol[j];
        }
    }
}


void invMixColumns(byte *data) {
    byte mixMatrix[] = {0x0e, 0x0b, 0x0d, 0x09, 0x09, 0x0e, 0x0b, 0x0d,
                        0x0d, 0x09, 0x0e, 0x0b, 0x0b, 0x0d, 0x09, 0x0e};

    byte dataCol[NB];

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j){
            dataCol[j] = data[j * 4 + i];
        }

        // apply the MixColumn on one column
        mixColumn(dataCol, mixMatrix);

        for (int j = 0; j < 4; ++j){
            data[j * 4 + i] = dataCol[j];
        }
    }
}


void keyExpansion(const byte *key, word *roundKey, VersionAES versionAES) {
    int Nk = NkAES[versionAES];
    int Nr = NrAES[versionAES];

    // copy the original key to the beginning of the extended key
    for (int i = 0; i < Nk; i++) {
        roundKey[i] = ((word) key[4 * i] << 24) |
                      ((word) key[4 * i + 1] << 16) |
                      ((word) key[4 * i + 2] << 8) |
                      ((word) key[4 * i + 3]);
    }

    // key expansion is performed here
    for (int i = Nk; i < NB * (Nr + 1); i++) {
        word temp = roundKey[i - 1];
        if (i % Nk == 0) {
            temp = subWord(rotWord(temp)) ^ Rcon[i / Nk];
        } else if ((Nk == NK_192) & (i % Nk == 4)) {
            temp = subWord(temp);
        }
        roundKey[i] = roundKey[i - Nk] ^ temp;
    }
}


word subWord(word keyWord) {
    word result = 0;
    for (int i = 0; i < NB; i++) {
        result |= (Sbox[(keyWord >> (i * 8)) & 0xFF] << (i * 8));
    }
    return result;
}


word rotWord(word keyWord) {
    return ((keyWord << 8) | (keyWord >> 24));
}
