#include <stdio.h>
#include <stdlib.h>

#include "AES.h"


int main(void) {
    size_t dataSize = 32;
    // data to be encrypted
    byte data[32] = {
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    byte key[KEY_AES_256] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                             0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    byte iv[IV_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // generation random key or iv
    /*if (keyGeneration(key, KEY_AES_128)) {
        return 1;
    }*/

    CryptData encryptData = encryptAES(data, dataSize, AES_256, AES_CBC, key, iv);

    printf("result encrypt:\n");
    for (size_t i = 1; i < encryptData.dataSize + 1; ++i) {
        printf("%02X ", encryptData.data[i - 1]);
        if (i % 16 == 0)
            printf("\n");
    }
    printf("\n\n");

    CryptData decryptData = decryptAES(encryptData.data, encryptData.dataSize, AES_256, AES_CBC, key, iv);

    printf("result decrypt:\n");
    for (size_t i = 1; i < decryptData.dataSize + 1; ++i) {
        printf("%02X ", decryptData.data[i - 1]);
        if (i % 16 == 0)
            printf("\n");
    }
    printf("\n\n");

    return 0;
}
