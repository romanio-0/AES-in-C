#include <stdio.h>
#include <stdlib.h>

#include "AES.h"


int main(void) {
    size_t dataSize = 32;
    // данные которые надо зашифровать
    // размер массива должен быть кратен размеру блока
    /*byte data[255] = {
            0x10,0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10,0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10
    };*/
    byte data[255] = "0123456789ABCDEF0123456789ABCDEF";
    //

    /*byte key[KEY_AES_256] = {0x00,0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                             0x00,0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};*/
    byte key[KEY_AES_128] = "1234567890123456";
    byte iv[KEY_AES_128] = "1234567890123456";

    /*if (keyGeneration(key, KEY_AES_128)) {
        return 1;
    }*/

    /**
     * надо обработчик ошибок
     */


    CryptData cryptData = encryptAES(data, dataSize, AES_128, AES_CBC, key, iv);


    printf("vse:\n");
    for (size_t i = 1; i < cryptData.dataSize + 1; ++i) {
        printf("%02X ", cryptData.data[i - 1]);
        if (i % 16 == 0)
            printf("\n");
    }
    printf("\n\n");

    cryptData = decryptAES(cryptData.data, cryptData.dataSize, AES_128, AES_CBC, key, iv);


    printf("vse:\n");
    for (size_t i = 1; i < cryptData.dataSize + 1; ++i) {
        printf("%02X ", cryptData.data[i - 1]);
        if (i % 16 == 0)
            printf("\n");
    }
    printf("\n\n");


    return 0;
}
