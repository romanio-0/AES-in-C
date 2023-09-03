#include <stdio.h>
#include <stdlib.h>

#include "AES.h"




int main() {
    size_t dataSize = 32;
    // данные которые надо зашифровать
    // размер массива должен быть кратен размеру блока
    byte data[255] = "1234567890123456789012345678901234";
    //

    byte key[KEY_AES_128];
    CryptData cryptData = encryptAES(data, dataSize, AES_128, AES_ECB, key);





    return 0;
}
