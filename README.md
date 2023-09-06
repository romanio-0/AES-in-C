# AES-in-C

This library allows you to encrypt and decrypt various data.
There is support for AES-128, AES-192, and AES-256 in ECB and CBC modes.

PKCS7 Padding is used to supplement blocks, it complements only if the block is not complete, but if the block is 
complete, another augmented block will not be created.

It is also possible to generate a truly random key, but only on Windows, on Linux this function will not
work in the library. In order for this function to work, you need to connect bcrypt.dll and add define _GEN_RAND_KEY.\
Most functions have prototypes in "AES.h" in order to be able to use them separately for their needs.

To receive progress messages, define _DEBUGE

There is a testMain.c file in which an example of the algorithm's operation is implemented.
___
## Main metods:

**-** **`CryptData encryptAES(byte *data, size_t dataSize, VersionAES version, ModeAES mode, byte *key, byte *iv)`** - the main function that encrypts data.
#### param:
    byte *data - accepts data to be encrypted.
    size_t dataSize - takes the size of the transferred data.
    VersionAES version - you need to pass the version of AES that should be used (AES-128, AES-192, AES-256).
    ModeAES mode - you need to pass the encryption mode that should be used (ECB or CBC).
    byte *key - accepts a key to encrypt data.
    byte *iv - accepts an initialization vector to encrypt data in CBC mode, if you are using a mode that doesn't need it then use NULL.

**-** **`CryptData decryptAES(byte *data, size_t dataSize, VersionAES version, ModeAES mode, byte *key, byte *iv)`** - the main function that decrypts data.
#### param:
    byte *data - accepts data to be decrypted.
    size_t dataSize - takes the size of the transferred data.
    VersionAES version - you need to pass the version of AES that should be used (AES-128, AES-192, AES-256).
    ModeAES mode - you need to pass the decryption mode that should be used (ECB or CBC).
    byte *key - accepts a key to decrypt data.
    byte *iv - accepts an initialization vector to decrypt data in CBC mode, if you are using a mode that doesn't need it then use NULL.
    
    return {0, NULL} - returns structures with empty data if the transmitted encrypted data is not a multiple of 16 bytes or there is no IV when using CBC mode.
___
