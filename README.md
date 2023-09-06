# AES-in-C

This library allows you to encrypt and decrypt various data.
There is support for AES-128, AES-192, and AES-256 in ECB and CBC modes.

PKCS7 Padding is used to supplement blocks, it complements only if the block is not complete, but if the block is 
complete, another augmented block will not be created.

It is also possible to generate a truly random key, but only on Windows, on Linux this function will not
work in the library. In order for this function to work, you need to connect bcrypt.dll and add define _GEN_RAND_KEY.\
Most functions have prototypes in "AES.h" in order to be able to use them separately for their needs.

To receive progress messages, define _DEBUGE