/**
 * \file khazad.h
 *
 * the crypto can not pass khazad_test.
 */
#ifndef KHAZAD_H
#define KHAZAD_H

#include <limits.h>

#define CRYPT_OK 0
#define CRYPT_ERROR -1

typedef signed char s8;
typedef unsigned char u8;

#if UINT_MAX >= 4294967295UL

typedef signed short s16;
typedef signed int s32;
typedef unsigned short u16;
typedef unsigned int u32;

#define ONE32   0xffffffffU

#else

typedef signed int s16;
typedef signed long s32;
typedef unsigned int u16;
typedef unsigned long u32;

#define ONE32   0xffffffffUL

#endif

#define R      8

typedef struct _khazad_key {
    u32 roundKeyEnc[R + 1][2];
    u32 roundKeyDec[R + 1][2];
} khazad_key;

/**
 * Create the Khazad key schedule for a given cipher key.
 * Both encryption and decryption key schedules are generated.
 *
 * @param key           The 128-bit cipher key.
 * @param structpointer Pointer to the structure that will hold the expanded key.
 */
void khazad_setup(const unsigned char * const key, khazad_key * const structpointer);

/**
 * Encrypt a data block.
 *
 * @param   structpointer   the expanded key.
 * @param   plaintext       the data block to be encrypted.
 * @param   ciphertext      the encrypted data block.
 */
void khazad_ecb_encrypt(const khazad_key * const structpointer, const unsigned char * const plaintext,
        unsigned char * const ciphertext);

/**
 * Decrypt a data block.
 *
 * @param   structpointer   the expanded key.
 * @param   ciphertext      the data block to be decrypted.
 * @param   plaintext       the decrypted data block.
 */
void khazad_ecb_decrypt(const khazad_key * const structpointer, const unsigned char * const ciphertext,
        unsigned char * const plaintext);

int khazad_test(void);

#endif				/* khazad.h */
