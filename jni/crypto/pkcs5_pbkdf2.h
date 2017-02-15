/**
 * \file md5.h
 */
#ifndef PKCS5_PBKDF2_H
#define PKCS5_PBKDF2_H



#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Output = pbkdf2 of sha1(password, salt, count, output)
 *
 * \param pass     password to be hidden
 * \param pass_len length of the password
 * \param salt     salt
 * \param salt_len length of the salt
 * \param rounds   the number of iterations
 * \param key      the output key
 * \param key_len  expected key length
 */
int
pkcs5_pbkdf2(unsigned char *pass, unsigned int pass_len, const unsigned char *salt,
        unsigned int salt_len, unsigned int rounds, unsigned char *key, unsigned int key_len);

#ifdef __cplusplus
}
#endif
#endif				/* md5.h */
