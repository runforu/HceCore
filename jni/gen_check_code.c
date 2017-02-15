/*
 *
 *  Copyright (C) 2006-2007  Du Hui
 *
 *  generate c code for APK checking
 *  Calculate the given signature from sig file by some crypto methods, and write the result to static.c file
 *  static.c file is used by native_impl.c file which do runtime check to see the hosted APK's signature
 *  is the same with that given by static.c
 *  The code assure that the APK is not modified or recompiled.
 *
 */

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>

#define	MINIMUM(a,b) (((a) < (b)) ? (a) : (b))
#define SHA1_DIGEST_LENGTH 20

typedef struct {
    unsigned long total[2]; /*!< number of bytes processed  */
    unsigned long state[5]; /*!< intermediate digest state  */
    unsigned char buffer[64]; /*!< data block being processed */

    unsigned char ipad[64]; /*!< HMAC: inner padding        */
    unsigned char opad[64]; /*!< HMAC: outer padding        */
} sha1_context;

/*
 *  The SHA-1 standard was published by NIST in 1993.
 *
 *  http://www.itl.nist.gov/fipspubs/fip180-1.htm
 */

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n, b, i)				\
{							\
	(n) = ((unsigned long)(b)[(i)    ] << 24)	\
	    | ((unsigned long)(b)[(i) + 1] << 16)	\
	    | ((unsigned long)(b)[(i) + 2] <<  8)	\
	    | ((unsigned long)(b)[(i) + 3]      );	\
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n, b, i)				\
{							\
	(b)[(i)    ] = (unsigned char)((n) >> 24);	\
	(b)[(i) + 1] = (unsigned char)((n) >> 16);	\
	(b)[(i) + 2] = (unsigned char)((n) >>  8);	\
	(b)[(i) + 3] = (unsigned char)((n)      );	\
}
#endif

/*
 * SHA-1 context setup
 */
void sha1_starts(sha1_context *ctx) {
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

static void sha1_process(sha1_context *ctx, unsigned char data[64]) {
    unsigned long temp, W[16], A, B, C, D, E;

    GET_ULONG_BE(W[0], data, 0);
    GET_ULONG_BE(W[1], data, 4);
    GET_ULONG_BE(W[2], data, 8);
    GET_ULONG_BE(W[3], data, 12);
    GET_ULONG_BE(W[4], data, 16);
    GET_ULONG_BE(W[5], data, 20);
    GET_ULONG_BE(W[6], data, 24);
    GET_ULONG_BE(W[7], data, 28);
    GET_ULONG_BE(W[8], data, 32);
    GET_ULONG_BE(W[9], data, 36);
    GET_ULONG_BE(W[10], data, 40);
    GET_ULONG_BE(W[11], data, 44);
    GET_ULONG_BE(W[12], data, 48);
    GET_ULONG_BE(W[13], data, 52);
    GET_ULONG_BE(W[14], data, 56);
    GET_ULONG_BE(W[15], data, 60);

#define S(x, n)	(((x) << (n)) | (((x) & 0xFFFFFFFF) >> (32 - (n))))

#define R(t)							\
(								\
	temp = W[((t) -  3) & 0x0F] ^ W[((t) - 8) & 0x0F] ^	\
	       W[((t) - 14) & 0x0F] ^ W[ (t)      & 0x0F],	\
	(W[(t) & 0x0F] = S(temp, 1))				\
)

#define P(a, b, c, d, e, x)                                  	\
{                                                       	\
	e += S(a, 5) + F(b, c, d) + K + (x); b = S(b, 30);	\
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];

#define F(x, y, z)	((z) ^ ((x) & ((y) ^ (z))))
#define K		0x5A827999

    P(A, B, C, D, E, W[0]);
    P(E, A, B, C, D, W[1]);
    P(D, E, A, B, C, W[2]);
    P(C, D, E, A, B, W[3]);
    P(B, C, D, E, A, W[4]);
    P(A, B, C, D, E, W[5]);
    P(E, A, B, C, D, W[6]);
    P(D, E, A, B, C, W[7]);
    P(C, D, E, A, B, W[8]);
    P(B, C, D, E, A, W[9]);
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x, y, z)	((x) ^ (y) ^ (z))
#define K		0x6ED9EBA1

    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x, y, z)	(((x) & (y)) | ((z) & ((x) | (y))))
#define K		0x8F1BBCDC

    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));

#undef K
#undef F

#define F(x, y, z)	((x) ^ (y) ^ (z))
#define K		0xCA62C1D6

    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));

#undef K
#undef F

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
}

/*
 * SHA-1 process buffer
 */
void sha1_update(sha1_context *ctx, unsigned char *input, int ilen) {
    int fill;
    unsigned long left;

    if (ilen <= 0)
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if (ctx->total[0] < (unsigned long) ilen)
        ctx->total[1]++;

    if (left && ilen >= fill) {
        memcpy((void *) (ctx->buffer + left), (void *) input, fill);
        sha1_process(ctx, ctx->buffer);
        input += fill;
        ilen -= fill;
        left = 0;
    }

    while (ilen >= 64) {
        sha1_process(ctx, input);
        input += 64;
        ilen -= 64;
    }

    if (ilen > 0) {
        memcpy((void *) (ctx->buffer + left), (void *) input, ilen);
    }
}

static const unsigned char sha1_padding[64] = { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0 };

/*
 * SHA-1 final digest
 */
void sha1_finish(sha1_context *ctx, unsigned char output[20]) {
    unsigned long last, padn;
    unsigned long high, low;
    unsigned char msglen[8];

    high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    low = (ctx->total[0] << 3);

    PUT_ULONG_BE(high, msglen, 0);
    PUT_ULONG_BE(low, msglen, 4);

    last = ctx->total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    sha1_update(ctx, (unsigned char *) sha1_padding, padn);
    sha1_update(ctx, msglen, 8);

    PUT_ULONG_BE(ctx->state[0], output, 0);
    PUT_ULONG_BE(ctx->state[1], output, 4);
    PUT_ULONG_BE(ctx->state[2], output, 8);
    PUT_ULONG_BE(ctx->state[3], output, 12);
    PUT_ULONG_BE(ctx->state[4], output, 16);
}

/*
 * output = SHA-1(input buffer)
 */
void sha1(unsigned char *input, int ilen, unsigned char output[20]) {
    sha1_context ctx;

    sha1_starts(&ctx);
    sha1_update(&ctx, input, ilen);
    sha1_finish(&ctx, output);

    memset(&ctx, 0, sizeof(sha1_context));
}

/*
 * output = SHA-1(file contents)
 */
int sha1_file(char *path, unsigned char output[20]) {
    FILE *f;
    unsigned int n;
    sha1_context ctx;
    unsigned char buf[1024];

    if ((f = fopen(path, "rb")) == NULL)
        return (1);

    sha1_starts(&ctx);

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha1_update(&ctx, buf, (int) n);

    sha1_finish(&ctx, output);

    memset(&ctx, 0, sizeof(sha1_context));

    if (ferror(f) != 0) {
        fclose(f);
        return (2);
    }

    fclose(f);
    return (0);
}

/*
 * SHA-1 HMAC context setup
 */
void sha1_hmac_starts(sha1_context *ctx, unsigned char *key, int keylen) {
    int i;
    unsigned char sum[20];

    if (keylen > 64) {
        sha1(key, keylen, sum);
        keylen = 20;
        key = sum;
    }

    memset(ctx->ipad, 0x36, 64);
    memset(ctx->opad, 0x5C, 64);

    for (i = 0; i < keylen; i++) {
        ctx->ipad[i] = (unsigned char) (ctx->ipad[i] ^ key[i]);
        ctx->opad[i] = (unsigned char) (ctx->opad[i] ^ key[i]);
    }

    sha1_starts(ctx);
    sha1_update(ctx, ctx->ipad, 64);

    memset(sum, 0, sizeof(sum));
}

/*
 * SHA-1 HMAC process buffer
 */
void sha1_hmac_update(sha1_context *ctx, unsigned char *input, int ilen) {
    sha1_update(ctx, input, ilen);
}

/*
 * SHA-1 HMAC final digest
 */
void sha1_hmac_finish(sha1_context *ctx, unsigned char output[20]) {
    unsigned char tmpbuf[20];

    sha1_finish(ctx, tmpbuf);
    sha1_starts(ctx);
    sha1_update(ctx, ctx->opad, 64);
    sha1_update(ctx, tmpbuf, 20);
    sha1_finish(ctx, output);

    memset(tmpbuf, 0, sizeof(tmpbuf));
}

/*
 * output = HMAC-SHA-1(hmac key, input buffer)
 */
void sha1_hmac(unsigned char *key, int keylen, unsigned char *input, int ilen, unsigned char output[20]) {
    sha1_context ctx;

    sha1_hmac_starts(&ctx, key, keylen);
    sha1_hmac_update(&ctx, input, ilen);
    sha1_hmac_finish(&ctx, output);

    memset(&ctx, 0, sizeof(sha1_context));
}

/*
 * Password-Based Key Derivation Function 2 (PKCS #5 v2.0).
 * Code based on IEEE Std 802.11-2007, Annex H.4.2.
 */
int pkcs5_pbkdf2(unsigned char *pass, unsigned int pass_len, const unsigned char *salt, unsigned int salt_len,
        unsigned int rounds, unsigned char *key, unsigned int key_len) {
    uint8_t *asalt, obuf[SHA1_DIGEST_LENGTH];
    uint8_t d1[SHA1_DIGEST_LENGTH], d2[SHA1_DIGEST_LENGTH];
    unsigned int i, j;
    unsigned int count;
    unsigned int r;

    if (rounds < 1 || key_len == 0)
        return -1;
    if (salt_len == 0 || salt_len > SIZE_MAX - 4)
        return -1;
    if ((asalt = malloc(salt_len + 4)) == NULL)
        return -1;

    memcpy(asalt, salt, salt_len);

    for (count = 1; key_len > 0; count++) {
        asalt[salt_len + 0] = (count >> 24) & 0xff;
        asalt[salt_len + 1] = (count >> 16) & 0xff;
        asalt[salt_len + 2] = (count >> 8) & 0xff;
        asalt[salt_len + 3] = count & 0xff;
        sha1_hmac(pass, pass_len, asalt, salt_len + 4, d1);
        memcpy(obuf, d1, sizeof(obuf));

        for (i = 1; i < rounds; i++) {
            sha1_hmac(pass, pass_len, d1, sizeof(d1), d2);
            memcpy(d1, d2, sizeof(d1));
            for (j = 0; j < sizeof(obuf); j++)
                obuf[j] ^= d1[j];
        }

        r = MINIMUM(key_len, SHA1_DIGEST_LENGTH);
        memcpy(key, obuf, r);
        key += r;
        key_len -= r;
    };
    free(asalt);

    return 0;
}

static char table[127] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0, 0, 0, 0,
        0, 0, 0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

char* hex_string_to_byte_array(const char *string, char* out, int len) {
    if (strlen(string) % 2 != 0) {
        return out;
    }
    char* q = out;
    for (const char* p = string; p < string + len * 2 && p < string + strlen(string); p += 2, q++) {
        *q = (table[*p] << 4) + table[*(p + 1)];
    }
    return out;
}

void byte_array_to_hex_string(char* bytes, int len, char* output) {
    char* q = bytes;
    char* hex_table = "0123456789ABCDEF";
    for (int i = 0; i < len; i++) {
        output[i * 2] = hex_table[(bytes[i] >> 4) & 0x0F];
        output[i * 2 + 1] = hex_table[bytes[i] & 0x0F];
    }
    output[len * 2] = 0;
}

int fio_write(const char* file_path, const char* buffer, unsigned int size) {
    if (file_path == NULL || buffer == NULL || size < 1) {
        return -1;
    }
    FILE * file;
    file = fopen(file_path, "w");
    if (file == NULL) {
        return -1;
    }
    int count = fwrite(buffer, 1, size, file);
    fclose(file);
    return count;
}

int fio_read(const char* file_path, char* buffer, unsigned int max_size) {
    if (file_path == NULL || buffer == NULL || max_size < 1) {
        return -1;
    }
    FILE * file;
    file = fopen(file_path, "rb");
    if (file == NULL) {
        return -1;
    }
    int count = fread(buffer, 1, max_size, file);
    fclose(file);
    return count;
}

void convert_to_big_endian(int* array, int* out, int size) {
    int i = 1;
    char *cp = (char *) &i;
    if (*cp) {
        for (int i = 0; i < size; i++) {
            int tmp = array[i];
            unsigned char *p = (unsigned char*) &tmp;
            out[i] = (((unsigned int) *p << 24) + ((unsigned int) *(p + 1) << 16) + ((unsigned int) *(p + 2) << 8)
                    + (unsigned int) *(p + 3));
        }
    } else {
        for (int i = 0; i < size; i++) {
            out[i] = array[i];
        }
    }
}

void test_1024() {
    int key[8] = { 0x29b9ad3d, 0x029c2e57, 0x02d799d3, 0x0ce32563, 0x4d33a88d, 0x2ff7d9d0, 0x7bc0b175, 0x5fdea51b};
    int crypto[8] = { 0xa283bede, 0x524d4d05, 0xe5d101ae, 0xca00e67c, 0x8986b27a, 0x7482014a, 0x4a6c578c, 0x64db188c};

    // du hui's debug signature
    char* sig =
            "3082023F308201A8A00302010202044D0D970C300D06092A864886F70D01010505003063310B300906035504061302636E3111300F060355040813087368616E676861693111300F060355040713087368616E67686169310F300D060355040A13067969746F6E67310F300D060355040B13067969746F6E67310C300A0603550403130379616F3020170D3130313231393035323432385A180F32303635303932313035323432385A3063310B300906035504061302636E3111300F060355040813087368616E676861693111300F060355040713087368616E67686169310F300D060355040A13067969746F6E67310F300D060355040B13067969746F6E67310C300A0603550403130379616F30819F300D06092A864886F70D010101050003818D0030818902818100B833E1F14B73DF6FDA7A68B4F8EAE6AFDCCD61A850CED5F6CA1E2FA68962BE0E1935AD664AF563C30EDDA2689545FCFE002CAF8B4593F056C44219432F75033E831A9BFB3EBFB4542F999937811EA4EA1446E14C4386213522EA1E1AA0D9085148F3DE3197EC1197302E3753E29D687DF3D5994FCCEDBE939196144A75FFD3E30203010001300D06092A864886F70D0101050500038181006F9E00A5D0B323C7C22C03C24492947DEDC775BA26F5E03BD22F674641F1C8F0DD14F582F8C1772FFFED8B7344808E18279F688DE1DB4B707ED409CC934BBAE5B8C782DF94F2CC2179BA8323A3599EC4BE60C1F2A765B84A25735762FC8BCE7D6AA14A603BA0B175075687DB214DCCEDC594D9BE4BBA9018253414CFF3BAF620";
    char buffer[1024] = { 0 };
    hex_string_to_byte_array(sig, buffer, 1024);
    int pass_be[8] = { 0 };
    int output[8] = { 0 };
    convert_to_big_endian(key, pass_be, 32 / sizeof(int));
    pkcs5_pbkdf2((char*) pass_be, 32, buffer, strlen(sig) / 2, 1024, (char*) output, 32);
    convert_to_big_endian(output, output, 32 / sizeof(int));
    for (int i = 0; i < 8; i++) {
        printf("%08x\n", key[i]);
    }
    for (int i = 0; i < 8; i++) {
        printf("%08x\n", output[i]);
    }
    if (memcmp(output, crypto, 32) != 0) {
        printf("Verify failed!\n");
    } else {
        printf("Verification passed!\n");
    }
}

#define fmt_16_int(c, a, b) "%s\nint key[8] = { 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x};\nint crypto[8] = { 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x};\n",c, a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]

int main(int argc, char** argv) {
#if 1
    test_1024();
#endif
    char *comments = "/*\n"
            " * Do not modify this file, it is generated by gen_c.exe. \n"
            " * Copyright (C) 2015-2016  Du Hui\n"
            " */\n";

    char buffer[2048] = { 0 };
    int len = fio_read("./sig", buffer, sizeof(buffer));

    char sig[1024] = { 0 };
    hex_string_to_byte_array(buffer, sig, len / 2);

    srand((int) time(0));
    int password[8] = { 0 };
    for (int i = 0; i < 8; i++) {
        password[i] = rand();
    }
    int output[8] = { 0 };
    int password_be[8] = { 0 };
    convert_to_big_endian(password, password_be, 32 / sizeof(int));
    pkcs5_pbkdf2((char*) password_be, 32, sig, len / 2, 1024, (char*) output, 32);
    convert_to_big_endian(output, output, 32 / sizeof(int));

    snprintf(buffer, sizeof(buffer), fmt_16_int(comments, password, output));
    printf(buffer);
    fio_write("./static.c", buffer, strlen(buffer));
}
