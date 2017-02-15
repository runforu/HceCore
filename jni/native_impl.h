/*
 *
 *  Copyright (C) 2015-2016  Du Hui
 *
 */

#include <jni.h>

#ifndef  NATIVE_IMPL_H
#define NATIVE_IMPL_H

void get_private_path(JNIEnv *env, jobject ctx, unsigned char path[512]);

void get_private_file(JNIEnv *env, jobject ctx, const char* file_name, unsigned char path[512]);

int save_pan(JNIEnv *env, jobject ctx, jstring pan);

jstring get_pan_jstring(JNIEnv *env, jobject ctx);

void checkup(JNIEnv *env, jobject ctx);

jstring compute_access_pin_hash(JNIEnv *env, jobject ctx, jstring salt, jstring acp);

unsigned char verify_access_pin_hash(JNIEnv *env, jobject ctx, jstring salt, jstring acp);

int set_access_pin(JNIEnv *env, jobject ctx, jstring acph);

void get_access_pin(JNIEnv *env, jobject ctx, unsigned char access_pin_hash[20]);

jstring get_package_name(JNIEnv* env, jobject ctx);

jbyteArray get_signature(JNIEnv* env, jobject ctx);

// output = sha1 of device_id XOR sha1 of signature, make sure output can contains 20 bytes, no assurance of 0 terminate.
void gen_key_hash(JNIEnv *env, jobject ctx, unsigned char output[20]);

// output = sha1 of device_id, make sure output can contains 20 bytes, no assurance of 0 terminate.
void get_device_id(JNIEnv *env, jobject ctx, unsigned char output[20]);

void get_device_id_string(JNIEnv *env, jobject context, unsigned char output[40]);

// write 8 bytes of salt into path
int save_salt(const char* path, unsigned char* salt, int len);

// read 8 bytes of salt into variant salt
int read_salt(const char* path, unsigned char* salt, int len);

// generate 8 bytes of salt.
void gen_salt(JNIEnv *env, jobject context, unsigned char output[8]);

// get salt, save salt to file for first time.
void get_salt(JNIEnv *env, jobject ctx, unsigned char output[8]);

// get token pan
int get_pan(JNIEnv *env, jobject ctx, unsigned char output[24]);

// pan: the most right 8 bytes like pboc udk.
void gen_aek(JNIEnv *env, jobject ctx, unsigned char output[16]);

void gen_fek(JNIEnv *env, jobject ctx, unsigned char output[16]);

int save_host_salt(JNIEnv *env, jobject ctx, jstring host_salt);

int get_host_salt_byte(JNIEnv *env, jobject ctx, unsigned char output[8]);

jstring get_host_salt_str(JNIEnv *env, jobject context);

void get_kek(JNIEnv *env, jobject ctx, unsigned char kek[16]);

int save_kek_crypted_dek(JNIEnv *env, jobject ctx, jstring wrap_dek);

// num_eights: the number of des3 ecb group, every group is 8 bytes
void des3_crypt(unsigned char key[16], unsigned char* input, unsigned char* output, unsigned int num_eights);

void des3_ecb_crypt(unsigned char key[16], unsigned char input[8], unsigned char output[8]);

// num_eights: the number of des3 ecb group, every group is 8 bytes
void des3_decrypt(unsigned char key[16], unsigned char* input, unsigned char* output, unsigned int num_eights);

void des3_ecb_decrypt(unsigned char key[16], unsigned char input[8], unsigned char output[8]);

// kcv1 kcv2 dek1 dek2 can be null
int get_kek_crypted_dek(JNIEnv *env, jobject ctx, unsigned char kcv1[8], unsigned char dek1[16], unsigned char kcv2[8],
        unsigned char dek2[16]);

// dek1 dek2 can be null
int get_dek(JNIEnv *env, jobject ctx, unsigned char dek1[16], unsigned char dek2[16]);

int set_card_properties(JNIEnv *env, jobject ctx, const char* file_name, jstring response);

// free the returned pointer
char* get_card_properties(JNIEnv *env, jobject ctx, const char* file_name);

int save_host_group(JNIEnv *env, jobject ctx, jstring group);

jstring get_host_group(JNIEnv *env, jobject ctx);

jstring build_gpo_response(JNIEnv *env, jobject ctx, jstring gpo, jstring cvr, jstring tag9F6C);

int remove_all_file(const char *dir);

int remove_payments(JNIEnv *env, jobject ctx);

int remove_card(JNIEnv *env, jobject context);

int save_payment(JNIEnv *env, jobject context, jint atc, jstring payment);

int get_minimal_payment(JNIEnv *env, jobject ctx, unsigned char atc[4], unsigned char strict_key[16]);

int get_payment_count(JNIEnv *env, jobject context);
#endif
