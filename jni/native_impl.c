/*
 *
 *  Copyright (C) 2015-2016  Du Hui
 *
 */

#include <jni.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "log.h"
#include "fio/file_util.h"
#include "crypto/aes.h"
#include "crypto/sha1.h"
#include "crypto/des.h"
#include "native.h"
#include "crypto/pkcs5_pbkdf2.h"
#include "native_impl.h"
#include "tag_list.h"
#include "static.h"

#define MIN(a, b) (a) > (b) ? (b) : (a)
#define MAX(a, b) (a) > (b) ? (a) : (b)

#define KEY_PBKDF2_ROUND 1024

/*
 static int key[8] = { 0x3082030D, 0x308201F5, 0x64726F69, 0x64204465, 0x5BADD6FF, 0xEB4796C1, 0xFBD5F413, 0x92208E0E };
 static int crypto[8] =
 { 0x10206783, 0x6ee70d76, 0x67e04847, 0x0f3fdf24, 0x2b979fa8, 0x2bdd2876, 0x3b69fbc5, 0xae842731 };
 */
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

void crash() {
    logi("%s", "antiCrack: Crash now");
    char c;
    memset(&c - 5000, 0, 10000);
    char* p = 0;
    *p = 0;
}

static void check_exception(JNIEnv* env) {
    jthrowable exception = (*env)->ExceptionOccurred(env);
    if (exception) {
        jclass exception_cls;
        (*env)->ExceptionDescribe(env);
        (*env)->DeleteLocalRef(env, exception);
        exception_cls = (*env)->FindClass(env, "java/lang/IException");
        if (exception_cls != NULL) {
            //(*env)->ThrowNew(env, exception_cls, "C invok code exception");
        }
        loge("C invok code exception");
    }
}

static jstring get_public_key(JNIEnv* env, jbyteArray signature) {
    // get ByteArrayInputStream instance
    jclass byte_input_stream_cls = (*env)->FindClass(env, "java/io/ByteArrayInputStream");
    jmethodID method_id_byte_input_stream_ctor = (*env)->GetMethodID(env, byte_input_stream_cls, "<init>", "([B)V");
    jobject byte_input_stream = (*env)->NewObject(env, byte_input_stream_cls, method_id_byte_input_stream_ctor,
            signature);
    (*env)->DeleteLocalRef(env, byte_input_stream_cls);

    // get CertificateFactory instance
    jclass certificate_factory_cls = (*env)->FindClass(env, "java/security/cert/CertificateFactory");
    jmethodID method_id_get_instance = (*env)->GetStaticMethodID(env, certificate_factory_cls, "getInstance",
            "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jstring x509 = (*env)->NewStringUTF(env, "X509");
    jobject certificate_factory = (*env)->CallStaticObjectMethod(env, certificate_factory_cls, method_id_get_instance,
            x509);
    (*env)->DeleteLocalRef(env, x509);

    // get Certificate instance
    jmethodID method_id_generate_certificate = (*env)->GetMethodID(env, certificate_factory_cls, "generateCertificate",
            "(Ljava/io/InputStream;)Ljava/security/cert/Certificate;");
    (*env)->DeleteLocalRef(env, certificate_factory_cls);
    jobject cert = (*env)->CallObjectMethod(env, certificate_factory, method_id_generate_certificate,
            byte_input_stream);
    (*env)->DeleteLocalRef(env, certificate_factory);
    (*env)->DeleteLocalRef(env, byte_input_stream);

    // get PublicKey instance
    jclass certificate_cls = (*env)->GetObjectClass(env, cert);
    jmethodID method_id_get_pubic_key = (*env)->GetMethodID(env, certificate_cls, "getPublicKey",
            "()Ljava/security/PublicKey;");
    (*env)->DeleteLocalRef(env, certificate_cls);
    jobject public_key = (*env)->CallObjectMethod(env, cert, method_id_get_pubic_key);
    (*env)->DeleteLocalRef(env, cert);

    // get public key string
    jclass public_key_cls = (*env)->GetObjectClass(env, public_key);
    jmethodID method_id_to_string = (*env)->GetMethodID(env, public_key_cls, "toString", "()Ljava/lang/String;");
    jstring public_key_str = (jstring) ((*env)->CallObjectMethod(env, public_key, method_id_to_string));
    (*env)->DeleteLocalRef(env, public_key_cls);
    (*env)->DeleteLocalRef(env, public_key);

    // get public key string
    jclass string_cls = (*env)->GetObjectClass(env, public_key_str);
    jmethodID method_id_index_of = (*env)->GetMethodID(env, string_cls, "indexOf", "(Ljava/lang/String;)I");
    jstring modulus_str = (*env)->NewStringUTF(env, "modulus");
    jint first = (*env)->CallIntMethod(env, public_key_str, method_id_index_of, modulus_str);
    jstring publicExponent_str = (*env)->NewStringUTF(env, "publicExponent");
    jint end = (*env)->CallIntMethod(env, public_key_str, method_id_index_of, publicExponent_str);
    (*env)->DeleteLocalRef(env, modulus_str);
    (*env)->DeleteLocalRef(env, publicExponent_str);

    jmethodID method_id_substring = (*env)->GetMethodID(env, string_cls, "substring", "(II)Ljava/lang/String;");
    (*env)->DeleteLocalRef(env, string_cls);
    jstring public_key_core = (jstring) ((*env)->CallObjectMethod(env, public_key_str, method_id_substring, first + 8,
            end - 1));

    check_exception(env);
    return public_key_core;
}

jstring get_package_name(JNIEnv* env, jobject context) {
    jclass native_cls = (*env)->GetObjectClass(env, context);
    jmethodID method_id_get_package_name = (*env)->GetMethodID(env, native_cls, "getPackageName",
            "()Ljava/lang/String;");
    jstring package_name = (jstring) ((*env)->CallObjectMethod(env, context, method_id_get_package_name));
    return package_name;
}

jbyteArray get_signature(JNIEnv* env, jobject context) {
    jclass context_cls = (*env)->GetObjectClass(env, context);

    jmethodID method_id_get_package_manager = (*env)->GetMethodID(env, context_cls, "getPackageManager",
            "()Landroid/content/pm/PackageManager;");

    jobject package_manager = (*env)->CallObjectMethod(env, context, method_id_get_package_manager);
    jclass pm_cls = (*env)->GetObjectClass(env, package_manager);

    jmethodID method_id_get_package_info = (*env)->GetMethodID(env, pm_cls, "getPackageInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");

    jmethodID method_id_get_package_name = (*env)->GetMethodID(env, context_cls, "getPackageName",
            "()Ljava/lang/String;");
    jstring package_name = (jstring) ((*env)->CallObjectMethod(env, context, method_id_get_package_name));

    // 0x00000040 = GET_SIGNATURES
    jobject package_info = (*env)->CallObjectMethod(env, package_manager, method_id_get_package_info, package_name,
            0x00000040);
    jclass pi_cls = (*env)->GetObjectClass(env, package_info);

    jfieldID field_id_signatures = (*env)->GetFieldID(env, pi_cls, "signatures", "[Landroid/content/pm/Signature;");
    jobjectArray signatures = (jobjectArray) ((*env)->GetObjectField(env, package_info, field_id_signatures));
    jobject signature = (*env)->GetObjectArrayElement(env, signatures, 0);

    jclass signature_cls = (*env)->GetObjectClass(env, signature);
    jmethodID method_id_to_byte_array = (*env)->GetMethodID(env, signature_cls, "toByteArray", "()[B");
    jbyteArray signature_bytes = (jbyteArray) ((*env)->CallObjectMethod(env, signature, method_id_to_byte_array));

    return signature_bytes;
}

void convert_to_big_endian(int* array, int* out, int size) {
    int i = 1;
    char *cp = (char *) &i;
    if (*cp) {
        logi("Little Endian");
        for (int i = 0; i < size; i++) {
            int tmp = array[i];
            //logi("%x", tmp);
            unsigned char *p = (unsigned char*) &tmp;
            out[i] = (((unsigned int) *p << 24) + ((unsigned int) *(p + 1) << 16) + ((unsigned int) *(p + 2) << 8)
                    + (unsigned int) *(p + 3));
            //logi("%x", out[i]);
        }
    } else {
        logi("Big Endian");
        for (int i = 0; i < size; i++) {
            out[i] = array[i];
        }
    }
}

void checkup(JNIEnv *env, jobject context) {
#if(!_DEBUG_)
    jbyteArray bytes = get_signature(env, context);
    jsize size_native = (*env)->GetArrayLength(env, bytes);
    logi("%d", size_native);
    jbyte* body_native = (*env)->GetByteArrayElements(env, bytes, 0);
    loghex(body_native, 511);

    int tmp[8] = { 0 };
    convert_to_big_endian(key, tmp, sizeof(tmp) / sizeof(int));
    loghex((char*)tmp, 32);
    char output[32] = { 0 };
    pkcs5_pbkdf2((char*) tmp, 32, body_native, size_native, 1024, output, 32);
    convert_to_big_endian(crypto, tmp, sizeof(tmp) / sizeof(int));
    loghex((char*)tmp, 32);

    if (memcmp(output, (void*) tmp, 32) == 0) {
        (*env)->ReleaseByteArrayElements(env, bytes, body_native, 0);
        return;
    }
    (*env)->ReleaseByteArrayElements(env, bytes, body_native, 0);
    crash();
#endif
}

void gen_key_hash(JNIEnv *env, jobject context, unsigned char output[20]) {
    jbyteArray signature = get_signature(env, context);
    jsize size = (*env)->GetArrayLength(env, signature);
    jbyte* signature_str = (*env)->GetByteArrayElements(env, signature, 0);
    sha1(signature_str, size, output);
    //loghex(output, 20);

    unsigned char tmp[20] = { 0 };
    get_device_id(env, context, tmp);
    //loghex(tmp, 20);

    for (int i = 0; i < 20 / sizeof(int); i++) {
        ((int*) output)[i] ^= ((int*) tmp)[i];
    }
    (*env)->ReleaseByteArrayElements(env, signature, signature_str, 0);
}

void get_device_id(JNIEnv *env, jobject context, unsigned char output[20]) {
    // get imei
    jclass activity_cls = (*env)->GetObjectClass(env, context);
    jclass context_cls = (*env)->FindClass(env, "android/content/Context");
    jfieldID field_id_telephone_service = (*env)->GetStaticFieldID(env, context_cls, "TELEPHONY_SERVICE",
            "Ljava/lang/String;");
    jstring telephone_service = (jstring) (*env)->GetStaticObjectField(env, context_cls, field_id_telephone_service);
    (*env)->DeleteLocalRef(env, context_cls);
    jmethodID method_id_get_system_service = (*env)->GetMethodID(env, activity_cls, "getSystemService",
            "(Ljava/lang/String;)Ljava/lang/Object;");
    jobject telephony_manager = (*env)->CallObjectMethod(env, context, method_id_get_system_service, telephone_service);
    (*env)->DeleteLocalRef(env, telephone_service);

    jclass telephony_manager_cls = (*env)->GetObjectClass(env, telephony_manager);
    jmethodID method_id_get_device_id = (*env)->GetMethodID(env, telephony_manager_cls, "getDeviceId",
            "()Ljava/lang/String;");
    jstring device_id = (jstring) (*env)->CallObjectMethod(env, telephony_manager, method_id_get_device_id);
    (*env)->DeleteLocalRef(env, telephony_manager);
    (*env)->DeleteLocalRef(env, telephony_manager_cls);
    (*env)->DeleteLocalRef(env, activity_cls);
    //logjs(env, device_id);

    jclass build_cls = (*env)->FindClass(env, "android/os/Build");
    jfieldID field_id_device = (*env)->GetStaticFieldID(env, build_cls, "DEVICE", "Ljava/lang/String;");
    jstring device = (jstring) (*env)->GetStaticObjectField(env, build_cls, field_id_device);
    //logjs(env, device);

    jfieldID field_id_serial = (*env)->GetStaticFieldID(env, build_cls, "SERIAL", "Ljava/lang/String;");
    jstring serial = (jstring) (*env)->GetStaticObjectField(env, build_cls, field_id_serial);
    //logjs(env, serial);

    char buffer[64] = { 0 };
    if (device != NULL) {
        const char* device_str = (*env)->GetStringUTFChars(env, device, 0);
        strncpy(buffer, device_str, sizeof(buffer));
        (*env)->ReleaseStringUTFChars(env, device, device_str);
    } else {
        strncpy(buffer, "8888888888888888", sizeof(buffer));
    }
    (*env)->DeleteLocalRef(env, device);

    if (serial != NULL) {
        const char* serial_str = (*env)->GetStringUTFChars(env, serial, 0);
        strncat(buffer, serial_str, sizeof(buffer) - strlen(buffer) - 1);
        (*env)->ReleaseStringUTFChars(env, serial, serial_str);
    } else {
        strncat(buffer, "0000000000000000", sizeof(buffer) - strlen(buffer) - 1);
    }
    (*env)->DeleteLocalRef(env, serial);

    if (device_id != NULL) {
        const char* device_id_str = (*env)->GetStringUTFChars(env, device_id, 0);
        strncat(buffer, device_id_str, sizeof(buffer) - strlen(buffer) - 1);
        (*env)->ReleaseStringUTFChars(env, device_id, device_id_str);
    } else {
        strncat(buffer, "FFFFFFFFFFFFFFFF", sizeof(buffer) - strlen(buffer) - 1);
    }
    (*env)->DeleteLocalRef(env, device_id);

    // fill buffer with 0xF0
    if (sizeof(buffer) > strlen(buffer)) {
        memset(buffer + strlen(buffer), 0xf0, sizeof(buffer) - strlen(buffer));
    }
    //loghex(buffer, 64);
    sha1(buffer, 64, output);
    loghex(output, 20);
}

void get_device_id_string(JNIEnv *env, jobject context, unsigned char output[40]) {
    char buffer[20] = { 0 };
    get_device_id(env, context, buffer);
    byte_array_to_hex_string(buffer, 20, output);
}

int save_salt(const char* path, unsigned char* salt, int len) {
    if (path != NULL && salt != NULL && len > 0) {
        return fio_write(path, salt, len);
    }
    return -1;
}

int read_salt(const char* path, unsigned char* salt, int len) {
    if (path != NULL && salt != NULL && len > 0) {
        return fio_read(path, salt, len);
    }
    return -1;
}

void gen_salt(JNIEnv *env, jobject context, unsigned char output[8]) {
    srand((int) time(0));
    ((int*) output)[0] = rand();
    ((int*) output)[1] = rand();
    char path[512] = { 0 };
    get_private_file(env, context, "salt", path);
    save_salt(path, output, 8);
    loghex(output, 8);
}

void get_private_file(JNIEnv *env, jobject context, const char* file_name, unsigned char path[512]) {
    jstring package_name = get_package_name(env, context);
    const char *package_name_str = (*env)->GetStringUTFChars(env, package_name, 0);
    snprintf(path, 512, "/data/data/%s/%s", package_name_str, file_name);
    (*env)->ReleaseStringUTFChars(env, package_name, package_name_str);
    (*env)->DeleteLocalRef(env, package_name);
}

void get_private_path(JNIEnv *env, jobject context, unsigned char path[512]) {
    jstring package_name = get_package_name(env, context);
    const char *package_name_str = (*env)->GetStringUTFChars(env, package_name, 0);
    snprintf(path, 512, "/data/data/%s/", package_name_str);
    (*env)->ReleaseStringUTFChars(env, package_name, package_name_str);
    (*env)->DeleteLocalRef(env, package_name);
}

void cd_private_path(JNIEnv *env, jobject context, unsigned char path[512]) {
    get_private_path(env, context, path);

#if(_DEBUG_)
    char current_work_dir[512];
    getcwd(current_work_dir, 512);
    logi(current_work_dir);
#endif
    chdir(path);
#if(_DEBUG_)
    getcwd(current_work_dir, 512);
    logi(current_work_dir);
#endif
}

int save_pan(JNIEnv *env, jobject context, jstring pan) {
    char path[512] = { 0 };
    get_private_file(env, context, "token", path);

    const char *pan_str = (*env)->GetStringUTFChars(env, pan, 0);
    if (strlen(pan_str) > 24) {
        return -1;
    }
    char buffer[24 + sizeof(int)] = { 0 };
    *((int*) buffer) = strlen(pan_str);
    memcpy(buffer + sizeof(int), pan_str, strlen(pan_str));
    loghex(buffer, sizeof(buffer));
    if (strlen(path) > 0 && pan_str != NULL && strlen(pan_str) > 0) {
        return fio_write(path, buffer, sizeof(buffer));
    }
    (*env)->ReleaseStringUTFChars(env, pan, pan_str);

    return -1;
}

jstring get_pan_jstring(JNIEnv *env, jobject context) {
    unsigned char token[24 + 1] = { 0 };
    if (get_pan(env, context, token) < 0) {
        return NULL;
    }
    return (*env)->NewStringUTF(env, token);
}

int get_pan(JNIEnv *env, jobject context, unsigned char output[24]) {
    char path[512] = { 0 };
    get_private_file(env, context, "token", path);

    if (strlen(path) <= 0) {
        return -1;
    }

    char buffer[24 + sizeof(int)] = { 0 };
    int len = fio_read(path, buffer, sizeof(buffer));
    if (len < 0) {
        return -1;
    }

    len = *(int*) buffer;
    if (len < 24) {
        memcpy(output, buffer + sizeof(int), len);
    } else {
        return -1;
    }
    logns(output, 24);
    return 0;
}

void get_salt(JNIEnv *env, jobject context, unsigned char output[8]) {
    char path[512] = { 0 };
    get_private_file(env, context, "salt", path);

    if (read_salt(path, output, 8) <= 0) {
        gen_salt(env, context, output);
    }
    loghex(output, 8);
}

void gen_aek(JNIEnv *env, jobject context, unsigned char output[16]) {
    char hash[20] = { 0 };
    gen_key_hash(env, context, hash);
    loghex(hash, 20);
    char salt[8];
    get_salt(env, context, salt);
    loghex(salt, 8);
    char pan[32] = { 0 };
    get_pan(env, context, pan);
    char pan_byte[8];
    if (strlen(pan) > 16) {
        hex_string_to_byte_array(pan + strlen(pan) - 8 * 2, pan_byte, 8);
    } else {
        hex_string_to_byte_array(pan, pan_byte, 8);
    }
    ((int*) salt)[0] ^= ((int*) pan_byte)[0];
    ((int*) salt)[1] ^= ((int*) pan_byte)[1];
    loghex(salt, 8);
    loghex(hash, 20);
    pkcs5_pbkdf2(hash, sizeof(hash), salt, sizeof(salt), 256, output, 16);
    loghex(output, 16);
}

void gen_fek(JNIEnv *env, jobject context, unsigned char output[16]) {
    char hash[20] = { 0 };
    gen_key_hash(env, context, hash);
    loghex(hash, 20);
    char salt[8];
    get_salt(env, context, salt);
    loghex(salt, 8);
    pkcs5_pbkdf2(hash, sizeof(hash), salt, sizeof(salt), 256, output, 16);
    loghex(output, 16);
}

void des3_crypt(unsigned char key[16], unsigned char* input, unsigned char* output, unsigned int num_eights) {
    for (int i = 0; i < (num_eights << 3); i += 8) {
        des3_ecb_crypt(key, input + i, output + i);
    }
}

void des3_ecb_crypt(unsigned char key[16], unsigned char input[8], unsigned char output[8]) {
    des3_context context;
    des3_set2key_enc(&context, key);
    des3_crypt_ecb(&context, input, output);
}

void des3_decrypt(unsigned char key[16], unsigned char* input, unsigned char* output, unsigned int num_eights) {
    for (int i = 0; i < (num_eights << 3); i += 8) {
        des3_ecb_decrypt(key, input + i, output + i);
    }
}

void des3_ecb_decrypt(unsigned char key[16], unsigned char input[8], unsigned char output[8]) {
    des3_context context;
    des3_set2key_dec(&context, key);
    des3_crypt_ecb(&context, input, output);
}

int compute_access_pin_hash_byte(JNIEnv *env, jobject context, jstring salt, jstring access_pin,
        unsigned char access_pin_hash[20 + 1]) {
    const char *access_pin_str = (*env)->GetStringUTFChars(env, access_pin, 0);
    const char *salt_str = (*env)->GetStringUTFChars(env, salt, 0);
    if (salt == NULL || access_pin_str == NULL) {
        return -1;
    }
    sha1_hmac((unsigned char *) salt_str, strlen(salt_str), (unsigned char *) access_pin_str, strlen(access_pin_str),
            access_pin_hash);
    loghex(access_pin_hash, 20);
    (*env)->ReleaseStringUTFChars(env, access_pin, access_pin_str);
    (*env)->ReleaseStringUTFChars(env, salt, salt_str);
    return 0;
}

jstring compute_access_pin_hash(JNIEnv *env, jobject context, jstring salt, jstring access_pin) {
    unsigned char access_pin_hash[20 + 1] = { 0 };
    if (compute_access_pin_hash_byte(env, context, salt, access_pin, access_pin_hash) < 0) {
        return NULL;
    }
    unsigned char access_pin_hash_hex_str[40 + 1] = { 0 };
    byte_array_to_hex_string(access_pin_hash, 20, access_pin_hash_hex_str);
    logi(access_pin_hash_hex_str);
    return (*env)->NewStringUTF(env, access_pin_hash_hex_str);
}

unsigned char verify_access_pin_hash(JNIEnv *env, jobject context, jstring salt, jstring access_pin) {
    unsigned char access_pin_hash[20 + 1] = { 0 };
    if (compute_access_pin_hash_byte(env, context, salt, access_pin, access_pin_hash) < 0) {
        return 0;
    }
    unsigned char saved_access_pin_hash[20 + 1] = { 0 };
    get_access_pin(env, context, saved_access_pin_hash);
    return !strncmp(access_pin_hash, saved_access_pin_hash, 20);
}

int set_access_pin(JNIEnv *env, jobject context, jstring access_pin_hash) {
    char buffer[32] = { 0 };
    const char *access_pin_hash_str = (*env)->GetStringUTFChars(env, access_pin_hash, 0);
    logi(access_pin_hash_str);
    logi("%d", strlen(access_pin_hash_str));
    if (strlen(access_pin_hash_str) != 40) {
        (*env)->ReleaseStringUTFChars(env, access_pin_hash, access_pin_hash_str);
        return -1;
    }
    logi(access_pin_hash_str);
    hex_string_to_byte_array(access_pin_hash_str, buffer, 20);
    (*env)->ReleaseStringUTFChars(env, access_pin_hash, access_pin_hash_str);

    unsigned char aek[16] = { 0 };
    gen_aek(env, context, aek);
    des3_crypt(aek, buffer, buffer, sizeof(buffer) / 8);
    loghex(buffer, 32);

    unsigned char fek[16] = { 0 };
    gen_fek(env, context, fek);
    unsigned char crypto_fek[32];
    des3_crypt(fek, buffer, buffer, sizeof(buffer) / 8);
    loghex(buffer, 32);

    char buf[36] = { 0 };
    // access pin hash is 20 bytes, do not count padding 0.
    *((int*) buf) = 20;
    memcpy(buf + sizeof(int), buffer, sizeof(buffer));
    loghex(buf, 36);

    char path[512] = { 0 };
    get_private_file(env, context, "aph", path);
    if (strlen(path) > 0) {
        fio_write(path, buf, sizeof(buf));
    } else {
        return -1;
    }
    return 0;
}

void get_access_pin(JNIEnv *env, jobject context, unsigned char access_pin_hash[20]) {
    char path[512] = { 0 };
    get_private_file(env, context, "aph", path);

    char buf[36];
    fio_read(path, buf, sizeof(buf));
    int len = *((int*) buf);

    unsigned char fek[16] = { 0 };
    gen_fek(env, context, fek);
    des3_decrypt(fek, buf + sizeof(int), buf + sizeof(int), 4);
    loghex(buf, 36);

    unsigned char aek[16] = { 0 };
    gen_aek(env, context, aek);
    des3_decrypt(aek, buf + sizeof(int), buf + sizeof(int), 4);
    loghex(buf, 36);

    memcpy(access_pin_hash, buf + sizeof(int), len);
    loghex(access_pin_hash, len);
}

int save_host_salt(JNIEnv *env, jobject context, jstring host_salt) {
    unsigned char salt[8] = { 0 };
    const char *host_salt_str = (*env)->GetStringUTFChars(env, host_salt, 0);
    if (strlen(host_salt_str) != 16) {
        (*env)->ReleaseStringUTFChars(env, host_salt, host_salt_str);
        return -1;
    }
    logi(host_salt_str);

    hex_string_to_byte_array(host_salt_str, salt, sizeof(salt));
    (*env)->ReleaseStringUTFChars(env, host_salt, host_salt_str);

    unsigned char aek[16] = { 0 };
    gen_aek(env, context, aek);
    des3_ecb_crypt(aek, salt, salt);
    loghex(salt, 8);

    unsigned char fek[16] = { 0 };
    gen_fek(env, context, fek);
    des3_ecb_crypt(fek, salt, salt);
    loghex(salt, 8);

    unsigned char path[512] = { 0 };
    get_private_file(env, context, "hsalt", path);
    if (strlen(path) > 0 && fio_write(path, salt, sizeof(salt))) {
        return 0;
    }
    return -1;
}

int get_host_salt_byte(JNIEnv *env, jobject context, unsigned char output[8]) {
    unsigned char salt[8];
    unsigned char path[512] = { 0 };
    get_private_file(env, context, "hsalt", path);
    if (strlen(path) <= 0) {
        return -1;
    }

    int count = 0;
    count = fio_read(path, salt, sizeof(salt));
    if (count <= 0) {
        return -1;
    }
    loghex(salt, 8);

    unsigned char fek[16] = { 0 };
    gen_fek(env, context, fek);
    des3_ecb_decrypt(fek, salt, salt);
    loghex(salt, 8);

    unsigned char aek[16] = { 0 };
    gen_aek(env, context, aek);
    des3_ecb_decrypt(aek, salt, output);
    loghex(output, 8);

    return count;
}

jstring get_host_salt_str(JNIEnv *env, jobject context) {
    unsigned char salt[8] = { 0 };
    if (get_host_salt_byte(env, context, salt) <= 0) {
        return NULL;
    }
    unsigned char output[16 + 1] = { 0 };
    byte_array_to_hex_string(salt, 8, output);
    return (*env)->NewStringUTF(env, output);
}

void get_kek(JNIEnv *env, jobject context, unsigned char kek[16]) {
    checkup(env, context);

    unsigned char salt[8];
    get_host_salt_byte(env, context, salt);
    loghex(salt, 8);

    unsigned char aph[20];
    get_access_pin(env, context, aph);
    loghex(aph, 20);

    pkcs5_pbkdf2(aph, sizeof(aph), salt, sizeof(salt), KEY_PBKDF2_ROUND, kek, 16);
    loghex(kek, 16);
}

void verify_dek(JNIEnv *env, jobject context, char kek_crypted_dek[16], char dek_crypted_kcv[8]) {
    char kek[16] = { 0 };
    get_kek(env, context, kek);

    char output[16];
    des3_decrypt(kek, kek_crypted_dek, output, 2);
    loghex(output, 16);

    char kcv[8];
    des3_ecb_decrypt(output, dek_crypted_kcv, kcv);
    loghex(kcv, 8);
}

// wrap_dek: 8 bytes kcv + 16 bytes dek1 + 8 bytes kcv + 16 bytes dek2
int save_kek_crypted_dek(JNIEnv *env, jobject context, jstring wrap_dek) {
    unsigned char buffer[48 + sizeof(int)];
    const char *wrap_dek_str = (*env)->GetStringUTFChars(env, wrap_dek, 0);
    if (strlen(wrap_dek_str) != 96) {
        (*env)->ReleaseStringUTFChars(env, wrap_dek, wrap_dek_str);
        return -1;
    }

    logi(wrap_dek_str);
    hex_string_to_byte_array(wrap_dek_str, buffer + sizeof(int), sizeof(buffer) - sizeof(int));
    (*env)->ReleaseStringUTFChars(env, wrap_dek, wrap_dek_str);
    loghex(buffer, 52);

#if(_DEBUG_)
    verify_dek(env, context, buffer + sizeof(int), buffer + sizeof(int) + 16);
    verify_dek(env, context, buffer + sizeof(int) + 24, buffer + 24 + sizeof(int) + 16);
#endif

    *((int*) buffer) = 48;

    unsigned char fek[16];
    gen_fek(env, context, fek);
    des3_crypt(fek, buffer + 4, buffer + 4, (sizeof(buffer) - sizeof(int)) / 8);
    loghex(buffer, 52);

    char path[512];
    get_private_file(env, context, "dek", path);
    if (strlen(path) > 0) {
        return fio_write(path, buffer, sizeof(buffer));
    }
    return -1;
}

int get_kek_crypted_dek(JNIEnv *env, jobject context, unsigned char kcv1[8], unsigned char dek1[16],
        unsigned char kcv2[8], unsigned char dek2[16]) {
    if (kcv1 == NULL && kcv2 == NULL && dek1 == NULL && dek2 == NULL) {
        return 0;
    }
    unsigned char buffer[48 + sizeof(int)];
    char path[512];
    get_private_file(env, context, "dek", path);
    int len = 0;
    if (strlen(path) > 0) {
        len = fio_read(path, buffer, sizeof(buffer));
    }

    if (len != 48 + sizeof(int)) {
        return -1;
    }

    len = *((int*) buffer);
    if (len != 48) {
        return -1;
    }

    loghex(buffer, 48 + sizeof(int));
    unsigned char fek[16];
    gen_fek(env, context, fek);
    des3_decrypt(fek, buffer + sizeof(int), buffer + sizeof(int), (sizeof(buffer) - sizeof(int)) / 8);

#if(_DEBUG_)
    verify_dek(env, context, buffer + sizeof(int), buffer + sizeof(int) + 16);
    verify_dek(env, context, buffer + sizeof(int) + 24, buffer + 24 + sizeof(int) + 16);
#endif

    loghex(buffer, 48 + sizeof(int));

    if (dek1 != NULL) {
        memcpy(dek1, buffer + 4, 16);
    }
    if (kcv1 != NULL) {
        memcpy(kcv1, buffer + 4 + 16, 8);
    }
    if (dek2 != NULL) {
        memcpy(dek2, buffer + 4 + 16 + 8, 16);
    }
    if (kcv2 != NULL) {
        memcpy(kcv2, buffer + 4 + 16 + 8 + 16, 8);
    }
    return 0;
}

int get_dek(JNIEnv *env, jobject context, unsigned char dek1[16], unsigned char dek2[16]) {
    if (dek1 == NULL && dek2 == NULL) {
        return 0;
    }
    if (get_kek_crypted_dek(env, context, NULL, dek1, NULL, dek2) != 0) {
        return -1;
    }
    unsigned char kek[16];
    get_kek(env, context, kek);
    if (dek1 != NULL) {
        des3_decrypt(kek, dek1, dek1, 2);
    }
    if (dek2 != NULL) {
        des3_decrypt(kek, dek2, dek2, 2);
    }
    return 0;
}

int set_card_properties(JNIEnv *env, jobject context, const char* file_name, jstring response) {
    unsigned char buffer[256 + sizeof(int)] = { 0 };
    // first two bytes are length
    const char *response_str = (*env)->GetStringUTFChars(env, response, 0);
    int len = strlen(response_str);
    logi("%d", len);
    // dek1 ecb crypted hex string should be 16 multiples
    if (len < 32 || len > 496 || (len & 0x0F)) {
        logi(response_str);
        (*env)->ReleaseStringUTFChars(env, response, response_str);
        return -1;
    }
    logi(response_str);

    int total_len = len / 2;
    logi("%d", total_len);
    *((int*) buffer) = total_len;
    hex_string_to_byte_array(response_str, buffer + sizeof(int), sizeof(buffer) - sizeof(int));
    (*env)->ReleaseStringUTFChars(env, response, response_str);
    loghex(buffer, 256);

    unsigned char fek[16];
    gen_fek(env, context, fek);
    des3_crypt(fek, buffer + sizeof(int), buffer + sizeof(int), (total_len + 7) / 8);
    loghex(buffer, total_len + sizeof(int));

    char path[512] = { 0 };
    get_private_file(env, context, file_name, path);
    if (strlen(path) > 0) {
        return fio_write(path, buffer, (total_len + 7) / 8 * 8 + sizeof(int));
    }
    return -1;
}

char* get_card_properties(JNIEnv *env, jobject context, const char* file_name) {
    char path[512] = { 0 };
    get_private_file(env, context, file_name, path);
    if (strlen(path) <= 0) {
        return NULL;
    }

    unsigned char buffer[256 + sizeof(int)] = { 0 };
    int n = fio_read(path, buffer, sizeof(buffer));
    if (n <= 0) {
        return NULL;
    }
    loghex(buffer, 256);

    int len = *(int*) buffer;
    if (len > 256) {
        return NULL;
    }

    unsigned char * p_data = buffer + sizeof(int);
    unsigned char fek[16];
    gen_fek(env, context, fek);
    des3_decrypt(fek, p_data, p_data, (len + 7) / 8);
    loghex(buffer + sizeof(int), 256);

    unsigned char dek1[16];
    get_dek(env, context, dek1, NULL);
    loghex(dek1, 16);

    unsigned char kcv1[8];
    unsigned char dek11[16];
    unsigned char kcv2[8];
    unsigned char dek22[16];
    get_kek_crypted_dek(env, context, kcv1, dek11, kcv2, dek22);
    des3_decrypt(dek1, p_data, p_data, (len + 7) / 8);

    //first byte is the plain text length
    len = *p_data;
    logi("%d", len);

    char * out = malloc(len * 2 + 1);
    if (out != NULL) {
        byte_array_to_hex_string(p_data + 1, len, out);
        out[len * 2] = 0;
        logi(out);
    }
    return out;
}

int save_host_group(JNIEnv *env, jobject context, jstring group) {
    char path[512] = { 0 };
    get_private_file(env, context, "group", path);
    if (strlen(path) <= 0) {
        return -1;
    }

    char group_id[8] = { 0 };
    const char *group_str = (*env)->GetStringUTFChars(env, group, 0);
    logi(group_str);
    hex_string_to_byte_array(group_str, group_id, sizeof(group_id));
    (*env)->ReleaseStringUTFChars(env, group, group_str);
    int count = fio_write(path, group_id, sizeof(group_id));

    loghex(group_id, 8);
    return count;
}

int get_host_group_str(JNIEnv *env, jobject context, char group_id_str[16 + 1]) {
    char path[512] = { 0 };
    get_private_file(env, context, "group", path);
    if (strlen(path) <= 0) {
        return -1;
    }
    char group_id[8] = { 0 };
    int count = fio_read(path, group_id, sizeof(group_id));
    loghex(group_id, 8);

    byte_array_to_hex_string(group_id, 8, group_id_str);
    return count;
}

jstring get_host_group(JNIEnv *env, jobject context) {
    char group_id_str[16 + 1] = { 0 };
    if (get_host_group_str(env, context, group_id_str) > 0) {
        return (*env)->NewStringUTF(env, group_id_str);
    } else {
        return NULL;
    }
}

int get_byte(char a, char b) {
    return (table[a] << 4) + table[b];
}

int get_tlv_length_byte_count(const char *p) {
    int len = get_byte(p[0], p[1]);
    if (len & 0x80) {
        // 2 3 4
        return (len & 0x0F) + 1;
    }
    return 1;
}

int get_int(const char*hex_str, int len) {
    int rt = 0;
    logi(hex_str);
    logi("%d", len);
    for (int i = 0; i < 4 && i < len; i++) {
        rt += get_byte(hex_str[i * 2], hex_str[i * 2 + 1]) << (8 * i);
    }
    return rt;
}

int get_tlv_len(const char *p) {
    logi(p);
    int count = get_tlv_length_byte_count(p);
    logi("%d", count);
    if (count == 1) {
        return get_int(p, count);
    } else {
        return get_int(p + 2, count - 1);
    }
}

// can not handle embeded tlv
int parse_tlv(const char* tlv, int length, tag_list *tl) {
    if (tlv == NULL || strlen(tlv) <= 0) {
        return -1;
    }
    const char *p = tlv;
    while (p < tlv + length) {
        int tag = get_byte(p[0], p[1]);
        // single tlv
        if ((tag & 0x20) != 0x20) {
            if ((tag & 0x1f) == 0x1f) {
                //double bytes
                int bytes = get_tlv_length_byte_count(p + 4);
                int len = get_tlv_len(p + 4);
                tag_list_put(tl, p, 4, p, 4 + bytes * 2 + len * 2);
                p += 4 + bytes * 2 + len * 2;
            } else {
                //sigle bytes
                int bytes = get_tlv_length_byte_count(p + 2);
                int len = get_tlv_len(p + 2);
                tag_list_put(tl, p, 2, p, 2 + bytes * 2 + len * 2);
                p += 2 + bytes * 2 + len * 2;
            }
        } else {
            // composite tlv
            if ((tag & 0x1f) == 0x1f) {
                //double bytes
                int bytes = get_tlv_length_byte_count(p + 4);
                int len = get_tlv_len(p + 4);
                tag_list_put(tl, p, 4, p, 4 + bytes * 2 + len * 2);
                parse_tlv(p + 4 + bytes * 2, len * 2, tl);
                p += 4 + bytes * 2 + len * 2;
            } else {
                //sigle bytes
                int bytes = get_tlv_length_byte_count(p + 2);
                int len = get_tlv_len(p + 2);
                tag_list_put(tl, p, 2, p, 2 + bytes * 2 + len * 2);
                parse_tlv(p + 2 + bytes * 2, len * 2, tl);
                p += 2 + bytes * 2 + len * 2;
            }
        }
    }
    return 0;
}

void xor_data(const char data1[8], const char data2[8], char output[8]) {
    for (int i = 0; i < 8; i++) {
        output[i] = data1[i] ^ data2[i];
    }
}

void des_ecb_crypt(unsigned char key[8], unsigned char input[8], unsigned char output[8]) {
    des_context context;
    des_setkey_enc(&context, key);
    des_crypt_ecb(&context, input, output);
}

void des_ecb_decrypt(unsigned char key[8], unsigned char input[8], unsigned char output[8]) {
    des_context context;
    des_setkey_dec(&context, key);
    des_crypt_ecb(&context, input, output);
}

void compute_mac(unsigned char key[16], const unsigned char init_v[8], const unsigned char* source, int source_len,
        unsigned char dest[8]) {
    unsigned char tmp[8];
    unsigned char block[8];
    memcpy(block, init_v, 8);
    for (int i = 0; i < (source_len / 8); i++) {
        xor_data(block, source + i * 8, tmp);
        des_ecb_crypt(key, tmp, block);
    }
    des_ecb_decrypt(key + 8, block, tmp);
    des_ecb_crypt(key, tmp, block);
    memcpy(dest, block, 8);
}

// dek2 is byte array, other arguments are hex string
int get_arqc(char dek2[16], const char* gpo, unsigned char aip[4], unsigned char atc[4], unsigned char cvr[8],
        unsigned char arqc[16]) {
    if (strlen(gpo) % 2 != 0 || strlen(gpo) > 496) {
        return -1;
    }

    int len = strlen(gpo) + 4/*aip*/+ 4/*atc*/+ 8/*cvr*/+ 16/*8000000000000000*/;
    char * buffer = malloc(len + 1);
    memset(buffer, 0, len);
    memcpy(buffer, gpo, strlen(gpo));
    strncat(buffer, aip, 4);
    strncat(buffer, atc, 4);
    strncat(buffer, cvr, 8);
    strncat(buffer, "8000000000000000", 16);

    len >>= 1; // len /= 2
    char *gpo_byte = malloc(len);
    hex_string_to_byte_array(buffer, gpo_byte, len);
    free(buffer);
    loghex(gpo_byte, len / 8 * 8);

    char arqc_byte[8] = { 0 };
    char init_v[8] = { 0 };
    compute_mac(dek2, init_v, gpo_byte, len / 8 * 8, arqc_byte);
    loghex(arqc_byte, 8);
    free(gpo_byte);

    byte_array_to_hex_string(arqc_byte, 8, arqc);
    return 0;
}

int get_gpo_response_header(int len, char gpo_header[11]) {
    if (len > 128) {
        if (len > 255) {
            if (len > 0xFFFF) {
                snprintf(gpo_header, 9, "7783%06X", len);
                return 10;
            } else {
                snprintf(gpo_header, 9, "7782%04X", len);
                return 8;
            }
        } else {
            snprintf(gpo_header, 9, "7781%02X", len);
            return 6;
        }
    } else {
        snprintf(gpo_header, 9, "77%02X", len);
        return 4;
    }
}

jstring build_gpo_response(JNIEnv *env, jobject context, jstring gpo, jstring cvr, jstring tag_9F6C) {
    char * tags = get_card_properties(env, context, "tag");
    tag_list * tl = create_tag_list();
    parse_tlv(tags, strlen(tags), tl);
    free(tags);
    logi("size =%d", tl->size);
    for (int i = 0; i < tl->size; i++) {
        logi((tl->tags[i].tag));
        logi((tl->tags[i].value));
    }

    char cvr_arr[8 + 1] = { 0 };
    const char *cvr_str = (*env)->GetStringUTFChars(env, cvr, 0);
    strncpy(cvr_arr, cvr_str, strlen(cvr_str));
    (*env)->ReleaseStringUTFChars(env, cvr, cvr_str);
    (*env)->DeleteLocalRef(env, cvr);

    const char * tag_82 = tag_list_find(tl, "82");
    char aip[4 + 1] = { 0 };
    memcpy(aip, tag_82 + strlen(tag_82) - 4, 4);
    logi(aip);

    char atc[4 + 1] = { 0 };
    char atc_byte[2];
    char luk_a2[16];
    int rt = get_minimal_payment(env, context, atc_byte, luk_a2);
    if (rt != 0) {
        tag_list_destroy(tl);
        return NULL;
    }
    byte_array_to_hex_string(atc_byte, 2, atc);
    loghex(atc_byte, 2);

    char dek2[16];
    get_dek(env, context, NULL, dek2);
    loghex(dek2, 16);
    des3_decrypt(dek2, luk_a2, luk_a2, sizeof(luk_a2) / 8);
    loghex(luk_a2, 16);

    char arqc[16 + 1] = { 0 };
    const char *gpo_str = (*env)->GetStringUTFChars(env, gpo, 0);
    get_arqc(luk_a2, gpo_str, aip, atc, cvr_arr, arqc);
    (*env)->ReleaseStringUTFChars(env, gpo, gpo_str);
    (*env)->DeleteLocalRef(env, gpo);

    char tag_9F6C_arr[4 + 1] = { 0 };
    const char *tag_9F6C_str = (*env)->GetStringUTFChars(env, tag_9F6C, 0);
    strncpy(tag_9F6C_arr, tag_9F6C_str, strlen(tag_9F6C_str));
    (*env)->ReleaseStringUTFChars(env, tag_9F6C, tag_9F6C_str);
    (*env)->DeleteLocalRef(env, tag_9F6C);

    char gpo_response[256] = { 0 };
    char *gpo_data = gpo_response + 10;
    int gpo_data_max_len = sizeof(gpo_response) - 10;
    const char * gpo_tags[] = { "82", "9F36", "57", "9F10", "9F26", "9F63", "5F34", "9F6C", "5F20" };
    for (int i = 0; i < sizeof(gpo_tags) / sizeof(const char *); i++) {
        char * tlv = tag_list_find(tl, gpo_tags[i]);
        if (tlv != NULL) {
            char buffer[128];
            if (strncmp(gpo_tags[i], "9F10", 4) == 0) {
                int byte_count = get_tlv_length_byte_count(tlv + 4);
                // 9F10160700A2--------010DA103170000----------------
                for (int j = 0; j < 8; j++) {
                    // 9F10160700A2 + CVR
                    tlv[12 + j] = cvr_arr[j];
                }
                logi(tlv);
                char group[16 + 1] = { 0 };
                get_host_group_str(env, context, group);
                for (int j = 0; j < sizeof(group); j++) {
                    tlv[34 + j] = group[j];
                }
                logi(tlv);
            }
            strncat(gpo_data, tlv, gpo_data_max_len - strlen(gpo_data));
        } else {
            if (strncmp(gpo_tags[i], "9F36", 4) == 0) {
                strncat(gpo_data, "9F3602", gpo_data_max_len - strlen(gpo_data));
                strncat(gpo_data, atc, gpo_data_max_len - strlen(gpo_data));
                continue;
            }
            if (strncmp(gpo_tags[i], "9F26", 4) == 0) {
                strncat(gpo_data, "9F2608", gpo_data_max_len - strlen(gpo_data));
                strncat(gpo_data, arqc, gpo_data_max_len - strlen(gpo_data));
                continue;
            }
            if (strncmp(gpo_tags[i], "9F6C", 4) == 0) {
                strncat(gpo_data, "9F6C02", gpo_data_max_len - strlen(gpo_data));
                strncat(gpo_data, tag_9F6C_arr, gpo_data_max_len - strlen(gpo_data));
            }
        }
    }
    logi(gpo_data);
    int total_len = strlen(gpo_data);
    char gpo_header[11] = { 0 };
    int len = get_gpo_response_header(total_len / 2, gpo_header);
    memcpy(gpo_data - len, gpo_header, len);
    tag_list_destroy(tl);
    return (*env)->NewStringUTF(env, gpo_data - len);
}

void get_c_string(JNIEnv *env, jstring java_string, char* out, int len) {
    const char *c_str = (*env)->GetStringUTFChars(env, java_string, 0);
    strncpy(out, c_str, len);
    (*env)->ReleaseStringUTFChars(env, java_string, c_str);
}

int save_payment(JNIEnv *env, jobject context, jint atc, jstring payment) {
    char private_path[512] = { 0 };
    get_private_path(env, context, private_path);

#if(_DEBUG_)
    char current_work_dir[512];
    getcwd(current_work_dir, 512);
    logi(current_work_dir);
#endif
    chdir(private_path);
#if(_DEBUG_)
    getcwd(current_work_dir, 512);
    logi(current_work_dir);
#endif

    //snprintf(path, 512, "%s/atc/", path);
    if (access("./atc", 0) != 0) {
        if (mkdir("./atc", 0700) == -1) {
            return -1;
        }
    }

    char luk_a2[24] = { 0 };
    const char *c_str = (*env)->GetStringUTFChars(env, payment, 0);
    logi(c_str);
    hex_string_to_byte_array(c_str, luk_a2, sizeof(luk_a2));
    (*env)->ReleaseStringUTFChars(env, payment, c_str);
    loghex(luk_a2, sizeof(luk_a2));

#if(_DEBUG_)
    char dek2[16]={0};
    get_dek(env, context, NULL, dek2);
    loghex(dek2,16);
    char luk_a2_plain[16]={0};
    des3_decrypt(dek2, luk_a2, luk_a2_plain, 2);
    loghex(luk_a2_plain, 16);
    char kcv[8]={0};
    des3_decrypt(luk_a2_plain, luk_a2+16, kcv, 1);
    loghex(kcv, 8);
#endif

    unsigned char fek[16];
    gen_fek(env, context, fek);
    des3_crypt(fek, luk_a2, luk_a2, (sizeof(luk_a2) + 7) / 8);
    loghex(luk_a2, sizeof(luk_a2));

    char relative_path[16] = { 0 };
    snprintf(relative_path, sizeof(relative_path), "./%s/%04X", "atc", atc);

    if (strlen(relative_path) > 0) {
        return fio_write(relative_path, luk_a2, sizeof(luk_a2));
    }
    return 0;
}

int remove_all_file(const char *dir) {
    char filename[512] = { 0 };
    struct dirent *dirp;
    DIR *dp = NULL;

    dp = opendir(dir);
    if (NULL == dp) {
        return -1;
    }
    while ((dirp = readdir(dp)) != NULL) {
        if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0) {
            continue;
        }
        snprintf(filename, sizeof(filename), "%s%s", dir, dirp->d_name);
        logi(filename);
        unlink(filename);
    }
    closedir(dp);
    return 0;
}

int remove_payments(JNIEnv *env, jobject context) {
    char private_path[512] = { 0 };
    cd_private_path(env, context, private_path);

    // delete all atc files
    char relative_path[24] = { 0 };
    snprintf(relative_path, sizeof(relative_path), "./%s/", "atc");
    remove_all_file(relative_path);

    const char* file_list[] = { "./hsalt", "./group", "./dek", "./ppse", "./aid", "./tag" };
    for (int i = 0; i < sizeof(file_list) / sizeof(const char*); i++) {
        unlink(file_list[i]);
    }

    return 0;
}

int remove_card(JNIEnv *env, jobject context) {
    char private_path[512] = { 0 };
    cd_private_path(env, context, private_path);

    // delete all atc files
    char relative_path[24] = { 0 };
    snprintf(relative_path, sizeof(relative_path), "./%s/", "atc");
    remove_all_file(relative_path);

    const char* file_list[] =
            { "./token", "./aph", "./salt", "./hsalt", "./group", "./dek", "./ppse", "./aid", "./tag" };
    for (int i = 0; i < sizeof(file_list) / sizeof(const char*); i++) {
        unlink(file_list[i]);
    }

    return 0;
}

int is_hex_digit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int atc_file_filter(const struct dirent * ent) {
    if (ent->d_type != DT_REG)
        return 0;

    return strlen(ent->d_name) == 4 && is_hex_digit(ent->d_name[0]) && is_hex_digit(ent->d_name[1])
            && is_hex_digit(ent->d_name[2]) && is_hex_digit(ent->d_name[3]);
}

int get_minimal_payment(JNIEnv *env, jobject context, unsigned char atc[2], unsigned char strict_key[16]) {
    char private_path[512] = { 0 };
    cd_private_path(env, context, private_path);

    char relative_path[24] = { 0 };
    snprintf(relative_path, sizeof(relative_path), "./%s/", "atc");

    struct dirent **namelist;
    int n = scandir(relative_path, &namelist, atc_file_filter, alphasort);
    if (n > 0) {
        hex_string_to_byte_array(namelist[0]->d_name, atc, 2);
        strncat(relative_path, namelist[0]->d_name, sizeof(relative_path) - strlen(relative_path));
        logi("atc file name: %s", relative_path);
        fio_read(relative_path, strict_key, 16);
        loghex(strict_key, 16);
        unsigned char fek[16] = { 0 };
        gen_fek(env, context, fek);
        des3_decrypt(fek, strict_key, strict_key, 2);
        loghex(strict_key, 16);
        // delete the payment
        unlink(relative_path);
        logi("atc file %s deleted.", relative_path);

        while (n--) {
            logi("%s", namelist[n]->d_name);
            free(namelist[n]);
        }
        free(namelist);
        return 0;
    }
    return -1;
}

int get_payment_count(JNIEnv *env, jobject context) {
    char private_path[512] = { 0 };
    cd_private_path(env, context, private_path);

    struct dirent *ent;
    DIR *dp = NULL;
    char relative_path[24] = { 0 };
    snprintf(relative_path, sizeof(relative_path), "./%s/", "atc");

    dp = opendir(relative_path);
    if (NULL == dp) {
        return -1;
    }
    int count = 0;
    while ((ent = readdir(dp)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        if (strlen(ent->d_name) == 4 && is_hex_digit(ent->d_name[0]) && is_hex_digit(ent->d_name[1])
                && is_hex_digit(ent->d_name[2]) && is_hex_digit(ent->d_name[3])) {
            count++;
        }
    }
    closedir(dp);
    return count;
}
