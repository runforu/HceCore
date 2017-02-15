#include <jni.h>
#include <stdlib.h>
#include "native_impl.h"
#include "log.h"

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    test
 * Signature: (Ljava/lang/Object;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_cbhb_hce_NativeUtil_test(JNIEnv *env, jclass cls, jobject context, jstring content) {
#if(_DEBUG_)
    extern void test(JNIEnv *env, jobject context);
    test(env, context);
#endif
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    computeAccessPinHash
 * Signature: (Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_cbhb_hce_NativeUtil_computeAccessPinHash(JNIEnv *env, jclass cls, jobject context,
        jstring salt, jstring access_pin) {
    return compute_access_pin_hash(env, context, salt, access_pin);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    verifyAccessPinHash
 * Signature: (Ljava/lang/Object;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_com_cbhb_hce_NativeUtil_verifyAccessPinHash(JNIEnv *env, jclass cls, jobject context,
        jstring salt, jstring access_pin) {
    checkup(env, context);
    return verify_access_pin_hash(env, context, salt, access_pin);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    init
 * Signature: (Ljava/lang/Object;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_cbhb_hce_NativeUtil_init(JNIEnv *env, jclass cls, jobject context, jstring pan) {
    checkup(env, context);
    unsigned char salt[8] = { 0 };
    gen_salt(env, context, salt);
    save_pan(env, context, pan);
}
/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    getToken
 * Signature: (Ljava/lang/Object;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_cbhb_hce_NativeUtil_getToken(JNIEnv *env, jclass cls, jobject context) {
    return get_pan_jstring(env, context);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    setHostSalt
 * Signature: (Ljava/lang/Object;Ljava/lang/String;)V
 */
JNIEXPORT jint JNICALL Java_com_cbhb_hce_NativeUtil_setHostSalt(JNIEnv *env, jclass cls, jobject context,
        jstring host_salt) {
    return save_host_salt(env, context, host_salt);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    getHostSalt
 * Signature: (Ljava/lang/Object;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_cbhb_hce_NativeUtil_getHostSalt(JNIEnv *env, jclass cls, jobject context) {
    return get_host_salt_str(env, context);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    setHostGroupId
 * Signature: (Ljava/lang/Object;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_cbhb_hce_NativeUtil_setHostGroupId(JNIEnv *env, jclass cls, jobject context,
        jstring group) {
    return save_host_group(env, context, group);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    getHostGroup
 * Signature: (Ljava/lang/Object;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_cbhb_hce_NativeUtil_getHostGroupId(JNIEnv *env, jclass cls, jobject context) {
    jstring s = get_host_group(env, context);
    return s;
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    setHostDek
 * Signature: (Ljava/lang/Object;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_cbhb_hce_NativeUtil_setHostDek(JNIEnv *env, jclass cls, jobject context,
        jstring wrap_dek) {
    return save_kek_crypted_dek(env, context, wrap_dek);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    setHostPpseResp
 * Signature: (Ljava/lang/Object;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_cbhb_hce_NativeUtil_setHostPpseResp(JNIEnv *env, jclass cls, jobject context,
        jstring res) {
    return set_card_properties(env, context, "ppse", res);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    setHostAidResp
 * Signature: (Ljava/lang/Object;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_cbhb_hce_NativeUtil_setHostAidResp(JNIEnv *env, jclass cls, jobject context,
        jstring res) {
    return set_card_properties(env, context, "aid", res);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    setHostCardInfo
 * Signature: (Ljava/lang/Object;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_cbhb_hce_NativeUtil_setHostCardInfo(JNIEnv *env, jclass cls, jobject context,
        jstring tlv) {
    return set_card_properties(env, context, "tag", tlv);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    setHostPayment
 * Signature: (Ljava/lang/Object;ILjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_cbhb_hce_NativeUtil_setHostPayment(JNIEnv *env, jclass cls, jobject context, jint atc,
        jstring payment) {
    return save_payment(env, context, atc, payment);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    setAccessPinHash
 * Signature: (Ljava/lang/Object;Ljava/lang/String;)I
 */
JNIEXPORT int JNICALL Java_com_cbhb_hce_NativeUtil_setAccessPinHash(JNIEnv *env, jclass cls, jobject context, jstring acp) {
    return set_access_pin(env, context, acp);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    checkup
 * Signature: (Ljava/lang/Object;)V
 */
JNIEXPORT void JNICALL Java_com_cbhb_hce_NativeUtil_checkup(JNIEnv *env, jclass cls, jobject context) {
    checkup(env, context);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    getGpoResponse
 * Signature: (Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_cbhb_hce_NativeUtil_getGpoResponse(JNIEnv *env, jclass cls, jobject context, jstring gpo,
        jstring cvr, jstring tag_9F6C) {
    checkup(env, context);
    return build_gpo_response(env, context, gpo, cvr, tag_9F6C);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    getSelectPpseResp
 * Signature: (Ljava/lang/Object;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_cbhb_hce_NativeUtil_getSelectPpseResp(JNIEnv *env, jclass cls, jobject context) {
    checkup(env, context);
    const char* out = get_card_properties(env, context, "ppse");
    jstring result = (*env)->NewStringUTF(env, out);
    free((void*) out);
    return result;
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    getSelectAidResp
 * Signature: (Ljava/lang/Object;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_cbhb_hce_NativeUtil_getSelectAidResp(JNIEnv *env, jclass cls, jobject context) {
    const char* out = get_card_properties(env, context, "aid");
    jstring result = (*env)->NewStringUTF(env, out);
    free((void*) out);
    return result;
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    removePayment
 * Signature: (Ljava/lang/Object;)V
 */
JNIEXPORT void JNICALL Java_com_cbhb_hce_NativeUtil_removePayment(JNIEnv *env, jclass cls, jobject context) {
    remove_payments(env, context);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    removeCard
 * Signature: (Ljava/lang/Object;)V
 */
JNIEXPORT void JNICALL Java_com_cbhb_hce_NativeUtil_removeCard(JNIEnv *env, jclass cls, jobject context) {
    remove_card(env, context);
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    getDeviceId
 * Signature: (Ljava/lang/Object;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_cbhb_hce_NativeUtil_getDeviceId(JNIEnv *env, jclass cls, jobject context) {
    char out[40 + 1] = { 0 };
    get_device_id_string(env, context, out);
    jstring result = (*env)->NewStringUTF(env, out);
    return result;
}

/*
 * Class:     com_cbhb_hce_NativeUtil
 * Method:    getPaymentCount
 * Signature: (Ljava/lang/Object;)I
 */
JNIEXPORT jint JNICALL Java_com_cbhb_hce_NativeUtil_getPaymentCount(JNIEnv *env, jclass cls, jobject context) {
    return get_payment_count(env, context);
}
