package com.cbhb.hce;

public class NativeUtil {
    static {
        System.loadLibrary("native");
    }

    public static native void test(Object ctx, String test);

    // salt: caller defined string;
    public static native String computeAccessPinHash(Object ctx, String salt, String accessPin);

    // accessPin not accesspin hash, java layer DO NOT save access pin hash.
    // salt: caller defined string;
    public static native boolean verifyAccessPinHash(Object ctx, String salt, String accessPin);

    // init first before call other method.
    public static native void init(Object ctx, String pan);

    // get token pan
    public static native String getToken(Object ctx);

    public static native int setHostSalt(Object ctx, String salt);

    public static native String getHostSalt(Object ctx);

    // CCCCYYMMDDHHNN80(8 bytes)
    public static native int setHostGroupId(Object ctx, String groupId);

    public static native String getHostGroupId(Object ctx);

    // wrap_dek hex string created from [8 bytes kcv + 16 bytes dek1 +  8 bytes kcv + 16 bytes dek2]
    public static native int setHostDek(Object ctx, String wrapDek);

    public static native int setHostPpseResp(Object ctx, String response);

    public static native int setHostAidResp(Object ctx, String response);

    public static native int setHostCardInfo(Object ctx, String tlv);

    // payment:  LUK_A2(16 bytes) + LUK_A2_KCV(8 bytes)
    public static native int setHostPayment(Object ctx, int atc, String payment);

    public static native int setAccessPinHash(Object ctx, String accessPinHash);

    public static native void checkup(Object ctx);

    public static native String getGpoResponse(Object ctx, String gpo, String cvr, String tag9F6C);

    public static native String getSelectPpseResp(Object ctx);

    public static native String getSelectAidResp(Object ctx);

    public static native void removePayment(Object ctx);

    public static native void removeCard(Object ctx);

    public static native String getDeviceId(Object ctx);

    public static native int getPaymentCount(Object ctx);
}
