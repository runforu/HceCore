package com.cbhb.hce;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map.Entry;

import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;

public class TestActivity extends Activity {

    private void initHce() {
        Payment payment = new Payment(getResources().getXml(R.xml.test));
        payment.setAccessPin("A992C362B23C60572A3D6806A3E0D28CC9A32467");

        NativeUtil.init(this, payment.getTokenPan());
        Log.i("cbhb", "！！！！！！！初始化成功");

        int set_pin = NativeUtil.setAccessPinHash(this, payment.getAccessPin());
        Log.i("cbhb", "！！！！！！！setAccessPinHash返回值 " + set_pin);

        int set_salt = NativeUtil.setHostSalt(this, payment.getHostSalt());
        Log.i("cbhb", "！！！！！！！setHostSalt返回值" + set_salt);

        String get_salt = NativeUtil.getHostSalt(this);
        Log.i("cbhb", "！！！！！！！getHostSalt返回值" + get_salt);

        int set_id = NativeUtil.setHostGroupId(this, payment.getHostGroup());
        Log.i("cbhb", "！！！！！！！setHostGroupId返回值" + set_id);

        String get_id = NativeUtil.getHostGroupId(this);
        Log.i("cbhb", "！！！！！！！getHostGroupId返回值" + get_id);

        int set_dek = NativeUtil.setHostDek(this, payment.getDek());
        Log.i("cbhb", "！！！！！！！setHostDek返回值" + set_dek);

        int set_ppse = NativeUtil.setHostPpseResp(this, payment.getSelectPpse());
        Log.i("cbhb", "！！！！！！！setHostPpseResp返回值" + set_ppse);

        int set_aid = NativeUtil.setHostAidResp(this, payment.getSelectAid());
        Log.i("cbhb", "！！！！！！！setHostAidResp返回值" + set_aid);

        int set_card = NativeUtil.setHostCardInfo(this, payment.getTlvs());
        Log.i("cbhb", "！！！！！！！setHostCardInfo返回值" + set_card);

        for (Entry<Integer, String> e : payment.getmPaymentMap().entrySet()) {
            int rt = NativeUtil.setHostPayment(this, e.getKey(), e.getValue());
            Log.i("cbhb", "！！！！！！！setHostPayment返回值 " + rt);
        }

        String ppse = NativeUtil.getSelectPpseResp(this);
        Log.i("cbhb", "！！！！！！！getSelectPpseResp返回值  " + ppse);
        Log.i("cbhb", "---------------------------------------------------------------------- ");

        String aid = NativeUtil.getSelectAidResp(this);
        Log.i("cbhb", "！！！！！！！getSelectAidResp返回值  " + aid);
        Log.i("cbhb", "---------------------------------------------------------------------- ");

        String gpo = NativeUtil.getGpoResponse(this, "00000000000100000000000001560000000000015615071400643d5d15",
                "03A02812", "0C00");
        Log.i("cbhb", "！！！！！！！getGpoResponse返回值  1" + gpo);

        NativeUtil.removePayment(this);
        Log.i("cbhb", "！！！！！！！删除支付凭证成功");
        Log.i("cbhb", NativeUtil.getToken(TestActivity.this));
        NativeUtil.removeCard(this);
        Log.i("cbhb", "！！！！！！！删除Card");
        Log.i("cbhb", "" + (null == NativeUtil.getToken(TestActivity.this)));

        String devId = NativeUtil.getDeviceId(this);
        Log.i("cbhb", "！！！！！！！获取设备指纹的值" + devId);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initHce();
        //new Handler().post(r);
    }

    public static String getString() {
        return null;
    }

    Runnable r = new Runnable() {

        @Override
        public void run() {
            for (int i = 0; i < 1; i++) {
                NativeUtil.checkup(TestActivity.this);
                initHce();
                NativeUtil.test(TestActivity.this, "");
            }
            new Handler().postDelayed(r, 1000);
        }
    };

    private byte[] getSignature(Context context) {
        PackageManager pm = context.getPackageManager();
        try {
            PackageInfo pi = pm.getPackageInfo(this.getPackageName(), PackageManager.GET_SIGNATURES);
            return pi.signatures[0].toByteArray();
        } catch (NameNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String ByteArrayToHexString(byte[] bytes) {
        final char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        char[] hexChars = new char[bytes.length * 2]; // Each byte has two hex characters (nibbles)
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF; // Cast bytes[j] to int, treating as unsigned value
            hexChars[j * 2] = hexArray[v >>> 4]; // Select hex character from upper nibble
            hexChars[j * 2 + 1] = hexArray[v & 0x0F]; // Select hex character from lower nibble
        }
        return new String(hexChars);
    }

    public static String getPublicKey(byte[] signature) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory
                    .generateCertificate(new ByteArrayInputStream(signature));
            String publicKey = cert.getPublicKey().toString();
            publicKey = publicKey.substring(publicKey.indexOf("modulus") + 8, publicKey.indexOf("publicExponent") - 1);
            return publicKey;
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
