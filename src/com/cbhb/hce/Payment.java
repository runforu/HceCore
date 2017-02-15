package com.cbhb.hce;

import java.util.HashMap;
import java.util.Map;

import org.xmlpull.v1.XmlPullParser;

import android.content.res.XmlResourceParser;
import android.util.Log;

public class Payment {

    public void parseXml(XmlResourceParser parser) {
        try {
            Integer integer = null;
            String luk_a2 = null;
            int event = parser.getEventType();
            while (event != XmlPullParser.END_DOCUMENT) {
                switch (event) {
                case XmlPullParser.START_DOCUMENT:
                    break;
                case XmlPullParser.START_TAG:
                    if ("Tok".equals(parser.getName())) {
                        this.setTokenPan(parser.nextText());
                    } else if ("ParaIdx".equals(parser.getName())) {
                        this.setHostGroup(parser.nextText());
                    } else if ("Salt".equals(parser.getName())) {
                        this.setHostSalt(parser.nextText());
                    } else if ("DEK".equals(parser.getName())) {
                        setDek(parser.nextText());
                    } else if ("PPSERS".equals(parser.getName())) {
                        setSelectPpse(parser.nextText());
                    } else if ("AIDRS".equals(parser.getName())) {
                        setSelectAid(parser.nextText());
                    } else if ("TLVRS".equals(parser.getName())) {
                        setTlvs(parser.nextText());
                    } else if ("Atc".equals(parser.getName())) {
                        integer = Integer.parseInt(parser.nextText(), 16);
                    } else if ("Luk_A2".equals(parser.getName())) {
                        luk_a2 = parser.nextText();
                    }
                    break;
                case XmlPullParser.END_TAG:
                    if ("Map".equals(parser.getName())) {
                        mPaymentMap.put(integer, luk_a2);
                    }
                    break;
                }
                event = parser.next();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Payment(XmlResourceParser parser) {
        parseXml(parser);
        Log.e("s", "a");
    }

    private String mAccessPin;

    public String getAccessPin() {
        return mAccessPin;
    }

    public void setAccessPin(String mAccessPin) {
        this.mAccessPin = mAccessPin;
    }

    public String getTokenPan() {
        return mTokenPan;
    }

    public void setTokenPan(String mTokenPan) {
        this.mTokenPan = mTokenPan;
    }

    public String getHostSalt() {
        return mHostSalt;
    }

    public void setHostSalt(String mHostSalt) {
        this.mHostSalt = mHostSalt;
    }

    public String getHostGroup() {
        return mHostGroup;
    }

    public void setHostGroup(String mHostGroup) {
        this.mHostGroup = mHostGroup;
    }

    public String getDek() {
        return mDek;
    }

    public void setDek(String mDek) {
        this.mDek = mDek;
    }

    public String getSelectPpse() {
        return mSelectPpse;
    }

    public void setSelectPpse(String mSelectPpse) {
        this.mSelectPpse = mSelectPpse;
    }

    public String getSelectAid() {
        return mSelectAid;
    }

    public void setSelectAid(String mSelectAid) {
        this.mSelectAid = mSelectAid;
    }

    public String getTlvs() {
        return mTlvs;
    }

    public void setTlvs(String mTlvs) {
        this.mTlvs = mTlvs;
    }

    private String mTokenPan;
    private String mHostSalt;
    private String mHostGroup;
    private String mDek;
    private String mSelectPpse;
    private String mSelectAid;
    private String mTlvs;
    private final Map<Integer, String> mPaymentMap = new HashMap<Integer, String>();

    public Map<Integer, String> getmPaymentMap() {
        return mPaymentMap;
    }
}
