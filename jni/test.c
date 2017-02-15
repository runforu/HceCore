/*
 * test.c
 *
 *  Created on: 2015-6-15
 *      Author: hui.du
 */
#if(_DEBUG_)
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "native_impl.h"
#include "log.h"
#include "tag_list.h"

extern char* hex_string_to_byte_array(const char *, char* , int );
extern void verify_dek(JNIEnv *, jobject , char [16], char [8]);
extern int get_arqc(char [16], const char* , unsigned char [4], unsigned char [4], unsigned char [8], unsigned char [16]);
extern int parse_tlv(const char* , int , tag_list *);
extern int remove_payments(JNIEnv *env, jobject context);
extern void crash();
extern void get_salt(JNIEnv *env, jobject context, unsigned char output[8]);

// TODO: should test a whole hce process.
void test(JNIEnv *env, jobject context) {
    {
        logi("test : get_salt gen_salt")
        unsigned char output[8];
        get_salt(env, context, output);
        get_salt(env, context, output);
        gen_salt(env, context, output);
        get_salt(env, context, output);
        logi("test : get_salt gen_salt 1")
        sleep(1);
        gen_salt(env, context, output);
        get_salt(env, context, output);
        logi("test : get_salt gen_salt 1")
        return;
    }
    {
        crash();
        return;
    }
    {
        jstring ss2 = get_host_salt_str(env, context);
        logjs(env, ss2);
        jstring salt = (*env)->NewStringUTF(env, "E7EC507AE2F95E02");
        save_host_salt(env, context, salt);
        jstring s = get_host_salt_str(env, context);
        remove_payments(env, context);
        jstring ss = get_host_salt_str(env, context);
        logjs(env, ss);
        return;
    }
    {
        jstring salt = (*env)->NewStringUTF(env, "E7EC507AE2F95E0212C45508A8DA29CFF1724A53");
        set_access_pin(env, context, salt);
        char buffer[128];
        get_access_pin(env, context,buffer);
        loghex(buffer,40);
        return;
    }
    {
        char kek_crypted_dek[16], *p="D0E7EF22F8108C66258FAF33D2EBD432";
        char dek_crypted_kcv[8], *q="B37E488D8FC3BBA4";
        hex_string_to_byte_array(p,kek_crypted_dek,16 );
        hex_string_to_byte_array(q,dek_crypted_kcv,8 );
        verify_dek(env, context, kek_crypted_dek, dek_crypted_kcv);
        return;
    }
    {
        char salt_c[8+1]= {0};
        jstring salt = (*env)->NewStringUTF(env, "0515875153092489");
        save_host_salt(env, context, salt);
        get_host_salt_byte(env, context, salt_c);
        logi(salt_c);
        return;
    }
    {
        jstring key = (*env)->NewStringUTF(env, "4F8B436BF63D0C2D07DF26C68C5A5109BF325B94");
        set_access_pin(env, context, key);
        //logjs(env, compute_access_pin_hash(env, context, key));
        return;
    }
    {
        jstring key = (*env)->NewStringUTF(env, "4F8B436BF63D0C2D07DF26C68C5A5109BF325B94B31D179E");
        save_payment(env, context, 0, key);
        save_payment(env, context, 2, key);
        save_payment(env, context, 1, key);
        save_payment(env, context, 3, key);
        save_payment(env, context, 4, key);
        char atc[5] = {0};
        char key_str[33] = {0};
        logi("%d", get_payment_count(env, context));
        get_minimal_payment(env, context, atc, key_str);
        return;
    }
    {
        jstring gpo = (*env)->NewStringUTF(env, "0000000010000000000000000156000000000001561103120012345678");
        jstring cvr = (*env)->NewStringUTF(env, "03A02812");
        jstring tag_9F6C = (*env)->NewStringUTF(env, "8080");
        jstring result = build_gpo_response(env, context, gpo, cvr, tag_9F6C);
        logjs(env, result);
        return;
    }
    {
        char * gpo = "0000000010000000000000000156000000000001561103120012345678";
        char * atc = "0029";
        char * aip = "7C00";
        char * crv = "03A02812";
        char luk_a2[16] = {0};
        hex_string_to_byte_array("FDC741953D9D9CB5D3882966A93C97B3", luk_a2, 16);
        //get_dek(env, context, NULL, dek2[]);
        char mac[16 + 1] = {0};
        get_arqc(luk_a2, gpo, aip, atc, crv, mac);
        //61110E09CDAFA202
        logi(mac);
        return;
    }
    {
        const char * tags =
        "8408A000000333010101A539500A50424F432044454249548701019F38099F7A019F02065F2A025F2D027A689F1101019F120A50424F43204445424954BF0C059F4D020B0A";
        tag_list * tl = create_tag_list();
        parse_tlv(tags, strlen(tags), tl);
        logi("size =%d", tl->size);
        for (int i = 0; i < tl->size; i++) {
            logi((tl->tags[i].tag));
            logi((tl->tags[i].value));
        }
    }
}
#endif
