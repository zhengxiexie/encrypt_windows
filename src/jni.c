#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "crypto.h"
#include "jni.h"
#include "utils.h"
#include "error.h"

static jstring j_charset = NULL;

static FILE * logfile = NULL;

JNIEXPORT jlong JNICALL Java_com_asiainfo_biframe_privacyprotection_util_DecryptContext_c_1init_1decrypt_1context
    (JNIEnv * env, jobject obj, jstring charset) {

    decrypt_context_t * ctx =
        (decrypt_context_t*)calloc(sizeof(decrypt_context_t), 1);

    char buf[1024];
	char day[12];

	get_day(day);

    /*sprintf(buf, "%s/" PREFIX "/privacyprot.log", getenv("HOME")); // linux*/
    sprintf(buf, "%s/" PREFIX "/privacyprot" "_%s" ".log", getenv("HOME")==NULL?"C:":getenv("HOME"), day); // windows

    init_decrypt_context(ctx);

    // init static values
    j_charset = (jstring)(*env)->NewGlobalRef(env, charset);
    logfile   = fopen(buf, "a+");
    return (jlong)(ctx);
}

JNIEXPORT jbyteArray JNICALL Java_com_asiainfo_biframe_privacyprotection_util_DecryptContext_c_1decrypt
    (JNIEnv * env, jobject obj, jlong ctx_ptr, jstring in_str) {

    if (!in_str) return NULL;

    decrypt_context_t * ctx = (decrypt_context_t *)(ctx_ptr);

    char buffer_dec[2000], buffer_dehex[2000];

    const char * buffer_raw = (*env)->GetStringUTFChars(env, in_str, NULL);
    if (!buffer_raw || 0 == strcasecmp("null", buffer_raw)) return NULL;

#define D(x) ((x >= '0' && x <= '9')? (x - '0'): \
             ((x >= 'a' && x <= 'f')? (x - 'a' + 10): \
             ((x >= 'A' && x <= 'F')? (x - 'A' + 10): 0)))
    // HEX to raw
    int pos = 0;
    for (pos = 0; buffer_raw[pos]; pos += 2) {
        buffer_dehex[pos / 2] = 0xff &
            (D(buffer_raw[pos]) * 16 | D(buffer_raw[pos + 1]));
    }
#undef D
    buffer_dehex[pos / 2] = 0;
    (*env)->ReleaseStringUTFChars(env, in_str, buffer_raw);

    // decrypt
    int ret = 0;
    if ((ret = do_decrypt(ctx, buffer_dehex, buffer_dec))) {
        // write log on decrypt fail
        if (logfile) {
            fprintf(logfile, "[JNI]:%d %s\n", ret, errmsg[ret]);
            fflush(logfile);
        }
        return NULL;
    }

    // Create a new Java String object and return it
    int ret_len = strlen(buffer_dec);
    jbyteArray bytes = (*env)->NewByteArray(env, ret_len);
    (*env)->SetByteArrayRegion(env, bytes, 0, ret_len, (jbyte*)buffer_dec);
    return bytes;
}

JNIEXPORT void JNICALL Java_com_asiainfo_biframe_privacyprotection_util_DecryptContext_c_1destory_1decrypt_1context
    (JNIEnv * env, jobject obj, jlong ctx_ptr) {
    decrypt_context_t * ctx = (decrypt_context_t *)(ctx_ptr);
    destroy_decrypt_context(ctx);
    if (j_charset) (*env)->DeleteGlobalRef(env, (jobject)j_charset);
    if (logfile) fclose(logfile);
}
