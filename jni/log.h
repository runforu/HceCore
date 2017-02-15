/*
 *
 *  Copyright (C) 2015-2016  Du Hui
 *
 */
#ifndef LOG_H
#define LOG_H

#if(_DEBUG_)
#include <android/log.h>

void _log_msg(const char *tag, int level, char *file, int line, const char *format, ...);

#define logi(fmt, ...)     \
    _log_msg("cbhb", ANDROID_LOG_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__);

#define logw(fmt, ...)     \
    _log_msg("cbhb", ANDROID_LOG_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__);

#define loge(fmt, ...) \
    _log_msg("cbhb", ANDROID_LOG_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__);

#define logd(fmt, ...)     \
    _log_msg("cbhb", ANDROID_LOG_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__);

#define logti(tag, fmt, ...)		\
    _log_msg(tag, ANDROID_LOG_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__);

#define logtw(tag, fmt, ...)		\
    _log_msg(tag, ANDROID_LOG_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__);

#define logte(tag, fmt, ...)	\
    _log_msg(tag, ANDROID_LOG_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__);

#define logtd(tag, fmt, ...)		\
    _log_msg(tag, ANDROID_LOG_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__);

#define loghex(a,b) do {\
        char* hex_table = "0123456789ABCDEF";\
        char __out__[512] = {0};\
        for (int __i__ = 0; __i__ < (b) && __i__ < sizeof(__out__) / 2; __i__++) {\
            __out__[__i__ * 2] = hex_table[((a)[__i__] >> 4) & 0x0F];\
            __out__[__i__ * 2 + 1] = hex_table[(a)[__i__] & 0x0F];\
        }\
        __out__[sizeof(__out__) - 1] = 0;\
        logi("%s",__out__);} while(0)

#define logjs(env, js)do {\
        if(js == NULL) {logi("null");break;}\
        const char *__str__ = (*env)->GetStringUTFChars(env, js, 0);\
            logi(__str__);\
            (*env)->ReleaseStringUTFChars(env, js, __str__);\
        } while(0)

#define logl logi("line?")

#define logns(s,n)\
        logi("%."#n"s", s)

#else               /* _DEBUG_ */

#define _NO_OP_  ((void)0)

#define logi(fmt, ...) _NO_OP_

#define logw(fmt, ...) _NO_OP_

#define loge(fmt, ...) _NO_OP_

#define logd(fmt, ...) _NO_OP_

#define logti(tag, fmt, ...) _NO_OP_

#define logtw(tag, fmt, ...) _NO_OP_

#define logte(tag, fmt, ...) _NO_OP_

#define logtd(tag, fmt, ...) _NO_OP_

#define loghex(a,b)  _NO_OP_

#define logjs(env, js) _NO_OP_

#define logl _NO_OP_

#define logns(s,n) _NO_OP_

#endif
#endif				/* log.h */
