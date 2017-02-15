/*
 *
 *  Copyright (C) 2015-2016  Du Hui
 *
 */
#include "log.h"

#if(_DEBUG_)

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void _log_msg(const char *tag, int level, char *file, int line, const char *format, ...) {
    char str[512];
    snprintf(str, sizeof(str), "%s(%04d): ", file, line);

    va_list argp;
    va_start(argp, format);
    vsnprintf(str + strlen(str), sizeof(str) - strlen(str), format, argp);
    va_end(argp);

    __android_log_write(level, tag, str);
}
#endif
