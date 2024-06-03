// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include "log.h"

static const enum LOG_LEVEL level_set = INFO;
#define MAX_FMT_STR_LENGTH 2048
const char log_level_str[][6] = {"FATAL", "ERROR", "WARN", "INFO", "DEBUG"};

static enum LOG_LEVEL get_log_level(void)
{
    return level_set;
}

void ma_log(enum LOG_LEVEL level, const char *format, ...)
{
    if (level > get_log_level())
        return;

    va_list ap;
    va_start(ap, format);
    char fmt_str[MAX_FMT_STR_LENGTH] = {0};
    if (vsnprintf_s(fmt_str, sizeof(fmt_str), sizeof(fmt_str) - 1, format, ap) == -1) {
        va_end(ap);
        return;
    }
    va_end(ap);

    (void)fprintf(stderr, "%s", fmt_str);
}
