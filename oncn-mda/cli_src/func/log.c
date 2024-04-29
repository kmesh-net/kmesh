/*
 * Copyright 2023 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
