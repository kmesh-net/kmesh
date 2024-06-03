/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef MACLI_LOG_H
#define MACLI_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include "securec.h"

enum LOG_LEVEL { FATAL = 0, ERR, WARN, INFO, DEBUG };

void ma_log(enum LOG_LEVEL level, const char *format, ...);

#define macli_log(level, format, ...) ma_log(level, format, ##__VA_ARGS__)

#endif // MACLI_LOG_H
