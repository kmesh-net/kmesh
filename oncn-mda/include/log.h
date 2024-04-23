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
 *
 * Description: this file define mdacli log
 */

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
