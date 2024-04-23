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

 * Author: LemmyHuang
 * Create: 2021-09-17
 */

#ifndef _BPF_LOG_H_
#define _BPF_LOG_H_

#include "common.h"

#define BPF_DEBUG_ON  0
#define BPF_DEBUG_OFF (-1)

#define BPF_LOG_LEVEL BPF_LOG_DEBUG

#define BPF_LOGTYPE_SOCKMAP BPF_DEBUG_OFF
#define BPF_LOGTYPE_KMESH   BPF_DEBUG_ON
#define BPF_LOGTYPE_SOCKOPS BPF_DEBUG_OFF
#define BPF_LOGTYPE_XDP     BPF_DEBUG_OFF
#define BPF_LOGTYPE_SENDMSG BPF_DEBUG_OFF
enum bpf_loglevel {
    BPF_LOG_ERR = 0,
    BPF_LOG_WARN,
    BPF_LOG_INFO,
    BPF_LOG_DEBUG,
};

#define BPF_LOG(l, t, f, ...)                                                                                          \
    do {                                                                                                               \
        int loglevel = BPF_MIN((int)BPF_LOG_LEVEL, ((int)BPF_LOG_DEBUG + (int)(BPF_LOGTYPE_##t)));                     \
        if ((int)(BPF_LOG_##l) <= loglevel) {                                                                          \
            char fmt[] = "[" #t "] " #l ": " f "";                                                                     \
            bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__);                                                         \
        }                                                                                                              \
    } while (0)

#endif // _BPF_LOG_H_
