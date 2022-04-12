/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-09-17
 */

#ifndef _BPF_LOG_H_
#define _BPF_LOG_H_

#include "common.h"

#define BPF_DEBUG_ON		0
#define BPF_DEBUG_OFF		(-1)

#define BPF_LOG_LEVEL		BPF_LOG_DEBUG

#define BPF_LOGTYPE_SOCKMAP		BPF_DEBUG_OFF
#define BPF_LOGTYPE_KMESH		BPF_DEBUG_ON

enum bpf_loglevel {
	BPF_LOG_ERR = 0,
	BPF_LOG_WARN,
	BPF_LOG_INFO,
	BPF_LOG_DEBUG,
};

#define BPF_LOG(l, t, f, ...)	\
	do {							\
		int loglevel = BPF_MIN(BPF_LOG_LEVEL, BPF_LOG_DEBUG + BPF_LOGTYPE_ ## t);	\
		if (BPF_LOG_ ## l <= loglevel)							\
			bpf_printk("["# t"] "# l": "f"", ##__VA_ARGS__);	\
	} while (0)

#endif // _BPF_LOG_H_