/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _BPF_LOG_H_
#define _BPF_LOG_H_

#include "config.h"
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

#endif //_BPF_LOG_H_