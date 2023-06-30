/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *	 http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: supercharge
 * Create: 2023-06-15
 */

#ifndef __TCP_PROXY_H__
#define __TCP_PROXY_H__

#include "filter/tcp_proxy.pb-c.h"
#include "kmesh_common.h"
#include "tail_call.h"

static inline int tcp_proxy_manager(const Filter__TcpProxy *tcpProxy, ctx_buff_t *ctx)
{
	int ret;
	char *cluster = NULL;
	DECLARE_VAR_ADDRESS(ctx, addr);
	ctx_key_t ctx_key = {0};
	ctx_val_t ctx_val = {0};
	if (NULL == tcpProxy)
		return convert_sock_errno(-EINVAL);
	cluster = (char *)kmesh_get_ptr_val(_(tcpProxy->cluster));
	ctx_key.address = addr;
	ctx_key.tail_call_index = KMESH_TAIL_CALL_CLUSTER + bpf_get_current_task();
	ret = bpf_strcpy(ctx_val.data, BPF_DATA_MAX_LEN, cluster);
	if (ret != 0) {
		BPF_LOG(ERR, FILTER, "failed to copy cluster %s\n", cluster);
		return convert_sock_errno(ret);
	}
	ret = kmesh_tail_update_ctx(&ctx_key, &ctx_val);
	if (ret != 0)
		return convert_sock_errno(ret);
	BPF_LOG(DEBUG, FILTER, "tcp_proxy_manager cluster %s\n", cluster);
	kmesh_tail_call(ctx, KMESH_TAIL_CALL_CLUSTER);
	kmesh_tail_delete_ctx(&ctx_key);
	return 0;
}
#endif // __TCP_PROXY_H__