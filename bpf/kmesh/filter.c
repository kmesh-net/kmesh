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

 * Author: nlgwcy
 * Create: 2022-02-17
 */

#include "bpf_log.h"
#include "filter.h"
#include "tail_call.h"
#include "tcp_proxy.h"

static inline int handle_http_connection_manager(
	const Filter__HttpConnectionManager *http_conn, const address_t *addr,
	ctx_buff_t *ctx, struct bpf_mem_ptr *msg)
{
	int ret;
	char *route_name = NULL;
	ctx_key_t ctx_key = {0};
	ctx_val_t ctx_val = {0};

	route_name = kmesh_get_ptr_val((http_conn->route_config_name));
	if (!route_name) {
		BPF_LOG(ERR, FILTER, "failed to get http conn route name\n");
		return -1;
	}

	if (!bpf_strncpy(ctx_val.data, BPF_DATA_MAX_LEN, route_name)) {
		BPF_LOG(ERR, FILTER, "http conn: route name(%s) copy failed:%d\n", route_name, ret);
		return -1;
	}

	ctx_key.address = *addr;
	ctx_key.tail_call_index = KMESH_TAIL_CALL_ROUTER_CONFIG + bpf_get_current_task();
	ctx_val.msg = msg;
	ret = kmesh_tail_update_ctx(&ctx_key, &ctx_val);
	if (ret != 0) {
		return -1;
	}

	kmesh_tail_call(ctx, KMESH_TAIL_CALL_ROUTER_CONFIG);
	kmesh_tail_delete_ctx(&ctx_key);
	return 0;
}

SEC_TAIL(KMESH_SOCKOPS_CALLS, KMESH_TAIL_CALL_FILTER)
int filter_manager(ctx_buff_t *ctx)
{
	int ret = 0;
	ctx_key_t ctx_key = {0};
	ctx_val_t *ctx_val = NULL;
	Listener__Filter *filter = NULL;
	Filter__HttpConnectionManager *http_conn = NULL;
	Filter__TcpProxy *tcp_proxy = NULL;

	DECLARE_VAR_ADDRESS(ctx, addr);
	ctx_key.address = addr;
	ctx_key.tail_call_index = KMESH_TAIL_CALL_FILTER + bpf_get_current_task();
	ctx_val = kmesh_tail_lookup_ctx(&ctx_key);
	if (!ctx_val) {
		BPF_LOG(ERR, FILTER, "failed to lookup tail call val\n");
		return convert_sockops_ret(-1);
	}

	filter = (Listener__Filter *)kmesh_get_ptr_val((void *)ctx_val->val);
	if (!filter) {
		BPF_LOG(ERR, FILTER, "failed to get filter\n");
		return convert_sockops_ret(-1);
	}
	kmesh_tail_delete_ctx(&ctx_key);

	switch (filter->config_type_case) {
		case LISTENER__FILTER__CONFIG_TYPE_HTTP_CONNECTION_MANAGER:
			http_conn = kmesh_get_ptr_val(filter->http_connection_manager);
			ret = bpf_parse_header_msg(ctx_val->msg);
			if (GET_RET_PROTO_TYPE(ret) != PROTO_HTTP_1_1) {
				BPF_LOG(DEBUG, FILTER, "http filter manager,only support http1.1 this version");
				return 0;
			}
			if (!http_conn) {
				BPF_LOG(ERR, FILTER, "get http_conn failed\n");
				ret = -1;
				break;
			}
			ret = handle_http_connection_manager(http_conn, &addr, ctx, ctx_val->msg);
			break;
		case LISTENER__FILTER__CONFIG_TYPE_TCP_PROXY:
			tcp_proxy = kmesh_get_ptr_val(filter->tcp_proxy);
			if (!tcp_proxy) {
				BPF_LOG(ERR, FILTER, "get tcp_prxoy failed\n");
				ret = -1;
				break;
			}
			ret = tcp_proxy_manager(tcp_proxy, ctx);
			break;
		default:
			break;
	}
	return convert_sockops_ret(ret);
}

SEC_TAIL(KMESH_SOCKOPS_CALLS, KMESH_TAIL_CALL_FILTER_CHAIN)
int filter_chain_manager(ctx_buff_t *ctx)
{
	int ret = 0;
	__u64 filter_idx = 0;
	ctx_key_t ctx_key = {0};
	ctx_val_t ctx_val = {0};
	ctx_val_t *ctx_val_ptr = NULL;
	Listener__FilterChain *filter_chain = NULL;
	Listener__Filter *filter = NULL;

	DECLARE_VAR_ADDRESS(ctx, addr);

	ctx_key.address = addr;
	ctx_key.tail_call_index = KMESH_TAIL_CALL_FILTER_CHAIN + bpf_get_current_task();

	ctx_val_ptr = kmesh_tail_lookup_ctx(&ctx_key);
	if (!ctx_val_ptr) {
		BPF_LOG(ERR, FILTERCHAIN, "failed to lookup tail ctx\n");
		return convert_sockops_ret(-1);
	}
	kmesh_tail_delete_ctx(&ctx_key);

	filter_chain = (Listener__FilterChain *)kmesh_get_ptr_val((void *)ctx_val_ptr->val);
	if (filter_chain == NULL) {
		return convert_sockops_ret(-1);
	}
	/* filter match */
	ret = filter_chain_filter_match(filter_chain, &addr, ctx, &filter, &filter_idx);
	if (ret != 0) {
		BPF_LOG(ERR, FILTERCHAIN, "no match filter, addr=%u\n", addr.ipv4);
		return convert_sockops_ret(-1);
	}

	// FIXME: when filter_manager unsuccessful,
	// we should skip back and handle next filter, rather than exit.

	ctx_key.address = addr;
	ctx_key.tail_call_index = KMESH_TAIL_CALL_FILTER + bpf_get_current_task();
	ctx_val.val = filter_idx;
	ctx_val.msg = ctx_val_ptr->msg;
	ret = kmesh_tail_update_ctx(&ctx_key, &ctx_val);
	if (ret != 0) {
		BPF_LOG(ERR, FILTERCHAIN, "kmesh_tail_update_ctx failed:%d\n", ret);
		return convert_sockops_ret(ret);
	}
	
	kmesh_tail_call(ctx, KMESH_TAIL_CALL_FILTER);
	kmesh_tail_delete_ctx(&ctx_key);
	return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
