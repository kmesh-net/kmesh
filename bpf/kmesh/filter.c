/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#include "bpf_log.h"
#include "filter.h"
#include "endpoint.h"
#include "tail_call.h"

static inline
int http_filter_manager(ctx_buff_t *ctx, http_filter_t *http_filter)
{
	//TODO
	return 0;
}

static inline
int filter_handle_http_connection_manager(
	ctx_buff_t *ctx,
	http_connection_manager_t *http_connection_manager)
{
	int ret;

	switch (http_connection_manager->at_type) {
		case HTTP_CONNECTION_MANAGER_RDS:
			ret = rds_manager(ctx, &http_connection_manager->rds);
			break;
		case HTTP_CONNECTION_MANAGER_ROUTE_CONFIG:
			ret = route_config_manager(ctx, &http_connection_manager->route_config);
			break;
		default:
			BPF_LOG(ERR, KMESH, "http_connection_manager at_type is wrong\n");
			ret = -ENOENT;
			break;
	}

	ret |= http_filter_manager(ctx, &http_connection_manager->http_filter);

	return ret;
}

static inline
int filter_check(ctx_buff_t *ctx, filter_t *filter)
{
	int ret;

	switch (filter->at_type) {
		case FILTER_NETWORK_HTTP_CONNECTION_MANAGER:
			ret = filter_handle_http_connection_manager(ctx, &filter->http_connection_manager);
			break;
		case FILTER_NETWORK_RATELIMIT:
			//TODO
			//ret = filter_handle_rds(filter->ratelimit);
			ret = -ENOENT;
			break;
		default:
			BPF_LOG(ERR, KMESH, "filter at_type is wrong\n");
			ret = -ENOENT;
			break;
	}

	return ret;
}

SEC_TAIL(socket, KMESH_TAIL_CALL_FILTER)
int filter_manager(ctx_buff_t *ctx)
{
	return 0;
}

SEC_TAIL(socket, KMESH_TAIL_CALL_FILTER_CHAIN)
int filter_chain_manager(ctx_buff_t *ctx)
{
	__u32 index;
	map_key_t map_key;
	filter_chain_t *filter_chain = NULL;
	filter_t *filter = NULL;

	DECLARE_VAR_ADDRESS(address, ctx);

	filter_chain = kmesh_tail_lookup_ctx(&address);
	if (filter_chain == NULL) {
		return -ENOENT;
	}

	map_key.nameid = filter_chain->map_key_of_filter.nameid;
	index = BPF_MIN(filter_chain->map_key_of_filter.index, MAP_SIZE_OF_FILTER);

	for (int i = 0; i < index; i++) {
		map_key.index = i;

		filter = map_lookup_filter(&map_key);
		if (filter == NULL) {
			BPF_LOG(DEBUG, KMESH, "map_of_filter get failed, map_key %u %u\n",
					map_key.nameid, map_key.index);
			return -ENOENT;
		}

		if (filter_check(ctx, filter) != 0)
			continue;

		if (kmesh_tail_update_ctx(&address, filter) != 0)
			return -ENOSPC;
		kmesh_tail_call(ctx, KMESH_TAIL_CALL_FILTER);
		kmesh_tail_delete_ctx(&address);

		BPF_LOG(ERR, KMESH, "kmesh_tail_call failed in %s\n", __func__);
		break;
	}

	return -ENOENT;
}

