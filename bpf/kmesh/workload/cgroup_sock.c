/*
 * Copyright 2024 The Kmesh Authors.
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

 * Author: kwb0523
 * Create: 2024-01-20
 */

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include "bpf_log.h"
#include "ctx/sock_addr.h"
#include "frontend.h"

static inline bool check_sock_enable_kmesh()
{
	/* currently, namespace that use Kmesh are marked by using the
	 * specified number in net_cls.classid of cgroupv1.
	 * When the container is started, the CNI adds the corresponding
	 * tag to the classid file of the container. eBPF obtains the tag
	 * to determine whether to manage the container in Kmesh.
	 */
	__u64 classid = bpf_get_cgroup_classid(NULL);
	if (classid != KMESH_CLASSID_MARK)
		return false;
	return true;
}

static inline int sock4_traffic_control(struct bpf_sock_addr *ctx)
{
	int ret;
	frontend_value *frontend_v = NULL;
	bool direct_backend = false;

	if (!check_sock_enable_kmesh())
		return 0;

	DECLARE_VAR_ADDRESS(ctx, address);

	BPF_LOG(DEBUG, KMESH, "origin addr=[%u:%u]\n", ctx->user_ip4, ctx->user_port);
	frontend_v = map_lookup_frontend(&address);
	if (!frontend_v) {
		address.service_port = 0;
		frontend_v = map_lookup_frontend(&address);
		if (!frontend_v) {
			BPF_LOG(ERR, KMESH, "find frontend failed\n");
			return -ENOENT;
		}
		direct_backend = true;
	}

	BPF_LOG(DEBUG, KMESH, "bpf find frontend addr=[%u:%u]\n", ctx->user_ip4, ctx->user_port);

	if (direct_backend) {
		backend_key backend_k = {0};
		backend_value *backend_v = NULL;

		backend_k.backend_uid = frontend_v->service_id;
		backend_v = map_lookup_backend(&backend_k);
		if (!backend_v) {
			BPF_LOG(ERR, KMESH, "find backend failed\n");
			return -ENOENT;
		}
		BPF_LOG(DEBUG, KMESH, "find pod frontend\n");
		ret = backend_manager(ctx, backend_v);
		if (ret < 0) {
			BPF_LOG(ERR, KMESH, "backend_manager failed, ret:%d\n", ret);
			return ret;
		}
	} else {
		ret = frontend_manager(ctx, frontend_v);
		if (ret != 0) {
			BPF_LOG(ERR, KMESH, "frontend_manager failed, ret:%d\n", ret);
			return ret;
		}
	}
	return 0;
}

SEC("cgroup/connect4")
int cgroup_connect4_prog(struct bpf_sock_addr *ctx)
{
	int ret = sock4_traffic_control(ctx);
	return CGROUP_SOCK_OK;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;


