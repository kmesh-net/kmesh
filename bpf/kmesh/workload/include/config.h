/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef _KMESH_CONFIG_H_
#define _KMESH_CONFIG_H_

// map size
#define MAP_SIZE_OF_FRONTEND      105000
#define MAP_SIZE_OF_SERVICE       5000
#define MAP_SIZE_OF_ENDPOINT      105000
#define MAP_SIZE_OF_BACKEND       100000
#define MAP_SIZE_OF_AUTH          8192
#define MAP_SIZE_OF_DSTINFO       8192
#define MAP_SIZE_OF_AUTH_TAILCALL 100000
#define MAP_SIZE_OF_AUTH_POLICY   512

// rename map to avoid truncation when name length exceeds BPF_OBJ_NAME_LEN = 16
#define map_of_frontend      km_frontend
#define map_of_service       km_service
#define map_of_endpoint      km_endpoint
#define map_of_backend       km_backend
#define map_of_auth_result   km_auth_res
#define map_of_auth_req      km_auth_req
#define map_of_tcp_probe     km_tcp_probe
#define map_of_authz_policy  km_authz_policy
#define map_of_cgr_tail_call km_cgr_tailcall
#define map_of_xdp_tailcall  km_xdp_tailcall
#define map_of_kmesh_socket  km_socket
#define kmesh_tc_args        km_tcargs
#define map_of_wl_policy     km_wlpolicy
#define kmesh_perf_map       km_perf_map
#define kmesh_perf_info      km_perf_info

#endif // _CONFIG_H_
