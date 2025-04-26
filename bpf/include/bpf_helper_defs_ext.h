/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

/*
 * Note: when compiling kmesh, the helper function IDs listed in this
 * file will be updated based on the file "/usr/include/linux/bpf.h"
 * in the compilation environment. In addition, newly developed helper
 * functions will also be added here in the future.
 *
 * By default, these IDs are in the 5.10 kernel with kmesh kernel patches.
 */

#define bpf_km_header_strnstr_num 175
#define bpf_km_header_strncmp_num 176
#define bpf_parse_header_msg_num  177

/*
 * Description
 *      Look for the string corresponding to the key in the results of the
 *      previous bpf_parse_header_msg parsing of the message header, and
 *      Search for the target substring in the string.
 * Return
 *      If found, return 1; otherwise, return 0.
 */
static long (*bpf_km_header_strnstr)(
    struct bpf_sock_addr *ctx, const char *key, int key_sz, const char *subptr, int subptr_sz) = (void *)
    bpf_km_header_strnstr_num;

/*
 * Description
 *      Look for the string corresponding to the key in the results of the
 *      previous bpf_parse_header_msg parsing of the message header, and
 *      compare it with the target string. Control whether it is an exact
 *      match or a prefix match through the opt.
 * Return
 *      If the strings are same, return 0.
 */
static long (*bpf_km_header_strncmp)(const char *key, int key_sz, const char *target, int target_sz, int opt) = (void *)
    bpf_km_header_strncmp_num;

/*
 * Description
 *      Get the memory pointer from ctx's t_ctx and parse the string information
 *      stored within. In this use case, t_ctx must be the HTTP protocol message
 *      header. After parsing, the message information will be stored in a
 *      red-black tree for subsequent lookup.
 * Return
 *      A HTTP PROTO TYPE is returned on success.
 *      **PROTO_UNKNOW** is returned if failure.
 */
static long (*bpf_parse_header_msg)(struct bpf_sock_addr *ctx) = (void *)bpf_parse_header_msg_num;
