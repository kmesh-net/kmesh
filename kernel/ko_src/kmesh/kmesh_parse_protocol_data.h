/*
 * Copyright 2023 The Kmesh Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 * Author: liuxin
 * Create: 2022-08-24
 */
#ifndef KMESH_PARSE_PROTOCOL_DATA
#define KMESH_PARSE_PROTOCOL_DATA

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/bpf.h>
#include <linux/percpu.h>

enum kmesh_l7_proto_type { PROTO_UNKNOW = 0, PROTO_HTTP_1_1, PROTO_HTTP_2_0 };

enum kmesh_l7_msg_type { MSG_UNKNOW = 0, MSG_REQUEST, MSG_MID_REPONSE, MSG_FINAL_RESPONSE };

#define KMESH_PROTO_TYPE_WIDTH (8)

#define SET_RET_PROTO_TYPE(n, type) (n) = (((n)&0xff00) | ((u32)(type)&0xff))
#define GET_RET_PROTO_TYPE(n)       ((n)&0xff)

#define SET_RET_MSG_TYPE(n, type) (n) = (((n)&0xff) | (((u32)(type)&0xff) << KMESH_PROTO_TYPE_WIDTH))
#define GET_RET_MSG_TYPE(n)       (((n) >> KMESH_PROTO_TYPE_WIDTH) & 0xff)

struct kmesh_data_node {
    struct rb_node node;
    char *keystring;
    struct bpf_mem_ptr value;
};

struct msg_protocol {
    struct list_head list;
    u32 (*parse_protocol_msg)(const struct bpf_mem_ptr *msg);
};

extern struct rb_root *g_kmesh_data_root;
extern struct list_head g_protocol_list_head;

struct kmesh_data_node *new_kmesh_data_node(u32 name_field_length);
void delete_kmesh_data_node(struct kmesh_data_node **data);

struct kmesh_data_node *kmesh_protocol_data_search(const char *key);
bool kmesh_protocol_data_insert(struct kmesh_data_node *value);
void kmesh_protocol_data_delete(const char *key);
void kmesh_protocol_data_clean_all(void);

void kmesh_protocol_data_clean_allcpu(void);

int __init proto_common_init(void);
void __exit proto_common_exit(void);

#endif /* KMESH_PARSE_PROTOCOL_DATA */
