/*
 * Copyright 2023 The Kmesh Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 * Author: liuxin
 * Create: 2022-08-24
 */
#include "kmesh_parse_protocol_data.h"

struct rb_root __percpu *g_kmesh_data_root;
struct list_head g_protocol_list_head = LIST_HEAD_INIT(g_protocol_list_head);

struct kmesh_data_node *new_kmesh_data_node(u32 name_field_length)
{
    struct kmesh_data_node *new = (struct kmesh_data_node *)kmalloc(sizeof(struct kmesh_data_node), GFP_ATOMIC);
    if (unlikely(!new)) {
        (void)pr_err("[kmesh data node] alloc data node memory failed! no memory!\n");
        return ERR_PTR(-ENOMEM);
    }
    (void)memset(new, 0x0, sizeof(struct kmesh_data_node));
    new->keystring = (char *)kmalloc(name_field_length * sizeof(char), GFP_ATOMIC);
    if (unlikely(!new->keystring)) {
        kfree(new);
        (void)pr_err("[kmesh data node] alloc data node key memory failed! no memory!\n");
        return ERR_PTR(-ENOMEM);
    }
    (void)memset(new->keystring, 0x0, sizeof(char) * name_field_length);
    return new;
}

void delete_kmesh_data_node(struct kmesh_data_node **data)
{
    if (!data)
        return;
    if ((*data)->keystring)
        kfree((*data)->keystring);
    kfree(*data);
    *data = NULL;
}

struct kmesh_data_node *kmesh_protocol_data_search(const char *key)
{
    struct rb_root *kmesh_data_root = per_cpu_ptr(g_kmesh_data_root, raw_smp_processor_id());
    struct rb_node *node = kmesh_data_root->rb_node;
    int cmp_result;
    while (node) {
        struct kmesh_data_node *data = rb_entry(node, struct kmesh_data_node, node);
        cmp_result = strcmp(data->keystring, key);

        if (cmp_result > 0)
            node = node->rb_left;
        else if (cmp_result < 0)
            node = node->rb_right;
        else
            return data;
    }
    return NULL;
}

bool kmesh_protocol_data_insert(struct kmesh_data_node *data)
{
    struct rb_root *kmesh_data_root = per_cpu_ptr(g_kmesh_data_root, raw_smp_processor_id());
    struct rb_node **new = &(kmesh_data_root->rb_node);
    struct rb_node *parent = NULL;

    while (*new) {
        struct kmesh_data_node *this = rb_entry(*new, struct kmesh_data_node, node);
        int cmp_result = strcmp(data->keystring, this->keystring);
        parent = *new;
        if (cmp_result < 0)
            new = &((*new)->rb_left);
        else if (cmp_result > 0)
            new = &((*new)->rb_right);
        else
            return false;
    }
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, kmesh_data_root);

    return true;
}

void kmesh_protocol_data_delete(const char *key)
{
    struct kmesh_data_node *data = kmesh_protocol_data_search(key);

    if (data != NULL) {
        struct rb_root *kmesh_data_root = per_cpu_ptr(g_kmesh_data_root, raw_smp_processor_id());
        rb_erase(&data->node, kmesh_data_root);
        delete_kmesh_data_node(&data);
    }
}

static void kmesh_protocol_clean_all(struct rb_root *kmesh_data_root)
{
    struct kmesh_data_node *data = NULL;
    struct kmesh_data_node *n = NULL;
    if (!kmesh_data_root)
        return;
    rbtree_postorder_for_each_entry_safe(data, n, kmesh_data_root, node) delete_kmesh_data_node(&data);
}

void kmesh_protocol_data_clean_all(void)
{
    struct rb_root *kmesh_data_root = per_cpu_ptr(g_kmesh_data_root, raw_smp_processor_id());
    kmesh_protocol_clean_all(kmesh_data_root);
    kmesh_data_root->rb_node = NULL;
}

void kmesh_protocol_data_clean_allcpu(void)
{
    int cpu_num;
    for_each_possible_cpu(cpu_num)
    {
        struct rb_root *kmesh_data_root = per_cpu_ptr(g_kmesh_data_root, cpu_num);
        kmesh_protocol_clean_all(kmesh_data_root);
    }
}

typedef u32 (*bpf_parse_protocol_func)(struct bpf_mem_ptr *msg);
extern bpf_parse_protocol_func parse_protocol_func;

typedef struct bpf_mem_ptr *(*bpf_get_protocol_element_func)(char *key);
extern bpf_get_protocol_element_func get_protocol_element_func;

static u32 parse_protocol_impl(struct bpf_mem_ptr *msg)
{
    u32 ret;
    struct msg_protocol *cur;
    kmesh_protocol_data_clean_all();
    list_for_each_entry(cur, &g_protocol_list_head, list)
    {
        if (!cur->parse_protocol_msg)
            continue;
        ret = cur->parse_protocol_msg(msg);
        if (ret)
            break;
    }
    return ret;
}

static struct bpf_mem_ptr *get_protocol_element_impl(char *key)
{
    struct kmesh_data_node *data = kmesh_protocol_data_search(key);
    if (!data)
        return NULL;
    return &data->value;
}

int __init proto_common_init(void)
{
    parse_protocol_func = parse_protocol_impl;
    get_protocol_element_func = get_protocol_element_impl;
    /* add protocol list */
    g_kmesh_data_root = alloc_percpu(struct rb_root);
    if (!g_kmesh_data_root)
        return -ENOMEM;

    return 0;
}

void __exit proto_common_exit(void)
{
    parse_protocol_func = NULL;
    get_protocol_element_func = NULL;
    kmesh_protocol_data_clean_allcpu();
    free_percpu(g_kmesh_data_root);
}
