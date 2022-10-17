/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 * Author: liuxin
 * Create: 2022-08-24
 */
#include "kmesh_parse_protocol_data.h"

struct rb_root *g_kmesh_data_root;
struct list_head g_protocol_list_head = LIST_HEAD_INIT(g_protocol_list_head);

struct kmesh_data_node* new_kmesh_data_node(u32 name_field_length)
{
	struct kmesh_data_node *new = (struct kmesh_data_node *)kmalloc(sizeof(struct kmesh_data_node), GFP_ATOMIC);
	if (unlikely(!new))
		return ERR_PTR(-ENOMEM);
	memset(new, 0x0, sizeof(struct kmesh_data_node));
	new->keystring = (char *)kmalloc(name_field_length * sizeof(char), GFP_ATOMIC);
	if (unlikely(!new->keystring)) {
		kfree(new);
		return ERR_PTR(-ENOMEM);
	}
	memset(new->keystring, 0x0, sizeof(char) * name_field_length);
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

struct kmesh_data_node* kmesh_protocol_data_search(const char* key)
{
	struct rb_root *kmesh_data_root = per_cpu_ptr(g_kmesh_data_root, raw_smp_processor_id());
	struct rb_node *node = kmesh_data_root->rb_node;
	int cmp_result;
	printk(KERN_ERR "begin find data search\n");
	while (node) {
		struct kmesh_data_node *data = rb_entry(node, struct kmesh_data_node, node);
		// printk(KERN_ERR "current data keystring is %s, value is %s, length is %d\n", data->keystring, (char *)data->value.ptr, data->value.size);
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

bool kmesh_protocol_data_insert(struct kmesh_data_node* data)
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

void kmesh_protocol_data_delete(const char* key)
{
	struct kmesh_data_node* data = kmesh_protocol_data_search(key);

	if (data != NULL) {
		struct rb_root *kmesh_data_root = per_cpu_ptr(g_kmesh_data_root, raw_smp_processor_id());
		rb_erase(&data->node, kmesh_data_root);
		delete_kmesh_data_node(&data);
	}
}

static void kmesh_protocol_clean_all(struct rb_root *kmesh_data_root)
{
	struct kmesh_data_node* data = NULL;
	struct kmesh_data_node* n = NULL;
	if (!kmesh_data_root)
		return;
	rbtree_postorder_for_each_entry_safe(data, n, kmesh_data_root, node) {
		rb_erase(&data->node, kmesh_data_root);
		delete_kmesh_data_node(&data);
	}
}

void kmesh_protocol_data_clean_all(void)
{
	struct rb_root *kmesh_data_root = per_cpu_ptr(g_kmesh_data_root, raw_smp_processor_id());
	kmesh_protocol_clean_all(kmesh_data_root);
}

void kmesh_protocol_data_clean_allcpu(void)
{
	int cpu_num;
	for_each_possible_cpu(cpu_num) {
		struct rb_root *kmesh_data_root = per_cpu_ptr(g_kmesh_data_root, cpu_num);
		kmesh_protocol_clean_all(kmesh_data_root);
	}
}

