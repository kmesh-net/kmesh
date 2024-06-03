/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __DESERIALIZATION_TO_BPF_MAP_H__
#define __DESERIALIZATION_TO_BPF_MAP_H__

/* equal MAP_SIZE_OF_OUTTER_MAP */
#define MAX_OUTTER_MAP_ENTRIES (8192)

int deserial_update_elem(void *key, void *value);
void *deserial_lookup_elem(void *key, const void *msg_desciptor);
void deserial_free_elem(void *value);
int deserial_delete_elem(void *key, const void *msg_desciptor);

int deserial_init();
void deserial_uninit();

#endif /* __DESERIALIZATION_TO_BPF_MAP_H__ */
