/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __DESERIALIZATION_TO_BPF_MAP_H__
#define __DESERIALIZATION_TO_BPF_MAP_H__

#include <stdbool.h>

/* equal MAP_SIZE_OF_OUTTER_MAP */
#define MAX_OUTTER_MAP_ENTRIES        (1 << 20)
#define OUTTER_MAP_USAGE_HIGH_PERCENT (0.7)
#define OUTTER_MAP_USAGE_LOW_PERCENT  (0.2)
#define TASK_SIZE                     (512)

// 32,768
#define OUTTER_MAP_SCALEUP_STEP (1 << 15)
// 8,192
#define OUTTER_MAP_SCALEIN_STEP (1 << 13)

#define ELASTIC_SLOTS_NUM                                                                                              \
    ((OUTTER_MAP_SCALEUP_STEP > OUTTER_MAP_SCALEIN_STEP) ? OUTTER_MAP_SCALEUP_STEP : OUTTER_MAP_SCALEIN_STEP)

int deserial_update_elem(void *key, void *value);
void *deserial_lookup_elem(void *key, const void *msg_desciptor);
void deserial_free_elem(void *value);
int deserial_delete_elem(void *key, const void *msg_desciptor);

int deserial_init();
void deserial_uninit(bool persist);
int inner_map_mng_persist();

#endif /* __DESERIALIZATION_TO_BPF_MAP_H__ */
