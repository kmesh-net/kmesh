/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __INNER_MAP_H__
#define __INNER_MAP_H__

#define BPF_INNER_MAP_DATA_LEN 1300

// map-in-map index:
// map_in_map_type(1 byte) + inner_index(3 bytes)

typedef enum {
    MAP_IN_MAP_TYPE_64,
    MAP_IN_MAP_TYPE_128,
    MAP_IN_MAP_TYPE_1024,
    MAP_IN_MAP_TYPE_8192,
    MAP_IN_MAP_TYPE_MAX
} map_in_map_type;

struct inner_map_meta {
    unsigned char used;
};

#define INNER_MAP_GET_PTR_VAL(ptrVal)           (void *)((char *)(ptrVal))
#define MAP_IN_MAP_GET_TYPE(idx)                (__u8)((__u32)(idx) >> 24)
#define MAP_IN_MAP_GET_INNER_IDX(idx)           (__u32)((__u32)(idx)&0xFFFFFF)
#define MAP_IN_MAP_GEN_OUTER_KEY(map_type, pos) ((__u32)((((__u8)(map_type)&0xFF) << 24) + ((__u32)(pos)&0xFFFFFF)))

#define INNER_MAP_VS_64       64
#define INNER_MAP_VS_128      128
#define INNER_MAP_VS_1024     1024
#define INNER_MAP_VS_8192     8192
#define INNER_MAP_MAX_ENTRIES 100000

#define SET_BIT(bitmap, n) ((bitmap)[(n) / 8] |= (1U << ((n) % 8)))

#define CLEAR_BIT(bitmap, n) ((bitmap)[(n) / 8] &= ~(1U << ((n) % 8)))

#define IS_SET(bitmap, n) (((bitmap)[(n) / 8] & (1U << ((n) % 8))) != 0)

#define IS_CLEAR(bitmap, n) (((bitmap)[(n) / 8] & (1U << ((n) % 8))) == 0)

#define FLIP_BIT(bitmap, n) ((bitmap)[(n) / 8] ^= (1U << ((n) % 8)))

#endif // __INNER_MAP_H__
