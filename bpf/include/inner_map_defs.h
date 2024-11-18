/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __INNER_MAP_H__
#define __INNER_MAP_H__

// outer key:
// map_type(1 byte) + inner_index(3 bytes)

typedef enum { MAP_TYPE_64, MAP_TYPE_192, MAP_TYPE_296, MAP_TYPE_1600, MAP_TYPE_MAX } map_in_map_type;

#define MAP_GET_TYPE(idx)                (__u8)((__u32)(idx) >> 24)
#define MAP_GET_INDEX(idx)               (__u32)((__u32)(idx)&0xFFFFFF)
#define MAP_GEN_OUTER_KEY(map_type, pos) ((__u32)((((__u8)(map_type)&0xFF) << 24) + ((__u32)(pos)&0xFFFFFF)))

#define MAP_VAL_SIZE_64   64
#define MAP_VAL_SIZE_192  192
#define MAP_VAL_SIZE_296  296
#define MAP_VAL_SIZE_1600 1600
#define MAP_MAX_ENTRIES   1000000

#define MAP_VAL_STR_SIZE    MAP_VAL_SIZE_192
#define MAP_VAL_REPEAT_SIZE MAP_VAL_SIZE_1600

#define SET_BIT(bitmap, n) ((bitmap)[(n) / 8] |= (1U << ((n) % 8)))

#define CLEAR_BIT(bitmap, n) ((bitmap)[(n) / 8] &= ~(1U << ((n) % 8)))

#define IS_SET(bitmap, n) (((bitmap)[(n) / 8] & (1U << ((n) % 8))) != 0)

#define IS_CLEAR(bitmap, n) (((bitmap)[(n) / 8] & (1U << ((n) % 8))) == 0)

#define FLIP_BIT(bitmap, n) ((bitmap)[(n) / 8] ^= (1U << ((n) % 8)))

#endif // __INNER_MAP_H__