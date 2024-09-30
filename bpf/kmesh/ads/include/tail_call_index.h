/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef _TAIL_CALL_INDEX_H_
#define _TAIL_CALL_INDEX_H_

typedef enum {
    KMESH_TAIL_CALL_LISTENER = 1,
    KMESH_TAIL_CALL_FILTER_CHAIN,
    KMESH_TAIL_CALL_FILTER,
    KMESH_TAIL_CALL_ROUTER,
    KMESH_TAIL_CALL_CLUSTER,
    KMESH_TAIL_CALL_ROUTER_CONFIG,
} tail_call_index_t;

#endif // _TAIL_CALL_INDEX_H_
