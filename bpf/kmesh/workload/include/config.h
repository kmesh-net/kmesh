/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef _KMESH_CONFIG_H_
#define _KMESH_CONFIG_H_

// map size
#define MAP_SIZE_OF_FRONTEND    105000
#define MAP_SIZE_OF_SERVICE     5000
#define MAP_SIZE_OF_ENDPOINT    105000
#define MAP_SIZE_OF_BACKEND     100000
#define MAP_SIZE_OF_AUTH        8192
#define MAP_SIZE_OF_DSTINFO     8192
#define MAP_SIZE_OF_AUTH_POLICY 512

// map name
#define map_of_frontend kmesh_frontend
#define map_of_service  kmesh_service
#define map_of_endpoint kmesh_endpoint
#define map_of_backend  kmesh_backend
#define map_of_manager  kmesh_manage

#endif // _CONFIG_H_
