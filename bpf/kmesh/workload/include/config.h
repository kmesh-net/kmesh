/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef _KMESH_CONFIG_H_
#define _KMESH_CONFIG_H_

// map size
#define MAP_SIZE_OF_FRONTEND 100
#define MAP_SIZE_OF_SERVICE  100
#define MAP_SIZE_OF_ENDPOINT 1000
#define MAP_SIZE_OF_BACKEND  500
#define MAP_SIZE_OF_AUTH     8192
#define MAP_SIZE_OF_DSTINFO  8192

// map name
#define map_of_frontend kmesh_frontend
#define map_of_service  kmesh_service
#define map_of_endpoint kmesh_endpoint
#define map_of_backend  kmesh_backend
#define map_of_manager  kmesh_manage

#endif // _CONFIG_H_
