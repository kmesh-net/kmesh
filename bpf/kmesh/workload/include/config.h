/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 * Author: kwb0523
 * Create: 2024-01-20
 */

#ifndef _KMESH_CONFIG_H_
#define _KMESH_CONFIG_H_

// map size
#define MAP_SIZE_OF_FRONTEND 100
#define MAP_SIZE_OF_SERVICE  100
#define MAP_SIZE_OF_ENDPOINT 1000
#define MAP_SIZE_OF_BACKEND  500
#define MAP_SIZE_OF_AUTH     8192
#define MAP_SIZE_OF_MANAGER  8192
#define MAP_SIZE_OF_DSTINFO  8192

// map name
#define map_of_frontend kmesh_frontend
#define map_of_service  kmesh_service
#define map_of_endpoint kmesh_endpoint
#define map_of_backend  kmesh_backend
#define map_of_manager  kmesh_manage

#endif // _CONFIG_H_
