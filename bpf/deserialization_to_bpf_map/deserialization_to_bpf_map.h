/*
 * Copyright 2023 The Kmesh Authors.
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
 */

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
