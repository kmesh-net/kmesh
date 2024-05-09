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
 */

package bpfcache

import (
	"kmesh.net/kmesh/bpf/kmesh/bpf2go"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("workload_bpfcache")

type Cache struct {
	bpfMap bpf2go.KmeshCgroupSockWorkloadMaps
}

func NewCache(workloadMap bpf2go.KmeshCgroupSockWorkloadMaps) *Cache {
	return &Cache{
		bpfMap: workloadMap,
	}
}
