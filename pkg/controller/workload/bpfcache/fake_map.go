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
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/bpf/kmesh/bpf2go"
)

func NewFakeWorkloadMap(t *testing.T) bpf2go.KmeshCgroupSockWorkloadMaps {
	backEndMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "kmesh_backend",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(BackendKey{})),
		ValueSize:  uint32(unsafe.Sizeof(BackendValue{})),
		MaxEntries: 1024,
	})
	if err != nil {
		t.Fatalf("create backEndMap map failed, err is %v", err)
	}

	endpointMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "kmesh_endpoint",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(EndpointKey{})),
		ValueSize:  uint32(unsafe.Sizeof(EndpointValue{})),
		MaxEntries: 1024,
	})
	if err != nil {
		t.Fatalf("create endpointMap map failed, err is %v", err)
	}

	frontendMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "kmesh_frontend",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(FrontendKey{})),
		ValueSize:  uint32(unsafe.Sizeof(FrontendValue{})),
		MaxEntries: 1024,
	})
	if err != nil {
		t.Fatalf("create frontendMap map failed, err is %v", err)
	}

	serviceMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "kmesh_service",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(ServiceKey{})),
		ValueSize:  uint32(unsafe.Sizeof(ServiceValue{})),
		MaxEntries: 1024,
	})
	if err != nil {
		t.Fatalf("create serviceMap map failed, err is %v", err)
	}

	// TODO: add other maps when needed

	return bpf2go.KmeshCgroupSockWorkloadMaps{
		KmeshBackend:  backEndMap,
		KmeshEndpoint: endpointMap,
		KmeshFrontend: frontendMap,
		KmeshService:  serviceMap,
	}
}

func CleanupFakeWorkloadMap(maps bpf2go.KmeshCgroupSockWorkloadMaps) {
	maps.KmeshBackend.Close()
	maps.KmeshEndpoint.Close()
	maps.KmeshFrontend.Close()
	maps.KmeshService.Close()
}
