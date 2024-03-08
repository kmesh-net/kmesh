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

package workload

import (
	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/pkg/bpf"
)

type EndpointKey struct {
	ServiceId    uint32 // service id
	BackendIndex uint32 // if endpoint_count = 3, then backend_index = 1/2/3
}

type EndpointValue struct {
	BackendUid uint32 // workloadUid to uint32
}

func EndpointUpdate(key *EndpointKey, value *EndpointValue) error {
	log.Debugf("EndpointUpdate [%#v], [%#v]", *key, *value)
	return bpf.ObjWorkload.KmeshWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps.KmeshEndpoint.
		Update(key, value, ebpf.UpdateAny)
}

func EndpointDelete(key *EndpointKey) error {
	log.Debugf("EndpointDelete [%#v]", *key)
	return bpf.ObjWorkload.KmeshWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps.KmeshEndpoint.
		Delete(key)
}

func EndpointLookup(key *EndpointKey, value *EndpointValue) error {
	log.Debugf("EndpointLookup [%#v]", *key)
	return bpf.ObjWorkload.KmeshWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps.KmeshEndpoint.
		Lookup(key, value)
}

func EndpointIterFindKey(workloadUid uint32) []EndpointKey {
	log.Debugf("EndpointIterFindKey [%#v]", workloadUid)
	var (
		key   = EndpointKey{}
		value = EndpointValue{}
		iter  = bpf.ObjWorkload.KmeshWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps.KmeshEndpoint.Iterate()
	)

	res := make([]EndpointKey, 0)
	for iter.Next(&key, &value) {
		if value.BackendUid == workloadUid {
			res = append(res, key)
		}
	}

	return res
}
