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

// Generally, frontend_key store Service ip and port, for app access Service,
// Specifically, for app access Pod directly: FrontendKey:{IPv4:<PodIP>, Port:0}, FrontendValue:{UpstreamId:BackendUid}
type FrontendKey struct {
	IPv4 uint32 // Service ip or Pod ip
	Port uint32 // actual port for Service or 0 for Pod
}

type FrontendValue struct {
	UpstreamId uint32 // service id for Service access or backend uid for Pod access
}

func FrontendUpdate(key *FrontendKey, value *FrontendValue) error {
	log.Debugf("FrontendUpdate [%#v], [%#v]", *key, *value)
	return bpf.ObjWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps.KmeshFrontend.
		Update(key, value, ebpf.UpdateAny)
}

func FrontendDelete(key *FrontendKey) error {
	log.Debugf("FrontendDelete [%#v]", *key)
	return bpf.ObjWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps.KmeshFrontend.
		Delete(key)
}

func FrontendLookup(key *FrontendKey, value *FrontendValue) error {
	log.Debugf("FrontendLookup [%#v]", *key)
	return bpf.ObjWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps.KmeshFrontend.
		Lookup(key, value)
}

func FrontendIterFindKey(upstreamId uint32) []FrontendKey {
	log.Debugf("FrontendIterFindKey [%#v]", upstreamId)
	var (
		key   = FrontendKey{}
		value = FrontendValue{}
		iter  = bpf.ObjWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps.KmeshFrontend.Iterate()
	)

	res := make([]FrontendKey, 0)
	for iter.Next(&key, &value) {
		if value.UpstreamId == upstreamId {
			res = append(res, key)
		}
	}

	log.Debugf("res:[%#v]", res)
	return res
}
