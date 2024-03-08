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

type BackendKey struct {
	BackendUid uint32 // workloadUid to uint32
}

type ServicePorts [MaxPortPairNum]uint32
type TargetPorts [MaxPortPairNum]uint32

type BackendValue struct {
	IPv4        uint32 // backend ip
	PortCount   uint32
	ServicePort ServicePorts // ServicePort[i] and TargetPort[i] are a pair, i starts from 0 and max value is PortCount-1
	TargetPort  TargetPorts
}

func BackendUpdate(key *BackendKey, value *BackendValue) error {
	log.Debugf("BackendUpdate [%#v], [%#v]", *key, *value)
	return bpf.ObjWorkload.KmeshWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps.KmeshBackend.
		Update(key, value, ebpf.UpdateAny)
}

func BackendDelete(key *BackendKey) error {
	log.Debugf("BackendDelete [%#v]", *key)
	return bpf.ObjWorkload.KmeshWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps.KmeshBackend.
		Delete(key)
}

func BackendLookup(key *BackendKey, value *BackendValue) error {
	log.Debugf("BackendLookup [%#v]", *key)
	return bpf.ObjWorkload.KmeshWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps.KmeshBackend.
		Lookup(key, value)
}
