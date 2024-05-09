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
	"github.com/cilium/ebpf"
)

type EndpointKey struct {
	ServiceId    uint32 // service id
	BackendIndex uint32 // if endpoint_count = 3, then backend_index = 1/2/3
}

type EndpointValue struct {
	BackendUid uint32 // workloadUid to uint32
}

func (c *Cache) EndpointUpdate(key *EndpointKey, value *EndpointValue) error {
	log.Debugf("EndpointUpdate [%#v], [%#v]", *key, *value)
	return c.bpfMap.KmeshEndpoint.Update(key, value, ebpf.UpdateAny)
}

func (c *Cache) EndpointDelete(key *EndpointKey) error {
	log.Debugf("EndpointDelete [%#v]", *key)
	return c.bpfMap.KmeshEndpoint.Delete(key)
}

func (c *Cache) EndpointLookup(key *EndpointKey, value *EndpointValue) error {
	log.Debugf("EndpointLookup [%#v]", *key)
	return c.bpfMap.KmeshEndpoint.Lookup(key, value)
}

func (c *Cache) EndpointIterFindKey(workloadUid uint32) []EndpointKey {
	log.Debugf("EndpointIterFindKey [%#v]", workloadUid)
	var (
		key   = EndpointKey{}
		value = EndpointValue{}
		iter  = c.bpfMap.KmeshEndpoint.Iterate()
	)

	res := make([]EndpointKey, 0)
	for iter.Next(&key, &value) {
		if value.BackendUid == workloadUid {
			res = append(res, key)
		}
	}

	return res
}
