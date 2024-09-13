/*
 * Copyright The Kmesh Authors.
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

type WorkloadPolicy_key struct {
	WorklodId uint32 // workloadIp to uint32
}

type WorkloadPolicy_value struct {
	PolicyIds [4]uint32 // name length is [MAX_MEMBER_NUM_PER_POLICY]
}

func (c *Cache) WorkloadPolicyUpdate(key *WorkloadPolicy_key, value *WorkloadPolicy_value) error {
	log.Debugf("workload policy update: [%#v], [%#v]", *key, *value)
	return c.bpfMap.MapOfWlPolicy.Update(key, value, ebpf.UpdateAny)
}

func (c *Cache) WorkloadPolicyDelete(key *WorkloadPolicy_key) error {
	log.Debugf("workload policy delete: [%#v]", *key)
	return c.bpfMap.MapOfWlPolicy.Delete(key)
}

func (c *Cache) WorkloadPolicyLookup(key *WorkloadPolicy_key, value *WorkloadPolicy_value) error {
	log.Debugf("workload policy lookup: [%#v]", *key)
	return c.bpfMap.MapOfWlPolicy.Lookup(key, value)
}

func (c *Cache) WorkloadPolicyLookupAll() []WorkloadPolicy_value {
	log.Debugf("WorkloadPolicyLookupAll")
	return LookupAll[WorkloadPolicy_key, WorkloadPolicy_value](c.bpfMap.MapOfWlPolicy)
}
