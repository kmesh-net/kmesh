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
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

type WorkloadPolicyKey struct {
	WorklodId uint32 // workloadIp to uint32
}

type WorkloadPolicyValue struct {
	PolicyIds [4]uint32 // name length is [MAX_MEMBER_NUM_PER_POLICY]
}

func (c *Cache) WorkloadPolicyUpdate(key *WorkloadPolicyKey, value *WorkloadPolicyValue) error {
	log.Debugf("workload policy update: [%#v], [%#v]", *key, *value)
	if err := c.bpfMap.KmWlpolicy.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update workload policy map for workload %d: %w", key.WorklodId, err)
	}
	return nil
}

func (c *Cache) WorkloadPolicyDelete(key *WorkloadPolicyKey) error {
	log.Debugf("workload policy delete: [%#v]", *key)
	err := c.bpfMap.KmWlpolicy.Delete(key)
	if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to delete workload policy map for workload %d: %w", key.WorklodId, err)
	}
	return nil
}

func (c *Cache) WorkloadPolicyLookup(key *WorkloadPolicyKey, value *WorkloadPolicyValue) error {
	log.Debugf("workload policy lookup: [%#v]", *key)
	if err := c.bpfMap.KmWlpolicy.Lookup(key, value); err != nil {
		return fmt.Errorf("failed to lookup workload policy map for workload %d: %w", key.WorklodId, err)
	}
	return nil
}

func (c *Cache) WorkloadPolicyLookupAll() []WorkloadPolicyValue {
	log.Debugf("WorkloadPolicyLookupAll")
	return LookupAll[WorkloadPolicyKey, WorkloadPolicyValue](c.bpfMap.KmWlpolicy)
}
