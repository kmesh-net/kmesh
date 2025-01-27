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

	"github.com/cilium/ebpf"
)

const (
	MaxServiceNum = 10
)

type BackendKey struct {
	BackendUid uint32 // workloadUid to uint32
}

type ServiceList [MaxServiceNum]uint32

type BackendValue struct {
	Ip           [16]byte
	ServiceCount uint32
	Services     ServiceList
	WaypointAddr [16]byte
	WaypointPort uint32
}

func (c *Cache) BackendUpdate(key *BackendKey, value *BackendValue) error {
	log.Debugf("BackendUpdate [%#v], [%#v]", *key, *value)
	return c.bpfMap.KmBackend.Update(key, value, ebpf.UpdateAny)
}

func (c *Cache) BackendDelete(key *BackendKey) error {
	log.Debugf("BackendDelete [%#v]", *key)
	err := c.bpfMap.KmBackend.Delete(key)
	if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (c *Cache) BackendLookup(key *BackendKey, value *BackendValue) error {
	log.Debugf("BackendLookup [%#v]", *key)
	return c.bpfMap.KmBackend.Lookup(key, value)
}

// BackendCount returns the length of backend map
// Note only used for testing
func (c *Cache) BackendCount() int {
	return len(c.BackendLookupAll())
}

func (c *Cache) BackendLookupAll() []BackendValue {
	log.Debugf("BackendLookupAll")
	return LookupAll[BackendKey, BackendValue](c.bpfMap.KmBackend)
}
