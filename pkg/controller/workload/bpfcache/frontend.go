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

type FrontendKey struct {
	Ip [16]byte // Service ip or Pod ip
}

type FrontendValue struct {
	UpstreamId uint32 // service id for Service access or backend uid for Pod access
}

func (c *Cache) FrontendUpdate(key *FrontendKey, value *FrontendValue) error {
	log.Debugf("FrontendUpdate [%#v], [%#v]", *key, *value)
	return c.bpfMap.KmFrontend.Update(key, value, ebpf.UpdateAny)
}

func (c *Cache) FrontendDelete(key *FrontendKey) error {
	log.Debugf("FrontendDelete [%#v]", *key)
	err := c.bpfMap.KmFrontend.Delete(key)
	if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (c *Cache) FrontendLookup(key *FrontendKey, value *FrontendValue) error {
	log.Debugf("FrontendLookup [%#v]", *key)
	return c.bpfMap.KmFrontend.
		Lookup(key, value)
}

func (c *Cache) FrontendIterFindKey(upstreamId uint32) []FrontendKey {
	log.Debugf("FrontendIterFindKey [%#v]", upstreamId)
	var (
		key   = FrontendKey{}
		value = FrontendValue{}
		iter  = c.bpfMap.KmFrontend.Iterate()
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

// FrontendCount returns the length of frontend map
// Note only used for testing
func (c *Cache) FrontendCount() int {
	return len(c.FrontendLookupAll())
}

func (c *Cache) FrontendLookupAll() []FrontendValue {
	log.Debugf("FrontendLookupAll")
	return LookupAll[FrontendKey, FrontendValue](c.bpfMap.KmFrontend)
}
