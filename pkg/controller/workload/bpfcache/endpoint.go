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
	"istio.io/istio/pkg/util/sets"
)

const (
	PrioCount = 7
)

type EndpointKey struct {
	ServiceId    uint32 // service id
	Prio         uint32
	BackendIndex uint32 // if endpoint_count = 3, then backend_index = 1/2/3
}

type EndpointValue struct {
	BackendUid uint32 // workloadUid to uint32
}

func (c *Cache) EndpointUpdate(key *EndpointKey, value *EndpointValue) error {
	log.Debugf("EndpointUpdate [%#v], [%#v]", *key, *value)
	// update endpointKeys index
	if c.endpointKeys[value.BackendUid] == nil {
		c.endpointKeys[value.BackendUid] = sets.New[EndpointKey](*key)
	} else {
		c.endpointKeys[value.BackendUid].Insert(*key)
	}

	return c.bpfMap.KmeshEndpoint.Update(key, value, ebpf.UpdateAny)
}

func (c *Cache) EndpointDelete(key *EndpointKey) error {
	log.Debugf("EndpointDelete [%#v]", *key)
	value := &EndpointValue{}
	// update endpointKeys index
	if err := c.bpfMap.KmeshEndpoint.Lookup(key, value); err != nil {
		log.Infof("endpoint [%#v] does not exist", key)
		return nil
	}
	c.endpointKeys[value.BackendUid].Delete(*key)
	if len(c.endpointKeys[value.BackendUid]) == 0 {
		delete(c.endpointKeys, value.BackendUid)
	}

	err := c.bpfMap.KmeshEndpoint.Delete(key)
	if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// EndpointSwap update the last endpoint index and remove the current endpoint
func (c *Cache) EndpointSwap(currentIndex, lastIndex uint32, serviceId uint32, prio uint32) error {
	if currentIndex == lastIndex {
		return c.EndpointDelete(&EndpointKey{
			ServiceId:    serviceId,
			Prio:         prio,
			BackendIndex: lastIndex,
		})
	}
	lastKey := &EndpointKey{
		ServiceId:    serviceId,
		Prio:         prio,
		BackendIndex: lastIndex,
	}
	lastValue := &EndpointValue{}
	if err := c.EndpointLookup(lastKey, lastValue); err != nil {
		return err
	}

	currentKey := &EndpointKey{
		ServiceId:    serviceId,
		Prio:         prio,
		BackendIndex: currentIndex,
	}
	currentValue := &EndpointValue{}
	if err := c.EndpointLookup(currentKey, currentValue); err != nil {
		return err
	}

	// update the last endpoint's index, in other word delete the current endpoint
	if err := c.bpfMap.KmeshEndpoint.Update(currentKey, lastValue, ebpf.UpdateAny); err != nil {
		return err
	}

	// delete the duplicate last endpoint
	if err := c.bpfMap.KmeshEndpoint.Delete(lastKey); err != nil {
		return err
	}

	// delete index for the current endpoint
	c.endpointKeys[currentValue.BackendUid].Delete(*currentKey)
	if len(c.endpointKeys[currentValue.BackendUid]) == 0 {
		delete(c.endpointKeys, currentValue.BackendUid)
	}

	// update the last endpoint index
	c.endpointKeys[lastValue.BackendUid].Delete(*lastKey)
	c.endpointKeys[lastValue.BackendUid].Insert(*currentKey)
	return nil
}

func (c *Cache) EndpointLookup(key *EndpointKey, value *EndpointValue) error {
	log.Debugf("EndpointLookup [%#v]", *key)
	return c.bpfMap.KmeshEndpoint.Lookup(key, value)
}

// RestoreEndpointKeys called on restart to construct endpoint indexes from bpf map
func (c *Cache) RestoreEndpointKeys() {
	log.Debugf("init endpoint keys")
	var (
		key   = EndpointKey{}
		value = EndpointValue{}
	)

	iter := c.bpfMap.KmeshEndpoint.Iterate()
	for iter.Next(&key, &value) {
		// update endpointKeys index
		if c.endpointKeys[value.BackendUid] == nil {
			c.endpointKeys[value.BackendUid] = sets.New[EndpointKey](key)
		} else {
			c.endpointKeys[value.BackendUid].Insert(key)
		}
	}
}

// GetAllEndpointsForService returns all the endpoints for a service
// Note only used for testing
func (c *Cache) GetAllEndpointsForService(serviceId uint32) []EndpointValue {
	log.Debugf("init endpoint keys")
	var (
		key   = EndpointKey{}
		value = EndpointValue{}
	)

	var res []EndpointValue

	iter := c.bpfMap.KmeshEndpoint.Iterate()
	for iter.Next(&key, &value) {
		if key.ServiceId == serviceId {
			res = append(res, value)
		}
	}
	return res
}

// EndpointCount returns the length of endpoint map
// Note only used for testing
func (c *Cache) EndpointCount() int {
	return len(c.EndpointLookupAll())
}

func (c *Cache) EndpointLookupAll() []EndpointValue {
	log.Debugf("EndpointLookupAll")
	return LookupAll[EndpointKey, EndpointValue](c.bpfMap.KmeshEndpoint)
}
