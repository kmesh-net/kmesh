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

const (
	MaxPortNum = 10
)

type ServiceKey struct {
	ServiceId uint32 // service id
}

type ServicePorts [MaxPortNum]uint32
type TargetPorts [MaxPortNum]uint32

type ServiceValue struct {
	EndpointCount uint32       // endpoint count of current service
	LbPolicy      uint32       // load balancing algorithm, currently only supports random algorithm
	ServicePort   ServicePorts // ServicePort[i] and TargetPort[i] are a pair, i starts from 0 and max value is MaxPortNum-1
	TargetPort    TargetPorts
	WaypointAddr  [16]byte
	WaypointPort  uint32
}

func (c *Cache) ServiceUpdate(key *ServiceKey, value *ServiceValue) error {
	log.Debugf("ServiceUpdate [%#v], [%#v]", *key, *value)
	return c.bpfMap.KmeshService.Update(key, value, ebpf.UpdateAny)
}

func (c *Cache) ServiceDelete(key *ServiceKey) error {
	log.Debugf("ServiceDelete [%#v]", *key)
	return c.bpfMap.KmeshService.Delete(key)
}

func (c *Cache) ServiceLookup(key *ServiceKey, value *ServiceValue) error {
	log.Debugf("ServiceLookup [%#v]", *key)
	return c.bpfMap.KmeshService.Lookup(key, value)
}
