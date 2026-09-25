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
package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEndpointCache(t *testing.T) {
	// Create a sample LocalityCache instance
	ec := NewEndpointCache()

	// create test endpoints
	serviceId := uint32(1)
	serviceId1 := uint32(2)
	prio := uint32(0)
	prio1 := uint32(1)

	ep1 := Endpoint{
		ServiceId:    serviceId,
		Prio:         prio,
		BackendIndex: 1,
	}
	ep2 := Endpoint{
		ServiceId:    serviceId,
		Prio:         prio,
		BackendIndex: 2,
	}
	ep3 := Endpoint{
		ServiceId:    serviceId,
		Prio:         prio1,
		BackendIndex: 1,
	}
	ep4 := Endpoint{
		ServiceId:    serviceId1,
		Prio:         prio,
		BackendIndex: 1,
	}

	// add to ec
	ec.AddEndpointToService(ep1, 123)
	ec.AddEndpointToService(ep2, 234)
	ec.AddEndpointToService(ep3, 345)
	ec.AddEndpointToService(ep4, 456)

	// check
	assert.Equal(t, 3, len(ec.endpointsByServiceId[serviceId]))
	assert.Equal(t, 1, len(ec.endpointsByServiceId[serviceId1]))

	// search
	eplist := ec.List(serviceId)
	assert.Equal(t, 3, len(eplist))

	// delete
	ec.DeleteEndpoint(ep2.ServiceId, 234)
	assert.Equal(t, 2, len(ec.endpointsByServiceId[serviceId]))
	eplist = ec.List(serviceId)
	assert.Equal(t, 2, len(eplist))

	// delete by serviceId
	ec.DeleteEndpointByServiceId(serviceId1)
	assert.Equal(t, 0, len(ec.List(serviceId1)))
}

func TestRestoreEndpoint(t *testing.T) {
	ec := NewEndpointCache()

	entries := []EndpointEntry{
		{ServiceId: 1, Prio: 0, BackendIndex: 1, WorkloadId: 100},
		{ServiceId: 1, Prio: 0, BackendIndex: 2, WorkloadId: 200},
		{ServiceId: 1, Prio: 1, BackendIndex: 1, WorkloadId: 300},
		{ServiceId: 2, Prio: 0, BackendIndex: 1, WorkloadId: 400},
	}

	ec.RestoreEndpoint(entries)

	// service 1 should have 3 workloads (100, 200, 300 keyed by workload id)
	svc1 := ec.List(1)
	assert.Equal(t, 3, len(svc1))
	assert.Equal(t, Endpoint{ServiceId: 1, Prio: 0, BackendIndex: 1}, svc1[100])
	assert.Equal(t, Endpoint{ServiceId: 1, Prio: 0, BackendIndex: 2}, svc1[200])
	assert.Equal(t, Endpoint{ServiceId: 1, Prio: 1, BackendIndex: 1}, svc1[300])

	// service 2 should have 1 workload
	svc2 := ec.List(2)
	assert.Equal(t, 1, len(svc2))
	assert.Equal(t, Endpoint{ServiceId: 2, Prio: 0, BackendIndex: 1}, svc2[400])

	// non-existent service returns empty map
	assert.Equal(t, 0, len(ec.List(99)))

	// calling RestoreEndpoint again on a fresh cache with an empty slice is a no-op
	ec2 := NewEndpointCache()
	ec2.RestoreEndpoint([]EndpointEntry{})
	assert.Equal(t, 0, len(ec2.List(1)))
}
