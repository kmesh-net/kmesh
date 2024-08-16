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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"kmesh.net/kmesh/api/v2/workloadapi"
)

func TestAddOrUpdateWorkload(t *testing.T) {
	t.Run("adding a workload when none exists", func(t *testing.T) {
		w := NewWorkloadCache()
		workload := &workloadapi.Workload{
			Name:    "ut-workload",
			Uid:     "123456",
			Network: "ut-net",
			Addresses: [][]byte{
				[]byte("192.168.224.22"),
				[]byte("1.2.3.4"),
			},
		}
		w.AddOrUpdateWorkload(workload)
		assert.Equal(t, workload, w.byUid["123456"])
		addr1, _ := netip.AddrFromSlice([]byte("192.168.224.22"))
		addr2, _ := netip.AddrFromSlice([]byte("1.2.3.4"))
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: workload.Network, Address: addr1}])
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: workload.Network, Address: addr2}])
	})

	t.Run("modify addresses in workload", func(t *testing.T) {
		w := NewWorkloadCache()
		workload := &workloadapi.Workload{
			Name:    "ut-workload",
			Uid:     "123456",
			Network: "ut-net",
			Addresses: [][]byte{
				[]byte("192.168.224.22"),
				[]byte("1.2.3.4"),
			},
		}
		w.AddOrUpdateWorkload(workload)
		assert.Equal(t, workload, w.byUid["123456"])
		addr1, _ := netip.AddrFromSlice([]byte("192.168.224.22"))
		addr2, _ := netip.AddrFromSlice([]byte("1.2.3.4"))
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: workload.Network, Address: addr1}])
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: workload.Network, Address: addr2}])
		newWorkload := &workloadapi.Workload{
			Name:    "ut-workload",
			Uid:     "123456",
			Network: "new-net",
			Addresses: [][]byte{
				[]byte("192.168.10.25"),
				[]byte("2.3.4.5"),
			},
		}
		w.AddOrUpdateWorkload(newWorkload)
		assert.Equal(t, newWorkload, w.byUid["123456"])
		addr3, _ := netip.AddrFromSlice([]byte("192.168.10.25"))
		addr4, _ := netip.AddrFromSlice([]byte("2.3.4.5"))
		assert.Equal(t, newWorkload, w.byAddr[NetworkAddress{Network: newWorkload.Network, Address: addr3}])
		assert.Equal(t, newWorkload, w.byAddr[NetworkAddress{Network: newWorkload.Network, Address: addr4}])
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byAddr[NetworkAddress{Network: workload.Network, Address: addr1}])
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byAddr[NetworkAddress{Network: workload.Network, Address: addr2}])
	})

	t.Run("add addresses to the same workload", func(t *testing.T) {
		w := NewWorkloadCache()
		workload := &workloadapi.Workload{
			Name:    "ut-workload",
			Uid:     "123456",
			Network: "ut-net",
			Addresses: [][]byte{
				[]byte("192.168.224.22"),
			},
		}
		w.AddOrUpdateWorkload(workload)
		assert.Equal(t, workload, w.byUid["123456"])
		addr, _ := netip.AddrFromSlice([]byte("192.168.224.22"))
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: workload.Network, Address: addr}])
		newWorkload := &workloadapi.Workload{
			Name:    "ut-workload",
			Uid:     "123456",
			Network: "new-net",
			Addresses: [][]byte{
				[]byte("192.168.224.22"),
				[]byte("2.3.4.5"),
			},
		}
		w.AddOrUpdateWorkload(newWorkload)
		assert.Equal(t, newWorkload, w.byUid["123456"])
		addr1, _ := netip.AddrFromSlice([]byte("192.168.224.22"))
		addr2, _ := netip.AddrFromSlice([]byte("2.3.4.5"))
		assert.Equal(t, newWorkload, w.byAddr[NetworkAddress{Network: newWorkload.Network, Address: addr1}])
		assert.Equal(t, newWorkload, w.byAddr[NetworkAddress{Network: newWorkload.Network, Address: addr2}])
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byAddr[NetworkAddress{Network: workload.Network, Address: addr}])
	})
}

func TestDeleteWorkload(t *testing.T) {
	t.Run("normal function test", func(t *testing.T) {
		w := NewWorkloadCache()
		workload := &workloadapi.Workload{
			Name:    "ut-workload",
			Uid:     "123456",
			Network: "ut-net",
			Addresses: [][]byte{
				[]byte("hello"),
				[]byte("world"),
			},
		}
		w.AddOrUpdateWorkload(workload)
		assert.Equal(t, workload, w.byUid["123456"])
		w.DeleteWorkload("123456")
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byUid["123456"])
		addr1, _ := netip.AddrFromSlice([]byte("hello"))
		addr2, _ := netip.AddrFromSlice([]byte("world"))
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byAddr[NetworkAddress{Network: "ut-net", Address: addr1}])
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byAddr[NetworkAddress{Network: "ut-net", Address: addr2}])
	})
}

func TestWorkloadRelationShip(t *testing.T) {
	t.Run("normal function test", func(t *testing.T) {
		w := NewWorkloadCache()

		var serviceId uint32 = 12345678
		var relationId uint32 = 87654321
		var workloadId uint32 = 12341234

		var relationKey = ServiceRelationShipByWorkload{
			workloadId: workloadId,
			serviceId:  serviceId,
		}
		var relationKeyById = ServiceRelationShipById{
			serviceId:  serviceId,
			relationId: relationId,
		}

		w.UpdateRelationShip(workloadId, serviceId, relationId)
		assert.Equal(t, workloadId, w.relationShipById[relationKeyById])
		assert.Equal(t, relationId, w.relationShipByWorkload[relationKey])

		val, ok := w.GetRelationShip(workloadId, serviceId)
		assert.Equal(t, ok, true)
		assert.Equal(t, val, relationId)

		w.DeleteRelationShip(serviceId, relationId)
		assert.Equal(t, (uint32)(0), w.relationShipById[relationKeyById])
	})
}
