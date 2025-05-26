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
	"kmesh.net/kmesh/pkg/controller/workload/common"
)

func TestAddOrUpdateWorkload(t *testing.T) {
	t.Run("adding a workload when none exists", func(t *testing.T) {
		w := NewWorkloadCache()
		Addresses := [][]byte{
			[]byte("192.168.224.22"),
			[]byte("1.2.3.4"),
		}
		// creating workload using fake workloads
		workload := common.CreateFakeWorkload("1.2.3.5", "", common.WithWorkloadBasicInfo("ut-workload", "123456", "ut-net"), common.WithAddresses(Addresses))

		w.AddOrUpdateWorkload(workload)
		assert.Equal(t, workload, w.byUid["123456"])
		addr1, _ := netip.AddrFromSlice([]byte("192.168.224.22"))
		addr2, _ := netip.AddrFromSlice([]byte("1.2.3.4"))
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: workload.Network, Address: addr1}])
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: workload.Network, Address: addr2}])
	})

	t.Run("workload service update", func(t *testing.T) {
		w := NewWorkloadCache()
		services := map[string]*workloadapi.PortList{
			"default/testsvc1.default.svc.cluster.local": {
				Ports: []*workloadapi.Port{
					{
						ServicePort: 80,
						TargetPort:  8080,
					},
					{
						ServicePort: 81,
						TargetPort:  8180,
					},
					{
						ServicePort: 82,
						TargetPort:  82,
					},
				},
			},
			"default/testsvc2.default.svc.cluster.local": {
				Ports: []*workloadapi.Port{
					{
						ServicePort: 80,
						TargetPort:  8080,
					},
				},
			},
		}

		// creating workload using fake workloads
		workload := common.CreateFakeWorkload("1.2.3.4", "", common.WithWorkloadBasicInfo("ut-workload", "123456", "ut-net"), common.WithAddresses([]byte("192.168.224.22")), common.WithServices(services))

		w.AddOrUpdateWorkload(workload)
		assert.Equal(t, workload, w.byUid["123456"])
		addr, _ := netip.AddrFromSlice([]byte("192.168.224.22"))
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: workload.Network, Address: addr}])

		services = map[string]*workloadapi.PortList{
			"default/testsvc1.default.svc.cluster.local": {
				Ports: []*workloadapi.Port{
					{
						ServicePort: 80,
						TargetPort:  8080,
					},
					{
						ServicePort: 81,
						TargetPort:  8180,
					},
					{
						ServicePort: 82,
						TargetPort:  82,
					},
				},
			},
			"default/testsvc3.default.svc.cluster.local": {
				Ports: []*workloadapi.Port{
					{
						ServicePort: 80,
						TargetPort:  8080,
					},
				},
			},
		}
		// creating workload using fake workloads
		newWorkload := common.CreateFakeWorkload("1.2.3.4", "", common.WithWorkloadBasicInfo("ut-workload", "123456", "ut-net"), common.WithAddresses([]byte("192.168.224.22")), common.WithServices(services))

		w.AddOrUpdateWorkload(newWorkload)
		assert.Equal(t, newWorkload, w.byUid["123456"])
		assert.Equal(t, newWorkload, w.byAddr[NetworkAddress{Network: newWorkload.Network, Address: addr}])
	})
}

func TestDeleteWorkload(t *testing.T) {
	t.Run("normal function test", func(t *testing.T) {
		w := NewWorkloadCache()
		Addresses := [][]byte{
			[]byte("hello"),
			[]byte("world"),
		}
		workload := common.CreateFakeWorkload("1.2.3.7", "", common.WithWorkloadBasicInfo("ut-workload", "123456", "ut-net"), common.WithAddresses(Addresses))

		w.AddOrUpdateWorkload(workload)
		assert.Equal(t, workload, w.byUid["123456"])
		w.DeleteWorkload("123456")
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byUid["123456"])
		addr1, _ := netip.AddrFromSlice([]byte("hello"))
		addr2, _ := netip.AddrFromSlice([]byte("world"))
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byAddr[NetworkAddress{Network: "ut-net", Address: addr1}])
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byAddr[NetworkAddress{Network: "ut-net", Address: addr2}])
	})

	t.Run("address override", func(t *testing.T) {
		w := NewWorkloadCache()
		Addresses := []string{
			"192.168.224.22",
			"1.2.3.4",
		}
		workload := common.CreateFakeWorkload("192.168.224.22", "", common.WithWorkloadBasicInfo("ut-workload", "123456", "ut-net"), common.WithAddresses(Addresses))
		w.AddOrUpdateWorkload(workload)

		// Both workload2 and workload point to address "192.168.224.22"
		workload2 := common.CreateFakeWorkload("192.168.224.22", "", common.WithWorkloadBasicInfo("ut-workload-2", "abcdefg", "ut-net"))
		w.AddOrUpdateWorkload(workload2)

		assert.Equal(t, workload, w.byUid["123456"])
		assert.Equal(t, workload2, w.byUid["abcdefg"])

		w.DeleteWorkload("123456")
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byUid["123456"])

		addr0 := netip.MustParseAddr(Addresses[0])
		addr1 := netip.MustParseAddr(Addresses[1])

		// Address "192.168.224.22" has been overwritten by workload2, so it will not be deleted
		assert.Equal(t, workload2, w.byAddr[NetworkAddress{Network: "ut-net", Address: addr0}])
		// Address "1.2.3.4" still points to workload, so it will be deleted.
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byAddr[NetworkAddress{Network: "ut-net", Address: addr1}])
	})
}
