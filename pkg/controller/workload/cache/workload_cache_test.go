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

		workload := common.CreateFakeWorkload(
			"ut-workload",                         // Name
			"123456",                              // UID
			"ut-net",                              // Network
			[]string{"192.168.224.22", "1.2.3.4"}, // Addresses
			workloadapi.NetworkMode_STANDARD,      // NetworkMode
		)
		w.AddOrUpdateWorkload(workload)
		assert.Equal(t, workload, w.byUid["123456"])
		addr1, _ := netip.AddrFromSlice([]byte("192.168.224.22"))
		addr2, _ := netip.AddrFromSlice([]byte("1.2.3.4"))
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: workload.Network, Address: addr1}])
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: workload.Network, Address: addr2}])
	})

	t.Run("workload service update", func(t *testing.T) {
		w := NewWorkloadCache()

		workload := common.CreateFakeWorkload(
			"ut-workload",                    // Name
			"192.168.224.22",                 // IP Address
			"123456",                         // UID
			workloadapi.NetworkMode_STANDARD, // Network Mode
			map[string][]*workloadapi.Port{ // Services
				"testsvc1": {
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
				"testsvc2": {
					{
						ServicePort: 80,
						TargetPort:  8080,
					},
				},
			},
		)

		w.AddOrUpdateWorkload(workload)
		assert.Equal(t, workload, w.byUid["123456"])
		addr, _ := netip.AddrFromSlice([]byte("192.168.224.22"))
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: workload.Network, Address: addr}])

		newWorkload := common.CreateFakeWorkload(
			"ut-workload",                    // Name
			"123456",                         // UID
			"new-net",                        // Network
			"192.168.224.22",                 // Address
			workloadapi.NetworkMode_STANDARD, // NetworkMode
			map[string][]*workloadapi.Port{
				"default/testsvc1.default.svc.cluster.local": {
					{ServicePort: 80, TargetPort: 8080},
					{ServicePort: 81, TargetPort: 8180},
					{ServicePort: 82, TargetPort: 82},
				},
				"default/testsvc3.default.svc.cluster.local": {
					{ServicePort: 80, TargetPort: 8080},
				},
			},
		)
		w.AddOrUpdateWorkload(newWorkload)
		assert.Equal(t, newWorkload, w.byUid["123456"])
		assert.Equal(t, newWorkload, w.byAddr[NetworkAddress{Network: newWorkload.Network, Address: addr}])
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
