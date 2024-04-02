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

package workload

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/nets"
)

func TestAddWorkload(t *testing.T) {
	t.Run("no old address workload", func(t *testing.T) {
		w := newWorkloadStore()
		workload := &workloadapi.Workload{
			Name:    "ut-workload",
			Uid:     "123456",
			Network: "ut-net",
			Addresses: [][]byte{
				[]byte("hello"),
				[]byte("world"),
			},
		}
		w.addWorkload(workload)
		assert.Equal(t, workload, w.byUid["123456"])
		addr1 := nets.ConvertIpByteToUint32([]byte("hello"))
		addr2 := nets.ConvertIpByteToUint32([]byte("world"))
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: "ut-net", Address: addr1}])
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: "ut-net", Address: addr2}])
	})

	t.Run("have old address workload", func(t *testing.T) {
		w := newWorkloadStore()
		workload := &workloadapi.Workload{
			Name:    "ut-workload",
			Uid:     "123456",
			Network: "ut-net",
			Addresses: [][]byte{
				[]byte("hello"),
				[]byte("world"),
			},
		}
		w.addWorkload(workload)
		assert.Equal(t, workload, w.byUid["123456"])
		addr1 := nets.ConvertIpByteToUint32([]byte("hello"))
		addr2 := nets.ConvertIpByteToUint32([]byte("world"))
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: "ut-net", Address: addr1}])
		assert.Equal(t, workload, w.byAddr[NetworkAddress{Network: "ut-net", Address: addr2}])
		newWorkload := &workloadapi.Workload{
			Name:    "ut-workload",
			Uid:     "123456",
			Network: "ut-net",
			Addresses: [][]byte{
				[]byte("welcome"),
				[]byte("kmesh"),
			},
		}
		w.addWorkload(newWorkload)
		assert.Equal(t, newWorkload, w.byUid["123456"])
		addr3 := nets.ConvertIpByteToUint32([]byte("welcome"))
		addr4 := nets.ConvertIpByteToUint32([]byte("kmesh"))
		assert.Equal(t, newWorkload, w.byAddr[NetworkAddress{Network: "ut-net", Address: addr3}])
		assert.Equal(t, newWorkload, w.byAddr[NetworkAddress{Network: "ut-net", Address: addr4}])
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byAddr[NetworkAddress{Network: "ut-net", Address: addr1}])
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byAddr[NetworkAddress{Network: "ut-net", Address: addr2}])
	})
}

func TestDeleteWorkload(t *testing.T) {
	t.Run("normal function test", func(t *testing.T) {
		w := newWorkloadStore()
		workload := &workloadapi.Workload{
			Name:    "ut-workload",
			Uid:     "123456",
			Network: "ut-net",
			Addresses: [][]byte{
				[]byte("hello"),
				[]byte("world"),
			},
		}
		w.addWorkload(workload)
		assert.Equal(t, workload, w.byUid["123456"])
		w.deleteWorkload("123456")
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byUid["123456"])
		addr1 := nets.ConvertIpByteToUint32([]byte("hello"))
		addr2 := nets.ConvertIpByteToUint32([]byte("world"))
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byAddr[NetworkAddress{Network: "ut-net", Address: addr1}])
		assert.Equal(t, (*workloadapi.Workload)(nil), w.byAddr[NetworkAddress{Network: "ut-net", Address: addr2}])
	})
}
