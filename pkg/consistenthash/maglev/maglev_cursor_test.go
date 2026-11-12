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

package maglev

import (
	"fmt"
	"slices"
	"testing"

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	"kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/api/v2/endpoint"
)

func lookupTableCluster(backends int) *cluster_v2.Cluster {
	eps := make([]*endpoint.Endpoint, backends)
	for i := range eps {
		eps[i] = &endpoint.Endpoint{Address: &core.SocketAddress{Ipv4: uint32(0x0a000001 + i), Port: 8080}}
	}
	return &cluster_v2.Cluster{
		Name:     "lookup-table-test",
		LbPolicy: cluster_v2.Cluster_MAGLEV,
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			Endpoints: []*endpoint.LocalityLbEndpoints{{LbEndpoints: eps}},
		},
	}
}

// referenceLookupTable deliberately searches each permutation from its beginning.
// It is slow, but specifies the existing slot assignments independently of the
// optimized implementation's persistent cursors.
func referenceLookupTable(cluster *cluster_v2.Cluster, size uint64) []int {
	table := make([]int, size)
	for i := range table {
		table[i] = -1
	}
	eps := cluster.LoadAssignment.Endpoints[0].LbEndpoints
	for assigned := 0; assigned < len(table); assigned++ {
		backend := assigned % len(eps)
		offset, skip := getOffsetAndSkip(eps[backend].Address.String(), size)
		for position := uint64(0); position < size; position++ {
			slot := (offset + position*skip) % size
			if table[slot] == -1 {
				table[slot] = backend
				break
			}
		}
	}
	return table
}

func TestLookupTablePreservesAssignments(t *testing.T) {
	oldSeed := seedMurmur
	defer func() { seedMurmur = oldSeed }()
	for _, seed := range []uint32{0, 0x24b7ef82} {
		seedMurmur = seed
		for _, size := range []uint64{7, 31, 251, DefaultTableSize} {
			for _, backends := range []int{1, 2, 4, 16, 64} {
				t.Run(fmt.Sprintf("seed=%d/size=%d/backends=%d", seed, size, backends), func(t *testing.T) {
					cluster := lookupTableCluster(backends)
					got, err := getLookupTable(cluster, size)
					if err != nil {
						t.Fatal(err)
					}
					want := referenceLookupTable(cluster, size)
					if !slices.Equal(got, want) {
						t.Fatal("lookup table changed slot assignments")
					}
					counts := make([]int, backends)
					for slot, backend := range got {
						if backend < 0 || backend >= backends {
							t.Fatalf("slot %d has invalid backend %d", slot, backend)
						}
						counts[backend]++
					}
					if slices.Max(counts)-slices.Min(counts) > 1 {
						t.Fatalf("unbalanced assignments: %v", counts)
					}
				})
			}
		}
	}
}

func BenchmarkLookupTable(b *testing.B) {
	oldSeed := seedMurmur
	seedMurmur = 0x24b7ef82 // First four bytes of DefaultHashSeed, decoded as big endian.
	defer func() { seedMurmur = oldSeed }()
	for _, size := range []uint64{4093, 8191, DefaultTableSize} {
		for _, backends := range []int{1, 4, 64} {
			b.Run(fmt.Sprintf("size=%d/backends=%d", size, backends), func(b *testing.B) {
				cluster := lookupTableCluster(backends)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := getLookupTable(cluster, size); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
