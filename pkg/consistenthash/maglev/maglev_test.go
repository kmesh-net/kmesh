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
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	"kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/api/v2/endpoint"
)

func TestMaglevTestSuite(t *testing.T) {
	m := setup()
	testCreateLB(t, m)
	testGetLookupTable(t, m)
	m.outer.Close()
}

func setup() *Maglev {
	dummyInnerMapSpec := newMaglevInnerMapSpecTest(uint32(DefaultTableSize))
	outer, err := newMaglevOuterMap(MaglevOuterMapName, 16384, dummyInnerMapSpec)
	if err != nil {
		fmt.Printf("NewMaglevOuterMap err: %v\n", err)
	}
	maglev, _ := InitMaglevMap(outer)
	return maglev
}

func testCreateLB(t *testing.T, maglev *Maglev) {
	cluster := newCluster()
	clusterName := cluster.GetName()

	err := maglev.CreateLB(cluster)
	if err != nil {
		t.Errorf("create lb err: %v \n", err)
	}

	var inner_fd uint32
	var maglevKey [ClusterNameMaxLen]byte

	copy(maglevKey[:], []byte(clusterName))
	err = maglev.outer.Lookup(maglevKey, &inner_fd)
	if err != nil {
		t.Fatalf("Lookup with key %v , err %v \n", clusterName, err)
	}
	fmt.Println("inner fd: ", inner_fd)
}

func testGetLookupTable(t *testing.T, maglev *Maglev) {
	cluster := newCluster()

	table, err := maglev.getLookupTable(cluster)
	if err != nil {
		t.Fatalf("getLookupTable err:%v \n", err)
	}
	backendCount := make(map[int]int)
	// print backend id distribute
	for i := 0; i < len(table); i++ {
		backendCount[table[i]]++
	}
	for k, v := range backendCount {
		fmt.Printf("\n backend_id:%v, count:%v\n", k, v)
	}
}

func newCluster() *cluster_v2.Cluster {
	var clusterName string = "outbound|5000||helloworld.default.svc.cluster.local"
	lbEndpoints := make([]*endpoint.Endpoint, 0)
	lbEndpoints = append(lbEndpoints, &endpoint.Endpoint{
		Address: &core.SocketAddress{
			Protocol: 0,
			Port:     0,
			Ipv4:     4369,
		},
	})
	lbEndpoints = append(lbEndpoints, &endpoint.Endpoint{
		Address: &core.SocketAddress{
			Protocol: 0,
			Port:     1,
			Ipv4:     4369,
		},
	})
	lbEndpoints = append(lbEndpoints, &endpoint.Endpoint{
		Address: &core.SocketAddress{
			Protocol: 0,
			Port:     2,
			Ipv4:     4369,
		},
	})
	lbEndpoints = append(lbEndpoints, &endpoint.Endpoint{
		Address: &core.SocketAddress{
			Protocol: 0,
			Port:     3,
			Ipv4:     4369,
		},
	})
	localityLbEndpoints := make([]*endpoint.LocalityLbEndpoints, 0)
	llbep := &endpoint.LocalityLbEndpoints{
		LbEndpoints: lbEndpoints,
	}
	localityLbEndpoints = append(localityLbEndpoints, llbep)
	cluster := &cluster_v2.Cluster{
		LbPolicy: cluster_v2.Cluster_MAGLEV,
		Name:     clusterName,
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: clusterName,
			Endpoints:   localityLbEndpoints,
		},
	}
	return cluster
}

// newMaglevInnerMapSpec returns the spec for a maglev inner map.
func newMaglevInnerMapSpecTest(tableSize uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       MaglevInnerMapName,
		Type:       ebpf.Array,
		KeySize:    uint32(unsafe.Sizeof(uint32(0))),
		ValueSize:  uint32(unsafe.Sizeof(uint32(0))) * tableSize,
		MaxEntries: 1,
	}
}

// newMaglevOuterMap returns a new object representing a maglev outer map.
func newMaglevOuterMap(name string, maxEntries int, innerMap *ebpf.MapSpec) (*ebpf.Map, error) {
	return ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.HashOfMaps,
		Flags:      1,
		KeySize:    ClusterNameMaxLen,
		ValueSize:  uint32(unsafe.Sizeof(uint32(0))),
		MaxEntries: uint32(maxEntries),
		InnerMap:   innerMap,
	}, ebpf.MapOptions{})
}
