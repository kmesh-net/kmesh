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
	"os"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/suite"

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	"kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/api/v2/endpoint"
)

func TestMaglevTestSuite(t *testing.T) {
	suite.Run(t, new(MaglevTestSuite))
}

type MaglevTestSuite struct {
	mapPath string
	suite.Suite
}

func (suite *MaglevTestSuite) SetupSuite() {
	mapPath := "/sys/fs/bpf/bpf_kmesh/map/"
	suite.mapPath = mapPath
	_, err := os.Stat(mapPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(mapPath, 0755)
		if err != nil {
			fmt.Println("can not mkdir bpf map path", err)
		}
	} else if err != nil {
		fmt.Println("other err:", err)
		return
	} else {
		fmt.Println("bpf map path already exist ", mapPath)
	}
	dummyInnerMapSpec := newMaglevInnerMapSpecTest(uint32(DefaultTableSize))
	_, err = NewMaglevOuterMap(MaglevOuterMapName, MaglevMapMaxEntries, uint32(DefaultTableSize), dummyInnerMapSpec, mapPath)
	if err != nil {
		fmt.Printf("NewMaglevOuterMap err: %v\n", err)
	}
	InitMaglevMap()
}

func (suite *MaglevTestSuite) TearDownSuite() {

	fmt.Println(">>> From TearDownSuite")
}

func (suite *MaglevTestSuite) TestCreateLB() {
	cluster := newCluster()
	clusterName := cluster.GetName()

	err := CreateLB(cluster)
	if err != nil {
		fmt.Println(err)
	}

	var inner_fd uint32
	var maglevKey [ClusterNameMaxLen]byte

	copy(maglevKey[:], []byte(clusterName))
	opt := &ebpf.LoadPinOptions{}
	outer_map, err := ebpf.LoadPinnedMap(suite.mapPath+MaglevOuterMapName, opt)
	if err != nil {
		fmt.Printf("LoadPinnedMap err: %v \n", err)
	}
	err = outer_map.Lookup(maglevKey, &inner_fd)
	if err != nil {
		fmt.Printf("Lookup with key %v , err %v \n", clusterName, err)
	}
	fmt.Println("inner fd: ", inner_fd)
}

func (suite *MaglevTestSuite) TestGetLookupTable() {
	cluster := newCluster()

	table, err := getLookupTable(cluster, DefaultTableSize)
	if err != nil {
		fmt.Printf("getLookupTable err:%v \n", err)
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

// NewMaglevOuterMap returns a new object representing a maglev outer map.
func NewMaglevOuterMap(name string, maxEntries int, tableSize uint32, innerMap *ebpf.MapSpec, pinPath string) (*ebpf.Map, error) {
	m, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.HashOfMaps,
		KeySize:    ClusterNameMaxLen,
		ValueSize:  uint32(unsafe.Sizeof(uint32(0))),
		MaxEntries: uint32(maxEntries),
		InnerMap:   innerMap,
		Pinning:    ebpf.PinByName,
	}, ebpf.MapOptions{
		PinPath: pinPath,
	})

	if err != nil {
		return nil, err
	}

	return m, nil
}
