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
	"encoding/base64"
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	
	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	"kmesh.net/kmesh/api/v2/endpoint"
	"kmesh.net/kmesh/pkg/utils/hash"
)

const (
	DefaultTableSize    uint64 = 16381
	DefaultHashSeed            = "JLfvgnHc2kaSUFaI"
	MaglevOuterMapName         = "outer_of_maglev"
	MaglevInnerMapName         = "inner_of_maglev"
	MaglevMapMaxEntries        = 65536
	ClusterNameMaxLen          = 192
)

var (
	outer           *ebpf.Map
	seedMurmur      uint32
	maglevTableSize uint64
)

type Backend struct {
	ep     *endpoint.Endpoint
	index  int
	offset uint64
	skip   uint64
	next   uint64
}

func InitMaglevMap() error {

	maglevTableSize = DefaultTableSize

	opt := &ebpf.LoadPinOptions{}
	outer_map, err := ebpf.LoadPinnedMap("/sys/fs/bpf"+"/bpf_kmesh/map/"+MaglevOuterMapName, opt)
	if err != nil {
		return fmt.Errorf("load outer map of maglev failed err: %v", err)
	}
	outer = outer_map

	d, err := base64.StdEncoding.DecodeString(DefaultHashSeed)
	if err != nil {
		return fmt.Errorf("cannot decode base64 Maglev hash seed %q: %w", DefaultHashSeed, err)
	}
	if len(d) != 12 {
		return fmt.Errorf("decoded hash seed is %d bytes (not 12 bytes)", len(d))
	}
	seedMurmur = uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3])

	return nil
}

// only trafficPolicy enable maglev in DestinationRule would create lb
func CreateLB(cluster *cluster_v2.Cluster) error {
	if cluster == nil {
		return errors.New("cluster is nil")
	}

	clusterName := cluster.GetName()
	table, err := getLookupTable(cluster, maglevTableSize)
	if err != nil {
		return err
	}
	backendIDs := make([]uint32, maglevTableSize)
	for i, id := range table {
		backendIDs[i] = uint32(id)
	}

	err = updateMaglevTable(backendIDs, clusterName)
	if err != nil {
		return fmt.Errorf("updateMaglevTable fail err:%v", err)
	}

	return nil
}

// createMaglevInnerMap creates a new Maglev inner map in the kernel
// using the given table size.
func createMaglevInnerMap(tableSize uint32) (*ebpf.Map, error) {
	spec := &ebpf.MapSpec{
		Name:       MaglevInnerMapName,
		Type:       ebpf.Array,
		KeySize:    uint32(unsafe.Sizeof(uint32(0))),
		ValueSize:  uint32(unsafe.Sizeof(uint32(0))) * tableSize,
		MaxEntries: 1,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func updateMaglevTable(backendIDs []uint32, clusterName string) error {
	if outer == nil {
		return errors.New("outer maglev maps not yet initialized")
	}
	inner, err := createMaglevInnerMap(uint32(maglevTableSize))
	if err != nil {
		return err
	}
	defer inner.Close()

	var key uint32 = 0
	if err := inner.Update(key, backendIDs, 0); err != nil {
		return fmt.Errorf("updating backends of cluster %v : %w", clusterName, err)
	}

	if len(clusterName) > ClusterNameMaxLen {
		clusterName = clusterName[:ClusterNameMaxLen]
	}
	var maglevKey [ClusterNameMaxLen]byte
	copy(maglevKey[:], []byte(clusterName))

	if err := outer.Update(maglevKey, uint32(inner.FD()), 0); err != nil {
		return fmt.Errorf("updating cluster %v: %w", clusterName, err)
	}
	return nil
}

func getOffsetAndSkip(address string, m uint64) (uint64, uint64) {
	h1, h2 := hash.Hash128([]byte(address), seedMurmur)
	offset := h1 % m
	skip := (h2 % (m - 1)) + 1

	return offset, skip
}

func getPermutation(b Backend) uint64 {
	return (b.offset + (b.skip * b.next)) % maglevTableSize
}

func getLookupTable(cluster *cluster_v2.Cluster, tableSize uint64) ([]int, error) {

	loadAssignment := cluster.GetLoadAssignment()
	clusterName := cluster.GetName()
	localityLbEps := loadAssignment.GetEndpoints()

	if len(localityLbEps) == 0 {
		return nil, fmt.Errorf("current cluster:%v has no any lb endpoints", clusterName)
	}

	flatEps := make([]*endpoint.Endpoint, 0)

	//yet not consider weight
	for _, localityLbEp := range localityLbEps {
		eps := localityLbEp.GetLbEndpoints()
		flatEps = append(flatEps, eps...)
	}
	backends := make([]Backend, 0, len(flatEps))

	for i, ep := range flatEps {
		epOffset, epSkip := getOffsetAndSkip(ep.GetAddress().String(), maglevTableSize)
		b := Backend{
			ep:     ep,
			index:  i,
			offset: epOffset,
			skip:   epSkip,
			next:   0,
		}
		backends = append(backends, b)
	}

	if len(backends) == 0 {
		return nil, fmt.Errorf("current cluster:%v has no any lb backends", clusterName)
	}

	length := len(backends)
	lookUpTable := make([]int, tableSize)

	for i := uint64(0); i < tableSize; i++ {
		lookUpTable[i] = -1
	}

	for n := uint64(0); n < tableSize; n++ {
		j := int(n) % length
		b := backends[j]
		for {
			c := getPermutation(b)
			for lookUpTable[c] >= 0 {
				b.next++
				c = getPermutation(b)
			}
			lookUpTable[c] = b.index
			b.next++
			break
		}
	}

	return lookUpTable, nil
}
