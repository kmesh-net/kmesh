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

// NOTE: THE CODE IN THIS FILE IS MAINLY REFERENCED FROM CILIUM MAGLEV
// ALGORITHM( https://github.com/cilium/cilium/blob/44ec948479bb7e4511ec39f1e0d19d794ca1fba3/pkg/maglev/maglev.go)
// AND ADAPTED FOR KMESH.

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
	DefaultTableSize   uint64 = 16381
	DefaultHashSeed           = "JLfvgnHc2kaSUFaI"
	MaglevOuterMapName        = "km_maglev_outer"
	MaglevInnerMapName        = "inner_of_maglev"
	ClusterNameMaxLen         = 192
)

type Maglev struct {
	outer           *ebpf.Map
	seedMurmur      uint32
	maglevTableSize uint64
}

type Backend struct {
	ep     *endpoint.Endpoint
	index  int
	offset uint64
	skip   uint64
	next   uint64
}

func InitMaglevMap(maglevMap *ebpf.Map) (*Maglev, error) {
	m := &Maglev{
		maglevTableSize: DefaultTableSize,
		outer:           maglevMap,
	}

	d, err := base64.StdEncoding.DecodeString(DefaultHashSeed)
	if err != nil {
		return nil, fmt.Errorf("cannot decode base64 Maglev hash seed %q: %w", DefaultHashSeed, err)
	}
	if len(d) != 12 {
		return nil, fmt.Errorf("decoded hash seed is %d bytes (not 12 bytes)", len(d))
	}
	m.seedMurmur = uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3])

	return m, nil
}

// only trafficPolicy enable maglev in DestinationRule would create lb
func (m *Maglev) CreateLB(cluster *cluster_v2.Cluster) error {
	if m == nil {
		return nil
	}

	if cluster == nil {
		return errors.New("cluster is nil")
	}

	clusterName := cluster.GetName()
	table, err := m.getLookupTable(cluster)
	if err != nil {
		return err
	}
	backendIDs := make([]uint32, m.maglevTableSize)
	for i, id := range table {
		backendIDs[i] = uint32(id)
	}

	err = m.updateMaglevTable(backendIDs, clusterName)
	if err != nil {
		return fmt.Errorf("updateMaglevTable fail err:%v", err)
	}

	return nil
}

// createMaglevInnerMap creates a new Maglev inner map in the kernel
func (m *Maglev) createMaglevInnerMap() (*ebpf.Map, error) {
	spec := &ebpf.MapSpec{
		Name:       MaglevInnerMapName,
		Type:       ebpf.Array,
		KeySize:    uint32(unsafe.Sizeof(uint32(0))),
		ValueSize:  uint32(unsafe.Sizeof(uint32(0))) * uint32(m.maglevTableSize),
		MaxEntries: 1,
	}

	inner, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, err
	}
	return inner, nil
}

func (m *Maglev) updateMaglevTable(backendIDs []uint32, clusterName string) error {
	inner, err := m.createMaglevInnerMap()
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

	if err := m.outer.Update(maglevKey, uint32(inner.FD()), 0); err != nil {
		return fmt.Errorf("updating cluster %v: %w", clusterName, err)
	}
	return nil
}

func (m *Maglev) getOffsetAndSkip(address string) (uint64, uint64) {
	h1, h2 := hash.Hash128([]byte(address), m.seedMurmur)
	offset := h1 % m.maglevTableSize
	skip := (h2 % (m.maglevTableSize - 1)) + 1

	return offset, skip
}

func getPermutation(b Backend, tableSize uint64) uint64 {
	return (b.offset + (b.skip * b.next)) % tableSize
}

func (m *Maglev) getLookupTable(cluster *cluster_v2.Cluster) ([]int, error) {
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
		epOffset, epSkip := m.getOffsetAndSkip(ep.GetAddress().String())
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
	lookUpTable := make([]int, m.maglevTableSize)

	for i := uint64(0); i < m.maglevTableSize; i++ {
		lookUpTable[i] = -1
	}

	for n := uint64(0); n < m.maglevTableSize; n++ {
		j := int(n) % length
		b := backends[j]
		for {
			c := getPermutation(b, m.maglevTableSize)
			for lookUpTable[c] >= 0 {
				b.next++
				c = getPermutation(b, m.maglevTableSize)
			}
			lookUpTable[c] = b.index
			b.next++
			break
		}
	}

	return lookUpTable, nil
}
