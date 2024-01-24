/*
 * Copyright 2023 The Kmesh Authors.
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

 * Author: LemmyHuang
 * Create: 2022-03-01
 */

package maps

// #cgo pkg-config: api-v2-c
// #include "deserialization_to_bpf_map.h"
// #include "cluster/cluster.pb-c.h"
import "C"
import (
	"fmt"
	"unsafe"

	"google.golang.org/protobuf/proto"

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
)

func clusterToGolang(goMsg *cluster_v2.Cluster, cMsg *C.Cluster__Cluster) error {
	buf := make([]byte, C.cluster__cluster__get_packed_size(cMsg))

	C.cluster__cluster__pack(cMsg, convertToPack(buf))
	if err := proto.Unmarshal(buf, goMsg); err != nil {
		return err
	}
	return nil
}

func clusterToClang(goMsg *cluster_v2.Cluster) (*C.Cluster__Cluster, error) {
	buf, err := proto.Marshal(goMsg)
	if err != nil {
		return nil, err
	}

	cMsg := C.cluster__cluster__unpack(nil, C.size_t(len(buf)), convertToPack(buf))
	if cMsg == nil {
		return nil, fmt.Errorf("cluster__cluster__unpack failed")
	}
	return cMsg, nil
}

func clusterFreeClang(cMsg *C.Cluster__Cluster) {
	C.cluster__cluster__free_unpacked(cMsg, nil)
}

func ClusterLookup(key string, value *cluster_v2.Cluster) error {
	var err error

	cKey := stringToClang(key)
	defer stringFreeClang(cKey)

	cMsg := C.deserial_lookup_elem(unsafe.Pointer(cKey), unsafe.Pointer(&C.cluster__cluster__descriptor))
	if cMsg == nil {
		return fmt.Errorf("ClusterLookup deserial_lookup_elem failed")
	}
	defer C.deserial_free_elem(unsafe.Pointer(cMsg))

	err = clusterToGolang(value, (*C.Cluster__Cluster)(cMsg))
	log.Debugf("ClusterLookup [%s], [%s]", key, value.String())
	return err
}

func ClusterUpdate(key string, value *cluster_v2.Cluster) error {
	log.Debugf("ClusterUpdate [%s], [%s]", key, value.String())

	cKey := stringToClang(key)
	defer stringFreeClang(cKey)

	cMsg, err := clusterToClang(value)
	if err != nil {
		return fmt.Errorf("ClusterUpdate %s", err)
	}
	defer clusterFreeClang(cMsg)

	testString(key, cKey)
	testCluster(value, cMsg)

	ret := C.deserial_update_elem(unsafe.Pointer(cKey), unsafe.Pointer(cMsg))
	if ret != 0 {
		return fmt.Errorf("ClusterUpdate deserial_update_elem failed")
	}

	return nil
}

func ClusterDelete(key string) error {
	log.Debugf("ClusterDelete [%s]", key)

	cKey := stringToClang(key)
	defer stringFreeClang(cKey)

	ret := C.deserial_delete_elem(unsafe.Pointer(cKey), unsafe.Pointer(&C.cluster__cluster__descriptor))
	if ret != 0 {
		return fmt.Errorf("ClusterDelete deserial_delete_elem failed")
	}
	return nil
}

func testCluster(goMsg *cluster_v2.Cluster, cMsg *C.Cluster__Cluster) {
	msg := &cluster_v2.Cluster{}

	if err := clusterToGolang(msg, cMsg); err != nil {
		log.Errorf("testCluster clusterToGolang failed")
	}
	if goMsg.String() != msg.String() {
		log.Errorf("testCluster invalid message")
		log.Errorf("testCluster [%s]", msg.String())
	}
}
