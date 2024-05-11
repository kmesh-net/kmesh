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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/rand"
	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/utils/test"
)

func BenchmarkHandleDataWithService(b *testing.B) {
	t := &testing.T{}
	config := options.BpfConfig{
		Mode:        constants.WorkloadMode,
		BpfFsPath:   "/sys/fs/bpf",
		Cgroup2Path: "/mnt/kmesh_cgroup2",
		EnableMda:   false,
	}
	cleanup, bpfLoader := test.InitBpfMap(t, config)
	b.Cleanup(cleanup)

	workload := &workloadapi.Workload{
		Uid:               "cluster0/networking.istio.io/WorkloadEntry/ns/name",
		Namespace:         "ns",
		Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
		Network:           "testnetwork",
		CanonicalName:     "foo",
		CanonicalRevision: "latest",
		WorkloadType:      workloadapi.WorkloadType_POD,
		WorkloadName:      "name",
		Status:            workloadapi.WorkloadStatus_HEALTHY,
		ClusterId:         "cluster0",
		Services: map[string]*workloadapi.PortList{
			"ns/hostname": {
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
		},
	}

	workloadController := NewController(bpfLoader.GetBpfKmeshWorkload().SockConn.KmeshCgroupSockWorkloadMaps)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		workload.Name = rand.String(6)
		err := workloadController.Processor.HandleDataWithService(workload)
		assert.NoError(t, err)
	}
}
