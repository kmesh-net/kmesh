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
	"kmesh.net/kmesh/pkg/controller/workload/bpfcache"
	"kmesh.net/kmesh/pkg/nets"
	"kmesh.net/kmesh/pkg/utils/test"
)

func Test_handleWorkload(t *testing.T) {
	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	defer bpfcache.CleanupFakeWorkloadMap(workloadMap)

	p := newProcessor(workloadMap)

	// 1. handle workload with service, but service not handled yet
	// In this case, only frontend map and backend map should be updated.
	wl := createTestWorkloadWithService()
	_ = p.handleDataWithService(createTestWorkloadWithService())
	var (
		ek bpfcache.EndpointKey
		ev bpfcache.EndpointValue
	)

	workloadID := checkFrontEndMap(t, wl.Addresses[0], p)
	checkBackendMap(t, p, workloadID, wl)

	epKeys := p.bpf.EndpointIterFindKey(workloadID)
	assert.Equal(t, len(epKeys), 0)
	for svcName := range wl.Services {
		endpoints := p.endpointsByService[svcName]
		assert.Len(t, endpoints, 1)
		if _, ok := endpoints[wl.Uid]; ok {
			assert.True(t, ok)
		}
	}

	// 2. add related service
	fakeSvc := createFakeService("testsvc", "10.240.10.1", "10.240.10.2")
	_ = p.handleService(fakeSvc)

	// 2.1 check front end map contains service
	svcID := checkFrontEndMap(t, fakeSvc.Addresses[0].Address, p)

	// 2.2 check service map contains service
	checkServiceMap(t, p, svcID, fakeSvc, 1)

	// 2.3 check endpoint map now contains the workloads
	ek.BackendIndex = 1
	ek.ServiceId = svcID
	err := p.bpf.EndpointLookup(&ek, &ev)
	assert.NoError(t, err)
	assert.Equal(t, ev.BackendUid, workloadID)

	// 3. add another workload with service
	workload2 := createFakeWorkload("1.2.3.5")
	_ = p.handleDataWithService(workload2)

	// 3.1 check endpoint map now contains the new workloads
	workload2ID := checkFrontEndMap(t, workload2.Addresses[0], p)
	ek.BackendIndex = 2
	ek.ServiceId = svcID
	err = p.bpf.EndpointLookup(&ek, &ev)
	assert.NoError(t, err)
	assert.Equal(t, ev.BackendUid, workload2ID)

	// 3.2 check service map contains service
	checkServiceMap(t, p, svcID, fakeSvc, 2)
}

func checkServiceMap(t *testing.T, p *Processor, svcId uint32, fakeSvc *workloadapi.Service, endpointCount uint32) {
	var sv bpfcache.ServiceValue
	err := p.bpf.ServiceLookup(&bpfcache.ServiceKey{ServiceId: svcId}, &sv)
	assert.NoError(t, err)
	assert.Equal(t, sv.EndpointCount, endpointCount)
	waypointAddr := fakeSvc.GetWaypoint().GetAddress().GetAddress()
	if waypointAddr != nil {
		assert.Equal(t, test.EqualIp(sv.WaypointAddr, waypointAddr), true)
	}
	assert.Equal(t, sv.WaypointPort, nets.ConvertPortToBigEndian(15008))
}

func checkBackendMap(t *testing.T, p *Processor, workloadID uint32, wl *workloadapi.Workload) {
	var bv bpfcache.BackendValue
	err := p.bpf.BackendLookup(&bpfcache.BackendKey{BackendUid: workloadID}, &bv)
	assert.NoError(t, err)
	assert.Equal(t, test.EqualIp(bv.Ip, wl.Addresses[0]), true)
	waypointAddr := wl.GetWaypoint().GetAddress().GetAddress()
	if waypointAddr != nil {
		assert.Equal(t, test.EqualIp(bv.WaypointAddr, waypointAddr), true)
	}
	assert.Equal(t, bv.WaypointPort, nets.ConvertPortToBigEndian(wl.GetWaypoint().GetHboneMtlsPort()))
}

func checkFrontEndMap(t *testing.T, ip []byte, p *Processor) (upstreamId uint32) {
	var fk bpfcache.FrontendKey
	var fv bpfcache.FrontendValue
	nets.CopyIpByteFromSlice(&fk.Ip, &ip)
	err := p.bpf.FrontendLookup(&fk, &fv)
	assert.NoError(t, err)
	upstreamId = fv.UpstreamId
	return
}

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

	workloadController := NewController(bpfLoader.GetBpfKmeshWorkload())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		workload := createTestWorkloadWithService()
		err := workloadController.Processor.handleDataWithService(workload)
		assert.NoError(t, err)
	}
}

func createTestWorkloadWithService() *workloadapi.Workload {
	workload := workloadapi.Workload{
		Namespace:         "ns",
		Name:              "name",
		Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
		Network:           "testnetwork",
		CanonicalName:     "foo",
		CanonicalRevision: "latest",
		WorkloadType:      workloadapi.WorkloadType_POD,
		WorkloadName:      "name",
		Status:            workloadapi.WorkloadStatus_HEALTHY,
		ClusterId:         "cluster0",
		Services: map[string]*workloadapi.PortList{
			"default/testsvc.default.svc.cluster.local": {
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
	workload.Uid = "cluster0/" + rand.String(6)
	return &workload
}

func createFakeWorkload(ip string) *workloadapi.Workload {
	workload := workloadapi.Workload{
		Namespace:         "ns",
		Name:              "name",
		Addresses:         [][]byte{netip.MustParseAddr(ip).AsSlice()},
		Network:           "testnetwork",
		CanonicalName:     "foo",
		CanonicalRevision: "latest",
		WorkloadType:      workloadapi.WorkloadType_POD,
		WorkloadName:      "name",
		Status:            workloadapi.WorkloadStatus_HEALTHY,
		ClusterId:         "cluster0",
		Services: map[string]*workloadapi.PortList{
			"default/testsvc.default.svc.cluster.local": {
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
	workload.Uid = "cluster0/" + rand.String(6)
	return &workload
}

func createFakeService(name, ip, waypoint string) *workloadapi.Service {
	return &workloadapi.Service{
		Name:      name,
		Namespace: "default",
		Hostname:  "testsvc.default.svc.cluster.local",
		Addresses: []*workloadapi.NetworkAddress{
			{
				Address: netip.MustParseAddr(ip).AsSlice(),
			},
		},
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
		Waypoint: &workloadapi.GatewayAddress{
			Destination: &workloadapi.GatewayAddress_Address{
				Address: &workloadapi.NetworkAddress{
					Address: netip.MustParseAddr(waypoint).AsSlice(),
				},
			},
			HboneMtlsPort: 15008,
		},
	}
}
