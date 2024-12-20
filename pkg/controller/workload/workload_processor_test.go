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

package workload

import (
	"net/netip"
	"os"
	"testing"

	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pilot/pkg/util/protoconv"
	"istio.io/istio/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/rand"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/workload/bpfcache"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
	"kmesh.net/kmesh/pkg/controller/workload/common"
	"kmesh.net/kmesh/pkg/nets"
	"kmesh.net/kmesh/pkg/utils/test"
)

func Test_handleWorkload(t *testing.T) {
	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	defer bpfcache.CleanupFakeWorkloadMap(workloadMap)

	p := NewProcessor(workloadMap)

	var (
		ek bpfcache.EndpointKey
		ev bpfcache.EndpointValue
	)

	// 1. add related service
	fakeSvc := common.CreateFakeService("testsvc", "10.240.10.1", "10.240.10.2", createLoadBalancing(workloadapi.LoadBalancing_UNSPECIFIED_MODE, make([]workloadapi.LoadBalancing_Scope, 0)))
	_ = p.handleService(fakeSvc)

	// 2. add workload
	workload1 := createTestWorkloadWithService(true)
	err := p.handleWorkload(workload1)
	assert.NoError(t, err)

	workloadID := checkFrontEndMap(t, workload1.Addresses[0], p)
	checkBackendMap(t, p, workloadID, workload1)

	// 2.1 check front end map contains service
	svcID := checkFrontEndMap(t, fakeSvc.Addresses[0].Address, p)

	// 2.2 check service map contains service
	checkServiceMap(t, p, svcID, fakeSvc, 0, 1)

	// 2.3 check endpoint map now contains the workloads
	ek.BackendIndex = 1
	ek.ServiceId = svcID
	err = p.bpf.EndpointLookup(&ek, &ev)
	assert.NoError(t, err)
	assert.Equal(t, ev.BackendUid, workloadID)

	// 3. add another workload with service
	workload2 := common.CreateFakeWorkload("1.2.3.5", "", common.WithNetworkMode(workloadapi.NetworkMode_STANDARD))
	err = p.handleWorkload(workload2)
	assert.NoError(t, err)

	// 3.1 check endpoint map now contains the new workloads
	workload2ID := checkFrontEndMap(t, workload2.Addresses[0], p)
	ek.BackendIndex = 2
	ek.ServiceId = svcID
	err = p.bpf.EndpointLookup(&ek, &ev)
	assert.NoError(t, err)
	assert.Equal(t, ev.BackendUid, workload2ID)

	// 3.2 check service map contains service
	checkServiceMap(t, p, svcID, fakeSvc, 0, 2)

	// 4 modify workload2 attribute not related with services
	workload2.Waypoint = &workloadapi.GatewayAddress{
		Destination: &workloadapi.GatewayAddress_Address{
			Address: &workloadapi.NetworkAddress{
				Address: netip.MustParseAddr("10.10.10.10").AsSlice(),
			},
		},
		HboneMtlsPort: 15008,
	}

	err = p.handleWorkload(workload2)
	assert.NoError(t, err)
	checkBackendMap(t, p, workload2ID, workload2)

	// 4.1 check endpoint map now contains the new workloads
	workload2ID = checkFrontEndMap(t, workload2.Addresses[0], p)
	ek.BackendIndex = 2
	ek.ServiceId = svcID
	err = p.bpf.EndpointLookup(&ek, &ev)
	assert.NoError(t, err)
	assert.Equal(t, ev.BackendUid, workload2ID)

	// 4.2 check service map contains service
	checkServiceMap(t, p, svcID, fakeSvc, 0, 2)

	// 4.3 check backend map contains waypoint
	checkBackendMap(t, p, workload2ID, workload2)

	// 5 update workload to remove the bound services
	workload1Updated := proto.Clone(workload1).(*workloadapi.Workload)
	workload1Updated.Services = nil
	err = p.handleWorkload(workload1Updated)
	assert.NoError(t, err)

	// 5.1 check service map
	checkServiceMap(t, p, svcID, fakeSvc, 0, 1)

	// 5.2 check endpoint map
	ek.BackendIndex = 1
	ek.ServiceId = svcID
	err = p.bpf.EndpointLookup(&ek, &ev)
	assert.NoError(t, err)
	assert.Equal(t, workload2ID, ev.BackendUid)

	// 6. add namespace scoped waypoint service
	wpSvc := common.CreateFakeService("waypoint", "10.240.10.5", "10.240.10.5", createLoadBalancing(workloadapi.LoadBalancing_UNSPECIFIED_MODE, make([]workloadapi.LoadBalancing_Scope, 0)))
	_ = p.handleService(wpSvc)
	assert.Nil(t, wpSvc.Waypoint)
	// 6.1 check front end map contains service
	svcID = checkFrontEndMap(t, wpSvc.Addresses[0].Address, p)
	// 6.2 check service map contains service, but no waypoint address
	checkServiceMap(t, p, svcID, wpSvc, 0, 0)

	// 7. test add unhealthy workload
	workload3 := common.CreateFakeWorkload("1.2.3.7", "", common.WithNetworkMode(workloadapi.NetworkMode_STANDARD))
	workload3.Status = workloadapi.WorkloadStatus_UNHEALTHY
	_ = p.handleWorkload(workload3)

	addr, _ := netip.AddrFromSlice(workload3.Addresses[0])
	networkAddress := cache.NetworkAddress{
		Network: workload3.Network,
		Address: addr,
	}
	got := p.WorkloadCache.GetWorkloadByAddr(networkAddress)
	assert.NotNil(t, got)
	assert.Equal(t, got.Status, workloadapi.WorkloadStatus_UNHEALTHY)
	checkNotExistInFrontEndMap(t, workload3.Addresses[0], p)

	// 8. update workload from healthy to unhealthy, should remove it from bpf map
	workload2.Status = workloadapi.WorkloadStatus_UNHEALTHY
	_ = p.handleWorkload(workload2)
	checkNotExistInFrontEndMap(t, workload2.Addresses[0], p)

	// 9. delete service
	p.handleRemovedAddresses([]string{fakeSvc.ResourceName()})
	checkNotExistInFrontEndMap(t, fakeSvc.Addresses[0].Address, p)

	hashNameClean(p)
}

func Test_handleWaypointWithHostname(t *testing.T) {
	// Mainly used to test whether processor can correctly handle
	// different types of waypoint address without panic.
	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	p := NewProcessor(workloadMap)

	// Waypoint with network address.
	svc1 := common.CreateFakeService("svc1", "10.240.10.1", "10.240.10.200", createLoadBalancing(workloadapi.LoadBalancing_UNSPECIFIED_MODE, make([]workloadapi.LoadBalancing_Scope, 0)))
	wl1 := common.CreateFakeWorkload("1.2.3.5", "10.240.10.200", common.WithNetworkMode(workloadapi.NetworkMode_STANDARD))
	// Waypoint with hostname.
	svc2 := common.CreateFakeService("svc2", "10.240.10.2", "default/waypoint.default.svc.cluster.local", createLoadBalancing(workloadapi.LoadBalancing_UNSPECIFIED_MODE, make([]workloadapi.LoadBalancing_Scope, 0)))
	wl2 := common.CreateFakeWorkload("1.2.3.6", "default/waypoint.default.svc.cluster.local", common.WithNetworkMode(workloadapi.NetworkMode_STANDARD))

	p.handleServicesAndWorkloads([]*workloadapi.Service{svc1, svc2}, []*workloadapi.Workload{wl1, wl2})

	// Front end map includes svc1 but not svc2 as its waypoint is not resolved.
	svc1ID := checkFrontEndMap(t, svc1.Addresses[0].Address, p)
	checkServiceMap(t, p, svc1ID, svc1, 0, 0)

	checkNotExistInFrontEndMap(t, svc2.Addresses[0].Address, p)

	// Back end map includes wl1 but not wl2 as its waypoint is not resolved.
	wl1ID := checkFrontEndMap(t, wl1.Addresses[0], p)
	checkBackendMap(t, p, wl1ID, wl1)

	checkNotExistInFrontEndMap(t, wl2.Addresses[0], p)

	waypointIP := "10.240.10.3"
	waypointsvc := common.CreateFakeService("waypoint", waypointIP, "", createLoadBalancing(workloadapi.LoadBalancing_UNSPECIFIED_MODE, make([]workloadapi.LoadBalancing_Scope, 0)))
	p.handleServicesAndWorkloads([]*workloadapi.Service{waypointsvc}, []*workloadapi.Workload{})

	// Front end map includes svc2 and waypointsvc now.
	svc2ID := checkFrontEndMap(t, svc2.Addresses[0].Address, p)
	checkServiceMap(t, p, svc2ID, svc2, 0, 0)
	wID := checkFrontEndMap(t, waypointsvc.Addresses[0].Address, p)
	checkServiceMap(t, p, wID, waypointsvc, 0, 0)

	// Front end map includes wl2 now.
	wl2ID := checkFrontEndMap(t, wl2.Addresses[0], p)
	checkBackendMap(t, p, wl2ID, wl2)

	// Insert svc and workload whose waypoint hostname can be resolved directly.
	svc3 := common.CreateFakeService("svc3", "10.240.10.4", "default/waypoint.default.svc.cluster.local", createLoadBalancing(workloadapi.LoadBalancing_UNSPECIFIED_MODE, make([]workloadapi.LoadBalancing_Scope, 0)))
	wl3 := common.CreateFakeWorkload("1.2.3.6", "default/waypoint.default.svc.cluster.local", common.WithNetworkMode(workloadapi.NetworkMode_STANDARD))
	p.handleServicesAndWorkloads([]*workloadapi.Service{svc3}, []*workloadapi.Workload{wl3})

	svc3ID := checkFrontEndMap(t, svc3.Addresses[0].Address, p)
	checkServiceMap(t, p, svc3ID, svc3, 0, 0)
	wl3ID := checkFrontEndMap(t, wl3.Addresses[0], p)
	checkBackendMap(t, p, wl3ID, wl3)
}

func Test_hostnameNetworkMode(t *testing.T) {
	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	p := NewProcessor(workloadMap)
	workload := common.CreateFakeWorkload("1.2.3.4", "", common.WithNetworkMode(workloadapi.NetworkMode_STANDARD))
	workloadWithoutService := common.CreateFakeWorkload("1.2.3.5", "", common.WithNetworkMode(workloadapi.NetworkMode_STANDARD))
	workloadWithoutService.Services = nil
	workloadHostname := common.CreateFakeWorkload("1.2.3.6", "", common.WithNetworkMode(workloadapi.NetworkMode_STANDARD))

	p.handleWorkload(workload)
	p.handleWorkload(workloadWithoutService)
	p.handleWorkload(workloadHostname)

	// Check Workload Cache
	checkWorkloadCache(t, p, workload)
	checkWorkloadCache(t, p, workloadWithoutService)
	checkWorkloadCache(t, p, workloadHostname)

	// Check Frontend Map
	checkFrontEndMapWithNetworkMode(t, workload.Addresses[0], p, workload.NetworkMode)
	checkFrontEndMapWithNetworkMode(t, workloadWithoutService.Addresses[0], p, workloadWithoutService.NetworkMode)
	checkFrontEndMapWithNetworkMode(t, workloadHostname.Addresses[0], p, workloadHostname.NetworkMode)
}

func checkWorkloadCache(t *testing.T, p *Processor, workload *workloadapi.Workload) {
	ip := workload.Addresses[0]
	address := cache.NetworkAddress{
		Network: workload.Network,
	}
	address.Address, _ = netip.AddrFromSlice(ip)
	// host network mode is not managed by kmesh
	if workload.NetworkMode == workloadapi.NetworkMode_HOST_NETWORK {
		assert.Nil(t, p.WorkloadCache.GetWorkloadByAddr(address))
	} else {
		assert.NotNil(t, p.WorkloadCache.GetWorkloadByAddr(address))
	}
	// We store pods by their uids regardless of their network mode
	assert.NotNil(t, p.WorkloadCache.GetWorkloadByUid(workload.Uid))
}

func checkServiceMap(t *testing.T, p *Processor, svcId uint32, fakeSvc *workloadapi.Service, priority uint32, endpointCount uint32) {
	var sv bpfcache.ServiceValue
	err := p.bpf.ServiceLookup(&bpfcache.ServiceKey{ServiceId: svcId}, &sv)
	assert.NoError(t, err)
	assert.Equal(t, endpointCount, sv.EndpointCount[priority])
	waypointAddr := fakeSvc.GetWaypoint().GetAddress().GetAddress()
	if waypointAddr != nil {
		assert.Equal(t, test.EqualIp(sv.WaypointAddr, waypointAddr), true)
	}

	assert.Equal(t, sv.WaypointPort, nets.ConvertPortToBigEndian(fakeSvc.Waypoint.GetHboneMtlsPort()))
}

func checkEndpointMap(t *testing.T, p *Processor, fakeSvc *workloadapi.Service, backendUid []uint32) {
	endpoints := p.bpf.GetAllEndpointsForService(p.hashName.Hash(fakeSvc.ResourceName()))
	assert.Equal(t, len(endpoints), len(backendUid))

	all := sets.New[uint32](backendUid...)
	for _, endpoint := range endpoints {
		if !all.Contains(endpoint.BackendUid) {
			t.Fatalf("endpoint %v, unexpected", endpoint.BackendUid)
		}
	}
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

func checkFrontEndMapWithNetworkMode(t *testing.T, ip []byte, p *Processor, networkMode workloadapi.NetworkMode) (upstreamId uint32) {
	var fk bpfcache.FrontendKey
	var fv bpfcache.FrontendValue
	nets.CopyIpByteFromSlice(&fk.Ip, ip)
	err := p.bpf.FrontendLookup(&fk, &fv)
	if networkMode != workloadapi.NetworkMode_HOST_NETWORK {
		assert.NoError(t, err)
		upstreamId = fv.UpstreamId
	} else {
		assert.Error(t, err)
	}
	return
}

func checkFrontEndMap(t *testing.T, ip []byte, p *Processor) (upstreamId uint32) {
	var fk bpfcache.FrontendKey
	var fv bpfcache.FrontendValue
	nets.CopyIpByteFromSlice(&fk.Ip, ip)
	err := p.bpf.FrontendLookup(&fk, &fv)
	assert.NoError(t, err)
	upstreamId = fv.UpstreamId
	return
}

func checkNotExistInFrontEndMap(t *testing.T, ip []byte, p *Processor) {
	var fk bpfcache.FrontendKey
	var fv bpfcache.FrontendValue
	nets.CopyIpByteFromSlice(&fk.Ip, ip)
	err := p.bpf.FrontendLookup(&fk, &fv)
	if err == nil {
		t.Fatalf("expected not exist error")
	}
}

func BenchmarkAddNewServicesWithWorkload(b *testing.B) {
	t := &testing.T{}
	config := options.BpfConfig{
		Mode:        constants.DualEngineMode,
		BpfFsPath:   "/sys/fs/bpf",
		Cgroup2Path: "/mnt/kmesh_cgroup2",
		EnableMda:   false,
	}
	cleanup, bpfLoader := test.InitBpfMap(t, config)
	b.Cleanup(cleanup)

	workloadController := NewController(bpfLoader.GetBpfWorkload(), false, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		workload := createTestWorkloadWithService(true)
		err := workloadController.Processor.handleWorkload(workload)
		assert.NoError(t, err)
	}
	workloadController.Processor.hashName.Reset()
}

func createTestWorkloadWithService(withService bool) *workloadapi.Workload {
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
		Services:          map[string]*workloadapi.PortList{},
	}

	if withService == true {
		workload.Services = map[string]*workloadapi.PortList{
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
		}
	}
	workload.Uid = "cluster0/" + rand.String(6)
	return &workload
}

func createLoadBalancing(mode workloadapi.LoadBalancing_Mode, scopes []workloadapi.LoadBalancing_Scope) *workloadapi.LoadBalancing {
	return &workloadapi.LoadBalancing{
		RoutingPreference: scopes,
		Mode:              mode,
	}
}

func createLocality(region, zone, subzone string) *workloadapi.Locality {
	return &workloadapi.Locality{
		Region:  region,
		Zone:    zone,
		Subzone: subzone,
	}
}

func createWorkload(name, ip, nodeName string, networkload workloadapi.NetworkMode, locality *workloadapi.Locality, services ...string) *workloadapi.Workload {
	workload := workloadapi.Workload{
		Uid:               "cluster0//Pod/default/" + name,
		Node:              nodeName,
		Namespace:         "default",
		Name:              name,
		Addresses:         [][]byte{netip.MustParseAddr(ip).AsSlice()},
		Network:           "testnetwork",
		CanonicalName:     "foo",
		CanonicalRevision: "latest",
		WorkloadType:      workloadapi.WorkloadType_POD,
		WorkloadName:      "name",
		Status:            workloadapi.WorkloadStatus_HEALTHY,
		ClusterId:         "cluster0",
		NetworkMode:       networkload,
		Locality:          locality,
	}
	workload.Services = make(map[string]*workloadapi.PortList, len(services))
	for _, svc := range services {
		workload.Services["default/"+svc+".default.svc.cluster.local"] = &workloadapi.PortList{
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
		}
	}
	return &workload
}

func TestRestart(t *testing.T) {
	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	defer bpfcache.CleanupFakeWorkloadMap(workloadMap)

	p := NewProcessor(workloadMap)

	res := &service_discovery_v3.DeltaDiscoveryResponse{}

	// 1. First simulate normal start
	// 1.1 add related service
	svc1 := common.CreateFakeService("svc1", "10.240.10.1", "10.240.10.200", createLoadBalancing(workloadapi.LoadBalancing_UNSPECIFIED_MODE, make([]workloadapi.LoadBalancing_Scope, 0)))
	svc2 := common.CreateFakeService("svc2", "10.240.10.2", "10.240.10.200", createLoadBalancing(workloadapi.LoadBalancing_UNSPECIFIED_MODE, make([]workloadapi.LoadBalancing_Scope, 0)))
	svc3 := common.CreateFakeService("svc3", "10.240.10.3", "10.240.10.200", createLoadBalancing(workloadapi.LoadBalancing_UNSPECIFIED_MODE, make([]workloadapi.LoadBalancing_Scope, 0)))
	for _, svc := range []*workloadapi.Service{svc1, svc2, svc3} {
		addr := serviceToAddress(svc)
		res.Resources = append(res.Resources, &service_discovery_v3.Resource{
			Resource: protoconv.MessageToAny(addr),
		})
	}

	// 1.2 add workload
	wl1 := createWorkload("wl1", "10.244.0.1", os.Getenv("NODE_NAME"), workloadapi.NetworkMode_STANDARD, createLocality("r1", "z1", "s1"), "svc1", "svc2")
	wl2 := createWorkload("wl2", "10.244.0.2", os.Getenv("NODE_NAME"), workloadapi.NetworkMode_STANDARD, createLocality("r1", "z1", "s1"), "svc2", "svc3")
	wl3 := createWorkload("wl3", "10.244.0.3", os.Getenv("NODE_NAME"), workloadapi.NetworkMode_STANDARD, createLocality("r1", "z1", "s1"), "svc3")
	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl3} {
		addr := workloadToAddress(wl)
		res.Resources = append(res.Resources, &service_discovery_v3.Resource{
			Resource: protoconv.MessageToAny(addr),
		})
	}

	err := p.handleAddressTypeResponse(res)
	assert.NoError(t, err)

	// check front end map
	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl3} {
		checkFrontEndMap(t, wl.Addresses[0], p)
	}
	for _, svc := range []*workloadapi.Service{svc1, svc2, svc3} {
		checkFrontEndMap(t, svc.Addresses[0].Address, p)
	}
	assert.Equal(t, 6, p.bpf.FrontendCount())
	// check service map
	t.Log("1. check service map")
	checkServiceMap(t, p, p.hashName.Hash(svc1.ResourceName()), svc1, 0, 1)
	checkServiceMap(t, p, p.hashName.Hash(svc2.ResourceName()), svc2, 0, 2)
	checkServiceMap(t, p, p.hashName.Hash(svc3.ResourceName()), svc3, 0, 2)
	assert.Equal(t, 3, p.bpf.ServiceCount())
	// check endpoint map
	t.Log("1. check endpoint map")
	checkEndpointMap(t, p, svc1, []uint32{p.hashName.Hash(wl1.ResourceName())})
	checkEndpointMap(t, p, svc2, []uint32{p.hashName.Hash(wl1.ResourceName()), p.hashName.Hash(wl2.ResourceName())})
	checkEndpointMap(t, p, svc3, []uint32{p.hashName.Hash(wl2.ResourceName()), p.hashName.Hash(wl3.ResourceName())})
	assert.Equal(t, 5, p.bpf.EndpointCount())
	// check backend map
	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl3} {
		checkBackendMap(t, p, p.hashName.Hash(wl.ResourceName()), wl)
	}
	assert.Equal(t, 3, p.bpf.BackendCount())

	// 2. Second simulate restart
	// Set a restart label and simulate missing data in the cache
	restart.SetStartType(restart.Restart)
	// reconstruct a new processor
	p = NewProcessor(workloadMap)
	p.bpf.RestoreEndpointKeys()
	// 2.1 simulate workload add/delete during restart
	// simulate workload update during restart

	// wl1 now only belong to svc1
	delete(wl1.Services, "default/svc2.default.svc.cluster.local")
	// wl2 now belong to svc1, svc2, svc3
	wl2.Services["default/svc1.default.svc.cluster.local"] = &workloadapi.PortList{
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
	}

	wl4 := createWorkload("wl4", "10.244.0.4", os.Getenv("NODE_NAME"), workloadapi.NetworkMode_STANDARD, createLocality("r1", "z1", "s1"), "svc4")
	svc4 := common.CreateFakeService("svc4", "10.240.10.4", "10.240.10.200", createLoadBalancing(workloadapi.LoadBalancing_UNSPECIFIED_MODE, make([]workloadapi.LoadBalancing_Scope, 0)))

	res = &service_discovery_v3.DeltaDiscoveryResponse{}
	// wl3 deleted during restart
	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl4} {
		addr := workloadToAddress(wl)
		res.Resources = append(res.Resources, &service_discovery_v3.Resource{
			Resource: protoconv.MessageToAny(addr),
		})
	}

	for _, svc := range []*workloadapi.Service{svc1, svc2, svc3, svc4} {
		addr := serviceToAddress(svc)
		res.Resources = append(res.Resources, &service_discovery_v3.Resource{
			Resource: protoconv.MessageToAny(addr),
		})
	}

	err = p.handleAddressTypeResponse(res)
	assert.NoError(t, err)

	// check front end map
	t.Log("2. check front end map")
	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl4} {
		checkFrontEndMap(t, wl.Addresses[0], p)
	}
	for _, svc := range []*workloadapi.Service{svc1, svc2, svc3, svc4} {
		checkFrontEndMap(t, svc.Addresses[0].Address, p)
	}
	assert.Equal(t, 7, p.bpf.FrontendCount())

	// check service map
	checkServiceMap(t, p, p.hashName.Hash(svc1.ResourceName()), svc1, 0, 2) // svc1 has 2 wl1, wl2
	checkServiceMap(t, p, p.hashName.Hash(svc2.ResourceName()), svc2, 0, 1) // svc2 has 1  wl2
	checkServiceMap(t, p, p.hashName.Hash(svc3.ResourceName()), svc3, 0, 1) // svc3 has 1  wl2
	checkServiceMap(t, p, p.hashName.Hash(svc4.ResourceName()), svc4, 0, 1) // svc4 has 1  wl4
	assert.Equal(t, 4, p.bpf.ServiceCount())
	// check endpoint map
	checkEndpointMap(t, p, svc1, []uint32{p.hashName.Hash(wl1.ResourceName()), p.hashName.Hash(wl2.ResourceName())})
	checkEndpointMap(t, p, svc2, []uint32{p.hashName.Hash(wl2.ResourceName())})
	checkEndpointMap(t, p, svc3, []uint32{p.hashName.Hash(wl2.ResourceName())})
	checkEndpointMap(t, p, svc4, []uint32{p.hashName.Hash(wl4.ResourceName())})
	assert.Equal(t, 5, p.bpf.EndpointCount())
	// check backend map
	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl4} {
		checkBackendMap(t, p, p.hashName.Hash(wl.ResourceName()), wl)
	}
	assert.Equal(t, 3, p.bpf.BackendCount())

	hashNameClean(p)
}

// The hashname will be saved as a file by default.
// If it is not cleaned, it will affect other use cases.
func hashNameClean(p *Processor) {
	for str := range p.hashName.GetStrToNum() {
		if err := p.removeWorkloadFromBpfMap(str); err != nil {
			log.Errorf("RemoveWorkloadResource failed: %v", err)
		}

		if err := p.removeServiceResourceFromBpfMap(nil, str); err != nil {
			log.Errorf("RemoveServiceResource failed: %v", err)
		}
		p.hashName.Delete(str)
	}
	p.hashName.Reset()
}

func workloadToAddress(wl *workloadapi.Workload) *workloadapi.Address {
	return &workloadapi.Address{
		Type: &workloadapi.Address_Workload{
			Workload: wl,
		},
	}
}

func serviceToAddress(service *workloadapi.Service) *workloadapi.Address {
	return &workloadapi.Address{
		Type: &workloadapi.Address_Service{
			Service: service,
		},
	}
}

func TestLBPolicyUpdate(t *testing.T) {
	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	defer bpfcache.CleanupFakeWorkloadMap(workloadMap)

	p := NewProcessor(workloadMap)

	res1 := &service_discovery_v3.DeltaDiscoveryResponse{}
	res2 := &service_discovery_v3.DeltaDiscoveryResponse{}
	res3 := &service_discovery_v3.DeltaDiscoveryResponse{}

	// 1. First normal start
	// 1.1 add related service
	localityLBScope := make([]workloadapi.LoadBalancing_Scope, 0)
	localityLBScope = append(localityLBScope, workloadapi.LoadBalancing_REGION)
	localityLBScope = append(localityLBScope, workloadapi.LoadBalancing_ZONE)
	localityLBScope = append(localityLBScope, workloadapi.LoadBalancing_SUBZONE)
	randomLoadBlanacing := createLoadBalancing(workloadapi.LoadBalancing_UNSPECIFIED_MODE, make([]workloadapi.LoadBalancing_Scope, 0))
	localityLoadBlanacing := createLoadBalancing(workloadapi.LoadBalancing_FAILOVER, localityLBScope)
	randomSvc := common.CreateFakeService("svc1", "10.240.10.1", "10.240.10.200", randomLoadBlanacing)
	llbSvc := common.CreateFakeService("svc1", "10.240.10.1", "10.240.10.200", localityLoadBlanacing)

	addr := serviceToAddress(randomSvc)
	res1.Resources = append(res1.Resources, &service_discovery_v3.Resource{
		Resource: protoconv.MessageToAny(addr),
	})

	// 1.2 add workload
	// The nodeName of kmesh processor are set with os.Getenv("NODE_NAME"), same nodeName means workload and kmesh are belongs to one node, they have same Locality.
	wl1 := createWorkload("wl1", "10.244.0.1", os.Getenv("NODE_NAME"), workloadapi.NetworkMode_STANDARD, createLocality("r1", "z1", "s1"), "svc1") // prio 0
	wl2 := createWorkload("wl2", "10.244.0.2", "other", workloadapi.NetworkMode_STANDARD, createLocality("r1", "z1", "s2"), "svc1")                // prio 1
	wl3 := createWorkload("wl3", "10.244.0.3", "other", workloadapi.NetworkMode_STANDARD, createLocality("r1", "z2", "s2"), "svc1")                // prio 2
	wl4 := createWorkload("wl4", "10.244.0.4", "other", workloadapi.NetworkMode_STANDARD, createLocality("r2", "z2", "s2"), "svc1")                // prio 3
	backendUid := []uint32{p.hashName.Hash(wl1.GetUid()), p.hashName.Hash((wl2.GetUid())), p.hashName.Hash((wl3.GetUid())), p.hashName.Hash((wl4.GetUid()))}

	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl3, wl4} {
		addr := workloadToAddress(wl)
		res1.Resources = append(res1.Resources, &service_discovery_v3.Resource{
			Resource: protoconv.MessageToAny(addr),
		})
	}

	err := p.handleAddressTypeResponse(res1)
	assert.NoError(t, err)

	// check front end map
	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl3, wl4} {
		checkFrontEndMap(t, wl.Addresses[0], p)
	}

	checkFrontEndMap(t, randomSvc.Addresses[0].Address, p)
	assert.Equal(t, 5, p.bpf.FrontendCount())

	// check service map
	t.Log("1. check service map")
	checkServiceMap(t, p, p.hashName.Hash(randomSvc.ResourceName()), randomSvc, 0, 4)
	checkServiceMap(t, p, p.hashName.Hash(randomSvc.ResourceName()), randomSvc, 1, 0)
	checkServiceMap(t, p, p.hashName.Hash(randomSvc.ResourceName()), randomSvc, 2, 0)
	checkServiceMap(t, p, p.hashName.Hash(randomSvc.ResourceName()), randomSvc, 3, 0)
	assert.Equal(t, 1, p.bpf.ServiceCount())
	// check endpoint map
	t.Log("2. check endpoint map")

	checkEndpointMap(t, p, randomSvc, backendUid)
	assert.Equal(t, 4, p.bpf.EndpointCount())
	// check backend map
	t.Log("3. check backend map")
	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl3, wl4} {
		checkBackendMap(t, p, p.hashName.Hash(wl.ResourceName()), wl)
	}
	assert.Equal(t, 4, p.bpf.BackendCount())

	// 2. Locality Loadbalance Update from random to locality LB
	t.Log("lb policy update to locality lb")
	addr = serviceToAddress(llbSvc)
	res2.Resources = append(res2.Resources, &service_discovery_v3.Resource{
		Resource: protoconv.MessageToAny(addr),
	})

	err = p.handleAddressTypeResponse(res2)
	assert.NoError(t, err)

	assert.Equal(t, 5, p.bpf.FrontendCount())
	// check service map
	t.Log("4. check service map")
	checkServiceMap(t, p, p.hashName.Hash(llbSvc.ResourceName()), llbSvc, 0, 1)
	checkServiceMap(t, p, p.hashName.Hash(llbSvc.ResourceName()), llbSvc, 1, 1)
	checkServiceMap(t, p, p.hashName.Hash(llbSvc.ResourceName()), llbSvc, 2, 1)
	checkServiceMap(t, p, p.hashName.Hash(llbSvc.ResourceName()), llbSvc, 3, 1)
	assert.Equal(t, 1, p.bpf.ServiceCount())
	// check endpoint map
	t.Log("5. check endpoint map")
	checkEndpointMap(t, p, llbSvc, backendUid)
	assert.Equal(t, 4, p.bpf.EndpointCount())

	// 3. Locality Loadbalance Update from locality LB to random
	addr = serviceToAddress(randomSvc)
	res3.Resources = append(res3.Resources, &service_discovery_v3.Resource{
		Resource: protoconv.MessageToAny(addr),
	})

	err = p.handleAddressTypeResponse(res3)
	assert.NoError(t, err)

	assert.Equal(t, 5, p.bpf.FrontendCount())
	// check service map
	t.Log("6. check service map")
	checkServiceMap(t, p, p.hashName.Hash(randomSvc.ResourceName()), randomSvc, 0, 4) // 4 1
	checkServiceMap(t, p, p.hashName.Hash(randomSvc.ResourceName()), randomSvc, 1, 0) // 0 1
	checkServiceMap(t, p, p.hashName.Hash(randomSvc.ResourceName()), randomSvc, 2, 0) // 0 1
	checkServiceMap(t, p, p.hashName.Hash(randomSvc.ResourceName()), randomSvc, 3, 0) // 0 1
	assert.Equal(t, 1, p.bpf.ServiceCount())
	// check endpoint map
	t.Log("7. check endpoint map")
	checkEndpointMap(t, p, randomSvc, backendUid)
	assert.Equal(t, 4, p.bpf.EndpointCount())

	hashNameClean(p)
}
