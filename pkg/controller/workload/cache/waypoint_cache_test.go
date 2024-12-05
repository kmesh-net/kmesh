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

package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/common"
)

func TestBasic(t *testing.T) {
	serviceCache := NewServiceCache()

	cache := NewWaypointCache(serviceCache)

	// No waypoint.
	svc1 := common.CreateFakeService("svc1", "10.240.10.1", "")
	wl1 := common.CreateFakeWorkload("1.2.3.5", "")

	// Waypoint with IP address.
	svc2 := common.CreateFakeService("svc2", "10.240.10.2", "10.240.10.10")
	wl2 := common.CreateFakeWorkload("1.2.3.6", "")

	waypointHostname := "default/waypoint.default.svc.cluster.local"
	// Waypoint with hostname.
	svc3 := common.CreateFakeService("svc3", "10.240.10.3", waypointHostname)
	wl3 := common.CreateFakeWorkload("1.2.3.7", waypointHostname)

	for _, svc := range []*workloadapi.Service{svc1, svc2, svc3} {
		cache.AddOrUpdateService(svc)
	}

	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl3} {
		cache.AddOrUpateWorkload(wl)
	}

	// Waypoint service has not been processed.
	assert.Equal(t, len(cache.serviceToWaypoint), 1)
	assert.Equal(t, len(cache.workloadToWaypoint), 1)
	assert.Equal(t, len(cache.waypointAssociatedObjects), 1)

	if _, ok := cache.serviceToWaypoint[svc3.ResourceName()]; !ok {
		t.Fatalf("service %s should be included in waypoint cache", svc3.ResourceName())
	}
	if _, ok := cache.workloadToWaypoint[wl3.ResourceName()]; !ok {
		t.Fatalf("workload %s should be included in waypoint cache", wl3.ResourceName())
	}
	if _, ok := cache.waypointAssociatedObjects[waypointHostname]; !ok {
		t.Fatalf("waypoint %s should be included in waypoint cache", waypointHostname)
	}

	associated := cache.waypointAssociatedObjects[waypointHostname]
	assert.Equal(t, associated.isResolved(), false)

	isHostnameTypeWaypoint := func(waypoint *workloadapi.GatewayAddress) bool {
		return waypoint.GetHostname() != nil
	}

	assert.Equal(t, isHostnameTypeWaypoint(associated.services[svc3.ResourceName()].Waypoint), true)
	assert.Equal(t, isHostnameTypeWaypoint(associated.workloads[wl3.ResourceName()].Waypoint), true)

	// Create waypoint service and process.
	waypointsvc := common.CreateFakeService("waypoint", "10.240.10.11", "")
	svcs, wls := cache.Refresh(waypointsvc)
	assert.Equal(t, len(svcs), 1)
	assert.Equal(t, len(wls), 1)
	assert.Equal(t, associated.isResolved(), true)
	assert.Equal(t, isHostnameTypeWaypoint(associated.services[svc3.ResourceName()].Waypoint), false)
	assert.Equal(t, isHostnameTypeWaypoint(associated.workloads[wl3.ResourceName()].Waypoint), false)

	// Create service and workload with waypoint which has been resolved.
	svc4 := common.CreateFakeService("svc4", "10.240.10.4", waypointHostname)
	wl4 := common.CreateFakeWorkload("1.2.3.8", waypointHostname)
	cache.AddOrUpdateService(svc4)
	cache.AddOrUpateWorkload(wl4)

	// svc4 and wl4 have been added to the waypoint cache and hostname of waypoint has been resolved.
	assert.Equal(t, isHostnameTypeWaypoint(associated.services[svc4.ResourceName()].Waypoint), false)
	assert.Equal(t, isHostnameTypeWaypoint(associated.workloads[wl4.ResourceName()].Waypoint), false)

	// Delete all svcs and workloads.
	for _, svc := range []*workloadapi.Service{svc1, svc2, svc3, svc4, waypointsvc} {
		cache.DeleteService(svc.ResourceName())
	}
	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl3, wl4} {
		cache.DeleteWorkload(wl.ResourceName())
	}

	assert.Equal(t, len(cache.serviceToWaypoint), 0)
	assert.Equal(t, len(cache.workloadToWaypoint), 0)
	assert.Equal(t, len(cache.waypointAssociatedObjects), 0)
}

// NOTE: All utility functions are simplified for the waypoint cache related tests and omit irrelevant fields.

// func createFakeWorkload(ip string, waypoint string) *workloadapi.Workload {
// 	w := common.ResolveWaypoint(waypoint)

// 	return &workloadapi.Workload{
// 		Uid:       "cluster0/" + rand.String(6),
// 		Namespace: "ns",
// 		Name:      "name",
// 		Addresses: [][]byte{netip.MustParseAddr(ip).AsSlice()},
// 		Waypoint:  w,
// 	}
// }

// func createFakeService(name string, ip string, waypoint string) *workloadapi.Service {
// 	w := resolveWaypoint(waypoint)

// 	return &workloadapi.Service{
// 		Name:      name,
// 		Namespace: "default",
// 		Hostname:  name + ".default.svc.cluster.local",
// 		Addresses: []*workloadapi.NetworkAddress{
// 			{
// 				Address: netip.MustParseAddr(ip).AsSlice(),
// 			},
// 		},
// 		Waypoint: w,
// 	}
// }

// func resolveWaypoint(waypoint string) *workloadapi.GatewayAddress {
// 	var w *workloadapi.GatewayAddress
// 	if waypoint != "" {
// 		res := strings.Split(waypoint, "/")
// 		if len(res) == 2 {
// 			w = &workloadapi.GatewayAddress{
// 				Destination: &workloadapi.GatewayAddress_Hostname{
// 					Hostname: &workloadapi.NamespacedHostname{
// 						Namespace: res[0],
// 						Hostname:  res[1],
// 					},
// 				},
// 				HboneMtlsPort: 15008,
// 			}
// 		} else {
// 			w = &workloadapi.GatewayAddress{
// 				Destination: &workloadapi.GatewayAddress_Address{
// 					Address: &workloadapi.NetworkAddress{
// 						Address: netip.MustParseAddr(waypoint).AsSlice(),
// 					},
// 				},
// 				HboneMtlsPort: 15008,
// 			}
// 		}
// 	}

// 	return w
// }
