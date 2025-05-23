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
	svc1 := common.CreateFakeService("svc1", "10.240.10.1", "", nil)
	wl1 := common.CreateFakeWorkload("1.2.3.5", "")

	// Waypoint with IP address.
	svc2 := common.CreateFakeService("svc2", "10.240.10.2", "10.240.10.10", nil)
	wl2 := common.CreateFakeWorkload("1.2.3.6", "")

	waypointHostname := "default/waypoint.default.svc.cluster.local"
	// Waypoint with hostname.
	svc3 := common.CreateFakeService("svc3", "10.240.10.3", waypointHostname, nil)
	wl3 := common.CreateFakeWorkload("1.2.3.7", waypointHostname)

	for _, svc := range []*workloadapi.Service{svc1, svc2, svc3} {
		cache.AddOrUpdateService(svc)
	}

	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl3} {
		cache.AddOrUpdateWorkload(wl)
	}

	// Waypoint service has not been processed.
	assert.Equal(t, 1, len(cache.serviceToWaypoint))
	assert.Equal(t, 1, len(cache.workloadToWaypoint))
	assert.Equal(t, 1, len(cache.waypointAssociatedObjects))

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
	assert.Equal(t, false, associated.isResolved())

	isHostnameTypeWaypoint := func(waypoint *workloadapi.GatewayAddress) bool {
		return waypoint.GetHostname() != nil
	}

	assert.Equal(t, true, isHostnameTypeWaypoint(associated.services[svc3.ResourceName()].Waypoint))
	assert.Equal(t, true, isHostnameTypeWaypoint(associated.workloads[wl3.ResourceName()].Waypoint))

	// Create waypoint service and process.
	waypointsvc := common.CreateFakeService("waypoint", "10.240.10.11", "", nil)
	svcs, wls := cache.Refresh(waypointsvc)
	assert.Equal(t, 1, len(svcs))
	assert.Equal(t, 1, len(wls))
	assert.Equal(t, true, associated.isResolved())
	assert.Equal(t, false, isHostnameTypeWaypoint(associated.services[svc3.ResourceName()].Waypoint))
	assert.Equal(t, false, isHostnameTypeWaypoint(associated.workloads[wl3.ResourceName()].Waypoint))

	// Create service and workload with waypoint which has been resolved.
	svc4 := common.CreateFakeService("svc4", "10.240.10.4", waypointHostname, nil)
	wl4 := common.CreateFakeWorkload("1.2.3.8", waypointHostname)
	cache.AddOrUpdateService(svc4)
	cache.AddOrUpdateWorkload(wl4)

	// svc4 and wl4 have been added to the waypoint cache and hostname of waypoint has been resolved.
	assert.Equal(t, false, isHostnameTypeWaypoint(associated.services[svc4.ResourceName()].Waypoint))
	assert.Equal(t, false, isHostnameTypeWaypoint(associated.workloads[wl4.ResourceName()].Waypoint))

	// Delete all svcs and workloads.
	for _, svc := range []*workloadapi.Service{svc1, svc2, svc3, svc4, waypointsvc} {
		cache.DeleteService(svc.ResourceName())
	}
	for _, wl := range []*workloadapi.Workload{wl1, wl2, wl3, wl4} {
		cache.DeleteWorkload(wl.ResourceName())
	}

	assert.Equal(t, 0, len(cache.serviceToWaypoint))
	assert.Equal(t, 0, len(cache.workloadToWaypoint))
	assert.Equal(t, 0, len(cache.waypointAssociatedObjects))
}
