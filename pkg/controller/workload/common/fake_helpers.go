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

package common

import (
	"net/netip"
	"strings"

	"k8s.io/apimachinery/pkg/util/rand"
	"kmesh.net/kmesh/api/v2/workloadapi"
)

func CreateFakeService(name, ip, waypoint string, optional ...interface{}) *workloadapi.Service {
	w := ResolveWaypoint(waypoint)

	service := &workloadapi.Service{
		Name:      name,
		Namespace: "default",
		Hostname:  name + ".default.svc.cluster.local",
		Addresses: []*workloadapi.NetworkAddress{
			{
				Address: netip.MustParseAddr(ip).AsSlice(),
			},
		},
		Waypoint: w,
	}

	if len(optional) > 0 {
		if lbPolicy, ok := optional[0].(*workloadapi.LoadBalancing); ok {
			service.Ports = []*workloadapi.Port{
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
			}
			service.LoadBalancing = lbPolicy
		}
	}

	return service
}
func ResolveWaypoint(waypoint string) *workloadapi.GatewayAddress {
	var w *workloadapi.GatewayAddress
	if waypoint != "" {
		res := strings.Split(waypoint, "/")
		if len(res) == 2 {
			w = &workloadapi.GatewayAddress{
				Destination: &workloadapi.GatewayAddress_Hostname{
					Hostname: &workloadapi.NamespacedHostname{
						Namespace: res[0],
						Hostname:  res[1],
					},
				},
				HboneMtlsPort: 15008,
			}
		} else {
			w = &workloadapi.GatewayAddress{
				Destination: &workloadapi.GatewayAddress_Address{
					Address: &workloadapi.NetworkAddress{
						Address: netip.MustParseAddr(waypoint).AsSlice(),
					},
				},
				HboneMtlsPort: 15008,
			}
		}
	}
	return w
}

func CreateFakeWorkload(params ...interface{}) *workloadapi.Workload {
	var (
		name, ip, nodeName, waypoint *string
		networkMode                  = workloadapi.NetworkMode_STANDARD
		locality                     *workloadapi.Locality
		services                     []string
		uid                          *string
	)

	for _, param := range params {
		switch v := param.(type) {
		case *string:
			if name == nil {
				name = v
			} else if ip == nil {
				ip = v
			} else if nodeName == nil {
				nodeName = v
			} else if waypoint == nil {
				waypoint = v
			} else if uid == nil {
				uid = v
			}
		case string:
			if name == nil {
				name = stringPtr(v)
			} else if ip == nil {
				ip = stringPtr(v)
			} else {
				services = append(services, v)
			}
		case workloadapi.NetworkMode:
			networkMode = v
		case *workloadapi.Locality:
			locality = v
		case []string:
			services = append(services, v...)
		}
	}

	if uid == nil {
		generatedUid := "cluster0/" + rand.String(6)
		if name != nil {
			generatedUid = "cluster0//Pod/default/" + *name
		}
		uid = stringPtr(generatedUid)
	}

	workload := &workloadapi.Workload{
		Uid:               *uid,
		Name:              *name,
		Node:              *nodeName,
		Namespace:         "default",
		Network:           "testnetwork",
		CanonicalName:     "foo",
		CanonicalRevision: "latest",
		WorkloadType:      workloadapi.WorkloadType_POD,
		WorkloadName:      "name",
		Status:            workloadapi.WorkloadStatus_HEALTHY,
		ClusterId:         "cluster0",
		NetworkMode:       networkMode,
		Locality:          locality,
	}

	if ip != nil {
		workload.Addresses = [][]byte{netip.MustParseAddr(*ip).AsSlice()}
	}

	if waypoint != nil {
		workload.Waypoint = ResolveWaypoint(*waypoint)
	}

	if len(services) > 0 {
		workload.Services = make(map[string]*workloadapi.PortList, len(services))
		for _, svc := range services {
			workload.Services["default/"+svc+".default.svc.cluster.local"] = &workloadapi.PortList{
				Ports: []*workloadapi.Port{
					{ServicePort: 80, TargetPort: 8080},
					{ServicePort: 81, TargetPort: 8180},
					{ServicePort: 82, TargetPort: 82},
				},
			}
		}
	}

	return workload
}

func stringPtr(s string) *string {
	return &s
}
