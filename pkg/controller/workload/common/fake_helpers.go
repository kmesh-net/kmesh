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
	"fmt"
	"log"

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

type WorkloadOption func(*workloadapi.Workload) error

func WithWorkloadBasicInfo(name, uid, network string) WorkloadOption {
	return func(w *workloadapi.Workload) error {
		w.Name = name
		w.Uid = uid
		w.Network = network
		return nil
	}
}

func WithAddresses(addresses ...interface{}) WorkloadOption {
	return func(w *workloadapi.Workload) error {
		w.Addresses = make([][]byte, len(addresses))
		for i, addr := range addresses {
			switch v := addr.(type) {
			case string:
				w.Addresses[i] = netip.MustParseAddr(v).AsSlice()
			case []byte:
				w.Addresses[i] = v
			case netip.Addr:
				w.Addresses[i] = v.AsSlice()
			default:
				return fmt.Errorf("unsupported address type: %T", v)
			}
		}
		return nil
	}
}

func WithNetworkMode(networkMode workloadapi.NetworkMode) WorkloadOption {
	return func(w *workloadapi.Workload) error {
		w.Uid = "cluster0/" + rand.String(6)
		w.NetworkMode = networkMode
		w.Name = "name"
		if w.Network == "" {
			w.Network = "testnetwork"
		}
		if w.CanonicalName == "" {
			w.CanonicalName = "foo"
		}
		if w.CanonicalRevision == "" {
			w.CanonicalRevision = "latest"
		}
		if w.WorkloadName == "" {
			w.WorkloadName = "name"
		}
		w.WorkloadType = workloadapi.WorkloadType_POD
		w.Status = workloadapi.WorkloadStatus_HEALTHY
		w.ClusterId = "cluster0"
		if w.Services == nil {
			w.Services = map[string]*workloadapi.PortList{
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
		return nil
	}
}

func WithServices(services map[string]*workloadapi.PortList) WorkloadOption {
	return func(w *workloadapi.Workload) error {
		w.Services = services
		return nil
	}
}

func CreatePort(servicePort, targetPort uint32) *workloadapi.Port {
	return &workloadapi.Port{
		ServicePort: servicePort,
		TargetPort:  targetPort,
	}
}

func CreateFakeWorkload(ip, waypoint string, opts ...WorkloadOption) *workloadapi.Workload {
	resolvedWaypoint := ResolveWaypoint(waypoint)

	workload := &workloadapi.Workload{
		Uid:       rand.String(6),
		Namespace: "ns",
		Name:      "test-workload",
		Addresses: [][]byte{netip.MustParseAddr(ip).AsSlice()},
		Waypoint:  resolvedWaypoint,
	}

	for _, opt := range opts {
		opt(workload)
	}
	log.Printf("Created workload: %+v", workload)
	return workload
}
