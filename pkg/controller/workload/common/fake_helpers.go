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
func CreateFakeWorkload(ip string, waypoint string, optional ...interface{}) *workloadapi.Workload {
	w := ResolveWaypoint(waypoint)

	workload := &workloadapi.Workload{
		Uid:       "cluster0/" + rand.String(6),
		Namespace: "ns",
		Name:      "name",
		Addresses: [][]byte{netip.MustParseAddr(ip).AsSlice()},
		Waypoint:  w,
	}

	if len(optional) > 0 {
		if networkMode, ok := optional[0].(workloadapi.NetworkMode); ok {
			workload.Network = "testnetwork"
			workload.CanonicalName = "foo"
			workload.CanonicalRevision = "latest"
			workload.WorkloadType = workloadapi.WorkloadType_POD
			workload.WorkloadName = "name"
			workload.Status = workloadapi.WorkloadStatus_HEALTHY
			workload.ClusterId = "cluster0"
			workload.NetworkMode = networkMode
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
	}

	return workload
}
