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

package status

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/api/v2/workloadapi/security"
	"kmesh.net/kmesh/pkg/controller/workload/bpfcache"
	"kmesh.net/kmesh/pkg/utils"
)

func TestConvertWorkload(t *testing.T) {
	testCases := []struct {
		name     string
		input    *workloadapi.Workload
		expected *Workload
	}{
		{
			name: "basic workload",
			input: &workloadapi.Workload{
				Uid:       "uid-1",
				Addresses: [][]byte{net.ParseIP("192.168.1.1")},
				Name:      "workload-1",
				Namespace: "default",
				Status:    workloadapi.WorkloadStatus_HEALTHY,
			},
			expected: &Workload{
				Uid:       "uid-1",
				Addresses: []string{"192.168.1.1"},
				Name:      "workload-1",
				Namespace: "default",
				Status:    "HEALTHY",
				Protocol:  "HBONE", // Default enum value 0 is HBONE
				WorkloadType: "POD", // Default enum value 0 is POD
			},
		},
		{
			name: "workload with waypoint address",
			input: &workloadapi.Workload{
				Uid: "uid-2",
				Waypoint: &workloadapi.GatewayAddress{
					Destination: &workloadapi.GatewayAddress_Address{
						Address: &workloadapi.NetworkAddress{
							Network: "network-1",
							Address: net.ParseIP("10.0.0.1"),
						},
					},
				},
			},
			expected: &Workload{
				Uid:      "uid-2",
				Waypoint: "network-1/10.0.0.1",
				Addresses: []string{},
				Protocol:  "HBONE",
				WorkloadType: "POD",
				Status: "HEALTHY",
			},
		},
		{
			name: "workload with waypoint hostname",
			input: &workloadapi.Workload{
				Uid: "uid-3",
				Waypoint: &workloadapi.GatewayAddress{
					Destination: &workloadapi.GatewayAddress_Hostname{
						Hostname: &workloadapi.NamespacedHostname{
							Namespace: "ns-1",
							Hostname:  "host-1",
						},
					},
				},
			},
			expected: &Workload{
				Uid:      "uid-3",
				Waypoint: "ns-1/host-1",
				Addresses: []string{},
				Protocol:  "HBONE",
				WorkloadType: "POD",
				Status: "HEALTHY",
			},
		},
		{
			name: "full workload details",
			input: &workloadapi.Workload{
				Uid:               "uid-4",
				Addresses:         [][]byte{net.ParseIP("172.16.0.1")},
				Name:              "auth-svc",
				Namespace:         "prod",
				ServiceAccount:    "auth-sa",
				WorkloadName:      "auth-v1",
				WorkloadType:      workloadapi.WorkloadType_DEPLOYMENT,
				CanonicalName:     "auth",
				CanonicalRevision: "v1",
				ClusterId:         "cluster-1",
				TrustDomain:       "cluster.local",
				Locality: &workloadapi.Locality{
					Region:  "us-east-1",
					Zone:    "us-east-1a",
					Subzone: "subzone-1",
				},
				Node:    "node-1",
				Network: "net-1",
				Status:  workloadapi.WorkloadStatus_UNHEALTHY,
				ApplicationTunnel: &workloadapi.ApplicationTunnel{
					Protocol: workloadapi.ApplicationTunnel_PROXY,
					Port:     8080,
				},
				Services: map[string]*workloadapi.PortList{
					"svc-1": {},
				},
				AuthorizationPolicies: []string{"policy-1"},
			},
			expected: &Workload{
				Uid:               "uid-4",
				Addresses:         []string{"172.16.0.1"},
				Name:              "auth-svc",
				Namespace:         "prod",
				ServiceAccount:    "auth-sa",
				WorkloadName:      "auth-v1",
				WorkloadType:      "DEPLOYMENT",
				CanonicalName:     "auth",
				CanonicalRevision: "v1",
				ClusterID:         "cluster-1",
				TrustDomain:       "cluster.local",
				Locality: Locality{
					Region:  "us-east-1",
					Zone:    "us-east-1a",
					Subzone: "subzone-1",
				},
				Node:    "node-1",
				Network: "net-1",
				Status:  "UNHEALTHY",
				Protocol: "HBONE",
				ApplicationTunnel: ApplicationTunnel{
					Protocol: "PROXY",
					Port:     8080,
				},
				Services:              []string{"svc-1"},
				AuthorizationPolicies: []string{"policy-1"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ConvertWorkload(tc.input)
			// Services are from a map, order is non-deterministic
			assert.ElementsMatch(t, tc.expected.Services, actual.Services)
			// Null the slices for the equal check below
			actual.Services = nil
			tc.expected.Services = nil
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestConvertService(t *testing.T) {
	testCases := []struct {
		name     string
		input    *workloadapi.Service
		expected *Service
	}{
		{
			name: "basic service",
			input: &workloadapi.Service{
				Name:      "svc-1",
				Namespace: "default",
				Hostname:  "svc-1.default.svc.cluster.local",
				Addresses: []*workloadapi.NetworkAddress{
					{
						Network: "net-1",
						Address: net.ParseIP("10.96.0.1"),
					},
				},
				Ports: []*workloadapi.Port{
					{
						ServicePort: 80,
						TargetPort:  8080,
					},
				},
			},
			expected: &Service{
				Name:      "svc-1",
				Namespace: "default",
				Hostname:  "svc-1.default.svc.cluster.local",
				Addresses: []string{"net-1/10.96.0.1"},
				Ports: []*workloadapi.Port{
					{
						ServicePort: 80,
						TargetPort:  8080,
					},
				},
				Waypoint: &Waypoint{Destination: ""},
			},
		},
		{
			name: "service with load balancing and waypoint",
			input: &workloadapi.Service{
				Name:      "svc-2",
				Namespace: "prod",
				LoadBalancing: &workloadapi.LoadBalancing{
					Mode: workloadapi.LoadBalancing_FAILOVER,
					RoutingPreference: []workloadapi.LoadBalancing_Scope{
						workloadapi.LoadBalancing_NETWORK,
					},
				},
				Waypoint: &workloadapi.GatewayAddress{
					Destination: &workloadapi.GatewayAddress_Hostname{
						Hostname: &workloadapi.NamespacedHostname{
							Namespace: "ns-waypoint",
							Hostname:  "wp-host",
						},
					},
				},
			},
			expected: &Service{
				Name:      "svc-2",
				Namespace: "prod",
				Addresses: []string{},
				Waypoint:  &Waypoint{Destination: "ns-waypoint/wp-host"},
				LoadBalancer: &LoadBalancer{
					Mode:               "FAILOVER",
					RoutingPreferences: []string{"NETWORK"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ConvertService(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestConvertAuthorizationPolicy(t *testing.T) {
	input := &security.Authorization{
		Name:      "authz-1",
		Namespace: "default",
		Scope:     security.Scope_NAMESPACE,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								Principals: []*security.StringMatch{
									{
										MatchType: &security.StringMatch_Exact{
											Exact: "spiffe://cluster.local/ns/default/sa/sleep",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	expected := &AuthorizationPolicy{
		Name:      "authz-1",
		Namespace: "default",
		Scope:     "NAMESPACE",
		Action:    "ALLOW",
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								Principals: []*security.StringMatch{
									{
										MatchType: &security.StringMatch_Exact{
											Exact: "spiffe://cluster.local/ns/default/sa/sleep",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	actual := ConvertAuthorizationPolicy(input)
	assert.Equal(t, expected, actual)
}

func TestWorkloadBpfDump(t *testing.T) {
	hashName := utils.NewHashName()
	policyId := hashName.Hash("policy-1")
	backendUid := hashName.Hash("backend-1")
	serviceId := hashName.Hash("service-1")

	dump := NewWorkloadBpfDump(hashName)

	t.Run("WithWorkloadPolicies", func(t *testing.T) {
		policies := []bpfcache.WorkloadPolicyValue{
			{
				PolicyIds: [4]uint32{policyId},
			},
		}
		res := dump.WithWorkloadPolicies(policies)
		expected := BpfWorkloadPolicyValue{PolicyIds: []string{"policy-1"}}
		assert.Equal(t, []BpfWorkloadPolicyValue{expected}, res.WorkloadPolicies)
	})

	t.Run("WithBackends", func(t *testing.T) {
		backends := []bpfcache.BackendValue{
			{
				Ip:           [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 168, 1, 1},
				ServiceCount: 1,
				Services:     bpfcache.ServiceList{serviceId},
			},
		}
		res := dump.WithBackends(backends)
		expected := BpfBackendValue{
			Ip:           "192.168.1.1",
			ServiceCount: 1,
			Services:     []string{"service-1"},
		}
		assert.Equal(t, []BpfBackendValue{expected}, res.Backends)
	})

	t.Run("WithEndpoints", func(t *testing.T) {
		endpoints := []bpfcache.EndpointValue{
			{
				BackendUid: backendUid,
			},
		}
		res := dump.WithEndpoints(endpoints)
		expected := BpfEndpointValue{BackendUid: "backend-1"}
		assert.Equal(t, []BpfEndpointValue{expected}, res.Endpoints)
	})

	t.Run("WithServices", func(t *testing.T) {
		services := []bpfcache.ServiceValue{
			{
				EndpointCount: [bpfcache.PrioCount]uint32{10},
				LbPolicy:      uint32(workloadapi.LoadBalancing_STRICT),
				ServicePort:   bpfcache.ServicePorts{80},
				TargetPort:    bpfcache.TargetPorts{8080},
			},
		}
		res := dump.WithServices(services)
		assert.Equal(t, 1, len(res.Services))
		assert.Equal(t, "STRICT", res.Services[0].LbPolicy)
	})
}
