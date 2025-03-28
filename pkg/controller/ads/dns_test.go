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

package ads

import (
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/test/util/retry"

	core_v2 "kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/pkg/dns"
)

func TestOverwriteDNSCluster(t *testing.T) {
	domain := "www.google.com"
	addrs := []string{"10.1.1.1", "10.1.1.2", "10.1.1.3"}
	cluster := &clusterv3.Cluster{
		Name: "ut-cluster",
		ClusterDiscoveryType: &clusterv3.Cluster_Type{
			Type: clusterv3.Cluster_LOGICAL_DNS,
		},
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: "ut-cluster",
			Endpoints: []*endpointv3.LocalityLbEndpoints{
				{
					LoadBalancingWeight: wrapperspb.UInt32(30),
					Priority:            uint32(15),
					LbEndpoints: []*endpointv3.LbEndpoint{
						{
							HealthStatus: v3.HealthStatus_HEALTHY,
							HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
								Endpoint: &endpointv3.Endpoint{
									Address: &v3.Address{
										Address: &v3.Address_SocketAddress{
											SocketAddress: &v3.SocketAddress{
												Address: domain,
												PortSpecifier: &v3.SocketAddress_PortValue{
													PortValue: uint32(9898),
												},
											},
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

	p := NewController(nil).Processor
	stopCh := make(chan struct{})
	defer close(stopCh)
	dnsResolver, err := NewDnsController(p.Cache)
	assert.NoError(t, err)
	p.DnsResolverChan = dnsResolver.clustersChan
	dnsResolver.pendingHostnames = map[string][]string{
		cluster.GetName(): {
			domain,
		},
	}
	patches := gomonkey.NewPatches()
	defer patches.Reset()
	patches.ApplyMethod(reflect.TypeOf(dnsResolver.dnsResolver), "GetDNSAddresses",
		func(_ *dns.DNSResolver, name string) []string {
			return addrs
		})

	ready, newCluster := dnsResolver.overwriteDnsCluster(cluster, domain, addrs)
	assert.Equal(t, true, ready)

	if ready {
		endpoints := newCluster.GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()
		if len(endpoints) != 3 {
			t.Errorf("Expected 3 LbEndpoints, but got %d", len(endpoints))
		}
		out := []string{}
		for _, e := range endpoints {
			socketAddr, ok := e.GetEndpoint().GetAddress().GetAddress().(*v3.Address_SocketAddress)
			if !ok {
				continue
			}
			address := socketAddr.SocketAddress.Address
			out = append(out, address)
		}
		if !slices.Equal(out, addrs) {
			t.Errorf("OverwriteDNSCluster error, expected %v, but got %v", out, addrs)
		}
	}
}

// This test aims to evaluate the concurrent writing behavior of the adsCache by utilizing the test race feature.
// The test verifies the ability of the adsCache to handle concurrent access and updates correctly in a multi-goroutine environment.
func TestADSCacheConcurrentWriting(t *testing.T) {
	adsCache := NewAdsCache(nil)
	cluster := &clusterv3.Cluster{
		Name: "ut-cluster",
		ClusterDiscoveryType: &clusterv3.Cluster_Type{
			Type: clusterv3.Cluster_LOGICAL_DNS,
		},
	}
	adsCache.CreateApiClusterByCds(core_v2.ApiStatus_NONE, cluster)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				currentStatus := adsCache.GetApiClusterStatus(cluster.GetName())
				newStatus := currentStatus + core_v2.ApiStatus(rand.Intn(3)-1)
				if rand.Intn(2) == 0 {
					adsCache.UpdateApiClusterIfExists(newStatus, cluster)
				} else {
					adsCache.UpdateApiClusterStatus(cluster.GetName(), newStatus)
				}
			}
		}()
	}

	wg.Wait()
}

func TestHandleCdsResponseWithDns(t *testing.T) {
	cluster1 := &clusterv3.Cluster{
		Name: "ut-cluster1",
		ClusterDiscoveryType: &clusterv3.Cluster_Type{
			Type: clusterv3.Cluster_LOGICAL_DNS,
		},
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			Endpoints: []*endpointv3.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpointv3.LbEndpoint{
						{
							HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
								Endpoint: &endpointv3.Endpoint{
									Address: &v3.Address{
										Address: &v3.Address_SocketAddress{
											SocketAddress: &v3.SocketAddress{
												Address: "foo.bar",
												PortSpecifier: &v3.SocketAddress_PortValue{
													PortValue: uint32(9898),
												},
											},
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
	cluster2 := &clusterv3.Cluster{
		Name: "ut-cluster2",
		ClusterDiscoveryType: &clusterv3.Cluster_Type{
			Type: clusterv3.Cluster_STRICT_DNS,
		},
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			Endpoints: []*endpointv3.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpointv3.LbEndpoint{
						{
							HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
								Endpoint: &endpointv3.Endpoint{
									Address: &v3.Address{
										Address: &v3.Address_SocketAddress{
											SocketAddress: &v3.SocketAddress{
												Address: "foo.baz",
												PortSpecifier: &v3.SocketAddress_PortValue{
													PortValue: uint32(9898),
												},
											},
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

	testcases := []struct {
		name     string
		clusters []*clusterv3.Cluster
		expected []string
	}{
		{
			name:     "add clusters with DNS type",
			clusters: []*clusterv3.Cluster{cluster1, cluster2},
			expected: []string{"foo.bar", "foo.baz"},
		},
	}

	p := NewController(nil).Processor
	stopCh := make(chan struct{})
	defer close(stopCh)
	dnsResolver, err := NewDnsController(p.Cache)
	assert.NoError(t, err)
	dnsResolver.Run(stopCh)
	p.DnsResolverChan = dnsResolver.clustersChan
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// notify dns resolver
			dnsResolver.clustersChan <- tc.clusters
			retry.UntilOrFail(t, func() bool {
				return slices.EqualUnordered(tc.expected, dnsResolver.dnsResolver.GetAllCachedDomains())
			}, retry.Timeout(1*time.Second))
		})
	}
}

func TestGetPendingResolveDomain(t *testing.T) {
	utCluster := clusterv3.Cluster{
		Name: "testCluster",
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			Endpoints: []*endpointv3.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpointv3.LbEndpoint{
						{
							HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
								Endpoint: &endpointv3.Endpoint{
									Address: &v3.Address{
										Address: &v3.Address_SocketAddress{
											SocketAddress: &v3.SocketAddress{
												Address: "192.168.2.1",
												PortSpecifier: &v3.SocketAddress_PortValue{
													PortValue: uint32(9898),
												},
											},
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

	utClusterWithHost := clusterv3.Cluster{
		Name: "testCluster",
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			Endpoints: []*endpointv3.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpointv3.LbEndpoint{
						{
							HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
								Endpoint: &endpointv3.Endpoint{
									Address: &v3.Address{
										Address: &v3.Address_SocketAddress{
											SocketAddress: &v3.SocketAddress{
												Address: "www.google.com",
												PortSpecifier: &v3.SocketAddress_PortValue{
													PortValue: uint32(9898),
												},
											},
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

	type args struct {
		clusters []*clusterv3.Cluster
	}
	tests := []struct {
		name string
		args args
		want map[string]interface{}
	}{
		{
			name: "empty domains test",
			args: args{
				clusters: []*clusterv3.Cluster{
					&utCluster,
				},
			},
			want: map[string]interface{}{},
		},
		{
			name: "cluster domain is not IP",
			args: args{
				clusters: []*clusterv3.Cluster{
					&utClusterWithHost,
				},
			},
			want: map[string]interface{}{
				"www.google.com": &pendingResolveDomain{
					Clusters: []*clusterv3.Cluster{
						&utClusterWithHost,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPendingResolveDomain(tt.args.clusters)
			assert.Equal(t, tt.want, got)
		})
	}
}
