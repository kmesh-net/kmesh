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

package dns

import (
	"math/rand"
	"slices"
	"sync"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/pkg/controller/ads"
)

type fakeAdsDnsServer struct {
}

func TestOverwriteDNSCluster(t *testing.T) {
	domain := "www.google.com"
	addrs := []string{"10.1.1.1", "10.1.1.2"}
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

	overwriteDnsCluster(cluster, domain, addrs)

	endpoints := cluster.GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()
	if len(endpoints) != 2 {
		t.Errorf("Expected 2 LbEndpoints, but got %d", len(endpoints))
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

// This test aims to evaluate the concurrent writing behavior of the adsCache by utilizing the test race feature.
// The test verifies the ability of the adsCache to handle concurrent access and updates correctly in a multi-goroutine environment.
func TestADSCacheConcurrentWriting(t *testing.T) {
	adsCache := ads.NewAdsCache(nil)
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
