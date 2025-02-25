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
		{
			name:     "remove all DNS type clusters",
			clusters: []*clusterv3.Cluster{},
			expected: []string{},
		},
	}

	p := NewController(nil).Processor
	stopCh := make(chan struct{})
	defer close(stopCh)
	dnsResolver, err := NewAdsDnsResolver(p.Cache)
	assert.NoError(t, err)
	dnsResolver.StartAdsDnsResolver(stopCh)
	p.DnsResolverChan = dnsResolver.Clusters
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// notify dns resolver
			dnsResolver.Clusters <- tc.clusters
			retry.UntilOrFail(t, func() bool {
				return slices.EqualUnordered(tc.expected, dnsResolver.dnsResolver.GetAllCachedDomains())
			}, retry.Timeout(1*time.Second))
		})
	}
}

func TestDNS(t *testing.T) {
	fakeDNSServer := dns.NewFakeDNSServer()

	testDNSResolver, err := NewAdsDnsResolver(NewAdsCache(nil))
	if err != nil {
		t.Fatal(err)
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	// testDNSResolver.StartAdsDnsResolver(stopCh)
	dnsServer := fakeDNSServer.Server.PacketConn.LocalAddr().String()
	testDNSResolver.dnsResolver.ResolvConfServers = []string{dnsServer}

	testCases := []struct {
		name             string
		domain           string
		refreshRate      time.Duration
		ttl              time.Duration
		expected         []string
		expectedAfterTTL []string
		registerDomain   func(domain string)
	}{
		{
			name:        "success",
			domain:      "www.google.com.",
			refreshRate: 10 * time.Second,
			expected:    []string{"10.0.0.1", "fd00::1"},
			registerDomain: func(domain string) {
				fakeDNSServer.SetHosts(domain, 1)
			},
		},
		{
			name:             "check dns refresh after ttl, ttl < refreshRate",
			domain:           "www.bing.com.",
			refreshRate:      10 * time.Second,
			ttl:              3 * time.Second,
			expected:         []string{"10.0.0.2", "fd00::2"},
			expectedAfterTTL: []string{"10.0.0.3", "fd00::3"},
			registerDomain: func(domain string) {
				fakeDNSServer.SetHosts(domain, 2)
				fakeDNSServer.SetTTL(uint32(3))
				time.AfterFunc(time.Second, func() {
					fakeDNSServer.SetHosts(domain, 3)
				})
			},
		},
		{
			name:             "check dns refresh after ttl without update bpfmap",
			domain:           "www.test.com.",
			refreshRate:      10 * time.Second,
			ttl:              3 * time.Second,
			expected:         []string{"10.0.0.2", "fd00::2"},
			expectedAfterTTL: []string{"10.0.0.2", "fd00::2"},
			registerDomain: func(domain string) {
				fakeDNSServer.SetHosts(domain, 2)
				fakeDNSServer.SetTTL(uint32(3))
			},
		},
		{
			name:             "check dns refresh after refreshRate, ttl > refreshRate",
			domain:           "www.baidu.com.",
			refreshRate:      3 * time.Second,
			ttl:              10 * time.Second,
			expected:         []string{"10.0.0.2", "fd00::2"},
			expectedAfterTTL: []string{"10.0.0.3", "fd00::3"},
			registerDomain: func(domain string) {
				fakeDNSServer.SetHosts(domain, 2)
				fakeDNSServer.SetTTL(uint32(10))
				time.AfterFunc(time.Second, func() {
					fakeDNSServer.SetHosts(domain, 3)
				})
			},
		},
		{
			name:        "failed to resolve",
			domain:      "www.kmesh.test.",
			refreshRate: 10 * time.Second,
			expected:    []string{},
		},
	}
	var wg sync.WaitGroup
	for _, testcase := range testCases {
		wg.Add(1)
		if testcase.registerDomain != nil {
			testcase.registerDomain(testcase.domain)
		}

		input := &dns.PendingResolveDomain{
			DomainName:  testcase.domain,
			RefreshRate: testcase.refreshRate,
		}
		testDNSResolver.dnsResolver.Lock()
		testDNSResolver.dnsResolver.Cache[testcase.domain] = &dns.DomainCacheEntry{}
		testDNSResolver.dnsResolver.Unlock()
		go testDNSResolver.refreshAdsWorker()

		_, ttl, err := testDNSResolver.dnsResolver.Resolve(input.DomainName)
		assert.NoError(t, err)
		if ttl > input.RefreshRate {
			ttl = input.RefreshRate
		}
		if ttl == 0 {
			ttl = dns.DeRefreshInterval
		}
		testDNSResolver.dnsRefreshQueue.AddAfter(input, ttl)
		time.Sleep(2 * time.Second)

		res := testDNSResolver.dnsResolver.GetDNSAddresses(testcase.domain)
		if len(res) != 0 || len(testcase.expected) != 0 {
			if !reflect.DeepEqual(res, testcase.expected) {
				t.Errorf("dns resolve for %s do not match. \n got %v\nwant %v", testcase.domain, res, testcase.expected)
			}

			if testcase.expectedAfterTTL != nil {
				time.Sleep(ttl + 1)
				res = testDNSResolver.dnsResolver.GetDNSAddresses(testcase.domain)
				if !reflect.DeepEqual(res, testcase.expectedAfterTTL) {
					t.Errorf("dns refresh after ttl failed, for %s do not match. \n got %v\nwant %v", testcase.domain, res, testcase.expectedAfterTTL)
				}
			}
		}
		wg.Done()
	}
	wg.Wait()
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
		want map[string]*dns.PendingResolveDomain
	}{
		{
			name: "empty domains test",
			args: args{
				clusters: []*clusterv3.Cluster{
					&utCluster,
				},
			},
			want: map[string]*dns.PendingResolveDomain{},
		},
		{
			name: "cluster domain is not IP",
			args: args{
				clusters: []*clusterv3.Cluster{
					&utClusterWithHost,
				},
			},
			want: map[string]*dns.PendingResolveDomain{
				"www.google.com": {
					DomainName: "www.google.com",
					Clusters:   []*clusterv3.Cluster{&utClusterWithHost},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getPendingResolveDomain(tt.args.clusters); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getPendingResolveDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
