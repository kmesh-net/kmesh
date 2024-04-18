/*
 * Copyright 2024 The Kmesh Authors.
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

package envoy

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	v31 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	filters_network_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcp_proxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	pkg_wellknown "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/util/protoconv"
	"k8s.io/apimachinery/pkg/util/rand"

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/pkg/bpf"
	cache_v2 "kmesh.net/kmesh/pkg/cache/v2"
	"kmesh.net/kmesh/pkg/utils/hash"
)

func createCluster() *config_cluster_v3.Cluster {
	return &config_cluster_v3.Cluster{
		Name: "inbound|9080|http|reviews.default.svc.cluster.local",
		ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
			Type: config_cluster_v3.Cluster_EDS,
		},
		ConnectTimeout: &duration.Duration{
			Seconds: int64(1),
		},
		LoadAssignment: &v31.ClusterLoadAssignment{
			ClusterName: "inbound|9080|http|reviews.default.svc.cluster.local",
			Endpoints: []*v31.LocalityLbEndpoints{
				{
					LbEndpoints: []*v31.LbEndpoint{
						{
							HostIdentifier: &v31.LbEndpoint_Endpoint{
								Endpoint: &v31.Endpoint{
									Address: &core_v3.Address{
										Address: &core_v3.Address_SocketAddress{
											SocketAddress: &core_v3.SocketAddress{
												Address: "127.0.0.1",
												PortSpecifier: &core_v3.SocketAddress_PortValue{
													PortValue: uint32(9080),
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
		CircuitBreakers: &config_cluster_v3.CircuitBreakers{
			Thresholds: []*config_cluster_v3.CircuitBreakers_Thresholds{
				{
					MaxConnections:     wrapperspb.UInt32(4294967295),
					MaxPendingRequests: wrapperspb.UInt32(4294967295),
					MaxRequests:        wrapperspb.UInt32(4294967295),
					MaxRetries:         wrapperspb.UInt32(4294967295),
				},
			},
		},
	}
}

func createListener() *config_listener_v3.Listener {
	return &config_listener_v3.Listener{
		Name: "10.96.0.10_53",
		Address: &core_v3.Address{
			Address: &core_v3.Address_SocketAddress{
				SocketAddress: &core_v3.SocketAddress{
					Address: "10.96.0.10",
					PortSpecifier: &core_v3.SocketAddress_PortValue{
						PortValue: uint32(53),
					},
				},
			},
		},
		FilterChains: []*config_listener_v3.FilterChain{
			{
				Filters: []*config_listener_v3.Filter{
					{
						Name: "istio.stats",
						ConfigType: &config_listener_v3.Filter_TypedConfig{
							TypedConfig: protoconv.MessageToAny(&tcp_proxyv3.TcpProxy{
								StatPrefix: "outbound|53||kube-dns.kube-system.svc.cluster.local",
								ClusterSpecifier: &tcp_proxyv3.TcpProxy_Cluster{
									Cluster: "outbound|53||kube-dns.kube-system.svc.cluster.local",
								},
								AccessLog: []*accesslogv3.AccessLog{
									{
										Name: "envoy.access_loggers.file",
										ConfigType: &accesslogv3.AccessLog_TypedConfig{
											TypedConfig: protoconv.MessageToAny(&meshconfig.MeshConfig_ExtensionProvider_EnvoyFileAccessLogProvider{
												Path: "/dev/stdout",
												LogFormat: &meshconfig.MeshConfig_ExtensionProvider_EnvoyFileAccessLogProvider_LogFormat{
													LogFormat: &meshconfig.MeshConfig_ExtensionProvider_EnvoyFileAccessLogProvider_LogFormat_Labels{
														Labels: &structpb.Struct{},
													},
												},
											}),
										},
									},
								},
							}),
						},
					},
				},
			},
		},
		ListenerFiltersTimeout: &duration.Duration{
			Seconds: int64(0),
		},
		ContinueOnListenerFiltersTimeout: true,
		TrafficDirection:                 core_v3.TrafficDirection_OUTBOUND,
		BindToPort: &wrapperspb.BoolValue{
			Value: false,
		},
	}
}

func TestHandleCdsResponse(t *testing.T) {
	initBpfMap(t)
	t.Cleanup(cleanupBpfMap)
	t.Run("new cluster, cluster type is eds", func(t *testing.T) {
		svc := NewServiceEvent()
		svc.LastNonce.edsNonce = "utkmesh"
		cluster := &config_cluster_v3.Cluster{
			Name: "ut-cluster",
			ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
				Type: config_cluster_v3.Cluster_EDS,
			},
		}
		anyCluster, err := anypb.New(cluster)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyCluster,
			},
		}
		err = svc.handleCdsResponse(rsp)
		assert.NoError(t, err)
		assert.Equal(t, []string{"ut-cluster"}, svc.DynamicLoader.edsClusterNames)
		wantHash := hash.Sum64String(anyCluster.String())
		actualHash := svc.DynamicLoader.ClusterCache.GetCdsHash(cluster.GetName())
		assert.Equal(t, wantHash, actualHash)
		assert.Equal(t, []string{"ut-cluster"}, svc.rqt.ResourceNames)
		assert.Equal(t, svc.LastNonce.edsNonce, svc.rqt.ResponseNonce)
		assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster(cluster.Name).ApiStatus, core_v2.ApiStatus_UPDATE)
	})

	t.Run("new cluster, cluster type is not eds", func(t *testing.T) {
		svc := NewServiceEvent()
		cluster := &config_cluster_v3.Cluster{
			Name: "ut-cluster",
			ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
				Type: config_cluster_v3.Cluster_LOGICAL_DNS,
			},
		}
		anyCluster, err := anypb.New(cluster)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyCluster,
			},
		}
		err = svc.handleCdsResponse(rsp)
		assert.NoError(t, err)
		assert.Equal(t, []string{}, svc.DynamicLoader.edsClusterNames)
		wantHash := hash.Sum64String(anyCluster.String())
		actualHash := svc.DynamicLoader.ClusterCache.GetCdsHash(cluster.GetName())
		assert.Equal(t, wantHash, actualHash)
		assert.Nil(t, svc.rqt)
	})

	t.Run("cluster update case", func(t *testing.T) {
		svc := NewServiceEvent()
		cluster := &config_cluster_v3.Cluster{
			Name: "ut-cluster",
			ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
				Type: config_cluster_v3.Cluster_LOGICAL_DNS,
			},
		}
		anyCluster, err := anypb.New(cluster)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyCluster,
			},
		}
		err = svc.handleCdsResponse(rsp)
		assert.NoError(t, err)

		cluster = &config_cluster_v3.Cluster{
			Name: "ut-cluster",
			ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
				Type: config_cluster_v3.Cluster_STRICT_DNS,
			},
		}
		anyCluster, err = anypb.New(cluster)
		assert.NoError(t, err)
		rsp = &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyCluster,
			},
		}
		err = svc.handleCdsResponse(rsp)
		assert.NoError(t, err)
		assert.Equal(t, []string{}, svc.DynamicLoader.edsClusterNames)
		wantHash := hash.Sum64String(anyCluster.String())
		actualHash := svc.DynamicLoader.ClusterCache.GetCdsHash(cluster.GetName())
		assert.Equal(t, wantHash, actualHash)
		assert.Nil(t, svc.rqt)
		assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster(cluster.Name).ApiStatus, core_v2.ApiStatus_NONE)
	})

	t.Run("have multiClusters, add a new eds cluster", func(t *testing.T) {
		svc := NewServiceEvent()
		svc.LastNonce.ldsNonce = "utEdstoLds"
		multiClusters := []*config_cluster_v3.Cluster{
			{
				Name: "ut-cluster1",
				ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
					Type: config_cluster_v3.Cluster_LOGICAL_DNS,
				},
			},
			{
				Name: "ut-cluster2",
				ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
					Type: config_cluster_v3.Cluster_EDS,
				},
			},
		}
		anyMultCluster1, err1 := anypb.New(multiClusters[0])
		anyMultCluster2, err2 := anypb.New(multiClusters[1])
		assert.NoError(t, err1)
		assert.NoError(t, err2)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyMultCluster1,
				anyMultCluster2,
			},
		}
		err := svc.handleCdsResponse(rsp)
		assert.NoError(t, err)

		newCluster := &config_cluster_v3.Cluster{
			Name: "new-ut-cluster",
			ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
				Type: config_cluster_v3.Cluster_EDS,
			},
		}
		anyCluster, err := anypb.New(newCluster)
		assert.NoError(t, err)
		rsp = &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyCluster,
			},
		}
		err = svc.handleCdsResponse(rsp)
		assert.NoError(t, err)
		assert.Equal(t, []string{"new-ut-cluster"}, svc.DynamicLoader.edsClusterNames)
		wantHash := hash.Sum64String(anyCluster.String())
		actualHash := svc.DynamicLoader.ClusterCache.GetCdsHash(newCluster.GetName())
		assert.Equal(t, wantHash, actualHash)
		wantOldClusterHash1 := hash.Sum64String(anyMultCluster1.String())
		actualOldClusterHash1 := svc.DynamicLoader.ClusterCache.GetCdsHash(multiClusters[0].GetName())
		assert.Equal(t, wantOldClusterHash1, actualOldClusterHash1)
		wantOldClusterHash2 := hash.Sum64String(anyMultCluster2.String())
		actualOldClusterHash2 := svc.DynamicLoader.ClusterCache.GetCdsHash(multiClusters[1].GetName())
		assert.Equal(t, wantOldClusterHash2, actualOldClusterHash2)
		assert.Equal(t, []string{"new-ut-cluster"}, svc.rqt.ResourceNames)
		assert.Equal(t, svc.LastNonce.edsNonce, svc.rqt.ResponseNonce)
	})

	t.Run("multiClusters in resp", func(t *testing.T) {
		svc := NewServiceEvent()
		cluster := &config_cluster_v3.Cluster{
			Name: "ut-cluster",
			ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
				Type: config_cluster_v3.Cluster_EDS,
			},
		}
		anyCluster, err := anypb.New(cluster)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyCluster,
			},
		}
		err = svc.handleCdsResponse(rsp)
		assert.NoError(t, err)

		newCluster1 := &config_cluster_v3.Cluster{
			Name: "new-ut-cluster1",
			ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
				Type: config_cluster_v3.Cluster_LOGICAL_DNS,
			},
		}
		newCluster2 := &config_cluster_v3.Cluster{
			Name: "new-ut-cluster2",
			ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
				Type: config_cluster_v3.Cluster_EDS,
			},
		}
		anyCluster1, err1 := anypb.New(newCluster1)
		assert.NoError(t, err1)
		anyCluster2, err2 := anypb.New(newCluster2)
		assert.NoError(t, err2)
		rsp = &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyCluster1,
				anyCluster2,
			},
		}
		err = svc.handleCdsResponse(rsp)
		assert.NoError(t, err)
		assert.Equal(t, []string{"new-ut-cluster2"}, svc.DynamicLoader.edsClusterNames)
		wantHash1 := hash.Sum64String(anyCluster1.String())
		wantHash2 := hash.Sum64String(anyCluster2.String())
		actualHash1 := svc.DynamicLoader.ClusterCache.GetCdsHash(newCluster1.GetName())
		assert.Equal(t, wantHash1, actualHash1)
		actualHash2 := svc.DynamicLoader.ClusterCache.GetCdsHash(newCluster2.GetName())
		assert.Equal(t, wantHash2, actualHash2)
		assert.Equal(t, []string{"new-ut-cluster2"}, svc.rqt.ResourceNames)
		assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster(cluster.Name).ApiStatus, core_v2.ApiStatus_DELETE)
	})

	t.Run("cluster bpf write test", func(t *testing.T) {
		result := testing.Benchmark(func(b *testing.B) {
			start := time.Now()
			for i := 0; i < b.N; i++ {
				svc := NewServiceEvent()
				cluster := createCluster()
				svc.DynamicLoader.edsClusterNames = []string{"inbound|9080|http|reviews.default.svc.cluster.local"}
				anyCluster, _ := anypb.New(cluster)
				rsp := &service_discovery_v3.DiscoveryResponse{
					Resources: []*anypb.Any{
						anyCluster,
					},
				}
				err := svc.handleCdsResponse(rsp)
				assert.NoError(t, err)
				assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster(cluster.Name).ApiStatus, core_v2.ApiStatus_NONE)
			}
			duration := time.Since(start)
			b.ReportMetric(duration.Seconds(), "seconds")
		})
		t.Logf("write cluster map average time: %fms\n", float64(result.NsPerOp())/1e6)
	})
}

func TestHandleEdsResponse(t *testing.T) {
	initBpfMap(t)
	t.Cleanup(cleanupBpfMap)
	t.Run("cluster's apiStatus is UPDATE", func(t *testing.T) {
		svc := NewServiceEvent()
		adsLoader := NewAdsLoader()
		adsLoader.ClusterCache = cache_v2.NewClusterCache()
		cluster := &cluster_v2.Cluster{
			Name:      "ut-cluster",
			ApiStatus: core_v2.ApiStatus_UPDATE,
		}
		adsLoader.ClusterCache.SetApiCluster("ut-cluster", cluster)
		svc.DynamicLoader = adsLoader
		svc.ack = &service_discovery_v3.DiscoveryRequest{
			ResourceNames: []string{
				"ut-far",
			},
		}
		loadAssignment := &config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "ut-cluster",
		}
		anyLoadAssignment, err := anypb.New(loadAssignment)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyLoadAssignment,
			},
		}
		err = svc.handleEdsResponse(rsp)
		assert.NoError(t, err)
		assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster("ut-cluster").ApiStatus, core_v2.ApiStatus_NONE)
		assert.Equal(t, []string{"ut-far", "ut-cluster"}, svc.ack.ResourceNames)
	})

	t.Run("not apiStatus_UPDATE", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.ClusterCache = cache_v2.NewClusterCache()
		cluster := &cluster_v2.Cluster{
			Name:      "ut-cluster",
			ApiStatus: core_v2.ApiStatus_ALL,
		}
		adsLoader.ClusterCache.SetApiCluster("ut-cluster", cluster)
		svc := NewServiceEvent()
		svc.DynamicLoader = adsLoader
		svc.ack = &service_discovery_v3.DiscoveryRequest{
			ResourceNames: []string{
				"ut-far",
			},
		}
		loadAssignment := &config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "ut-cluster",
		}
		anyLoadAssignment, err := anypb.New(loadAssignment)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyLoadAssignment,
			},
		}
		err = svc.handleEdsResponse(rsp)
		assert.NoError(t, err)
		assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster("ut-cluster").ApiStatus, core_v2.ApiStatus_NONE)
		assert.Equal(t, []string{"ut-far", "ut-cluster"}, svc.ack.ResourceNames)
	})

	t.Run("already have cluster, not update", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.ClusterCache = cache_v2.NewClusterCache()
		cluster := &cluster_v2.Cluster{
			Name:      "ut-cluster",
			ApiStatus: core_v2.ApiStatus_ALL,
		}
		adsLoader.ClusterCache.SetApiCluster("ut-cluster", cluster)
		svc := NewServiceEvent()
		svc.DynamicLoader = adsLoader
		svc.ack = &service_discovery_v3.DiscoveryRequest{
			ResourceNames: []string{
				"ut-far",
			},
		}
		loadAssignment := &config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "ut-cluster",
		}
		anyLoadAssignment, err := anypb.New(loadAssignment)
		assert.NoError(t, err)
		hashLoadAssignment := hash.Sum64String(anyLoadAssignment.String())
		svc.DynamicLoader.ClusterCache.SetEdsHash(loadAssignment.GetClusterName(), hashLoadAssignment)

		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyLoadAssignment,
			},
		}
		err = svc.handleEdsResponse(rsp)
		assert.NoError(t, err)
		assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster("ut-cluster").ApiStatus, core_v2.ApiStatus_ALL)
		assert.Equal(t, []string{"ut-far", "ut-cluster"}, svc.ack.ResourceNames)
	})

	t.Run("no apicluster, svc.ack not be changed", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.ClusterCache = cache_v2.NewClusterCache()
		cluster := &cluster_v2.Cluster{}
		adsLoader.ClusterCache.SetApiCluster("", cluster)
		svc := NewServiceEvent()
		svc.DynamicLoader = adsLoader
		svc.ack = &service_discovery_v3.DiscoveryRequest{
			ResourceNames: []string{
				"ut-far",
			},
		}
		loadAssignment := &config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "ut-cluster",
		}
		anyLoadAssignment, err := anypb.New(loadAssignment)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyLoadAssignment,
			},
		}
		err = svc.handleEdsResponse(rsp)
		assert.NoError(t, err)
		assert.Equal(t, []string{"ut-far"}, svc.ack.ResourceNames)
	})

	t.Run("empty loadAssignment", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.ClusterCache = cache_v2.NewClusterCache()
		cluster := &cluster_v2.Cluster{
			Name:      "ut-cluster",
			ApiStatus: core_v2.ApiStatus_ALL,
		}
		adsLoader.ClusterCache.SetApiCluster("ut-cluster", cluster)
		svc := NewServiceEvent()
		svc.DynamicLoader = adsLoader
		svc.ack = &service_discovery_v3.DiscoveryRequest{
			ResourceNames: []string{
				"ut-far",
			},
		}
		loadAssignment := &config_endpoint_v3.ClusterLoadAssignment{}
		anyLoadAssignment, err := anypb.New(loadAssignment)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyLoadAssignment,
			},
		}
		err = svc.handleEdsResponse(rsp)
		assert.NoError(t, err)
		assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster("ut-cluster").ApiStatus, core_v2.ApiStatus_ALL)
		assert.Equal(t, []string{"ut-far"}, svc.ack.ResourceNames)
	})
}

func initBpfMap(t *testing.T) {
	err := os.MkdirAll("/mnt/kmesh_cgroup2", 0755)
	if err != nil {
		t.Fatalf("Failed to create dir /mnt/kmesh_cgroup2: %v", err)
	}
	err = syscall.Mount("none", "/mnt/kmesh_cgroup2/", "cgroup2", 0, "")
	if err != nil {
		cleanupBpfMap()
		t.Fatalf("Failed to mount /mnt/kmesh_cgroup2/: %v", err)
	}
	err = syscall.Mount("/sys/fs/bpf", "/sys/fs/bpf", "bpf", 0, "")
	if err != nil {
		cleanupBpfMap()
		t.Fatalf("Failed to mount /sys/fs/bpf: %v", err)
	}
	config := bpf.GetConfig()
	config.BpfFsPath = "/sys/fs/bpf"
	config.Cgroup2Path = "/mnt/kmesh_cgroup2"
	err = bpf.StartKmesh()
	if err != nil {
		cleanupBpfMap()
		t.Fatalf("bpf init failed: %v", err)
	}
}

func cleanupBpfMap() {
	bpf.Stop()
	err := syscall.Unmount("/mnt/kmesh_cgroup2", 0)
	if err != nil {
		fmt.Println("unmount /mnt/kmesh_cgroup2 error: ", err)
	}
	err = syscall.Unmount("/sys/fs/bpf", 0)
	if err != nil {
		fmt.Println("unmount /sys/fs/bpf error: ", err)
	}
	err = os.RemoveAll("/mnt/kmesh_cgroup2")
	if err != nil {
		fmt.Println("remove /mnt/kmesh_cgroup2 error: ", err)
	}
}

func TestHandleLdsResponse(t *testing.T) {
	initBpfMap(t)
	t.Cleanup(cleanupBpfMap)
	t.Run("normal function test", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.routeNames = []string{
			"ut-route-to-client",
			"ut-route-to-service",
		}
		svc := NewServiceEvent()
		svc.DynamicLoader = adsLoader
		svc.LastNonce.rdsNonce = "utLdstoRds"
		filterHttp := &filters_network_http.HttpConnectionManager{
			RouteSpecifier: &filters_network_http.HttpConnectionManager_Rds{
				Rds: &filters_network_http.Rds{
					RouteConfigName: "ut-rds",
				},
			},
		}
		anyfilterHttp, err := anypb.New(filterHttp)
		assert.NoError(t, err)
		listener := &config_listener_v3.Listener{
			Name: "ut-listener",
			Address: &core_v3.Address{
				Address: &core_v3.Address_SocketAddress{
					SocketAddress: &core_v3.SocketAddress{
						Address:  "127.0.0.1",
						Protocol: core_v3.SocketAddress_TCP,
					},
				},
			},
			FilterChains: []*config_listener_v3.FilterChain{
				{
					Filters: []*config_listener_v3.Filter{
						{
							Name: pkg_wellknown.HTTPConnectionManager,
							ConfigType: &config_listener_v3.Filter_TypedConfig{
								TypedConfig: anyfilterHttp,
							},
						},
					},
				},
			},
		}
		anyListener, err := anypb.New(listener)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyListener,
			},
		}
		err = svc.handleLdsResponse(rsp)
		assert.NoError(t, err)
		apiMethod := svc.DynamicLoader.ListenerCache.GetApiListener("ut-listener").ApiStatus
		assert.Equal(t, core_v2.ApiStatus_NONE, apiMethod)
		wantHash := hash.Sum64String(anyListener.String())
		actualHash := svc.DynamicLoader.ListenerCache.GetLdsHash(listener.GetName())
		assert.Equal(t, wantHash, actualHash)
		assert.Equal(t, []string{"ut-rds"}, svc.rqt.ResourceNames)
		assert.Equal(t, svc.LastNonce.rdsNonce, svc.rqt.ResponseNonce)
	})

	t.Run("listenerCache already has resource and it has not been changed", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.routeNames = []string{
			"ut-route-to-client",
			"ut-route-to-service",
		}
		svc := NewServiceEvent()
		svc.DynamicLoader = adsLoader
		listener := &config_listener_v3.Listener{
			Name: "ut-listener",
			Address: &core_v3.Address{
				Address: &core_v3.Address_SocketAddress{
					SocketAddress: &core_v3.SocketAddress{
						Address:  "127.0.0.1",
						Protocol: core_v3.SocketAddress_TCP,
					},
				},
			},
		}
		anyListener, err := anypb.New(listener)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyListener,
			},
		}
		err = svc.handleLdsResponse(rsp)
		assert.NoError(t, err)
		apiMethod := svc.DynamicLoader.ListenerCache.GetApiListener(listener.GetName()).ApiStatus
		assert.Equal(t, core_v2.ApiStatus_NONE, apiMethod)
		err = svc.handleLdsResponse(rsp)
		assert.NoError(t, err)
		apiMethod = svc.DynamicLoader.ListenerCache.GetApiListener(listener.GetName()).ApiStatus
		assert.Equal(t, core_v2.ApiStatus_NONE, apiMethod)
		wantHash := hash.Sum64String(anyListener.String())
		actualHash := svc.DynamicLoader.ListenerCache.GetLdsHash(listener.GetName())
		assert.Equal(t, wantHash, actualHash)
	})

	t.Run("listenerCache already has resource and it has been changed", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.routeNames = []string{
			"ut-route-to-client",
			"ut-route-to-service",
		}
		svc := NewServiceEvent()
		svc.DynamicLoader = adsLoader
		listener := &config_listener_v3.Listener{
			Name: "ut-listener",
			Address: &core_v3.Address{
				Address: &core_v3.Address_SocketAddress{
					SocketAddress: &core_v3.SocketAddress{
						Address:  "127.0.0.1",
						Protocol: core_v3.SocketAddress_TCP,
					},
				},
			},
		}
		filterHttp := &filters_network_http.HttpConnectionManager{
			RouteSpecifier: &filters_network_http.HttpConnectionManager_Rds{
				Rds: &filters_network_http.Rds{
					RouteConfigName: "ut-rds",
				},
			},
		}
		anyfilterHttp, err := anypb.New(filterHttp)
		assert.NoError(t, err)
		filterChains := []*config_listener_v3.FilterChain{
			{
				Filters: []*config_listener_v3.Filter{
					{
						Name: pkg_wellknown.HTTPConnectionManager,
						ConfigType: &config_listener_v3.Filter_TypedConfig{
							TypedConfig: anyfilterHttp,
						},
					},
				},
			},
		}
		anyListener, err := anypb.New(listener)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyListener,
			},
		}
		err = svc.handleLdsResponse(rsp)
		assert.NoError(t, err)
		apiMethod := svc.DynamicLoader.ListenerCache.GetApiListener(listener.GetName()).ApiStatus
		assert.Equal(t, core_v2.ApiStatus_NONE, apiMethod)

		listener.FilterChains = filterChains
		anyListener, err = anypb.New(listener)
		assert.NoError(t, err)
		rsp = &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyListener,
			},
		}
		err = svc.handleLdsResponse(rsp)
		assert.NoError(t, err)
		apiMethod = svc.DynamicLoader.ListenerCache.GetApiListener(listener.GetName()).ApiStatus
		assert.Equal(t, core_v2.ApiStatus_NONE, apiMethod)
		wantHash := hash.Sum64String(anyListener.String())
		actualHash := svc.DynamicLoader.ListenerCache.GetLdsHash(listener.GetName())
		assert.Equal(t, wantHash, actualHash)
		assert.Equal(t, []string{"ut-rds"}, svc.rqt.ResourceNames)
	})

	t.Run("listener map write test", func(t *testing.T) {
		result := testing.Benchmark(func(b *testing.B) {
			start := time.Now()
			listener := createListener()
			for i := 0; i < b.N; i++ {
				adsLoader := NewAdsLoader()
				adsLoader.routeNames = []string{
					"ut-route-to-client",
					"ut-route-to-service",
				}
				svc := NewServiceEvent()
				svc.DynamicLoader = adsLoader
				svc.LastNonce.rdsNonce = "utLdstoRds"
				listener.Name = rand.String(6)
				anyListener, err := anypb.New(listener)
				assert.NoError(t, err)
				rsp := &service_discovery_v3.DiscoveryResponse{
					Resources: []*anypb.Any{
						anyListener,
					},
				}
				err = svc.handleLdsResponse(rsp)
				assert.NoError(t, err)
				apiMethod := svc.DynamicLoader.ListenerCache.GetApiListener(listener.GetName()).ApiStatus
				assert.Equal(t, core_v2.ApiStatus_NONE, apiMethod)
			}
			duration := time.Since(start)
			b.ReportMetric(duration.Seconds(), "seconds")
		})
		t.Logf("write listener map average time: %fms\n", float64(result.NsPerOp())/1e6)
	})
}

func TestHandleRdsResponse(t *testing.T) {
	initBpfMap(t)
	t.Cleanup(cleanupBpfMap)
	t.Run("normal function test", func(t *testing.T) {
		svc := NewServiceEvent()
		svc.ack = &service_discovery_v3.DiscoveryRequest{
			ResourceNames: []string{
				"ut-routeclient",
			},
		}
		routeConfig := &config_route_v3.RouteConfiguration{
			Name: "ut-routeconfig",
			VirtualHosts: []*config_route_v3.VirtualHost{
				{
					Name: "ut-host",
				},
			},
		}
		anyRouteConfig, err := anypb.New(routeConfig)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyRouteConfig,
			},
		}
		err = svc.handleRdsResponse(rsp)
		assert.NoError(t, err)
		wantHash := hash.Sum64String(anyRouteConfig.String())
		actualHash := svc.DynamicLoader.RouteCache.GetRdsHash(routeConfig.GetName())
		assert.Equal(t, wantHash, actualHash)
		assert.Equal(t, []string{"ut-routeclient", "ut-routeconfig"}, svc.ack.ResourceNames)
	})

	t.Run("empty routeConfig", func(t *testing.T) {
		svc := NewServiceEvent()
		svc.ack = &service_discovery_v3.DiscoveryRequest{
			ResourceNames: []string{
				"ut-routeclient",
			},
		}
		routeConfig := &config_route_v3.RouteConfiguration{}
		anyRouteConfig, err := anypb.New(routeConfig)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyRouteConfig,
			},
		}
		err = svc.handleRdsResponse(rsp)
		assert.NoError(t, err)
		wantHash := hash.Sum64String(anyRouteConfig.String())
		actualHash := svc.DynamicLoader.RouteCache.GetRdsHash(routeConfig.GetName())
		assert.Equal(t, wantHash, actualHash)
		assert.Equal(t, []string{"ut-routeclient"}, svc.ack.ResourceNames)
	})

	t.Run("already have a Rds, RdsHash has been changed", func(t *testing.T) {
		svc := NewServiceEvent()
		svc.ack = &service_discovery_v3.DiscoveryRequest{
			ResourceNames: []string{
				"ut-routeclient",
			},
		}
		routeConfig := &config_route_v3.RouteConfiguration{
			Name: "ut-routeconfig",
			VirtualHosts: []*config_route_v3.VirtualHost{
				{
					Name: "ut-host",
				},
			},
		}
		anyRouteConfig, err := anypb.New(routeConfig)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyRouteConfig,
			},
		}
		err = svc.handleRdsResponse(rsp)
		assert.NoError(t, err)

		routeConfig.VirtualHosts = append(routeConfig.VirtualHosts, &config_route_v3.VirtualHost{Name: "new-ut-host"})
		anyRouteConfig, err = anypb.New(routeConfig)
		assert.NoError(t, err)
		rsp = &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyRouteConfig,
			},
		}
		svc.ack = newAckRequest(rsp)
		err = svc.handleRdsResponse(rsp)
		assert.NoError(t, err)
		wantHash := hash.Sum64String(anyRouteConfig.String())
		actualHash := svc.DynamicLoader.RouteCache.GetRdsHash(routeConfig.GetName())
		assert.Equal(t, wantHash, actualHash)
		assert.Equal(t, []string{"ut-routeconfig"}, svc.ack.ResourceNames)
	})

	t.Run("already have a Rds, RdsHash has been change. And have multiRouteconfig in resp", func(t *testing.T) {
		svc := NewServiceEvent()
		svc.ack = &service_discovery_v3.DiscoveryRequest{
			ResourceNames: []string{
				"ut-routeclient",
			},
		}
		routeConfig1 := &config_route_v3.RouteConfiguration{
			Name: "ut-routeconfig1",
			VirtualHosts: []*config_route_v3.VirtualHost{
				{
					Name: "ut-host1",
				},
			},
		}
		anyRouteConfig1, err1 := anypb.New(routeConfig1)
		assert.NoError(t, err1)
		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyRouteConfig1,
			},
		}
		err1 = svc.handleRdsResponse(rsp)
		assert.NoError(t, err1)
		routeConfig1.VirtualHosts = append(routeConfig1.VirtualHosts, &config_route_v3.VirtualHost{Name: "new-ut-host"})
		anyRouteConfig1, err1 = anypb.New(routeConfig1)
		assert.NoError(t, err1)

		routeConfig2 := &config_route_v3.RouteConfiguration{
			Name: "ut-routeconfig2",
			VirtualHosts: []*config_route_v3.VirtualHost{
				{
					Name: "ut-host2",
				},
			},
		}
		anyRouteConfig2, err2 := anypb.New(routeConfig2)
		assert.NoError(t, err2)

		rsp = &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyRouteConfig1,
				anyRouteConfig2,
			},
		}
		svc.ack = newAckRequest(rsp)
		err := svc.handleRdsResponse(rsp)
		assert.NoError(t, err)
		wantHash1 := hash.Sum64String(anyRouteConfig1.String())
		actualHash1 := svc.DynamicLoader.RouteCache.GetRdsHash(routeConfig1.GetName())
		assert.Equal(t, wantHash1, actualHash1)
		wantHash2 := hash.Sum64String(anyRouteConfig2.String())
		actualHash2 := svc.DynamicLoader.RouteCache.GetRdsHash(routeConfig2.GetName())
		assert.Equal(t, wantHash2, actualHash2)
		assert.Equal(t, []string{"ut-routeconfig1", "ut-routeconfig2"}, svc.ack.ResourceNames)
	})
}
