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

package ads

import (
	"testing"

	config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	filters_network_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	pkg_wellknown "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	cache_v2 "kmesh.net/kmesh/pkg/cache/v2"
	"kmesh.net/kmesh/pkg/utils/hash"
	"kmesh.net/kmesh/pkg/utils/test"
)

func TestHandleCdsResponse(t *testing.T) {
	test.InitBpfMap(t)
	t.Cleanup(test.CleanupBpfMap)
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
		assert.Equal(t, []string{"ut-cluster"}, svc.req.ResourceNames)
		assert.Equal(t, svc.LastNonce.edsNonce, svc.req.ResponseNonce)
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
		assert.Nil(t, svc.req)
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
		assert.Nil(t, svc.req)
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
		assert.Equal(t, []string{"new-ut-cluster"}, svc.req.ResourceNames)
		assert.Equal(t, svc.LastNonce.edsNonce, svc.req.ResponseNonce)
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
		assert.Equal(t, []string{"new-ut-cluster2"}, svc.req.ResourceNames)
		assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster(cluster.Name).ApiStatus, core_v2.ApiStatus_DELETE)
	})
}

func TestHandleEdsResponse(t *testing.T) {
	test.InitBpfMap(t)
	t.Cleanup(test.CleanupBpfMap)
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

func TestHandleLdsResponse(t *testing.T) {
	test.InitBpfMap(t)
	t.Cleanup(test.CleanupBpfMap)
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
		assert.Equal(t, []string{"ut-rds"}, svc.req.ResourceNames)
		assert.Equal(t, svc.LastNonce.rdsNonce, svc.req.ResponseNonce)
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
		assert.Equal(t, []string{"ut-rds"}, svc.req.ResourceNames)
	})
}

func TestHandleRdsResponse(t *testing.T) {
	test.InitBpfMap(t)
	t.Cleanup(test.CleanupBpfMap)
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
