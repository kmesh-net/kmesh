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
	"testing"

	config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	cache_v2 "kmesh.net/kmesh/pkg/cache/v2"
	"kmesh.net/kmesh/pkg/utils/hash"
)

func TestHandleCdsResponse(t *testing.T) {
	t.Run("test1: new cluster, cluster type is eds", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		svc := &ServiceEvent{
			DynamicLoader: adsLoader,
		}
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
	})

	t.Run("test2: new cluster, cluster type is not eds", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		svc := &ServiceEvent{
			DynamicLoader: adsLoader,
		}
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
	})

	t.Run("test3: nil cluster", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		svc := &ServiceEvent{
			DynamicLoader: adsLoader,
		}
		cluster := &config_cluster_v3.Cluster{}
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
	})

	t.Run("test4: already have cluster, change cluster hash", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		svc := &ServiceEvent{
			DynamicLoader: adsLoader,
		}
		cluster := &config_cluster_v3.Cluster{
			Name: "ut-cluster",
			ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
				Type: config_cluster_v3.Cluster_LOGICAL_DNS,
			},
		}
		anyCluster, err := anypb.New(cluster)
		assert.NoError(t, err)
		clusterHash := hash.Sum64String(anyCluster.String())
		svc.DynamicLoader.ClusterCache.SetCdsHash(cluster.GetName(), clusterHash)
		apiStatus := core_v2.ApiStatus_UPDATE
		svc.DynamicLoader.CreateApiClusterByCds(apiStatus, cluster)

		cluster.Name = "cluster"
		anyCluster, err = anypb.New(cluster)
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
	})

	t.Run("test5: have mult clusters, add a new  eds cluster", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		svc := &ServiceEvent{
			DynamicLoader: adsLoader,
		}
		multClusters := []*config_cluster_v3.Cluster{
			&config_cluster_v3.Cluster{
				Name: "ut-cluster1",
				ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
					Type: config_cluster_v3.Cluster_LOGICAL_DNS,
				},
			},
			&config_cluster_v3.Cluster{
				Name: "ut-cluster2",
				ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
					Type: config_cluster_v3.Cluster_EDS,
				},
			},
		}
		for _, cluster := range multClusters {
			anyCluster, err := anypb.New(cluster)
			assert.NoError(t, err)
			clusterHash := hash.Sum64String(anyCluster.String())
			svc.DynamicLoader.ClusterCache.SetCdsHash(cluster.GetName(), clusterHash)
			apiStatus := core_v2.ApiStatus_UPDATE
			svc.DynamicLoader.CreateApiClusterByCds(apiStatus, cluster)
			svc.DynamicLoader.edsClusterNames = []string{
				"ut-cluster2",
			}
		}

		newCluster := &config_cluster_v3.Cluster{
			Name: "new-ut-cluster",
			ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
				Type: config_cluster_v3.Cluster_EDS,
			},
		}
		anyCluster, err := anypb.New(newCluster)
		assert.NoError(t, err)
		rsp := &service_discovery_v3.DiscoveryResponse{
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
	})

	t.Run("test6: mult clusters in rsp", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		svc := &ServiceEvent{
			DynamicLoader: adsLoader,
		}
		cluster := &config_cluster_v3.Cluster{
			Name: "ut-cluster",
			ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
				Type: config_cluster_v3.Cluster_LOGICAL_DNS,
			},
		}
		anyCluster, err := anypb.New(cluster)
		assert.NoError(t, err)
		clusterHash := hash.Sum64String(anyCluster.String())
		svc.DynamicLoader.ClusterCache.SetCdsHash(cluster.GetName(), clusterHash)
		apiStatus := core_v2.ApiStatus_UPDATE
		svc.DynamicLoader.CreateApiClusterByCds(apiStatus, cluster)

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
		rsp := &service_discovery_v3.DiscoveryResponse{
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
	})
}

func TestHandleEdsResponse(t *testing.T) {
	t.Run("test1: cluster's apiStatus is UPDATE", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.ClusterCache = cache_v2.NewClusterCache()
		cluster := &cluster_v2.Cluster{
			Name:      "ut-cluster",
			ApiStatus: core_v2.ApiStatus_UPDATE,
		}
		adsLoader.ClusterCache.SetApiCluster("ut-cluster", cluster)
		svc := ServiceEvent{
			DynamicLoader: adsLoader,
			ack: &service_discovery_v3.DiscoveryRequest{
				ResourceNames: []string{
					"ut-far",
				},
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
		assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster("ut-cluster").ApiStatus, core_v2.ApiStatus_UPDATE)
		assert.Equal(t, []string{"ut-far", "ut-cluster"}, svc.ack.ResourceNames)
	})

	t.Run("test2: not apiStatus_UPDATE", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.ClusterCache = cache_v2.NewClusterCache()
		cluster := &cluster_v2.Cluster{
			Name:      "ut-cluster",
			ApiStatus: core_v2.ApiStatus_DELETE,
		}
		adsLoader.ClusterCache.SetApiCluster("ut-cluster", cluster)
		svc := ServiceEvent{
			DynamicLoader: adsLoader,
			ack: &service_discovery_v3.DiscoveryRequest{
				ResourceNames: []string{
					"ut-far",
				},
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
		assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster("ut-cluster").ApiStatus, core_v2.ApiStatus_UPDATE)
		assert.Equal(t, []string{"ut-far", "ut-cluster"}, svc.ack.ResourceNames)
	})

	t.Run("test3: already have cluster, not update", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.ClusterCache = cache_v2.NewClusterCache()
		cluster := &cluster_v2.Cluster{
			Name:      "ut-cluster",
			ApiStatus: core_v2.ApiStatus_DELETE,
		}
		adsLoader.ClusterCache.SetApiCluster("ut-cluster", cluster)
		svc := ServiceEvent{
			DynamicLoader: adsLoader,
			ack: &service_discovery_v3.DiscoveryRequest{
				ResourceNames: []string{
					"ut-far",
				},
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
		assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster("ut-cluster").ApiStatus, core_v2.ApiStatus_DELETE)
		assert.Equal(t, []string{"ut-far", "ut-cluster"}, svc.ack.ResourceNames)
	})

	t.Run("test4: no apicluster, svc.ack not chamge", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.ClusterCache = cache_v2.NewClusterCache()
		cluster := &cluster_v2.Cluster{}
		adsLoader.ClusterCache.SetApiCluster("", cluster)
		svc := ServiceEvent{
			DynamicLoader: adsLoader,
			ack: &service_discovery_v3.DiscoveryRequest{
				ResourceNames: []string{
					"ut-far",
				},
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

	t.Run("test5: no loadAssignment", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.ClusterCache = cache_v2.NewClusterCache()
		cluster := &cluster_v2.Cluster{
			Name:      "ut-cluster",
			ApiStatus: core_v2.ApiStatus_DELETE,
		}
		adsLoader.ClusterCache.SetApiCluster("ut-cluster", cluster)
		svc := ServiceEvent{
			DynamicLoader: adsLoader,
			ack: &service_discovery_v3.DiscoveryRequest{
				ResourceNames: []string{
					"ut-far",
				},
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
		assert.Equal(t, svc.DynamicLoader.ClusterCache.GetApiCluster("ut-cluster").ApiStatus, core_v2.ApiStatus_DELETE)
		assert.Equal(t, []string{"ut-far"}, svc.ack.ResourceNames)
	})
}

func TestHandleLdsResponse(t *testing.T) {
	t.Run("test1: normal function test", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.routeNames = []string{
			"ut-route-to-client",
			"ut-route-to-service",
		}
		svc := &ServiceEvent{
			DynamicLoader: adsLoader,
		}
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
		apiMethod := svc.DynamicLoader.ListenerCache.GetApiListener("ut-listener").ApiStatus
		assert.Equal(t, core_v2.ApiStatus_UPDATE, apiMethod)
		wantHash := hash.Sum64String(anyListener.String())
		actualHash := svc.DynamicLoader.ListenerCache.GetLdsHash(listener.GetName())
		assert.Equal(t, wantHash, actualHash)
	})

	t.Run("listenerCache already has resource", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		adsLoader.routeNames = []string{
			"ut-route-to-client",
			"ut-route-to-service",
		}
		svc := &ServiceEvent{
			DynamicLoader: adsLoader,
		}
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
		listenerHash := hash.Sum64String(anyListener.String())
		svc.DynamicLoader.ListenerCache.AddOrUpdateLdsHash(listener.GetName(), listenerHash)
		svc.DynamicLoader.CreateApiListenerByLds(core_v2.ApiStatus_ALL, listener)
		err = svc.handleLdsResponse(rsp)
		assert.NoError(t, err)
		apiMethod := svc.DynamicLoader.ListenerCache.GetApiListener(listener.GetName()).ApiStatus
		assert.Equal(t, core_v2.ApiStatus_ALL, apiMethod)
		wantHash := hash.Sum64String(anyListener.String())
		actualHash := svc.DynamicLoader.ListenerCache.GetLdsHash(listener.GetName())
		assert.Equal(t, wantHash, actualHash)
	})

	// t.Run("test3: listener in rsp is nil", func(t *testing.T) {
	// 	adsLoader := NewAdsLoader()
	// 	adsLoader.routeNames = []string{
	// 		"ut-route-to-client",
	// 		"ut-route-to-service",
	// 	}
	// 	svc := &ServiceEvent{
	// 		DynamicLoader: adsLoader,
	// 	}
	// 	listener := &config_listener_v3.Listener{}
	// 	anyListener, err := anypb.New(listener)
	// 	assert.NoError(t, err)
	// 	rsp := &service_discovery_v3.DiscoveryResponse{
	// 		Resources: []*anypb.Any{
	// 			anyListener,
	// 		},
	// 	}
	// 	err = svc.handleLdsResponse(rsp)
	// 	assert.NoError(t, err)
	// 	apiMethod := svc.DynamicLoader.ListenerCache.GetApiListener("ut-listener").ApiStatus
	// 	assert.Equal(t, core_v2.ApiStatus_UPDATE, apiMethod)
	// 	wantHash := hash.Sum64String(anyListener.String())
	// 	actualHash := svc.DynamicLoader.ListenerCache.GetLdsHash(listener.GetName())
	// 	assert.Equal(t, wantHash, actualHash)
	// })

	t.Run("test4: ", func(t *testing.T) {})
}

func TestHandleRdsResponse(t *testing.T) {
	t.Run("test1: normal function test", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		svc := &ServiceEvent{
			DynamicLoader: adsLoader,
			ack: &service_discovery_v3.DiscoveryRequest{
				ResourceNames: []string{
					"ut-routeclient",
				},
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

	t.Run("test2: nil routeConfig", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		svc := &ServiceEvent{
			DynamicLoader: adsLoader,
			ack: &service_discovery_v3.DiscoveryRequest{
				ResourceNames: []string{
					"ut-routeclient",
				},
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

	t.Run("test3: already have a Rda, RdaHash has change", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		svc := &ServiceEvent{
			DynamicLoader: adsLoader,
			ack: &service_discovery_v3.DiscoveryRequest{
				ResourceNames: []string{
					"ut-routeclient",
				},
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
		routeHash := hash.Sum64String(anyRouteConfig.String())
		svc.DynamicLoader.RouteCache.SetRdsHash(routeConfig.GetName(), routeHash)
		routeConfig.Name = "new-ut-routeconfig"
		anyRouteConfig, err = anypb.New(routeConfig)
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
		assert.Equal(t, []string{"ut-routeclient", "new-ut-routeconfig"}, svc.ack.ResourceNames)
	})

	t.Run("test4: already have a Rda, RdaHash has change. And have mult routeconfig in rsp", func(t *testing.T) {
		adsLoader := NewAdsLoader()
		svc := &ServiceEvent{
			DynamicLoader: adsLoader,
			ack: &service_discovery_v3.DiscoveryRequest{
				ResourceNames: []string{
					"ut-routeclient",
				},
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
		routeHash := hash.Sum64String(anyRouteConfig1.String())
		svc.DynamicLoader.RouteCache.SetRdsHash(routeConfig1.GetName(), routeHash)
		routeConfig1.Name = "new-ut-routeconfig"
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

		rsp := &service_discovery_v3.DiscoveryResponse{
			Resources: []*anypb.Any{
				anyRouteConfig1,
				anyRouteConfig2,
			},
		}
		err := svc.handleRdsResponse(rsp)
		assert.NoError(t, err)
		wantHash1 := hash.Sum64String(anyRouteConfig1.String())
		actualHash1 := svc.DynamicLoader.RouteCache.GetRdsHash(routeConfig1.GetName())
		assert.Equal(t, wantHash1, actualHash1)
		wantHash2 := hash.Sum64String(anyRouteConfig2.String())
		actualHash2 := svc.DynamicLoader.RouteCache.GetRdsHash(routeConfig2.GetName())
		assert.Equal(t, wantHash2, actualHash2)
		assert.Equal(t, []string{"ut-routeclient", "new-ut-routeconfig", "ut-routeconfig2"}, svc.ack.ResourceNames)
	})
}
