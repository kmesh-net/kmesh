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
	"testing"

	config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	filters_network_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	filters_network_tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	pkg_wellknown "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	//"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	core_v2 "kmesh.net/kmesh/api/v2/core"
	listener_v2 "kmesh.net/kmesh/api/v2/listener"
	"kmesh.net/kmesh/pkg/nets"
)

func TestCreateApiClusterByCds(t *testing.T) {
	tests := []struct {
		name    string
		loader  *AdsCache
		status  core_v2.ApiStatus
		cluster *config_cluster_v3.Cluster
		want    bool
	}{
		{
			name:   "test1: ApiStatus is update, cluster type is EDS",
			loader: NewAdsCache(),
			status: core_v2.ApiStatus_UPDATE,
			cluster: &config_cluster_v3.Cluster{
				Name: "ut-cluster",
				ConnectTimeout: &durationpb.Duration{
					Seconds: int64(30),
				},
				ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
					Type: config_cluster_v3.Cluster_EDS,
				},
				LoadAssignment: &config_endpoint_v3.ClusterLoadAssignment{
					ClusterName: "ut-cluster",
					Endpoints: []*config_endpoint_v3.LocalityLbEndpoints{
						{
							LoadBalancingWeight: wrapperspb.UInt32(30),
							Priority:            uint32(15),
							LbEndpoints: []*config_endpoint_v3.LbEndpoint{
								{
									HealthStatus: v3.HealthStatus_HEALTHY,
								},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name:   "test2: ApiStatus is update, cluster type is not EDS",
			loader: NewAdsCache(),
			status: core_v2.ApiStatus_UPDATE,
			cluster: &config_cluster_v3.Cluster{
				Name: "ut-cluster",
				ConnectTimeout: &durationpb.Duration{
					Seconds: int64(30),
				},
				ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
					Type: config_cluster_v3.Cluster_STATIC,
				},
				LoadAssignment: &config_endpoint_v3.ClusterLoadAssignment{
					ClusterName: "ut-cluster",
					Endpoints: []*config_endpoint_v3.LocalityLbEndpoints{
						{
							LoadBalancingWeight: wrapperspb.UInt32(30),
							Priority:            uint32(15),
							LbEndpoints: []*config_endpoint_v3.LbEndpoint{
								{
									HealthStatus: v3.HealthStatus_HEALTHY,
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name:   "test3: Apistatus is update, cluster type is EDS and cluster not has name",
			loader: NewAdsCache(),
			status: core_v2.ApiStatus_UPDATE,
			cluster: &config_cluster_v3.Cluster{
				ConnectTimeout: &durationpb.Duration{
					Seconds: int64(30),
				},
				ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
					Type: config_cluster_v3.Cluster_EDS,
				},
				LoadAssignment: &config_endpoint_v3.ClusterLoadAssignment{
					ClusterName: "ut-cluster",
					Endpoints: []*config_endpoint_v3.LocalityLbEndpoints{
						{
							LoadBalancingWeight: wrapperspb.UInt32(30),
							Priority:            uint32(15),
							LbEndpoints: []*config_endpoint_v3.LbEndpoint{
								{
									HealthStatus: v3.HealthStatus_HEALTHY,
								},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name:   "test4: Apistatus is update, cluster type is not EDS and cluster not has name",
			loader: NewAdsCache(),
			status: core_v2.ApiStatus_UPDATE,
			cluster: &config_cluster_v3.Cluster{
				ConnectTimeout: &durationpb.Duration{
					Seconds: int64(30),
				},
				ClusterDiscoveryType: &config_cluster_v3.Cluster_Type{
					Type: config_cluster_v3.Cluster_STATIC,
				},
				LoadAssignment: &config_endpoint_v3.ClusterLoadAssignment{
					ClusterName: "ut-cluster",
					Endpoints: []*config_endpoint_v3.LocalityLbEndpoints{
						{
							LoadBalancingWeight: wrapperspb.UInt32(30),
							Priority:            uint32(15),
							LbEndpoints: []*config_endpoint_v3.LbEndpoint{
								{
									HealthStatus: v3.HealthStatus_HEALTHY,
								},
							},
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.loader.CreateApiClusterByCds(tt.status, tt.cluster)
			assert.Equal(t, tt.status, tt.loader.ClusterCache.GetApiCluster(tt.cluster.GetName()).ApiStatus, tt.status)
			if (tt.loader.ClusterCache.GetApiCluster(tt.cluster.GetName()).GetLoadAssignment() == nil) != tt.want {
				t.Errorf("AdsCache.CreateApiClusterByCds() error, create LoadAssignment failed")
				return
			}
			assert.Equal(t, uint32(30), tt.loader.ClusterCache.GetApiCluster(tt.cluster.GetName()).ConnectTimeout)
		})
	}
}

func TestNewApiClusterLoadAssignment(t *testing.T) {
	t.Run("test1: normal function test", func(t *testing.T) {
		loadAssignment := &config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "ut-cluster",
			Endpoints: []*config_endpoint_v3.LocalityLbEndpoints{
				{
					LoadBalancingWeight: wrapperspb.UInt32(30),
					Priority:            uint32(15),
					LbEndpoints: []*config_endpoint_v3.LbEndpoint{
						{
							HealthStatus: v3.HealthStatus_HEALTHY,
							HostIdentifier: &config_endpoint_v3.LbEndpoint_Endpoint{
								Endpoint: &config_endpoint_v3.Endpoint{
									Address: &v3.Address{
										Address: &v3.Address_SocketAddress{
											SocketAddress: &v3.SocketAddress{
												Address: "192.168.127.1",
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
		clusterLoadAssignment := newApiClusterLoadAssignment(loadAssignment)
		assert.Equal(t, clusterLoadAssignment.Endpoints[0].LoadBalancingWeight, loadAssignment.Endpoints[0].GetLoadBalancingWeight().GetValue())
		assert.Equal(t, clusterLoadAssignment.Endpoints[0].Priority, loadAssignment.Endpoints[0].Priority)
		address := loadAssignment.Endpoints[0].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress().Address
		ipv4 := nets.ConvertIpToUint32(address)
		actualipv4 := clusterLoadAssignment.Endpoints[0].LbEndpoints[0].GetAddress().GetIpv4()
		assert.Equal(t, ipv4, actualipv4)
	})

	t.Run("test2: no socketAddress in LbEndpoints", func(t *testing.T) {
		loadAssignment := &config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "ut-cluster",
			Endpoints: []*config_endpoint_v3.LocalityLbEndpoints{
				{
					LoadBalancingWeight: wrapperspb.UInt32(30),
					Priority:            uint32(15),
					LbEndpoints: []*config_endpoint_v3.LbEndpoint{
						{
							HealthStatus: v3.HealthStatus_HEALTHY,
						},
					},
				},
			},
		}
		clusterLoadAssignment := newApiClusterLoadAssignment(loadAssignment)
		assert.Equal(t, clusterLoadAssignment.Endpoints[0].LoadBalancingWeight, loadAssignment.Endpoints[0].GetLoadBalancingWeight().GetValue())
		assert.Equal(t, clusterLoadAssignment.Endpoints[0].Priority, loadAssignment.Endpoints[0].Priority)
	})

	t.Run("test3: LbEndPointes is nil", func(t *testing.T) {
		loadAssignment := &config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "ut-cluster",
			Endpoints: []*config_endpoint_v3.LocalityLbEndpoints{
				{
					LoadBalancingWeight: wrapperspb.UInt32(30),
					Priority:            uint32(15),
					LbEndpoints:         []*config_endpoint_v3.LbEndpoint{},
				},
			},
		}
		clusterLoadAssignment := newApiClusterLoadAssignment(loadAssignment)
		assert.Equal(t, clusterLoadAssignment.Endpoints[0].LoadBalancingWeight, loadAssignment.Endpoints[0].GetLoadBalancingWeight().GetValue())
		assert.Equal(t, clusterLoadAssignment.Endpoints[0].Priority, loadAssignment.Endpoints[0].Priority)
	})

	t.Run("test4: mult LbEndPoints", func(t *testing.T) {
		loadAssignment := &config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "ut-cluster",
			Endpoints: []*config_endpoint_v3.LocalityLbEndpoints{
				{
					LoadBalancingWeight: wrapperspb.UInt32(30),
					Priority:            uint32(15),
					LbEndpoints: []*config_endpoint_v3.LbEndpoint{
						{
							HealthStatus: v3.HealthStatus_HEALTHY,
							HostIdentifier: &config_endpoint_v3.LbEndpoint_Endpoint{
								Endpoint: &config_endpoint_v3.Endpoint{
									Address: &v3.Address{
										Address: &v3.Address_SocketAddress{
											SocketAddress: &v3.SocketAddress{
												Address: "192.168.127.1",
											},
										},
									},
								},
							},
						},
						{
							HealthStatus: v3.HealthStatus_HEALTHY,
						},
						{
							HealthStatus: v3.HealthStatus_UNHEALTHY,
						},
						{
							HostIdentifier: &config_endpoint_v3.LbEndpoint_Endpoint{
								Endpoint: &config_endpoint_v3.Endpoint{
									Address: &v3.Address{
										Address: &v3.Address_SocketAddress{
											SocketAddress: &v3.SocketAddress{
												Address: "192.168.127.63",
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
		clusterLoadAssignment := newApiClusterLoadAssignment(loadAssignment)
		assert.Equal(t, clusterLoadAssignment.Endpoints[0].LoadBalancingWeight, loadAssignment.Endpoints[0].GetLoadBalancingWeight().GetValue())
		assert.Equal(t, clusterLoadAssignment.Endpoints[0].Priority, loadAssignment.Endpoints[0].Priority)
		address := loadAssignment.Endpoints[0].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress().Address
		ipv4 := nets.ConvertIpToUint32(address)
		actualipv4 := clusterLoadAssignment.Endpoints[0].LbEndpoints[0].GetAddress().GetIpv4()
		assert.Equal(t, ipv4, actualipv4)
		address = loadAssignment.Endpoints[0].LbEndpoints[3].GetEndpoint().GetAddress().GetSocketAddress().Address
		ipv4 = nets.ConvertIpToUint32(address)
		actualipv4 = clusterLoadAssignment.Endpoints[0].LbEndpoints[1].GetAddress().GetIpv4()
		assert.Equal(t, ipv4, actualipv4)
	})

	t.Run("test5: mult EndPoints", func(t *testing.T) {
		loadAssignment := &config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "ut-cluster",
			Endpoints: []*config_endpoint_v3.LocalityLbEndpoints{
				{
					LoadBalancingWeight: wrapperspb.UInt32(30),
					Priority:            uint32(15),
					LbEndpoints: []*config_endpoint_v3.LbEndpoint{
						{
							HealthStatus: v3.HealthStatus_HEALTHY,
							HostIdentifier: &config_endpoint_v3.LbEndpoint_Endpoint{
								Endpoint: &config_endpoint_v3.Endpoint{
									Address: &v3.Address{
										Address: &v3.Address_SocketAddress{
											SocketAddress: &v3.SocketAddress{
												Address: "192.168.127.1",
											},
										},
									},
								},
							},
						},
					},
				},
				{
					LoadBalancingWeight: wrapperspb.UInt32(60),
					Priority:            uint32(30),
					LbEndpoints: []*config_endpoint_v3.LbEndpoint{
						{
							HealthStatus: v3.HealthStatus_HEALTHY,
							HostIdentifier: &config_endpoint_v3.LbEndpoint_Endpoint{
								Endpoint: &config_endpoint_v3.Endpoint{
									Address: &v3.Address{
										Address: &v3.Address_SocketAddress{
											SocketAddress: &v3.SocketAddress{
												Address: "192.168.127.63",
											},
										},
									},
								},
							},
						},
					},
				},
				{
					LoadBalancingWeight: wrapperspb.UInt32(60),
					Priority:            uint32(30),
					LbEndpoints:         []*config_endpoint_v3.LbEndpoint{},
				},
			},
		}
		clusterLoadAssignment := newApiClusterLoadAssignment(loadAssignment)
		assert.Equal(t, clusterLoadAssignment.Endpoints[0].LoadBalancingWeight, loadAssignment.Endpoints[0].GetLoadBalancingWeight().GetValue())
		assert.Equal(t, clusterLoadAssignment.Endpoints[0].Priority, loadAssignment.Endpoints[0].Priority)
		address := loadAssignment.Endpoints[0].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress().Address
		ipv4 := nets.ConvertIpToUint32(address)
		actualipv4 := clusterLoadAssignment.Endpoints[0].LbEndpoints[0].GetAddress().GetIpv4()
		assert.Equal(t, ipv4, actualipv4)

		assert.Equal(t, clusterLoadAssignment.Endpoints[1].LoadBalancingWeight, loadAssignment.Endpoints[1].GetLoadBalancingWeight().GetValue())
		assert.Equal(t, clusterLoadAssignment.Endpoints[1].Priority, loadAssignment.Endpoints[1].Priority)
		address = loadAssignment.Endpoints[1].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress().Address
		ipv4 = nets.ConvertIpToUint32(address)
		actualipv4 = clusterLoadAssignment.Endpoints[1].LbEndpoints[0].GetAddress().GetIpv4()
		assert.Equal(t, ipv4, actualipv4)
	})
}

func TestNewApiSocketAddress(t *testing.T) {
	t.Run("test1: normal function test", func(t *testing.T) {
		addr := &v3.Address{
			Address: &v3.Address_SocketAddress{
				SocketAddress: &v3.SocketAddress{
					Address:  "192.168.127.63",
					Protocol: v3.SocketAddress_TCP,
					PortSpecifier: &v3.SocketAddress_PortValue{
						PortValue: uint32(9898),
					},
				},
			},
		}
		kmeshSocketAddr := newApiSocketAddress(addr)
		port := nets.ConvertPortToBigEndian(addr.GetSocketAddress().GetPortValue())
		assert.Equal(t, port, kmeshSocketAddr.Port)
		address := addr.GetSocketAddress().Address
		ipv4 := nets.ConvertIpToUint32(address)
		assert.Equal(t, ipv4, kmeshSocketAddr.Ipv4)
	})
	t.Run("test2: protocol is UDP", func(t *testing.T) {
		addr := &v3.Address{
			Address: &v3.Address_SocketAddress{
				SocketAddress: &v3.SocketAddress{
					Address:  "192.168.127.63",
					Protocol: v3.SocketAddress_UDP,
					PortSpecifier: &v3.SocketAddress_PortValue{
						PortValue: uint32(9898),
					},
				},
			},
		}
		kmeshSocketAddr := newApiSocketAddress(addr)
		assert.Nil(t, kmeshSocketAddr)
	})

	t.Run("test4: address is address pipe", func(t *testing.T) {
		addr := &v3.Address{
			Address: &v3.Address_Pipe{
				Pipe: &v3.Pipe{
					Path: "/run/grpc.sock",
				},
			},
		}
		kmeshSocketAddr := newApiSocketAddress(addr)
		assert.Nil(t, kmeshSocketAddr)
	})
}

func TestCreateApiListenerByLds(t *testing.T) {
	t.Run("listener filter configtype is filter_typedconfig", func(t *testing.T) {
		loader := NewAdsCache()
		loader.routeNames = []string{
			"ut-route",
		}
		status := core_v2.ApiStatus_UPDATE
		typedConfig := &filters_network_tcp.TcpProxy{
			StatPrefix: "ut-test",
			MaxConnectAttempts: &wrapperspb.UInt32Value{
				Value: uint32(3),
			},
			ClusterSpecifier: &filters_network_tcp.TcpProxy_Cluster{
				Cluster: "ut-cluster",
			},
		}
		anyTypedConfig, err := anypb.New(typedConfig)
		assert.NoError(t, err)
		listener := &config_listener_v3.Listener{
			Name: "ut-listener",
			Address: &v3.Address{
				Address: &v3.Address_SocketAddress{
					SocketAddress: &v3.SocketAddress{
						Address:  "127.0.0.1",
						Protocol: v3.SocketAddress_TCP,
					},
				},
			},
			FilterChains: []*config_listener_v3.FilterChain{
				{
					Name:             "ut-filterchain",
					FilterChainMatch: &config_listener_v3.FilterChainMatch{},
					Filters: []*config_listener_v3.Filter{
						{
							Name: pkg_wellknown.TCPProxy,
							ConfigType: &config_listener_v3.Filter_TypedConfig{
								TypedConfig: anyTypedConfig,
							},
						},
					},
				},
			},
		}
		loader.CreateApiListenerByLds(status, listener)
		apiListener := loader.ListenerCache.GetApiListener(listener.GetName())
		assert.Equal(t, apiListener.ApiStatus, status)
		apiConfigType := apiListener.FilterChains[0].Filters[0].ConfigType
		configType := &listener_v2.Filter_TcpProxy{
			TcpProxy: newFilterTcpProxy(typedConfig),
		}
		assert.Equal(t, configType, apiConfigType)
		assert.Equal(t, []string{"ut-route"}, loader.routeNames)
	})

	t.Run("listener filter configtype is filter_ConfigDiscover", func(t *testing.T) {
		loader := NewAdsCache()
		loader.routeNames = []string{
			"ut-route",
		}
		status := core_v2.ApiStatus_UPDATE
		typedConfig := &filters_network_tcp.TcpProxy{
			StatPrefix: "ut-test",
			MaxConnectAttempts: &wrapperspb.UInt32Value{
				Value: uint32(3),
			},
			ClusterSpecifier: &filters_network_tcp.TcpProxy_Cluster{
				Cluster: "ut-cluster",
			},
		}
		anyTypedConfig, err := anypb.New(typedConfig)
		assert.NoError(t, err)
		listener := &config_listener_v3.Listener{
			Name: "ut-listener",
			Address: &v3.Address{
				Address: &v3.Address_SocketAddress{
					SocketAddress: &v3.SocketAddress{
						Address:  "127.0.0.1",
						Protocol: v3.SocketAddress_TCP,
					},
				},
			},
			FilterChains: []*config_listener_v3.FilterChain{
				{
					Name:             "ut-filterchain",
					FilterChainMatch: &config_listener_v3.FilterChainMatch{},
					Filters: []*config_listener_v3.Filter{
						{
							Name: pkg_wellknown.TCPProxy,
							ConfigType: &config_listener_v3.Filter_ConfigDiscovery{
								ConfigDiscovery: &v3.ExtensionConfigSource{
									DefaultConfig: anyTypedConfig,
								},
							},
						},
					},
				},
			},
		}
		loader.CreateApiListenerByLds(status, listener)
		apiListener := loader.ListenerCache.GetApiListener(listener.GetName())
		assert.Equal(t, apiListener.ApiStatus, status)
		filterChain := apiListener.FilterChains[0].Filters
		assert.Nil(t, filterChain)
		assert.Equal(t, []string{"ut-route"}, loader.routeNames)
	})

	t.Run("status is UNCHANGED", func(t *testing.T) {
		loader := NewAdsCache()
		loader.routeNames = []string{
			"ut-route",
		}
		status := core_v2.ApiStatus_UNCHANGED
		typedConfig := &filters_network_tcp.TcpProxy{
			StatPrefix: "ut-test",
			MaxConnectAttempts: &wrapperspb.UInt32Value{
				Value: uint32(3),
			},
			ClusterSpecifier: &filters_network_tcp.TcpProxy_Cluster{
				Cluster: "ut-cluster",
			},
		}
		anyTypedConfig, err := anypb.New(typedConfig)
		assert.NoError(t, err)
		listener := &config_listener_v3.Listener{
			Name: "ut-listener",
			Address: &v3.Address{
				Address: &v3.Address_SocketAddress{
					SocketAddress: &v3.SocketAddress{
						Address:  "127.0.0.1",
						Protocol: v3.SocketAddress_TCP,
					},
				},
			},
			FilterChains: []*config_listener_v3.FilterChain{
				{
					Name:             "ut-filterchain",
					FilterChainMatch: &config_listener_v3.FilterChainMatch{},
					Filters: []*config_listener_v3.Filter{
						{
							Name: pkg_wellknown.TCPProxy,
							ConfigType: &config_listener_v3.Filter_TypedConfig{
								TypedConfig: anyTypedConfig,
							},
						},
					},
				},
			},
		}
		loader.CreateApiListenerByLds(status, listener)
		apiListener := loader.ListenerCache.GetApiListener(listener.GetName())
		assert.Nil(t, apiListener)
		assert.Equal(t, []string{"ut-route"}, loader.routeNames)
	})

	t.Run("status is UNCHANGED, filterName is pkg_wellknown.HTTPConnectionManager", func(t *testing.T) {
		loader := NewAdsCache()
		loader.routeNames = []string{
			"ut-route",
		}
		status := core_v2.ApiStatus_UNCHANGED
		typedConfig := &filters_network_http.HttpConnectionManager{
			StatPrefix: "ut-test",
			RouteSpecifier: &filters_network_http.HttpConnectionManager_Rds{
				Rds: &filters_network_http.Rds{
					RouteConfigName: "new-ut-route",
				},
			},
		}
		anyTypedConfig, err := anypb.New(typedConfig)
		assert.NoError(t, err)
		listener := &config_listener_v3.Listener{
			Name: "ut-listener",
			Address: &v3.Address{
				Address: &v3.Address_SocketAddress{
					SocketAddress: &v3.SocketAddress{
						Address:  "127.0.0.1",
						Protocol: v3.SocketAddress_TCP,
					},
				},
			},
			FilterChains: []*config_listener_v3.FilterChain{
				{
					Name:             "ut-filterchain",
					FilterChainMatch: &config_listener_v3.FilterChainMatch{},
					Filters: []*config_listener_v3.Filter{
						{
							Name: pkg_wellknown.HTTPConnectionManager,
							ConfigType: &config_listener_v3.Filter_TypedConfig{
								TypedConfig: anyTypedConfig,
							},
						},
					},
				},
			},
		}
		loader.CreateApiListenerByLds(status, listener)
		apiListener := loader.ListenerCache.GetApiListener(listener.GetName())
		assert.Nil(t, apiListener)
		assert.Equal(t, []string{"ut-route", "new-ut-route"}, loader.routeNames)
	})
}
