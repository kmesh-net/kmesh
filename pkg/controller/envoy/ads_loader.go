/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2022-01-24
 */

package envoy

import (
	config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	filters_network_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	filters_network_tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	pkg_wellknown "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	cluster_v2 "openeuler.io/mesh/api/v2/cluster"
	core_v2 "openeuler.io/mesh/api/v2/core"
	endpoint_v2 "openeuler.io/mesh/api/v2/endpoint"
	filter_v2 "openeuler.io/mesh/api/v2/filter"
	listener_v2 "openeuler.io/mesh/api/v2/listener"
	route_v2 "openeuler.io/mesh/api/v2/route"
	cache_v2 "openeuler.io/mesh/pkg/cache/v2"
	"openeuler.io/mesh/pkg/nets"
)

type adsLoader struct {
	// subscribe to EDS by cluster Name
	clusterNames []string
	// subscribe to RDS by RouteConfiguration Name
	routeNames []string

	listenerCache cache_v2.ApiListenerCache
	clusterCache  cache_v2.ApiClusterCache
	routeCache    cache_v2.ApiRouteConfigurationCache
}

func newAdsLoader() *adsLoader {
	return &adsLoader{
		listenerCache: cache_v2.NewApiListenerCache(),
		clusterCache:  cache_v2.NewApiClusterCache(),
		routeCache:    cache_v2.NewApiRouteConfigurationCache(),
	}
}

func (load *adsLoader) createApiClusterByCds(status core_v2.ApiStatus, cluster *config_cluster_v3.Cluster) {
	apiCluster := &cluster_v2.Cluster{
		ApiStatus: status,
		Name: cluster.GetName(),
		ConnectTimeout: uint32(cluster.GetConnectTimeout().GetSeconds()),
		LbPolicy: cluster_v2.Cluster_LbPolicy(cluster.GetLbPolicy()),
		CircuitBreakers: newApiCircuitBreakers(cluster.GetCircuitBreakers()),
	}

	if cluster.GetType() == config_cluster_v3.Cluster_EDS {
		load.clusterNames = append(load.clusterNames, cluster.GetName())
	} else {
		apiCluster.LoadAssignment = newApiClusterLoadAssignment(cluster.GetLoadAssignment())
	}

	load.clusterCache[cluster.GetName()] = apiCluster
}

func (load *adsLoader) createApiClusterByEds(status core_v2.ApiStatus, loadAssignment *config_endpoint_v3.ClusterLoadAssignment) {
	apiCluster := load.clusterCache[loadAssignment.GetClusterName()]
	if apiCluster == nil {
		return
	}

	apiCluster.LoadAssignment = newApiClusterLoadAssignment(loadAssignment)
}

func newApiClusterLoadAssignment(loadAssignment *config_endpoint_v3.ClusterLoadAssignment) *endpoint_v2.ClusterLoadAssignment {
	apiLoadAssignment := &endpoint_v2.ClusterLoadAssignment{
		ClusterName: loadAssignment.GetClusterName(),
	}

	for _, localityLb := range loadAssignment.GetEndpoints() {
		apiLocalityLb := &endpoint_v2.LocalityLbEndpoints{
			LoadBalancingWeight: localityLb.GetLoadBalancingWeight().GetValue(),
			Priority: localityLb.GetPriority(),
			LbEndpoints: nil,
		}

		for _, endpoint := range localityLb.GetLbEndpoints() {
			apiEndpoint := &endpoint_v2.Endpoint{
				Address: newApiSocketAddress(endpoint.GetEndpoint().GetAddress()),
			}
			if apiEndpoint.GetAddress() == nil {
				continue
			}
			apiLocalityLb.LbEndpoints = append(apiLocalityLb.LbEndpoints, apiEndpoint)
		}

		apiLoadAssignment.Endpoints = append(apiLoadAssignment.Endpoints, apiLocalityLb)
	}

	return apiLoadAssignment
}

func newApiSocketAddress(address *config_core_v3.Address) *core_v2.SocketAddress {
	var addr *config_core_v3.SocketAddress

	switch address.GetAddress().(type) {
	case *config_core_v3.Address_SocketAddress:
		addr = address.GetSocketAddress()
	default:
		return nil
	}

	if !nets.GetConfig().IsEnabledProtocol(addr.GetProtocol().String()) {
		return nil
	}

	return &core_v2.SocketAddress{
		//Protocol: core_v2.SocketAddress_Protocol(addr.GetProtocol()),
		Port: nets.ConvertPortToLittleEndian(addr.GetPortValue()),
		Ipv4: nets.ConvertIpToUint32(addr.GetAddress()),
	}
}

func newApiCircuitBreakers(cb *config_cluster_v3.CircuitBreakers) *cluster_v2.CircuitBreakers {
	if cb == nil {
		return nil
	}

	thresholds := cb.GetThresholds()
	if len(thresholds) == 0 {
		return nil
	}

	return &cluster_v2.CircuitBreakers{
		Priority: core_v2.RoutingPriority(thresholds[0].GetPriority()),
		MaxConnections: thresholds[0].GetMaxConnections().GetValue(),
		MaxConnectionPools: thresholds[0].GetMaxConnectionPools().GetValue(),
		MaxRequests: thresholds[0].GetMaxRequests().GetValue(),
		MaxPendingRequests: thresholds[0].GetMaxPendingRequests().GetValue(),
		MaxRetries: thresholds[0].GetMaxRetries().GetValue(),
	}
}

func (load *adsLoader) createApiListenerByLds(status core_v2.ApiStatus, listener *config_listener_v3.Listener) {
	apiListener := &listener_v2.Listener{
		ApiStatus: status,
		Name: listener.GetName(),
		Address: newApiSocketAddress(listener.GetAddress()),
	}

	for _, filterChain := range listener.GetFilterChains() {
		apiFilterChain := &listener_v2.FilterChain{
			Name: filterChain.GetName(),
			FilterChainMatch: newApiFilterChainMatch(filterChain.GetFilterChainMatch()),
			Filters: nil,
		}

		for _, filter := range filterChain.GetFilters() {
			apiFilter, routeName := newApiFilterAndRouteName(filter)
			if apiFilter != nil {
				apiFilterChain.Filters = append(apiFilterChain.Filters, apiFilter)
			}
			if routeName != "" {
				load.routeNames = append(load.routeNames, routeName)
			}
		}

		apiListener.FilterChains = append(apiListener.FilterChains, apiFilterChain)
	}

	load.listenerCache[apiListener.GetName()] = apiListener
}

func newApiFilterChainMatch(match *config_listener_v3.FilterChainMatch) *listener_v2.FilterChainMatch {
	apiMatch := &listener_v2.FilterChainMatch{
		DestinationPort: match.GetDestinationPort().GetValue(),
		ApplicationProtocols: match.GetApplicationProtocols(),
	}

	// TODO
	apiMatch.PrefixRanges = nil
	return apiMatch
}

func newApiFilterAndRouteName(filter *config_listener_v3.Filter) (*listener_v2.Filter, string) {
	var err error
	var routeName string
	apiFilter := &listener_v2.Filter{
		Name: filter.GetName(),
	}

	switch filter.GetConfigType().(type) {
	case *config_listener_v3.Filter_TypedConfig:
		switch filter.GetName() {
		case pkg_wellknown.TCPProxy:
			filterTcp := &filters_network_tcp.TcpProxy{}
			if err = anypb.UnmarshalTo(filter.GetTypedConfig(), filterTcp, proto.UnmarshalOptions{}); err != nil {
				return nil, ""
			}

			apiFilter.ConfigType = &listener_v2.Filter_TcpProxy{
				TcpProxy: &filter_v2.TcpProxy{
					Cluster: filterTcp.GetCluster(),
				},
			}
		case pkg_wellknown.HTTPConnectionManager:
			var apiFilterHttp listener_v2.Filter_HttpConnectionManager
			filterHttp := &filters_network_http.HttpConnectionManager{}
			if err = anypb.UnmarshalTo(filter.GetTypedConfig(), filterHttp, proto.UnmarshalOptions{}); err != nil {
				return nil, ""
			}

			// RouteConfiguration
			if filterHttp.GetRouteConfig() != nil {
				apiFilterHttp.HttpConnectionManager = &filter_v2.HttpConnectionManager{
					RouteSpecifier: &filter_v2.HttpConnectionManager_RouteConfig{
						RouteConfig: newApiRouteConfiguration(filterHttp.GetRouteConfig()),
					},
				}
			} else if filterHttp.GetRds() != nil {
				routeName = filterHttp.GetRds().GetRouteConfigName()
				apiFilterHttp.HttpConnectionManager = &filter_v2.HttpConnectionManager{
					RouteSpecifier: &filter_v2.HttpConnectionManager_RouteConfigName{
						RouteConfigName: routeName,
					},
				}
			}
			apiFilter.ConfigType = &apiFilterHttp
		default:
		}
	case *config_listener_v3.Filter_ConfigDiscovery:
	default:
	}

	if apiFilter.ConfigType == nil {
		return nil, ""
	}
	return apiFilter, routeName
}

func (load *adsLoader) createApiRouteByRds(status core_v2.ApiStatus, routeConfig *config_route_v3.RouteConfiguration) {
	apiRouteConfig := newApiRouteConfiguration(routeConfig)
	apiRouteConfig.ApiStatus = status
	load.routeCache[apiRouteConfig.GetName()] = apiRouteConfig
}

func newApiRouteConfiguration(routeConfig *config_route_v3.RouteConfiguration) *route_v2.RouteConfiguration {
	apiRouteConfig := &route_v2.RouteConfiguration{
		Name: routeConfig.GetName(),
		VirtualHosts: nil,
	}

	for _, host := range routeConfig.GetVirtualHosts() {
		apiHost := &route_v2.VirtualHost{
			Name: host.GetName(),
			Domains: host.GetDomains(),
			Routes: nil,
		}

		for _, route := range host.GetRoutes() {
			apiRoute := newApiRoute(route)
			if apiRoute == nil {
				continue
			}
			apiHost.Routes = append(apiHost.Routes, apiRoute)
		}
		apiRouteConfig.VirtualHosts = append(apiRouteConfig.VirtualHosts, apiHost)
	}

	return apiRouteConfig
}

func newApiRoute(route *config_route_v3.Route) *route_v2.Route {
	apiRoute := &route_v2.Route{
		Name: route.GetName(),
		Match: &route_v2.RouteMatch{
			Prefix: route.GetMatch().GetPrefix(),
		},
	}

	switch route.GetAction().(type) {
	case *config_route_v3.Route_Route:
		action := route.GetRoute()
		apiRoute.Route = &route_v2.RouteAction{
			Cluster: action.GetCluster(),
			Timeout: uint32(action.GetTimeout().GetSeconds()),
			RetryPolicy: &route_v2.RetryPolicy{
				NumRetries: action.GetRetryPolicy().GetNumRetries().GetValue(),
			},
		}
	case *config_route_v3.Route_FilterAction:
	case *config_route_v3.Route_Redirect:
	default:
	}

	if apiRoute.Route == nil {
		return nil
	}
	return apiRoute
}
