/*
 * Copyright 2023 The Kmesh Authors.
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
	config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	filters_network_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	filters_network_tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	pkg_wellknown "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	endpoint_v2 "kmesh.net/kmesh/api/v2/endpoint"
	filter_v2 "kmesh.net/kmesh/api/v2/filter"
	listener_v2 "kmesh.net/kmesh/api/v2/listener"
	route_v2 "kmesh.net/kmesh/api/v2/route"
	cache_v2 "kmesh.net/kmesh/pkg/cache/v2"
	"kmesh.net/kmesh/pkg/nets"
)

type AdsCache struct {
	// eds names to be subscribed, which is inferred from cluster
	edsClusterNames []string
	// route names to be subscribed, which is inferred from listener
	routeNames    []string
	ListenerCache cache_v2.ListenerCache
	ClusterCache  cache_v2.ClusterCache
	RouteCache    cache_v2.RouteConfigCache
}

func NewAdsCache() *AdsCache {
	return &AdsCache{
		ListenerCache: cache_v2.NewListenerCache(),
		ClusterCache:  cache_v2.NewClusterCache(),
		RouteCache:    cache_v2.NewRouteConfigCache(),
	}
}

func (load *AdsCache) CreateApiClusterByCds(status core_v2.ApiStatus, cluster *config_cluster_v3.Cluster) {
	apiCluster := &cluster_v2.Cluster{
		ApiStatus:       status,
		Name:            cluster.GetName(),
		ConnectTimeout:  uint32(cluster.GetConnectTimeout().GetSeconds()),
		LbPolicy:        cluster_v2.Cluster_LbPolicy(cluster.GetLbPolicy()),
		CircuitBreakers: newApiCircuitBreakers(cluster.GetCircuitBreakers()),
	}

	if cluster.GetType() != config_cluster_v3.Cluster_EDS {
		apiCluster.LoadAssignment = newApiClusterLoadAssignment(cluster.GetLoadAssignment())
	}
	load.ClusterCache.SetApiCluster(cluster.GetName(), apiCluster)
}

// UpdateApiClusterIfExists only update api cluster if it exists
func (load *AdsCache) UpdateApiClusterIfExists(status core_v2.ApiStatus, cluster *config_cluster_v3.Cluster) bool {
	apiCluster := &cluster_v2.Cluster{
		ApiStatus:       status,
		Name:            cluster.GetName(),
		ConnectTimeout:  uint32(cluster.GetConnectTimeout().GetSeconds()),
		LbPolicy:        cluster_v2.Cluster_LbPolicy(cluster.GetLbPolicy()),
		CircuitBreakers: newApiCircuitBreakers(cluster.GetCircuitBreakers()),
	}
	if cluster.GetType() != config_cluster_v3.Cluster_EDS {
		apiCluster.LoadAssignment = newApiClusterLoadAssignment(cluster.GetLoadAssignment())
	}
	return load.ClusterCache.UpdateApiClusterIfExists(cluster.GetName(), apiCluster)
}

func (load *AdsCache) UpdateApiClusterStatus(key string, status core_v2.ApiStatus) {
	load.ClusterCache.UpdateApiClusterStatus(key, status)
}

func (load *AdsCache) GetApiClusterStatus(key string) core_v2.ApiStatus {
	return load.ClusterCache.GetApiClusterStatus(key)
}

func (load *AdsCache) CreateApiClusterByEds(status core_v2.ApiStatus,
	loadAssignment *config_endpoint_v3.ClusterLoadAssignment,
) {
	apiCluster := load.ClusterCache.GetApiCluster(loadAssignment.GetClusterName())
	if apiCluster == nil {
		return
	}
	apiCluster.ApiStatus = status
	apiCluster.LoadAssignment = newApiClusterLoadAssignment(loadAssignment)
}

func newApiClusterLoadAssignment(
	loadAssignment *config_endpoint_v3.ClusterLoadAssignment,
) *endpoint_v2.ClusterLoadAssignment {
	apiLoadAssignment := &endpoint_v2.ClusterLoadAssignment{
		ClusterName: loadAssignment.GetClusterName(),
	}

	for _, localityLb := range loadAssignment.GetEndpoints() {
		apiLocalityLb := &endpoint_v2.LocalityLbEndpoints{
			LoadBalancingWeight: localityLb.GetLoadBalancingWeight().GetValue(),
			Priority:            localityLb.GetPriority(),
			LbEndpoints:         nil,
		}

		for _, endpoint := range localityLb.GetLbEndpoints() {
			apiEndpoint := &endpoint_v2.Endpoint{
				Address: newApiSocketAddress(endpoint.GetEndpoint().GetAddress()),
			}
			if apiEndpoint.GetAddress() == nil || apiEndpoint.Address.Ipv4 == 0 {
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

	if address == nil {
		return nil
	}

	switch address.GetAddress().(type) {
	case *config_core_v3.Address_SocketAddress:
		addr = address.GetSocketAddress()
	default:
		return nil
	}

	// only support TCP, UDP is not supported yet
	if addr == nil || addr.GetProtocol() != config_core_v3.SocketAddress_TCP {
		log.Debugf("listener addr is nil or protocol is not TCP")
		return nil
	}

	return &core_v2.SocketAddress{
		Protocol: core_v2.SocketAddress_Protocol(addr.GetProtocol()),
		Port:     nets.ConvertPortToBigEndian(addr.GetPortValue()),
		Ipv4:     nets.ConvertIpToUint32(addr.GetAddress()),
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
		Priority:           core_v2.RoutingPriority(thresholds[0].GetPriority()),
		MaxConnections:     thresholds[0].GetMaxConnections().GetValue(),
		MaxConnectionPools: thresholds[0].GetMaxConnectionPools().GetValue(),
		MaxRequests:        thresholds[0].GetMaxRequests().GetValue(),
		MaxPendingRequests: thresholds[0].GetMaxPendingRequests().GetValue(),
		MaxRetries:         thresholds[0].GetMaxRetries().GetValue(),
	}
}

func (load *AdsCache) UpdateApiListenerStatus(key string, status core_v2.ApiStatus) {
	load.ListenerCache.UpdateApiListenerStatus(key, status)
}

func (load *AdsCache) CreateApiListenerByLds(status core_v2.ApiStatus, listener *config_listener_v3.Listener) {
	if listener == nil {
		return
	}

	apiListener := &listener_v2.Listener{
		ApiStatus: status,
		Name:      listener.GetName(),
		Address:   newApiSocketAddress(listener.GetAddress()),
	}

	for _, filterChain := range listener.GetFilterChains() {
		apiFilterChain := &listener_v2.FilterChain{
			Name:             filterChain.GetName(),
			FilterChainMatch: newApiFilterChainMatch(filterChain.GetFilterChainMatch()),
			Filters:          nil,
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

	if status == core_v2.ApiStatus_UNCHANGED {
		return
	}
	load.ListenerCache.SetApiListener(apiListener.GetName(), apiListener)
}

func newApiFilterChainMatch(match *config_listener_v3.FilterChainMatch) *listener_v2.FilterChainMatch {
	if match == nil {
		return &listener_v2.FilterChainMatch{}
	}

	apiMatch := &listener_v2.FilterChainMatch{
		DestinationPort:      match.GetDestinationPort().GetValue(),
		TransportProtocol:    match.GetTransportProtocol(),
		ApplicationProtocols: match.GetApplicationProtocols(),
	}

	for _, prefixRange := range match.GetPrefixRanges() {
		apiMatch.PrefixRanges = append(apiMatch.PrefixRanges, &core_v2.CidrRange{
			AddressPrefix: prefixRange.GetAddressPrefix(),
			PrefixLen:     prefixRange.GetPrefixLen().GetValue(),
		})
	}

	return apiMatch
}

func newApiFilterAndRouteName(filter *config_listener_v3.Filter) (*listener_v2.Filter, string) {
	var err error
	var routeName string

	if filter == nil {
		return nil, ""
	}

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
				TcpProxy: newFilterTcpProxy(filterTcp),
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

func (load *AdsCache) CreateApiRouteByRds(status core_v2.ApiStatus, routeConfig *config_route_v3.RouteConfiguration) {
	apiRouteConfig := newApiRouteConfiguration(routeConfig)
	apiRouteConfig.ApiStatus = status
	load.RouteCache.SetApiRouteConfig(apiRouteConfig.GetName(), apiRouteConfig)
}

func (load *AdsCache) UpateApiRouteStatus(key string, status core_v2.ApiStatus) {
	load.RouteCache.UpdateApiRouteStatus(key, status)
}

func newApiRouteConfiguration(routeConfig *config_route_v3.RouteConfiguration) *route_v2.RouteConfiguration {
	if routeConfig == nil {
		return nil
	}
	apiRouteConfig := &route_v2.RouteConfiguration{
		Name:         routeConfig.GetName(),
		VirtualHosts: nil,
	}

	for _, host := range routeConfig.GetVirtualHosts() {
		apiHost := &route_v2.VirtualHost{
			Name:    host.GetName(),
			Domains: host.GetDomains(),
			Routes:  nil,
		}
		// default route is first one without match headers
		// append it to the end
		var defaultRoute *route_v2.Route = nil
		for _, route := range host.GetRoutes() {
			apiRoute := newApiRoute(route)
			if apiRoute == nil {
				continue
			}
			if apiRoute.Match.Headers == nil && defaultRoute == nil {
				defaultRoute = apiRoute
			} else {
				apiHost.Routes = append(apiHost.Routes, apiRoute)
			}
		}
		apiHost.Routes = append(apiHost.Routes, defaultRoute)

		apiRouteConfig.VirtualHosts = append(apiRouteConfig.VirtualHosts, apiHost)
	}

	return apiRouteConfig
}

func newApiRoute(route *config_route_v3.Route) *route_v2.Route {
	if route == nil {
		return nil
	}

	apiRoute := &route_v2.Route{
		Name:  route.GetName(),
		Match: newApiRouteMatch(route.GetMatch()),
	}

	switch route.GetAction().(type) {
	case *config_route_v3.Route_Route:
		apiRoute.Route = newApiRouteAction(route.GetRoute())
	case *config_route_v3.Route_FilterAction:
	case *config_route_v3.Route_Redirect:
	default:
		return nil
	}

	return apiRoute
}

func newApiRouteMatch(match *config_route_v3.RouteMatch) *route_v2.RouteMatch {
	var apiHeaders []*route_v2.HeaderMatcher

	if match == nil {
		return &route_v2.RouteMatch{}
	}
	for _, header := range match.GetHeaders() {
		apiHeader := &route_v2.HeaderMatcher{
			Name:                 header.GetName(),
			HeaderMatchSpecifier: nil,
		}

		switch header.GetHeaderMatchSpecifier().(type) {
		case *config_route_v3.HeaderMatcher_PrefixMatch:
			apiHeader.HeaderMatchSpecifier = &route_v2.HeaderMatcher_PrefixMatch{
				// TODO: stop using deprecated field
				PrefixMatch: header.GetPrefixMatch(), // nolint
			}
		case *config_route_v3.HeaderMatcher_ExactMatch:
			apiHeader.HeaderMatchSpecifier = &route_v2.HeaderMatcher_ExactMatch{
				// TODO: stop using deprecated field
				ExactMatch: header.GetExactMatch(), // nolint
			}
		case *config_route_v3.HeaderMatcher_StringMatch:
			parseStringMatch(header, apiHeader)
		default:
			log.Infof("newApiRouteMatch default continue, type is %T", header.GetHeaderMatchSpecifier())
			continue
		}

		apiHeaders = append(apiHeaders, apiHeader)
	}

	return &route_v2.RouteMatch{
		Prefix:        match.GetPrefix(),
		CaseSensitive: match.GetCaseSensitive().GetValue(),
		Headers:       apiHeaders,
	}
}

func parseStringMatch(configHeader *config_route_v3.HeaderMatcher, apiHeader *route_v2.HeaderMatcher) {
	if configHeader == nil {
		return
	}
	switch configHeader.GetStringMatch().GetMatchPattern().(type) {
	case *envoy_type_matcher_v3.StringMatcher_Exact:
		apiHeader.HeaderMatchSpecifier = &route_v2.HeaderMatcher_ExactMatch{
			ExactMatch: configHeader.GetStringMatch().GetExact(),
		}
	case *envoy_type_matcher_v3.StringMatcher_Prefix:
		apiHeader.HeaderMatchSpecifier = &route_v2.HeaderMatcher_PrefixMatch{
			PrefixMatch: configHeader.GetStringMatch().GetPrefix(),
		}
	default:
		log.Infof("unsupport, type is %T", configHeader.GetStringMatch().GetMatchPattern())
	}
}

func newApiRouteAction(action *config_route_v3.RouteAction) *route_v2.RouteAction {
	if action == nil {
		return &route_v2.RouteAction{}
	}
	apiAction := &route_v2.RouteAction{
		ClusterSpecifier: nil,
		Timeout:          uint32(action.GetTimeout().GetSeconds()),
		RetryPolicy: &route_v2.RetryPolicy{
			NumRetries: action.GetRetryPolicy().GetNumRetries().GetValue(),
		},
	}

	switch action.GetClusterSpecifier().(type) {
	case *config_route_v3.RouteAction_Cluster:
		apiAction.ClusterSpecifier = &route_v2.RouteAction_Cluster{
			Cluster: action.GetCluster(),
		}
	case *config_route_v3.RouteAction_WeightedClusters:
		var apiClusters []*route_v2.ClusterWeight
		for _, cluster := range action.GetWeightedClusters().GetClusters() {
			apiClusters = append(apiClusters, &route_v2.ClusterWeight{
				Name:   cluster.GetName(),
				Weight: cluster.GetWeight().GetValue(),
			})
			log.Debugf("cluster name:%v, weighet:%v", cluster.GetName(), cluster.GetWeight().GetValue())
		}

		apiAction.ClusterSpecifier = &route_v2.RouteAction_WeightedClusters{
			WeightedClusters: &route_v2.WeightedCluster{
				Clusters: apiClusters,
			},
		}
	default:
		log.Errorf("newApiRouteAction default, type is %T", action.GetClusterSpecifier())
		return nil
	}

	return apiAction
}
