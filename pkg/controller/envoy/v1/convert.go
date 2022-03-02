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

import "C"
import (
	config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	filters_network_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	filters_network_tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	pkg_wellknown "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	api_v1 "openeuler.io/mesh/api/v1"
	cache_v1 "openeuler.io/mesh/pkg/cache/v1"
	"openeuler.io/mesh/pkg/nets"
)

var (
	hashName = cache_v1.NewHashName()
)

type clusterLoad struct {
	cluster        cache_v1.ClusterCache
	clusterCount   cache_v1.CacheCount

	endpoint       cache_v1.EndpointCache
	endpointsCount cache_v1.CacheCount
	endpointsAddressToMapKey cache_v1.AddressToMapKey
}
// k = clusterName
type clusterLoadCache map[string]*clusterLoad

func (lc clusterLoadCache) getClusterLoad(name string) *clusterLoad {
	var load *clusterLoad

	if load = lc[name]; load == nil {
		load = newClusterLoad()
		lc[name] = load
	}
	return load
}

func newClusterLoad() *clusterLoad {
	return &clusterLoad{
		cluster:        make(cache_v1.ClusterCache),
		clusterCount:   make(cache_v1.CacheCount),
		endpoint:       make(cache_v1.EndpointCache),
		endpointsCount: make(cache_v1.CacheCount),
		endpointsAddressToMapKey: make(cache_v1.AddressToMapKey),
	}
}

func extractEndpointCache(loadCache clusterLoadCache, flag cache_v1.CacheOptionFlag, lbAssignment *config_endpoint_v3.ClusterLoadAssignment) {
	var kv cache_v1.EndpointKeyAndValue

	if lbAssignment == nil {
		return
	}
	clusterName := lbAssignment.GetClusterName()
	kv.Key.NameID = hashName.StrToNum(clusterName)

	for _, localityLb := range lbAssignment.GetEndpoints() {
		for _, lb := range localityLb.GetLbEndpoints() {
			addr := getSocketAddress(lb.GetEndpoint().GetAddress())
			if addr == nil {
				continue
			}

			kv.Value.Address.Protocol = api_v1.ProtocolStrToC[addr.GetProtocol().String()]
			kv.Value.Address.IPv4 = nets.ConvertIpToUint32(addr.GetAddress())
			kv.Value.Address.Port = nets.ConvertPortToLittleEndian(addr.GetPortValue())

			kv.Key.Port = 0 // cluster port

			load := loadCache.getClusterLoad(clusterName)
			load.endpoint[kv] |= flag
		}
	}
}

func setEndpointCacheClusterPort(cache cache_v1.EndpointCache, name string, port uint32) {
	nameID := hashName.StrToNum(name)
	for kv, flag := range cache {
		if kv.Key.NameID == nameID {
			kv.Key.Port = nets.ConvertPortToLittleEndian(port)
			cache[kv] = flag
		}
	}
}

func extractClusterCache(loadCache clusterLoadCache, flag cache_v1.CacheOptionFlag, listener *config_listener_v3.Listener) {
	var kv cache_v1.ClusterKeyAndValue

	if listener == nil {
		return
	}

	clusterName := getFilterChainClusterName(listener.GetFilterChains())
	if clusterName == "" {
		return
	} else {
		kv.Key.NameID = hashName.StrToNum(clusterName)
		kv.Value.LoadAssignment.MapKeyOfEndpoint.NameID = kv.Key.NameID
	}

	{
		addr := getSocketAddress(listener.GetAddress())
		if addr == nil {
			return
		}

		kv.Value.LoadAssignment.MapKeyOfEndpoint.Port = nets.ConvertPortToLittleEndian(addr.GetPortValue())
		kv.Key.Port = nets.ConvertPortToLittleEndian(addr.GetPortValue())

		load := loadCache.getClusterLoad(clusterName)
		load.cluster[kv] |= flag
		setEndpointCacheClusterPort(load.endpoint, clusterName, addr.GetPortValue())
	}
}

func extractListenerCache(cache cache_v1.ListenerCache, flag cache_v1.CacheOptionFlag, listener *config_listener_v3.Listener) {
	var kv cache_v1.ListenerKeyAndValue

	if listener == nil {
		return
	}

	clusterName := getFilterChainClusterName(listener.GetFilterChains())
	if clusterName == "" {
		return
	} else {
		// TODO: should be calculated at bpf
		kv.Value.MapKey.NameID = hashName.StrToNum(clusterName)
	}

	{
		addr := getSocketAddress(listener.GetAddress())
		if addr == nil {
			return
		}

		kv.Value.MapKey.Port = nets.ConvertPortToLittleEndian(addr.GetPortValue())
		kv.Key.Port = nets.ConvertPortToLittleEndian(addr.GetPortValue())
		kv.Key.IPv4 = nets.ConvertIpToUint32(addr.GetAddress())

		kv.Value.Address = kv.Key
		cache[kv] |= flag
	}
}

func extractRouteCache(cache cache_v1.ListenerCache, flag cache_v1.CacheOptionFlag, rsp *service_discovery_v3.DiscoveryResponse) {
	return
}

func getSocketAddress(address *config_core_v3.Address) *config_core_v3.SocketAddress {
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

	return addr
}

// TODO: extract filter
func getFilterChainClusterName(filterChains []*config_listener_v3.FilterChain) string {
	var err error

	if filterChains == nil {
		return ""
	}

	for _, chain := range filterChains {
		for _, filter := range chain.GetFilters() {
			switch filter.GetConfigType().(type) {
			case *config_listener_v3.Filter_TypedConfig:
				switch filter.GetName() {
				case pkg_wellknown.TCPProxy:
					cfgTcp := &filters_network_tcp.TcpProxy{}
					if err = anypb.UnmarshalTo(filter.GetTypedConfig(), cfgTcp, proto.UnmarshalOptions{}); err != nil {
						continue
					}
					return cfgTcp.GetCluster()
				case pkg_wellknown.HTTPConnectionManager:
					cfgHttp := &filters_network_http.HttpConnectionManager{}
					if err = anypb.UnmarshalTo(filter.GetTypedConfig(), cfgHttp, proto.UnmarshalOptions{}); err != nil {
						continue
					}
					if cfgHttp.GetRds() == nil {
						continue
					}
					return cfgHttp.GetRds().GetRouteConfigName()
				default:
					continue
				}
			case *config_listener_v3.Filter_ConfigDiscovery:
				continue
			default:
			}
		}
	}

	return ""
}