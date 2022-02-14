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
	configCoreV3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	configEndpointV3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	configListenerV3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	filtersNetworkHttp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	filtersNetworkTcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	serviceDiscoveryV3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	pkgWellknown "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"openeuler.io/mesh/pkg/cache/v1"
	"openeuler.io/mesh/pkg/cache/v1/types"
	"openeuler.io/mesh/pkg/nets"
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

func extractEndpointCache(loadCache clusterLoadCache, flag cache_v1.CacheOptionFlag, lbAssignment *configEndpointV3.ClusterLoadAssignment) {
	var kv cache_v1.EndpointKeyAndValue

	if lbAssignment == nil {
		return
	}
	clusterName := lbAssignment.GetClusterName()
	kv.Key.NameID = convert.StrToNum(clusterName)

	for _, localityLb := range lbAssignment.GetEndpoints() {
		for _, lb := range localityLb.GetLbEndpoints() {
			addr := getSocketAddress(lb.GetEndpoint().GetAddress())
			if addr == nil {
				continue
			}

			kv.Value.Address.Protocol = types.ProtocolStrToC[addr.GetProtocol().String()]
			kv.Value.Address.IPv4 = nets.ConvertIpToUint32(addr.GetAddress())
			kv.Value.Address.Port = nets.ConvertPortToLittleEndian(addr.GetPortValue())

			kv.Key.Port = 0 // cluster port

			load := loadCache.getClusterLoad(clusterName)
			load.endpoint[kv] |= flag
		}
	}
}

func setEndpointCacheClusterPort(cache cache_v1.EndpointCache, name string, port uint32) {
	nameID := convert.StrToNum(name)
	for kv, flag := range cache {
		if kv.Key.NameID == nameID {
			kv.Key.Port = nets.ConvertPortToLittleEndian(port)
			cache[kv] = flag
		}
	}
}

func extractClusterCache(loadCache clusterLoadCache, flag cache_v1.CacheOptionFlag, listener *configListenerV3.Listener) {
	var kv cache_v1.ClusterKeyAndValue

	if listener == nil {
		return
	}

	clusterName := getFilterChainClusterName(listener.GetFilterChains())
	if clusterName == "" {
		return
	} else {
		kv.Key.NameID = convert.StrToNum(clusterName)
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

func extractListenerCache(cache cache_v1.ListenerCache, flag cache_v1.CacheOptionFlag, listener *configListenerV3.Listener) {
	var kv cache_v1.ListenerKeyAndValue

	if listener == nil {
		return
	}

	clusterName := getFilterChainClusterName(listener.GetFilterChains())
	if clusterName == "" {
		return
	} else {
		// TODO: should be calculated at bpf
		kv.Value.MapKey.NameID = convert.StrToNum(clusterName)
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

func extractRouteCache(cache cache_v1.ListenerCache, flag cache_v1.CacheOptionFlag, rsp *serviceDiscoveryV3.DiscoveryResponse) {
	return
}

func getSocketAddress(address *configCoreV3.Address) *configCoreV3.SocketAddress {
	var addr *configCoreV3.SocketAddress

	switch address.GetAddress().(type) {
	case *configCoreV3.Address_SocketAddress:
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
func getFilterChainClusterName(filterChains []*configListenerV3.FilterChain) string {
	var err error

	if filterChains == nil {
		return ""
	}

	for _, chain := range filterChains {
		for _, filter := range chain.GetFilters() {
			switch filter.GetConfigType().(type) {
			case *configListenerV3.Filter_TypedConfig:
				switch filter.GetName() {
				case pkgWellknown.TCPProxy:
					cfgTcp := &filtersNetworkTcp.TcpProxy{}
					if err = anypb.UnmarshalTo(filter.GetTypedConfig(), cfgTcp, proto.UnmarshalOptions{}); err != nil {
						continue
					}
					return cfgTcp.GetCluster()
				case pkgWellknown.HTTPConnectionManager:
					cfgHttp := &filtersNetworkHttp.HttpConnectionManager{}
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
			case *configListenerV3.Filter_ConfigDiscovery:
				continue
			default:
			}
		}
	}

	return ""
}