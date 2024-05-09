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
	envoy_filters_tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"

	"kmesh.net/kmesh/api/v2/filter"
)

func newFilterTcpProxy(envoyTcpProxy *envoy_filters_tcp_proxy.TcpProxy) *filter.TcpProxy {
	tcpProxy := &filter.TcpProxy{
		StatPrefix:         envoyTcpProxy.GetStatPrefix(),
		ClusterSpecifier:   nil,
		MaxConnectAttempts: envoyTcpProxy.GetMaxConnectAttempts().GetValue(),
	}

	switch envoyTcpProxy.ClusterSpecifier.(type) {
	case *envoy_filters_tcp_proxy.TcpProxy_Cluster:
		tcpProxy.ClusterSpecifier = &filter.TcpProxy_Cluster{
			Cluster: envoyTcpProxy.GetCluster(),
		}
	case *envoy_filters_tcp_proxy.TcpProxy_WeightedClusters:
		var weightedClusters []*filter.TcpProxy_WeightedCluster_ClusterWeight
		for _, cluster := range envoyTcpProxy.GetWeightedClusters().GetClusters() {
			weightedClusters = append(weightedClusters, &filter.TcpProxy_WeightedCluster_ClusterWeight{
				Name:   cluster.GetName(),
				Weight: cluster.GetWeight(),
			})
		}
		tcpProxy.ClusterSpecifier = &filter.TcpProxy_WeightedClusters{
			WeightedClusters: &filter.TcpProxy_WeightedCluster{
				Clusters: weightedClusters,
			},
		}
	}
	return tcpProxy
}
