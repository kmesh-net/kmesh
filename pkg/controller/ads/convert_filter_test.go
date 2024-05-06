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
	"testing"

	envoy_filters_tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"

	"kmesh.net/kmesh/api/v2/filter"
)

func TestNewFilterTcpProxy(t *testing.T) {
	t.Run("ClusterSpecifier is Cluster", func(t *testing.T) {
		envoyTcpProxy := &envoy_filters_tcp_proxy.TcpProxy{
			StatPrefix: "ut-test",
			MaxConnectAttempts: &wrappers.UInt32Value{
				Value: uint32(3),
			},
			ClusterSpecifier: &envoy_filters_tcp_proxy.TcpProxy_Cluster{
				Cluster: "ut-cluster",
			},
		}
		tcpProxy := newFilterTcpProxy(envoyTcpProxy)
		require.NotNil(t, tcpProxy)
		assert.Equal(t, tcpProxy.GetCluster(), "ut-cluster")
	})
	t.Run("ClusterSpecifier is WeightedClusters", func(t *testing.T) {
		weightedClusters := []*envoy_filters_tcp_proxy.TcpProxy_WeightedCluster_ClusterWeight{
			{
				Name:   "ut-bar",
				Weight: 1,
			},
			{
				Name:   "ut-baz",
				Weight: 3,
			},
		}
		envoyTcpProxy := &envoy_filters_tcp_proxy.TcpProxy{
			StatPrefix: "ut-test",
			MaxConnectAttempts: &wrappers.UInt32Value{
				Value: uint32(3),
			},
			ClusterSpecifier: &envoy_filters_tcp_proxy.TcpProxy_WeightedClusters{
				WeightedClusters: &envoy_filters_tcp_proxy.TcpProxy_WeightedCluster{
					Clusters: weightedClusters,
				},
			},
		}
		tcpProxy := newFilterTcpProxy(envoyTcpProxy)
		require.NotNil(t, tcpProxy)
		weightedClustersSpecifier, ok := tcpProxy.ClusterSpecifier.(*filter.TcpProxy_WeightedClusters)
		require.True(t, ok)
		assert.Equal(t, "ut-bar", weightedClustersSpecifier.WeightedClusters.Clusters[0].Name)
		assert.Equal(t, uint32(1), weightedClustersSpecifier.WeightedClusters.Clusters[0].Weight)
		assert.Equal(t, "ut-baz", weightedClustersSpecifier.WeightedClusters.Clusters[1].Name)
		assert.Equal(t, uint32(3), weightedClustersSpecifier.WeightedClusters.Clusters[1].Weight)
	})
}
