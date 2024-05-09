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

package cache_v2

import (
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/slices"
	"k8s.io/apimachinery/pkg/util/rand"

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/api/v2/endpoint"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
	"kmesh.net/kmesh/pkg/nets"
	"kmesh.net/kmesh/pkg/utils/hash"
	"kmesh.net/kmesh/pkg/utils/test"
)

func TestClusterFlush(t *testing.T) {
	t.Run("cluster status is UPDATE", func(t *testing.T) {
		updateClusterName := []string{}
		deleteClusterName := []string{}

		patches1 := gomonkey.NewPatches()
		patches2 := gomonkey.NewPatches()
		patches1.ApplyFunc(maps_v2.ClusterUpdate, func(key string, value *cluster_v2.Cluster) error {
			updateClusterName = append(updateClusterName, key)
			return nil
		})
		patches2.ApplyFunc(maps_v2.ClusterDelete, func(key string) error {
			deleteClusterName = append(deleteClusterName, key)
			return nil
		})
		defer func() {
			patches1.Reset()
			patches2.Reset()
		}()

		cache := NewClusterCache()
		cluster1 := &cluster_v2.Cluster{
			ApiStatus:      core_v2.ApiStatus_UPDATE,
			Name:           "ut-cluster1",
			ConnectTimeout: uint32(30),
			LbPolicy:       cluster_v2.Cluster_RANDOM,
		}
		cluster2 := &cluster_v2.Cluster{
			ApiStatus:      core_v2.ApiStatus_UPDATE,
			Name:           "ut-cluster2",
			ConnectTimeout: uint32(60),
			LbPolicy:       cluster_v2.Cluster_ROUND_ROBIN,
		}
		cache.SetApiCluster(cluster1.Name, cluster1)
		cache.SetApiCluster(cluster2.Name, cluster2)
		cache.Flush()
		apiCluster1 := cache.GetApiCluster(cluster1.GetName())
		apiCluster2 := cache.GetApiCluster(cluster2.GetName())
		assert.Equal(t, core_v2.ApiStatus_NONE, apiCluster1.ApiStatus)
		assert.Equal(t, core_v2.ApiStatus_NONE, apiCluster2.ApiStatus)
		assert.Equal(t, true, slices.EqualUnordered([]string{"ut-cluster2", "ut-cluster1"}, updateClusterName))
		assert.Equal(t, []string{}, deleteClusterName)
	})

	t.Run("one cluster status is UPDATE, one cluster status is DELETE", func(t *testing.T) {
		updateClusterName := []string{}
		deleteClusterName := []string{}

		patches1 := gomonkey.NewPatches()
		patches2 := gomonkey.NewPatches()
		patches1.ApplyFunc(maps_v2.ClusterUpdate, func(key string, value *cluster_v2.Cluster) error {
			updateClusterName = append(updateClusterName, key)
			return nil
		})
		patches2.ApplyFunc(maps_v2.ClusterDelete, func(key string) error {
			deleteClusterName = append(deleteClusterName, key)
			return nil
		})
		defer func() {
			patches1.Reset()
			patches2.Reset()
		}()

		cache := NewClusterCache()
		cluster1 := &cluster_v2.Cluster{
			ApiStatus:      core_v2.ApiStatus_UPDATE,
			Name:           "ut-cluster1",
			ConnectTimeout: uint32(30),
			LbPolicy:       cluster_v2.Cluster_RANDOM,
		}
		cluster2 := &cluster_v2.Cluster{
			ApiStatus:      core_v2.ApiStatus_DELETE,
			Name:           "ut-cluster2",
			ConnectTimeout: uint32(60),
			LbPolicy:       cluster_v2.Cluster_ROUND_ROBIN,
		}
		anyCluster1, err1 := anypb.New(cluster1)
		anyCluster2, err2 := anypb.New(cluster2)
		assert.NoError(t, err1)
		assert.NoError(t, err2)
		cache.SetCdsHash(cluster1.Name, hash.Sum64String(anyCluster1.String()))
		cache.SetCdsHash(cluster2.Name, hash.Sum64String(anyCluster2.String()))
		cache.SetApiCluster(cluster1.Name, cluster1)
		cache.SetApiCluster(cluster2.Name, cluster2)
		cache.Flush()
		apiCluster1 := cache.GetApiCluster(cluster1.GetName())
		apiCluster2 := cache.GetApiCluster(cluster2.GetName())
		assert.Equal(t, core_v2.ApiStatus_NONE, apiCluster1.ApiStatus)
		assert.Nil(t, apiCluster2)
		apiRouteHash1 := cache.GetCdsHash(cluster1.GetName())
		apiRouteHash2 := cache.GetCdsHash(cluster2.GetName())
		zeroHash := uint64(0)
		assert.Equal(t, hash.Sum64String(anyCluster1.String()), apiRouteHash1)
		assert.Equal(t, zeroHash, apiRouteHash2)
		assert.Equal(t, []string{"ut-cluster1"}, updateClusterName)
		assert.Equal(t, []string{"ut-cluster2"}, deleteClusterName)
	})

	t.Run("cluster status isn't UPDATE or DELETE", func(t *testing.T) {
		updateClusterName := []string{}
		deleteClusterName := []string{}

		patches1 := gomonkey.NewPatches()
		patches2 := gomonkey.NewPatches()
		patches1.ApplyFunc(maps_v2.ClusterUpdate, func(key string, value *cluster_v2.Cluster) error {
			updateClusterName = append(updateClusterName, key)
			return nil
		})
		patches2.ApplyFunc(maps_v2.ClusterDelete, func(key string) error {
			deleteClusterName = append(deleteClusterName, key)
			return nil
		})
		defer func() {
			patches1.Reset()
			patches2.Reset()
		}()

		cache := NewClusterCache()
		cluster1 := &cluster_v2.Cluster{
			ApiStatus:      core_v2.ApiStatus_UNCHANGED,
			Name:           "ut-cluster1",
			ConnectTimeout: uint32(30),
			LbPolicy:       cluster_v2.Cluster_RANDOM,
		}
		cluster2 := &cluster_v2.Cluster{
			ApiStatus:      core_v2.ApiStatus_ALL,
			Name:           "ut-cluster2",
			ConnectTimeout: uint32(60),
			LbPolicy:       cluster_v2.Cluster_ROUND_ROBIN,
		}
		cache.SetApiCluster(cluster1.Name, cluster1)
		cache.SetApiCluster(cluster2.Name, cluster2)
		cache.Flush()
		apiCluster1 := cache.GetApiCluster(cluster1.GetName())
		apiCluster2 := cache.GetApiCluster(cluster2.GetName())
		assert.Equal(t, core_v2.ApiStatus_UNCHANGED, apiCluster1.ApiStatus)
		assert.Equal(t, core_v2.ApiStatus_ALL, apiCluster2.ApiStatus)
		assert.Equal(t, []string{}, updateClusterName)
		assert.Equal(t, []string{}, deleteClusterName)
	})
}

func BenchmarkClusterFlush(b *testing.B) {
	t := &testing.T{}
	cleanup := test.InitBpfMap(t)
	b.Cleanup(cleanup)

	cluster := cluster_v2.Cluster{
		ApiStatus:      core_v2.ApiStatus_UPDATE,
		ConnectTimeout: uint32(1),
		CircuitBreakers: &cluster_v2.CircuitBreakers{
			MaxConnections:     uint32(4294967295),
			MaxPendingRequests: uint32(4294967295),
			MaxRequests:        uint32(4294967295),
			MaxRetries:         uint32(4294967295),
		},
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: "inbound|9080|http|reviews.default.svc.cluster.local",
			Endpoints: []*endpoint.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9090),
								Ipv4: nets.ConvertIpToUint32("192.168.127.240"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9091),
								Ipv4: nets.ConvertIpToUint32("192.168.127.241"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9092),
								Ipv4: nets.ConvertIpToUint32("192.168.127.242"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9293),
								Ipv4: nets.ConvertIpToUint32("192.168.127.243"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9294),
								Ipv4: nets.ConvertIpToUint32("192.168.127.244"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9095),
								Ipv4: nets.ConvertIpToUint32("192.168.127.245"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9096),
								Ipv4: nets.ConvertIpToUint32("192.168.127.246"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9097),
								Ipv4: nets.ConvertIpToUint32("192.168.127.247"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9098),
								Ipv4: nets.ConvertIpToUint32("192.168.127.248"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9099),
								Ipv4: nets.ConvertIpToUint32("192.168.127.249"),
							},
						},
					},
				},
			},
		},
		LbPolicy: cluster_v2.Cluster_ROUND_ROBIN,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache := NewClusterCache()
		cluster.Name = rand.String(6)
		cluster.ApiStatus = core_v2.ApiStatus_UPDATE
		cache.SetApiCluster(cluster.Name, &cluster)

		cache.Flush()
		assert.Equal(t, core_v2.ApiStatus_NONE, cluster.GetApiStatus())
	}
}
