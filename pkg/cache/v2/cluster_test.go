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

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
	"kmesh.net/kmesh/pkg/utils/hash"
)

func TestClusterFlush(t *testing.T) {
	t.Run("cluster status is UPDATE", func(t *testing.T) {
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
	})

	t.Run("one cluster status is UPDATE, one cluster status is DELETE", func(t *testing.T) {
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
