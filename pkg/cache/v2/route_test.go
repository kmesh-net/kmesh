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

package cache_v2

import (
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/slices"

	core_v2 "kmesh.net/kmesh/api/v2/core"
	route_v2 "kmesh.net/kmesh/api/v2/route"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
	"kmesh.net/kmesh/pkg/utils/hash"
)

func TestRouteFlush(t *testing.T) {
	t.Run("route status is UPDATE", func(t *testing.T) {
		updateRouterName := []string{}
		deleteRouterName := []string{}

		patches1 := gomonkey.NewPatches()
		patches2 := gomonkey.NewPatches()
		patches1.ApplyFunc(maps_v2.RouteConfigUpdate, func(key string, value *route_v2.RouteConfiguration) error {
			updateRouterName = append(updateRouterName, key)
			return nil
		})
		patches1.ApplyFunc(maps_v2.RouteConfigDelete, func(key string) error {
			deleteRouterName = append(deleteRouterName, key)
			return nil
		})
		defer func() {
			patches1.Reset()
			patches2.Reset()
		}()

		cache := NewRouteConfigCache()
		routeConfig1 := &route_v2.RouteConfiguration{
			ApiStatus: core_v2.ApiStatus_UPDATE,
			Name:      "ut-route1",
			VirtualHosts: []*route_v2.VirtualHost{
				{
					Name: "ut-virtualHost1",
				},
			},
		}
		routeConfig2 := &route_v2.RouteConfiguration{
			ApiStatus: core_v2.ApiStatus_UPDATE,
			Name:      "ut-route2",
			VirtualHosts: []*route_v2.VirtualHost{
				{
					Name: "ut-virtualHost2",
				},
			},
		}
		cache.SetApiRouteConfig(routeConfig1.Name, routeConfig1)
		cache.SetApiRouteConfig(routeConfig2.Name, routeConfig2)
		cache.Flush()
		apiRouteConfig1 := cache.GetApiRouteConfig(routeConfig1.Name)
		apiRouteConfig2 := cache.GetApiRouteConfig(routeConfig2.Name)
		assert.Equal(t, core_v2.ApiStatus_NONE, apiRouteConfig1.ApiStatus)
		assert.Equal(t, core_v2.ApiStatus_NONE, apiRouteConfig2.ApiStatus)
		assert.Equal(t, true, slices.EqualUnordered([]string{"ut-route1", "ut-route2"}, updateRouterName))
		assert.Equal(t, []string{}, deleteRouterName)
	})

	t.Run("one route status is UPDATE, one route status is DELETE", func(t *testing.T) {
		updateRouterName := []string{}
		deleteRouterName := []string{}

		patches1 := gomonkey.NewPatches()
		patches2 := gomonkey.NewPatches()
		patches1.ApplyFunc(maps_v2.RouteConfigUpdate, func(key string, value *route_v2.RouteConfiguration) error {
			updateRouterName = append(updateRouterName, key)
			return nil
		})
		patches1.ApplyFunc(maps_v2.RouteConfigDelete, func(key string) error {
			deleteRouterName = append(deleteRouterName, key)
			return nil
		})
		defer func() {
			patches1.Reset()
			patches2.Reset()
		}()

		cache := NewRouteConfigCache()
		routeConfig1 := &route_v2.RouteConfiguration{
			ApiStatus: core_v2.ApiStatus_UPDATE,
			Name:      "ut-route1",
			VirtualHosts: []*route_v2.VirtualHost{
				{
					Name: "ut-virtualHost1",
				},
			},
		}
		routeConfig2 := &route_v2.RouteConfiguration{
			ApiStatus: core_v2.ApiStatus_DELETE,
			Name:      "ut-route2",
			VirtualHosts: []*route_v2.VirtualHost{
				{
					Name: "ut-virtualHost2",
				},
			},
		}
		anyRouteConfig1, err1 := anypb.New(routeConfig1)
		anyRouteConfig2, err2 := anypb.New(routeConfig2)
		assert.NoError(t, err1)
		assert.NoError(t, err2)
		cache.SetRdsHash(routeConfig1.Name, hash.Sum64String(anyRouteConfig1.String()))
		cache.SetRdsHash(routeConfig2.Name, hash.Sum64String(anyRouteConfig2.String()))
		cache.SetApiRouteConfig(routeConfig1.Name, routeConfig1)
		cache.SetApiRouteConfig(routeConfig2.Name, routeConfig2)
		cache.Flush()
		apiRouteConfig1 := cache.GetApiRouteConfig(routeConfig1.Name)
		apiRouteConfig2 := cache.GetApiRouteConfig(routeConfig2.Name)
		assert.Equal(t, core_v2.ApiStatus_NONE, apiRouteConfig1.ApiStatus)
		assert.Nil(t, apiRouteConfig2)
		apiRouteHash1 := cache.GetRdsHash(routeConfig1.Name)
		apiRouteHash2 := cache.GetRdsHash(routeConfig2.Name)
		zeroHash := uint64(0)
		assert.Equal(t, hash.Sum64String(anyRouteConfig1.String()), apiRouteHash1)
		assert.Equal(t, zeroHash, apiRouteHash2)
		assert.Equal(t, []string{"ut-route1"}, updateRouterName)
		assert.Equal(t, []string{"ut-route2"}, deleteRouterName)
	})

	t.Run("route status isn't UPDATE or DELETE", func(t *testing.T) {
		updateRouterName := []string{}
		deleteRouterName := []string{}

		patches1 := gomonkey.NewPatches()
		patches2 := gomonkey.NewPatches()
		patches1.ApplyFunc(maps_v2.RouteConfigUpdate, func(key string, value *route_v2.RouteConfiguration) error {
			updateRouterName = append(updateRouterName, key)
			return nil
		})
		patches1.ApplyFunc(maps_v2.RouteConfigDelete, func(key string) error {
			deleteRouterName = append(deleteRouterName, key)
			return nil
		})
		defer func() {
			patches1.Reset()
			patches2.Reset()
		}()

		cache := NewRouteConfigCache()
		routeConfig1 := &route_v2.RouteConfiguration{
			Name:      "ut-route1",
			ApiStatus: core_v2.ApiStatus_UNCHANGED,
			VirtualHosts: []*route_v2.VirtualHost{
				{
					Name: "ut-virtualHost1",
				},
			},
		}
		routeConfig2 := &route_v2.RouteConfiguration{
			Name:      "ut-route2",
			ApiStatus: core_v2.ApiStatus_ALL,
			VirtualHosts: []*route_v2.VirtualHost{
				{
					Name: "ut-virtualHost2",
				},
			},
		}
		cache.SetApiRouteConfig(routeConfig1.Name, routeConfig1)
		cache.SetApiRouteConfig(routeConfig2.Name, routeConfig2)
		cache.Flush()
		apiRouteConfig1 := cache.GetApiRouteConfig(routeConfig1.Name)
		apiRouteConfig2 := cache.GetApiRouteConfig(routeConfig2.Name)
		assert.Equal(t, core_v2.ApiStatus_UNCHANGED, apiRouteConfig1.ApiStatus)
		assert.Equal(t, core_v2.ApiStatus_ALL, apiRouteConfig2.ApiStatus)
		assert.Equal(t, []string{}, updateRouterName)
		assert.Equal(t, []string{}, deleteRouterName)
	})
}
