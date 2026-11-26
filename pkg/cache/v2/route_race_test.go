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

package cache_v2

import (
	"sync"
	"testing"

	route_v2 "kmesh.net/kmesh/api/v2/route"
)

// Regression for #1975: SetApiRouteConfig used to take RLock while writing the
// map, so a concurrent Dump could fatal with "concurrent map iteration and map write".
func TestSetApiRouteConfigConcurrentWithDump(t *testing.T) {
	cache := NewRouteConfigCache()
	route := &route_v2.RouteConfiguration{
		Name: "race-route",
		VirtualHosts: []*route_v2.VirtualHost{
			{Name: "vh"},
		},
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			cache.SetApiRouteConfig(route.Name, route)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = cache.Dump()
		}
	}()
	wg.Wait()
}
