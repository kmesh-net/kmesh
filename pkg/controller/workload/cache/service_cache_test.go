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

package cache

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/common"
)

func TestAddOrUpdateService(t *testing.T) {
	cache := NewServiceCache()

	svc1 := common.CreateFakeService("svc1", "10.240.10.1", "", nil)

	cache.AddOrUpdateService(svc1)

	name := svc1.ResourceName()

	assert.Equal(t, svc1, cache.GetService(name))
	assert.Equal(t, svc1, cache.GetServiceByAddr(NetworkAddress{Address: netip.MustParseAddr("10.240.10.1")}))
}

func TestDeleteService(t *testing.T) {
	t.Run("normal delete", func(t *testing.T) {
		cache := NewServiceCache()

		svc1 := common.CreateFakeService("svc1", "10.240.10.1", "", nil)

		cache.AddOrUpdateService(svc1)

		name := svc1.ResourceName()
		assert.Equal(t, svc1, cache.GetService(name))

		cache.DeleteService(name)
		assert.Equal(t, (*workloadapi.Service)(nil), cache.GetService(name))
		assert.Equal(t, (*workloadapi.Service)(nil), cache.GetServiceByAddr(NetworkAddress{Address: netip.MustParseAddr("10.240.10.1")}))
	})

	t.Run("address override", func(t *testing.T) {
		cache := NewServiceCache()

		svc1 := common.CreateFakeService("svc1", "10.240.10.1", "", nil)
		cache.AddOrUpdateService(svc1)

		// Both svc1 and svc2 point to address "10.240.10.1"
		svc2 := common.CreateFakeService("svc2", "10.240.10.1", "", nil)
		cache.AddOrUpdateService(svc2)

		name1 := svc1.ResourceName()
		name2 := svc2.ResourceName()

		assert.Equal(t, svc1, cache.GetService(name1))
		assert.Equal(t, svc2, cache.GetService(name2))

		// Delete svc1
		cache.DeleteService(name1)
		// Address "10.240.10.1" has been overwritten by svc2, so it will not be deleted
		assert.Equal(t, svc2, cache.GetServiceByAddr(NetworkAddress{Address: netip.MustParseAddr("10.240.10.1")}))
	})
}
