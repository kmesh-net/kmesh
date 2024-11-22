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

package bpfcache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEndpointSwap(t *testing.T) {
	workloadMap := NewFakeWorkloadMap(t)
	defer CleanupFakeWorkloadMap(workloadMap)

	c := NewCache(workloadMap)
	endpointsMap := map[*EndpointKey]*EndpointValue{
		{ServiceId: 1, Prio: 1, BackendIndex: 1}: {BackendUid: 1},
		{ServiceId: 1, Prio: 1, BackendIndex: 2}: {BackendUid: 2},
		{ServiceId: 1, Prio: 1, BackendIndex: 3}: {BackendUid: 3},
		{ServiceId: 1, Prio: 1, BackendIndex: 4}: {BackendUid: 4},
		{ServiceId: 1, Prio: 1, BackendIndex: 5}: {BackendUid: 5},
	}
	for k, v := range endpointsMap {
		c.EndpointUpdate(k, v)
	}

	// invalid currentIndex
	err := c.EndpointSwap(6, 5, 1, 1)
	assert.ErrorContains(t, err, "> lastIndex")

	// delete mid element 3 -> 1 2 5 4
	err = c.EndpointSwap(3, 5, 1, 1)
	assert.Nil(t, err)

	// delete the last element 4 -> 1 2 5
	err = c.EndpointSwap(4, 4, 1, 1)
	assert.Nil(t, err)

	// delete the first element 1 -> 5 2
	err = c.EndpointSwap(1, 3, 1, 1)
	assert.Nil(t, err)

	eps := c.GetAllEndpointsForService(1)
	assert.Equal(t, len(eps), 2)

	assert.Equal(t, 2, len(c.endpointKeys))
	epKs := c.GetEndpointKeys(2)
	assert.Equal(t, 1, epKs.Len())
	epKs = c.GetEndpointKeys(5)
	assert.Equal(t, 1, epKs.Len())
}
