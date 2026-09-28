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

func TestServiceBatchUpdate(t *testing.T) {
	// 1. Setup Fake BPF Map (Same helper as in endpoint_test.go)
	workloadMap := NewFakeWorkloadMap(t)
	defer CleanupFakeWorkloadMap(workloadMap)

	c := NewCache(workloadMap)

	// 2. Prepare Batch Data
	keys := []ServiceKey{
		{ServiceId: 100},
		{ServiceId: 200},
	}
	values := []ServiceValue{
		{LbPolicy: 1}, // Random
		{LbPolicy: 1},
	}

	// 3. Call the function we need to cover
	count, err := c.ServiceBatchUpdate(keys, values)

	// 4. Assertions
	assert.Nil(t, err)
	assert.Equal(t, 2, count)

	// 5. Verify data was actually written to the map
	var lookupVal ServiceValue
	err = c.ServiceLookup(&keys[0], &lookupVal)
	assert.Nil(t, err)
	assert.Equal(t, values[0].LbPolicy, lookupVal.LbPolicy)
}
