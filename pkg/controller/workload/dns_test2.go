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

package workload

import (
	"github.com/stretchr/testify/assert"
	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
	"testing"
)

func TestDnsController_UpdateWorkloads_Coverage(t *testing.T) {
	workloadCache := cache.NewWorkloadCache()
	dnsController, _ := NewDnsController(workloadCache)

	uid := "test-uid-coverage"
	domain := "example.com"
	addrs := []string{"192.168.1.1"}

	workload := &workloadapi.Workload{
		Uid:      uid,
		Name:     "test-workload",
		Hostname: domain,
	}

	pendingDomain := &pendingResolveDomain{
		Workload: []*workloadapi.Workload{workload},
	}

	// Case 1: Channel in map, send succeeds
	ch := make(chan *workloadapi.Workload, 1)
	dnsController.ResolvedDomainChanMap.Store(uid, ch)
	dnsController.updateWorkloads(pendingDomain, domain, addrs)

	_, ok := dnsController.ResolvedDomainChanMap.Load(uid)
	assert.False(t, ok, "channel should be deleted from map")

	newWl := <-ch
	assert.NotNil(t, newWl)

	// Case 2: Channel in map, but invalid type
	dnsController.ResolvedDomainChanMap.Store(uid, "invalid-type")
	dnsController.updateWorkloads(pendingDomain, domain, addrs)
	_, ok = dnsController.ResolvedDomainChanMap.Load(uid)
	assert.True(t, ok, "channel should still be in map if invalid type")

	// Case 3: Channel in map, but channel is full (timeout)
	ch2 := make(chan *workloadapi.Workload, 1)
	ch2 <- workload // fill channel
	dnsController.ResolvedDomainChanMap.Store(uid, ch2)

	// Temporarily override WorkloadChannelSendTimeout inside dns.go if possible,
	// but since it's a const, the test will just sleep 100ms.
	dnsController.updateWorkloads(pendingDomain, domain, addrs)
	_, ok = dnsController.ResolvedDomainChanMap.Load(uid)
	assert.False(t, ok, "channel should be deleted even if timeout")
}
