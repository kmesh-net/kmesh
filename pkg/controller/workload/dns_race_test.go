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
	"sync"
	"testing"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
)

func TestDnsControllerConcurrentMapAccess(t *testing.T) {
	workloadCache := cache.NewWorkloadCache()
	dnsController, err := NewDnsController(workloadCache)
	if err != nil {
		t.Fatalf("failed to create DNS controller: %v", err)
	}

	var wg sync.WaitGroup

	domain := "example.com"
	numIter := 1000

	wg.Add(2)

	// Goroutine 1: Simulate the workload processor writing to the sync map and waiting on channel (or timeout)
	go func() {
		defer wg.Done()
		for i := 0; i < numIter; i++ {
			uid := "test-uid-1"
			ch := make(chan *workloadapi.Workload, 1)
			dnsController.ResolvedDomainChanMap.Store(uid, ch)

			// simulate timeout and cleanup
			dnsController.ResolvedDomainChanMap.Delete(uid)
		}
	}()

	// Goroutine 2: Simulate dnsController reading from the sync map and writing to the channel
	go func() {
		defer wg.Done()
		for i := 0; i < numIter; i++ {
			uid := "test-uid-1"
			pendingDomain := &pendingResolveDomain{
				Workload: []*workloadapi.Workload{
					{Uid: uid, Name: "test-workload", Hostname: domain},
				},
			}
			addrs := []string{"192.168.1.1"}
			dnsController.updateWorkloads(pendingDomain, domain, addrs)
		}
	}()

	wg.Wait()
}
