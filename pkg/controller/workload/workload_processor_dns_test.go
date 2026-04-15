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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/bpfcache"
)

func TestProcessor_HandleServicesAndWorkloads_Dns(t *testing.T) {
	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	p := NewProcessor(workloadMap)

	// Test 1: No DNS resolver
	wl1 := &workloadapi.Workload{
		Uid:      "wl1",
		Name:     "wl1",
		Hostname: "example.com",
	}
	p.handleServicesAndWorkloads(nil, []*workloadapi.Workload{wl1})
	// Should just warn and continue, so nothing crashes

	// Test 2: DNS resolution timeout
	p.DnsResolverChan = make(chan *workloadapi.Workload, 10)

	// Temporarily replace dnsResolveTimeout with 10ms for test speed
	oldTimeout := dnsResolveTimeout
	dnsResolveTimeout = 10 * time.Millisecond
	defer func() { dnsResolveTimeout = oldTimeout }()

	wl2 := &workloadapi.Workload{
		Uid:      "wl2",
		Name:     "wl2",
		Hostname: "timeout.com",
	}
	p.handleServicesAndWorkloads(nil, []*workloadapi.Workload{wl2})

	_, ok := p.ResolvedDomainChanMap.Load("wl2")
	assert.False(t, ok, "channel should be deleted after timeout")

	// Test 3: DNS resolution succeeds
	wl3 := &workloadapi.Workload{
		Uid:      "wl3",
		Name:     "wl3",
		Hostname: "success.com",
	}

	go func() {
		time.Sleep(2 * time.Millisecond)
		val, ok := p.ResolvedDomainChanMap.Load("wl3")
		if ok {
			if ch, ok := val.(chan *workloadapi.Workload); ok {
				ch <- &workloadapi.Workload{
					Uid:       "wl3",
					Name:      "wl3",
					Hostname:  "success.com",
					Addresses: [][]byte{{192, 168, 1, 1}},
				}
			}
		}
	}()
	p.handleServicesAndWorkloads(nil, []*workloadapi.Workload{wl3})

	// Test 4: DNS resolution succeeds with nil newWorkload or addresses
	wl4 := &workloadapi.Workload{
		Uid:      "wl4",
		Name:     "wl4",
		Hostname: "fail.com",
	}

	go func() {
		time.Sleep(2 * time.Millisecond)
		val, ok := p.ResolvedDomainChanMap.Load("wl4")
		if ok {
			if ch, ok := val.(chan *workloadapi.Workload); ok {
				ch <- &workloadapi.Workload{
					Uid:       "wl4",
					Name:      "wl4",
					Hostname:  "fail.com",
					Addresses: nil, // force nil addresses code branch
				}
			}
		}
	}()
	p.handleServicesAndWorkloads(nil, []*workloadapi.Workload{wl4})
}
