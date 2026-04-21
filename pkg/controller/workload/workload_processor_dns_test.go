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

	"github.com/stretchr/testify/assert"
	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/bpfcache"
)

func TestProcessor_HandleServicesAndWorkloads_Dns_Async(t *testing.T) {
	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	p := NewProcessor(workloadMap)

	// Test: Asynchronous DNS resolution trigger
	p.DnsResolverChan = make(chan *workloadapi.Workload, 10)

	wl := &workloadapi.Workload{
		Uid:      "wl-async",
		Name:     "wl-async",
		Hostname: "example.com",
	}

	// This should trigger the asynchronous path
	p.handleServicesAndWorkloads(nil, []*workloadapi.Workload{wl})

	// Verify that the workload was sent to the DNS resolver channel
	select {
	case receivedWl := <-p.DnsResolverChan:
		assert.Equal(t, wl.Uid, receivedWl.Uid)
	default:
		t.Fatal("workload was not sent to DnsResolverChan")
	}
}
