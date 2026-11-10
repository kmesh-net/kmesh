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

package dns

import (
	"math"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestDNS(t *testing.T) {
	fakeDNSServer := NewFakeDNSServer()

	testDNSResolver, err := NewDNSResolver()
	if err != nil {
		t.Fatal(err)
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	// testDNSResolver.StartAdsDnsResolver(stopCh)
	dnsServer := fakeDNSServer.Server.PacketConn.LocalAddr().String()
	testDNSResolver.delegates = []Resolver{NewUpstreamResolver(dnsServer)}
	go testDNSResolver.StartDnsResolver(stopCh)

	testCases := []struct {
		name             string
		domain           string
		refreshRate      time.Duration
		ttl              time.Duration
		expected         []string
		expectedAfterTTL []string
		registerDomain   func(domain string)
	}{
		{
			name:        "success",
			domain:      "www.google.com.",
			refreshRate: 10 * time.Second,
			expected:    []string{"10.0.0.1", "fd00::1"},
			registerDomain: func(domain string) {
				fakeDNSServer.SetHosts(domain, 1)
			},
		},
		{
			name:             "check dns refresh after ttl, ttl < refreshRate",
			domain:           "www.bing.com.",
			refreshRate:      10 * time.Second,
			ttl:              3 * time.Second,
			expected:         []string{"10.0.0.2", "fd00::2"},
			expectedAfterTTL: []string{"10.0.0.3", "fd00::3"},
			registerDomain: func(domain string) {
				fakeDNSServer.SetHosts(domain, 2)
				fakeDNSServer.SetTTL(uint32(3))
				time.AfterFunc(time.Second, func() {
					fakeDNSServer.SetHosts(domain, 3)
				})
			},
		},
		{
			name:             "check dns refresh after ttl without update bpfmap",
			domain:           "www.test.com.",
			refreshRate:      10 * time.Second,
			ttl:              3 * time.Second,
			expected:         []string{"10.0.0.2", "fd00::2"},
			expectedAfterTTL: []string{"10.0.0.2", "fd00::2"},
			registerDomain: func(domain string) {
				fakeDNSServer.SetHosts(domain, 2)
				fakeDNSServer.SetTTL(uint32(3))
			},
		},
		{
			name:             "check dns refresh after refreshRate, ttl > refreshRate",
			domain:           "www.baidu.com.",
			refreshRate:      3 * time.Second,
			ttl:              10 * time.Second,
			expected:         []string{"10.0.0.2", "fd00::2"},
			expectedAfterTTL: []string{"10.0.0.3", "fd00::3"},
			registerDomain: func(domain string) {
				fakeDNSServer.SetHosts(domain, 2)
				fakeDNSServer.SetTTL(uint32(10))
				time.AfterFunc(time.Second, func() {
					fakeDNSServer.SetHosts(domain, 3)
				})
			},
		},
		{
			name:        "failed to resolve",
			domain:      "www.kmesh.test.",
			refreshRate: 10 * time.Second,
			expected:    []string{},
		},
	}
	var wg sync.WaitGroup
	for _, testcase := range testCases {
		wg.Add(1)
		if testcase.registerDomain != nil {
			testcase.registerDomain(testcase.domain)
		}

		input := &DomainInfo{
			Domain:      testcase.domain,
			RefreshRate: testcase.refreshRate,
		}
		testDNSResolver.AddDomainInQueue(input, 0)

		time.Sleep(2 * time.Second)

		res := testDNSResolver.GetDNSAddresses(testcase.domain)
		if len(res) != 0 || len(testcase.expected) != 0 {
			if !reflect.DeepEqual(res, testcase.expected) {
				t.Errorf("dns resolve for %s do not match. \n got %v\nwant %v", testcase.domain, res, testcase.expected)
			}

			if testcase.expectedAfterTTL != nil {
				ttl := time.Duration(math.Min(float64(testcase.ttl), float64(testcase.refreshRate)))
				time.Sleep(ttl + 1)
				res = testDNSResolver.GetDNSAddresses(testcase.domain)
				if !reflect.DeepEqual(res, testcase.expectedAfterTTL) {
					t.Errorf("dns refresh after ttl failed, for %s do not match. \n got %v\nwant %v", testcase.domain, res, testcase.expectedAfterTTL)
				}
			}
		}
		wg.Done()
	}
	wg.Wait()
}

// Repeated AddDomainInQueue calls for one hostname must collapse into a single
// queue entry instead of starting one refresh loop per call.
func TestAddDomainInQueueDedupesQueuedDomain(t *testing.T) {
	r, err := NewDNSResolver()
	if err != nil {
		t.Fatal(err)
	}
	defer r.refreshQueue.ShutDown()

	for _, rate := range []time.Duration{15 * time.Second, 5 * time.Second, 60 * time.Second} {
		r.AddDomainInQueue(&DomainInfo{Domain: "www.kmesh.test.", RefreshRate: rate}, 0)
	}

	if got := r.refreshQueue.Len(); got != 1 {
		t.Fatalf("expected one queued refresh for the domain, got %d", got)
	}
	r.RLock()
	rate := r.cache["www.kmesh.test."].RefreshRate
	r.RUnlock()
	if rate != 5*time.Second {
		t.Fatalf("expected the strictest refresh rate (5s) to be kept, got %v", rate)
	}
}

func TestAddDomainInQueueSingleRefreshLoop(t *testing.T) {
	fakeDNSServer := NewFakeDNSServer()
	const domain = "www.kmesh.test."
	fakeDNSServer.SetHosts(domain, 1)
	fakeDNSServer.SetTTL(1)

	r, err := NewDNSResolver()
	if err != nil {
		t.Fatal(err)
	}
	r.delegates = []Resolver{NewUpstreamResolver(fakeDNSServer.Server.PacketConn.LocalAddr().String())}

	// Enqueue before the worker starts so the four calls collapse into one
	// queue entry deterministically; a worker racing the calls could re-resolve
	// once more and make the count depend on scheduling.
	for i := 0; i < 4; i++ {
		r.AddDomainInQueue(&DomainInfo{Domain: domain, RefreshRate: 15 * time.Second}, 0)
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go r.StartDnsResolver(stopCh)

	// With a 1s TTL a single loop notifies at t=0,1,2,3s within 3.5s; one loop
	// per enqueue would notify about four times as often.
	notifications := 0
	deadline := time.After(3500 * time.Millisecond)
	for {
		select {
		case <-r.DnsChan:
			notifications++
			continue
		case <-deadline:
		}
		break
	}
	if notifications < 3 || notifications > 4 {
		t.Fatalf("expected a single refresh loop (3..4 notifications in 3.5s), got %d", notifications)
	}
}
