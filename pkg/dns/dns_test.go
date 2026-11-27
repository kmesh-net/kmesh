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
		testDNSResolver.Lock()
		testDNSResolver.cache[testcase.domain] = &DomainCacheEntry{}
		testDNSResolver.Unlock()
		testDNSResolver.refreshQueue.AddAfter(input, 0)

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

func TestDNSRefreshRetryOnFailure(t *testing.T) {
	fakeDNSServer := NewFakeDNSServer()
	testDNSResolver, err := NewDNSResolver()
	if err != nil {
		t.Fatal(err)
	}
	stopCh := make(chan struct{})
	defer close(stopCh)

	dnsServer := fakeDNSServer.Server.PacketConn.LocalAddr().String()
	testDNSResolver.delegates = []Resolver{NewUpstreamResolver(dnsServer)}
	go testDNSResolver.StartDnsResolver(stopCh)

	domain := "www.retry-test.com."
	fakeDNSServer.SetHosts(domain, 1)
	fakeDNSServer.SetTTL(1) // 1 second TTL

	// Initial resolution
	testDNSResolver.AddDomainInQueue(&DomainInfo{
		Domain:      domain,
		RefreshRate: 10 * time.Second,
	}, 0)

	// Wait for initial resolution to populate cache
	expectedInitial := []string{"10.0.0.1", "fd00::1"}
	var addresses []string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		addresses = testDNSResolver.GetDNSAddresses(domain)
		if reflect.DeepEqual(addresses, expectedInitial) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !reflect.DeepEqual(addresses, expectedInitial) {
		t.Fatalf("initial resolution failed: got %v, want %v", addresses, expectedInitial)
	}

	// Simulate temporary upstream DNS failure
	fakeDNSServer.SetFailure(true)
	// Update backend host to return new IP once healthy
	fakeDNSServer.SetHosts(domain, 2)

	// Wait for TTL (1s) to expire so refreshDns() executes and encounters the failure
	time.Sleep(1500 * time.Millisecond)

	// DNS resolution failed during refresh; previous addresses should still remain in cache
	addresses = testDNSResolver.GetDNSAddresses(domain)
	if !reflect.DeepEqual(addresses, expectedInitial) {
		t.Fatalf("cache should retain previous addresses on failure: got %v, want %v", addresses, expectedInitial)
	}

	// Restore DNS health
	fakeDNSServer.SetFailure(false)

	// If refreshDns() correctly retries failed domains, it will re-attempt and update the cache.
	// In the un-fixed code, the domain is dropped from the queue and this check times out.
	expectedRecovered := []string{"10.0.0.2", "fd00::2"}
	recovered := false
	retryDeadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(retryDeadline) {
		addresses = testDNSResolver.GetDNSAddresses(domain)
		if reflect.DeepEqual(addresses, expectedRecovered) {
			recovered = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !recovered {
		t.Fatalf("domain failed to recover after temporary DNS failure; refresh queue dropped domain: got %v, want %v", addresses, expectedRecovered)
	}
}

func TestDNSRefreshUnwatchedDomainNotRetried(t *testing.T) {
	fakeDNSServer := NewFakeDNSServer()
	testDNSResolver, err := NewDNSResolver()
	if err != nil {
		t.Fatal(err)
	}
	stopCh := make(chan struct{})
	defer close(stopCh)

	dnsServer := fakeDNSServer.Server.PacketConn.LocalAddr().String()
	testDNSResolver.delegates = []Resolver{NewUpstreamResolver(dnsServer)}
	go testDNSResolver.StartDnsResolver(stopCh)

	domain := "www.unwatch-test.com."
	fakeDNSServer.SetFailure(true)

	// Add domain in queue
	testDNSResolver.AddDomainInQueue(&DomainInfo{
		Domain:      domain,
		RefreshRate: 10 * time.Second,
	}, 0)

	// Now remove from watch
	testDNSResolver.RemoveUnwatchDomain(map[string]interface{}{})

	// Wait for retry interval
	time.Sleep(1500 * time.Millisecond)

	// Verify domain is not in cache
	testDNSResolver.Lock()
	_, exist := testDNSResolver.cache[domain]
	testDNSResolver.Unlock()
	if exist {
		t.Fatalf("unwatched domain should not exist in cache")
	}
}
