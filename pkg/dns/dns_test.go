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
	testDNSResolver.resolvConfServers = []string{dnsServer}
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
