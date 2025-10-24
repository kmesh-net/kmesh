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
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/test/util/retry"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/bpfcache"
	"kmesh.net/kmesh/pkg/dns"
)

func TestOverwriteDnsWorkloadWithIPv4(t *testing.T) {
	domain := "example.com"
	// Test with only IPv4 addresses
	addrs := []string{"192.168.1.1", "192.168.1.2", "10.0.0.1"}
	workload := &workloadapi.Workload{
		Uid:      "test-uid-ipv4",
		Name:     "test-workload-ipv4",
		Hostname: domain,
	}

	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	defer bpfcache.CleanupFakeWorkloadMap(workloadMap)

	p := NewProcessor(workloadMap)
	stopCh := make(chan struct{})
	defer close(stopCh)

	dnsController, err := NewDnsController(p.WorkloadCache)
	assert.NoError(t, err)
	p.DnsResolverChan = dnsController.workloadsChan

	ready, newWorkload := dnsController.overwriteDnsWorkload(workload, domain, addrs)
	assert.True(t, ready, "should successfully process IPv4 addresses")

	// Verify all IPv4 addresses are correctly added
	expectedAddrs := []string{"192.168.1.1", "192.168.1.2", "10.0.0.1"}
	actualAddrs := make([]string, 0, len(newWorkload.Addresses))
	for _, addr := range newWorkload.Addresses {
		ip, _ := netip.AddrFromSlice(addr)
		actualAddrs = append(actualAddrs, ip.String())
	}
	assert.Equal(t, expectedAddrs, actualAddrs)
}

func TestOverwriteDnsWorkloadWithIPv6(t *testing.T) {
	domain := "example.com"
	// Test with only IPv6 addresses
	addrs := []string{"2001:db8::1", "fe80::1", "2001:db8::2"}
	workload := &workloadapi.Workload{
		Uid:      "test-uid-ipv6",
		Name:     "test-workload-ipv6",
		Hostname: domain,
	}

	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	defer bpfcache.CleanupFakeWorkloadMap(workloadMap)

	p := NewProcessor(workloadMap)
	stopCh := make(chan struct{})
	defer close(stopCh)

	dnsController, err := NewDnsController(p.WorkloadCache)
	assert.NoError(t, err)

	ready, newWorkload := dnsController.overwriteDnsWorkload(workload, domain, addrs)
	assert.True(t, ready, "should successfully process IPv6 addresses")

	// Verify all IPv6 addresses are correctly added
	expectedAddrs := []string{"2001:db8::1", "fe80::1", "2001:db8::2"}
	actualAddrs := make([]string, 0, len(newWorkload.Addresses))
	for _, addr := range newWorkload.Addresses {
		ip, _ := netip.AddrFromSlice(addr)
		actualAddrs = append(actualAddrs, ip.String())
	}
	assert.Equal(t, expectedAddrs, actualAddrs)
}

func TestOverwriteDnsWorkloadWithMixedAddresses(t *testing.T) {
	domain := "example.com"
	// Test with both IPv4 and IPv6 addresses mixed
	addrs := []string{"192.168.1.1", "2001:db8::1", "10.0.0.1", "fe80::1"}
	workload := &workloadapi.Workload{
		Uid:      "test-uid-mixed",
		Name:     "test-workload-mixed",
		Hostname: domain,
	}

	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	defer bpfcache.CleanupFakeWorkloadMap(workloadMap)

	p := NewProcessor(workloadMap)
	stopCh := make(chan struct{})
	defer close(stopCh)

	dnsController, err := NewDnsController(p.WorkloadCache)
	assert.NoError(t, err)

	ready, newWorkload := dnsController.overwriteDnsWorkload(workload, domain, addrs)
	assert.True(t, ready, "should successfully process mixed IPv4 and IPv6 addresses")

	// Verify both IPv4 and IPv6 addresses are correctly added
	expectedAddrs := []string{"192.168.1.1", "2001:db8::1", "10.0.0.1", "fe80::1"}
	actualAddrs := make([]string, 0, len(newWorkload.Addresses))
	for _, addr := range newWorkload.Addresses {
		ip, _ := netip.AddrFromSlice(addr)
		actualAddrs = append(actualAddrs, ip.String())
	}
	assert.Equal(t, expectedAddrs, actualAddrs)
}

func TestHandleWorkloadsWithDns(t *testing.T) {
	workload1 := &workloadapi.Workload{
		Uid:      "test-uid-1",
		Name:     "test-workload-1",
		Hostname: "foo.bar",
	}
	workload2 := &workloadapi.Workload{
		Uid:       "test-uid-2",
		Name:      "test-workload-2",
		Hostname:  "foo.baz",
		Addresses: [][]byte{netip.MustParseAddr("192.168.1.1").AsSlice()},
	}

	testcases := []struct {
		name      string
		workloads []*workloadapi.Workload
		expected  []string
	}{
		{
			name:      "add workloads with DNS hostname",
			workloads: []*workloadapi.Workload{workload1, workload2},
			expected:  []string{"foo.bar"},
		},
	}

	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	defer bpfcache.CleanupFakeWorkloadMap(workloadMap)

	p := NewProcessor(workloadMap)
	stopCh := make(chan struct{})
	defer close(stopCh)

	dnsController, err := NewDnsController(p.WorkloadCache)
	assert.NoError(t, err)
	dnsController.Run(stopCh)
	p.DnsResolverChan = dnsController.workloadsChan

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Send workloads that need DNS resolution
			for _, wl := range tc.workloads {
				if wl.GetAddresses() == nil {
					dnsController.workloadsChan <- wl
				}
			}

			// Verify pending domains are correct
			retry.UntilOrFail(t, func() bool {
				domains := make([]string, 0)
				for _, wl := range tc.workloads {
					if wl.GetAddresses() == nil {
						result := getPendingResolveDomain(wl)
						for domain := range result {
							domains = append(domains, domain)
						}
					}
				}
				return slices.EqualUnordered(tc.expected, domains)
			}, retry.Timeout(1*time.Second))
		})
	}
}

func TestGetPendingResolveDomain(t *testing.T) {
	tests := []struct {
		name     string
		workload *workloadapi.Workload
		expected []string
	}{
		{
			name: "valid hostname",
			workload: &workloadapi.Workload{
				Uid:      "test-uid-1",
				Name:     "test-workload",
				Hostname: "example.com",
			},
			expected: []string{"example.com"},
		},
		{
			name: "empty hostname",
			workload: &workloadapi.Workload{
				Uid:      "test-uid-2",
				Name:     "test-workload-2",
				Hostname: "",
			},
			expected: []string{},
		},
		{
			name: "ip address as hostname",
			workload: &workloadapi.Workload{
				Uid:      "test-uid-3",
				Name:     "test-workload-3",
				Hostname: "192.168.1.1",
			},
			expected: []string{},
		},
		{
			name: "ipv6 address as hostname",
			workload: &workloadapi.Workload{
				Uid:      "test-uid-4",
				Name:     "test-workload-4",
				Hostname: "2001:db8::1",
			},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPendingResolveDomain(tt.workload)
			domains := make([]string, 0, len(result))
			for domain := range result {
				domains = append(domains, domain)
			}
			assert.True(t, slices.EqualUnordered(tt.expected, domains))
		})
	}
}

func TestDnsController_ProcessDomains(t *testing.T) {
	workloadMap := bpfcache.NewFakeWorkloadMap(t)
	defer bpfcache.CleanupFakeWorkloadMap(workloadMap)

	p := NewProcessor(workloadMap)
	dnsController, err := NewDnsController(p.WorkloadCache)
	assert.NoError(t, err)

	workload := &workloadapi.Workload{
		Uid:      "test-uid",
		Name:     "test-workload",
		Hostname: "example.com",
	}

	patches := gomonkey.NewPatches()
	defer patches.Reset()
	patches.ApplyMethod(reflect.TypeOf(dnsController.dnsResolver), "GetDNSAddresses",
		func(_ *dns.DNSResolver, domain string) []string {
			return nil // Mock initial cache miss scenario
		})
	patches.ApplyMethod(reflect.TypeOf(dnsController.dnsResolver), "RemoveUnwatchDomain",
		func(_ *dns.DNSResolver, domains map[string]any) {
			// Mock domain unwatch removal
		})
	patches.ApplyMethod(reflect.TypeOf(dnsController.dnsResolver), "AddDomainInQueue",
		func(_ *dns.DNSResolver, domainInfo *dns.DomainInfo, delay time.Duration) {
			// Mock adding domain to queue
		})

	// Test domain processing
	dnsController.processDomains(workload)

	// Verify workloadCache is updated
	assert.Contains(t, dnsController.workloadCache, "example.com")
	assert.Contains(t, dnsController.pendingHostnames, "test-workload")
	assert.Equal(t, "example.com", dnsController.pendingHostnames["test-workload"])

	pendingDomain := dnsController.workloadCache["example.com"]
	assert.NotNil(t, pendingDomain)
	assert.Equal(t, 1, len(pendingDomain.Workload))
	assert.Equal(t, workload, pendingDomain.Workload[0])
	assert.Equal(t, WorkloadDnsRefreshRate, pendingDomain.RefreshRate)
}

func TestCloneWorkload(t *testing.T) {
	tests := []struct {
		name     string
		workload *workloadapi.Workload
		wantNil  bool
	}{
		{
			name:     "nil workload",
			workload: nil,
			wantNil:  true,
		},
		{
			name: "valid workload",
			workload: &workloadapi.Workload{
				Uid:      "test-uid",
				Name:     "test-workload",
				Hostname: "example.com",
				Addresses: [][]byte{
					netip.MustParseAddr("192.168.1.1").AsSlice(),
				},
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cloneWorkload(tt.workload)

			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tt.workload.Uid, result.Uid)
				assert.Equal(t, tt.workload.Name, result.Name)
				assert.Equal(t, tt.workload.Hostname, result.Hostname)
				assert.Equal(t, len(tt.workload.Addresses), len(result.Addresses))

				// Verify different object instances
				assert.NotSame(t, tt.workload, result)
			}
		})
	}
}
