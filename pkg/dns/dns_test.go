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
	"fmt"
	"math"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/miekg/dns"

	"kmesh.net/kmesh/pkg/controller/ads"
)

type fakeDNSServer struct {
	*dns.Server
	ttl     uint32
	failure bool

	mu sync.Mutex
	// map fqdn hostname -> ip suffix
	hosts map[string]int
}

func TestDNS(t *testing.T) {
	fakeDNSServer := newFakeDNSServer()

	// testDNSResolver, err := NewDNSResolver(ads.NewAdsCache(nil))
	testDNSResolver, err := NewAdsDnsResolver(ads.NewAdsCache(nil))
	if err != nil {
		t.Fatal(err)
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	testDNSResolver.StartAdsDnsResolver(stopCh)
	dnsServer := fakeDNSServer.Server.PacketConn.LocalAddr().String()
	testDNSResolver.DnsResolver.resolvConfServers = []string{dnsServer}

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
				fakeDNSServer.setHosts(domain, 1)
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
				fakeDNSServer.setHosts(domain, 2)
				fakeDNSServer.setTTL(uint32(3))
				time.AfterFunc(time.Second, func() {
					fakeDNSServer.setHosts(domain, 3)
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
				fakeDNSServer.setHosts(domain, 2)
				fakeDNSServer.setTTL(uint32(3))
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
				fakeDNSServer.setHosts(domain, 2)
				fakeDNSServer.setTTL(uint32(10))
				time.AfterFunc(time.Second, func() {
					fakeDNSServer.setHosts(domain, 3)
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

		input := &pendingResolveDomain{
			domainName:  testcase.domain,
			refreshRate: testcase.refreshRate,
		}
		testDNSResolver.DnsResolver.Lock()
		testDNSResolver.DnsResolver.cache[testcase.domain] = &domainCacheEntry{}
		testDNSResolver.DnsResolver.Unlock()

		testDNSResolver.DnsResolver.resolve(input)

		time.Sleep(2 * time.Second)

		res := testDNSResolver.DnsResolver.GetDNSAddresses(testcase.domain)
		if len(res) != 0 || len(testcase.expected) != 0 {
			if !reflect.DeepEqual(res, testcase.expected) {
				t.Errorf("dns resolve for %s do not match. \n got %v\nwant %v", testcase.domain, res, testcase.expected)
			}

			if testcase.expectedAfterTTL != nil {
				ttl := time.Duration(math.Min(float64(testcase.ttl), float64(testcase.refreshRate)))
				time.Sleep(ttl + 1)
				res = testDNSResolver.DnsResolver.GetDNSAddresses(testcase.domain)
				if !reflect.DeepEqual(res, testcase.expectedAfterTTL) {
					t.Errorf("dns refresh after ttl failed, for %s do not match. \n got %v\nwant %v", testcase.domain, res, testcase.expectedAfterTTL)
				}
			}
		}
		wg.Done()
	}
	wg.Wait()
}

func newFakeDNSServer() *fakeDNSServer {
	var wg sync.WaitGroup
	wg.Add(1)
	s := &fakeDNSServer{
		Server: &dns.Server{Addr: ":0", Net: "udp", NotifyStartedFunc: wg.Done},
		hosts:  make(map[string]int),
		// default ttl is 20
		ttl: uint32(20),
	}
	s.Handler = s

	go func() {
		if err := s.ListenAndServe(); err != nil {
			log.Errorf("fake dns server error: %v", err)
		}
	}()
	wg.Wait()
	return s
}

func (s *fakeDNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	s.mu.Lock()
	defer s.mu.Unlock()

	msg := (&dns.Msg{}).SetReply(r)
	if s.failure {
		msg.Rcode = dns.RcodeServerFailure
	} else {
		domain := msg.Question[0].Name
		c, ok := s.hosts[domain]
		if ok {
			switch r.Question[0].Qtype {
			case dns.TypeA:
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.ttl},
					A:   net.ParseIP(fmt.Sprintf("10.0.0.%d", c)),
				})
			case dns.TypeAAAA:
				// set a long TTL for AAAA
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.ttl * 10},
					AAAA: net.ParseIP(fmt.Sprintf("fd00::%x", c)),
				})
			// simulate behavior of some public/cloud DNS like Cloudflare or DigitalOcean
			case dns.TypeANY:
				msg.Rcode = dns.RcodeRefused
			default:
				msg.Rcode = dns.RcodeNotImplemented
			}
		} else {
			msg.Rcode = dns.RcodeNameError
		}
	}
	if err := w.WriteMsg(msg); err != nil {
		log.Errorf("failed writing fake DNS response: %v", err)
	}
}

func (s *fakeDNSServer) setHosts(domain string, surfix int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts[dns.Fqdn(domain)] = surfix
}

func (s *fakeDNSServer) setTTL(ttl uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttl = ttl
}

func (r *DNSResolver) GetAllCachedDomains() []string {
	r.RLock()
	defer r.RUnlock()
	out := make([]string, 0, len(r.cache))
	for domain := range r.cache {
		out = append(out, domain)
	}
	return out
}

func (r *DNSResolver) GetDNSAddresses(domain string) []string {
	r.Lock()
	defer r.Unlock()
	if entry, ok := r.cache[domain]; ok {
		return entry.addresses
	}
	return nil
}

func TestGetPendingResolveDomain(t *testing.T) {
	utCluster := clusterv3.Cluster{
		Name: "testCluster",
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			Endpoints: []*endpointv3.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpointv3.LbEndpoint{
						{
							HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
								Endpoint: &endpointv3.Endpoint{
									Address: &v3.Address{
										Address: &v3.Address_SocketAddress{
											SocketAddress: &v3.SocketAddress{
												Address: "192.168.2.1",
												PortSpecifier: &v3.SocketAddress_PortValue{
													PortValue: uint32(9898),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	utClusterWithHost := clusterv3.Cluster{
		Name: "testCluster",
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			Endpoints: []*endpointv3.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpointv3.LbEndpoint{
						{
							HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
								Endpoint: &endpointv3.Endpoint{
									Address: &v3.Address{
										Address: &v3.Address_SocketAddress{
											SocketAddress: &v3.SocketAddress{
												Address: "www.google.com",
												PortSpecifier: &v3.SocketAddress_PortValue{
													PortValue: uint32(9898),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	type args struct {
		clusters []*clusterv3.Cluster
	}
	tests := []struct {
		name string
		args args
		want map[string]*pendingResolveDomain
	}{
		{
			name: "empty domains test",
			args: args{
				clusters: []*clusterv3.Cluster{
					&utCluster,
				},
			},
			want: map[string]*pendingResolveDomain{},
		},
		{
			name: "cluster domain is not IP",
			args: args{
				clusters: []*clusterv3.Cluster{
					&utClusterWithHost,
				},
			},
			want: map[string]*pendingResolveDomain{
				"www.google.com": {
					domainName: "www.google.com",
					clusters:   []*clusterv3.Cluster{&utClusterWithHost},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getPendingResolveDomain(tt.args.clusters); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getPendingResolveDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
