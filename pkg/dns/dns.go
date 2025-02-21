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
	"net"
	"sort"
	"sync"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/miekg/dns"

	"kmesh.net/kmesh/pkg/logger"
)

var (
	log = logger.NewLoggerScope("dns_resolver")
)

const (
	MaxConcurrency    uint32 = 5
	RetryAfter               = 5 * time.Millisecond
	DeRefreshInterval        = 15 * time.Second
)

type DNSResolver struct {
	client            *dns.Client
	ResolvConfServers []string
	Cache             map[string]*DomainCacheEntry
	sync.RWMutex
}

type DomainCacheEntry struct {
	addresses []string
}

// pending resolve domain info of Kennel-Native Mode,
// domain name is used for dns resolution
// cluster is used for create the apicluster
type PendingResolveDomain struct {
	DomainName  string
	Clusters    []*clusterv3.Cluster
	RefreshRate time.Duration
}

func NewDNSResolver() (*DNSResolver, error) {
	r := &DNSResolver{
		Cache: map[string]*DomainCacheEntry{},
		client: &dns.Client{
			DialTimeout:  5 * time.Second,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
	}

	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	if dnsConfig != nil {
		for _, s := range dnsConfig.Servers {
			r.ResolvConfServers = append(r.ResolvConfServers, net.JoinHostPort(s, dnsConfig.Port))
		}
	}

	return r, nil
}

// removeUnwatchedDomain cancels any scheduled re-resolve for names we no longer care about
func (r *DNSResolver) RemoveUnwatchedDomain(domains map[string]*PendingResolveDomain) {
	r.Lock()
	defer r.Unlock()
	for domain := range r.Cache {
		if _, ok := domains[domain]; ok {
			continue
		}
		delete(r.Cache, domain)
	}
}

// This functions were copied and adapted from github.com/istio/istio/pilot/pkg/model/network.go.
func (r *DNSResolver) Resolve(domainName string) ([]string, time.Duration, error) {
	r.RLock()
	entry := r.Cache[domainName]
	// This can happen when the domain is deleted before the refresher tick reaches
	if entry == nil {
		r.RUnlock()
		return []string{}, DeRefreshInterval, fmt.Errorf("cache entry for domain %s not found", domainName)
	}
	r.RUnlock()

	addrs, ttl, err := r.doResolve(domainName)
	if err != nil {
		return []string{}, DeRefreshInterval, fmt.Errorf("dns resolve failed: %v", err)
	}

	r.RLock()
	entry.addresses = addrs
	r.RUnlock()

	return addrs, ttl, nil
}

// resolveDomains takes a slice of cluster
func (r *DNSResolver) ResolveDomains(domainName string) {
	r.Lock()
	if r.Cache[domainName] == nil {
		r.Cache[domainName] = &DomainCacheEntry{}
	}
	r.Unlock()
}

// doResolve is copied and adapted from github.com/istio/istio/pilot/pkg/model/network.go.
func (r *DNSResolver) doResolve(domain string) ([]string, time.Duration, error) {
	var out []string
	ttl := DeRefreshInterval
	var mu sync.Mutex
	var wg sync.WaitGroup
	var errs = []error{}

	doResolve := func(dnsType uint16) {
		defer wg.Done()

		res := r.Query(new(dns.Msg).SetQuestion(dns.Fqdn(domain), dnsType))

		mu.Lock()
		defer mu.Unlock()
		if res.Rcode == dns.RcodeServerFailure {
			errs = append(errs, fmt.Errorf("upstream dns failure, qtype: %v", dnsType))
			return
		}
		for _, rr := range res.Answer {
			switch record := rr.(type) {
			case *dns.A:
				out = append(out, record.A.String())
			case *dns.AAAA:
				out = append(out, record.AAAA.String())
			}
		}
		if minTTL := getMinTTL(res, DeRefreshInterval); minTTL < ttl {
			ttl = minTTL
		}
	}

	wg.Add(2)
	go doResolve(dns.TypeA)
	go doResolve(dns.TypeAAAA)
	wg.Wait()

	if len(errs) == 2 {
		// return error only if all requests are failed
		return out, DeRefreshInterval, fmt.Errorf("upstream dns failure")
	}

	sort.Strings(out)
	return out, ttl, nil
}

// Query is copied and adapted from github.com/istio/istio/pilot/pkg/model/network.go.
func (r *DNSResolver) Query(req *dns.Msg) *dns.Msg {
	var response *dns.Msg
	for _, upstream := range r.ResolvConfServers {
		resp, _, err := r.client.Exchange(req, upstream)
		if err != nil || resp == nil {
			continue
		}

		response = resp
		if resp.Rcode == dns.RcodeSuccess {
			break
		}
	}
	if response == nil {
		response = new(dns.Msg)
		response.SetReply(req)
		response.Rcode = dns.RcodeServerFailure
	}
	return response
}

// This functions were copied and adapted from github.com/istio/istio/pilot/pkg/model/network.go.
func getMinTTL(m *dns.Msg, refreshRate time.Duration) time.Duration {
	// No records or OPT is the only record, return a short ttl as a fail safe.
	if len(m.Answer)+len(m.Ns) == 0 &&
		(len(m.Extra) == 0 || (len(m.Extra) == 1 && m.Extra[0].Header().Rrtype == dns.TypeOPT)) {
		return refreshRate
	}

	minTTL := refreshRate
	for _, r := range m.Answer {
		if r.Header().Ttl < uint32(minTTL.Seconds()) {
			minTTL = time.Duration(r.Header().Ttl) * time.Second
		}
	}
	for _, r := range m.Ns {
		if r.Header().Ttl < uint32(minTTL.Seconds()) {
			minTTL = time.Duration(r.Header().Ttl) * time.Second
		}
	}

	for _, r := range m.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			// OPT records use TTL field for extended rcode and flags
			continue
		}
		if r.Header().Ttl < uint32(minTTL.Seconds()) {
			minTTL = time.Duration(r.Header().Ttl) * time.Second
		}
	}
	return minTTL
}

func (r *DNSResolver) GetAllCachedDomains() []string {
	r.RLock()
	defer r.RUnlock()
	out := make([]string, 0, len(r.Cache))
	for domain := range r.Cache {
		out = append(out, domain)
	}
	return out
}
