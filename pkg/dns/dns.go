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

	"github.com/miekg/dns"
	"k8s.io/client-go/util/workqueue"

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
	DnsChan           chan string
	resolvConfServers []string
	cache             map[string]*DomainCacheEntry
	refreshQueue      workqueue.TypedDelayingInterface[any]
	sync.RWMutex
}

type DomainCacheEntry struct {
	Addresses []string
}

type DomainInfo struct {
	Domain      string
	RefreshRate time.Duration
}

func NewDNSResolver() (*DNSResolver, error) {
	r := &DNSResolver{
		DnsChan: make(chan string, 100),
		cache:   map[string]*DomainCacheEntry{},
		client: &dns.Client{
			DialTimeout:  5 * time.Second,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		refreshQueue: workqueue.NewTypedDelayingQueueWithConfig(workqueue.TypedDelayingQueueConfig[any]{Name: "refreshQueue"}),
	}

	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	if dnsConfig != nil {
		for _, s := range dnsConfig.Servers {
			r.resolvConfServers = append(r.resolvConfServers, net.JoinHostPort(s, dnsConfig.Port))
		}
	}

	return r, nil
}

func (r *DNSResolver) StartDnsResolver(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			r.refreshQueue.ShutDown()
			return
		default:
			r.refreshDns()
		}
	}
}

func (r *DNSResolver) refreshDns() {
	element, quit := r.refreshQueue.Get()
	if quit {
		return
	}
	defer r.refreshQueue.Done(element)
	e := element.(*DomainInfo)

	r.Lock()
	_, exist := r.cache[e.Domain]
	r.Unlock()
	// if the domain is no longer watched, no need to refresh it
	if !exist {
		return
	}
	_, ttl, err := r.resolve(e.Domain)
	if err != nil {
		log.Errorf("failed to dns resolve: %v", err)
		return
	}
	if ttl > e.RefreshRate {
		ttl = e.RefreshRate
	}
	if ttl == 0 {
		ttl = DeRefreshInterval
	}
	r.refreshQueue.AddAfter(e, ttl)
	r.DnsChan <- e.Domain
}

// This functions were copied and adapted from github.com/istio/istio/pilot/pkg/model/network.go.
func (r *DNSResolver) resolve(domainName string) ([]string, time.Duration, error) {
	r.RLock()
	entry := r.cache[domainName]
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
	entry.Addresses = addrs
	r.RUnlock()

	return addrs, ttl, nil
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
	for _, upstream := range r.resolvConfServers {
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
	out := make([]string, 0, len(r.cache))
	for domain := range r.cache {
		out = append(out, domain)
	}
	return out
}

func (r *DNSResolver) GetDomainAddress(domain string) ([]string, bool) {
	r.RLock()
	addresses, ok := r.cache[domain]
	r.RUnlock()
	return addresses.Addresses, ok
}

func (r *DNSResolver) GetBatchAddressesFromCache(domains map[string]struct{}) map[string]*DomainCacheEntry {
	r.RLock()
	defer r.RUnlock()

	alreadyResolveDomains := make(map[string]*DomainCacheEntry)
	for domain := range domains {
		if v, ok := r.cache[domain]; ok {
			alreadyResolveDomains[domain] = v
		}
	}
	return alreadyResolveDomains
}

func (r *DNSResolver) RemoveUnwatchDomain(domains map[string]interface{}) {
	r.Lock()
	defer r.Unlock()

	for domain := range r.cache {
		if _, ok := domains[domain]; ok {
			continue
		}
		delete(r.cache, domain)
	}
}

func (r *DNSResolver) AddDomainInQueue(info *DomainInfo, time time.Duration) {
	if info == nil {
		return
	}

	// init pending domain in dns cache
	r.Lock()
	if r.cache[info.Domain] == nil {
		r.cache[info.Domain] = &DomainCacheEntry{}
	}
	r.Unlock()

	r.refreshQueue.AddAfter(info, time)
}
