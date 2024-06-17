/*
 * Copyright 2024 The Kmesh Authors.
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
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
	"k8s.io/client-go/util/workqueue"
	"kmesh.net/kmesh/pkg/logger"
)

var (
	log = logger.NewLoggerField("ads_controller")
)

type DNSResolver struct {
	DnsResolverChan   chan map[string]time.Duration
	client            *dns.Client
	resolvConfServers []string
	cache             map[string]domainCacheEntry
	// dns refresh priority queue based on exp
	dnsRefreshQueue workqueue.DelayingInterface
	sync.RWMutex
}

// domainCacheEntry stores dns result with expiry time, and also response to trigger dns refresh
type domainCacheEntry struct {
	value  []string
	expiry time.Time
}

type domainWithRefreshRate struct {
	name        string
	refreshRate time.Duration
}

const MaxConcurrency uint32 = 5

func NewDNSResolver() (*DNSResolver, error) {
	r := &DNSResolver{
		DnsResolverChan: make(chan map[string]time.Duration),
		cache:           map[string]domainCacheEntry{},
		dnsRefreshQueue: workqueue.NewDelayingQueue(),
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
			r.resolvConfServers = append(r.resolvConfServers, net.JoinHostPort(s, dnsConfig.Port))
		}
	}

	return r, nil
}

func (r *DNSResolver) StartDNSResolver(stopCh <-chan struct{}) {
	go r.startResolver()
	go r.refreshDNS()
	go func() {
		<-stopCh
		r.dnsRefreshQueue.ShutDown()
		close(r.DnsResolverChan)
	}()
}

// startResolver watches the DnsResolver Channel
func (r *DNSResolver) startResolver() {
	temp := make(chan struct{}, MaxConcurrency)
	var wg sync.WaitGroup
	for domains := range r.DnsResolverChan {
		temp <- struct{}{}
		wg.Add(1)

		go func(domains map[string]time.Duration) {
			defer wg.Done()
			defer func() { <-temp }()
			r.resolveDomains(domains)
		}(domains)
	}
	wg.Wait()
}

// resolveDomains takes a map of hostnames and refresh rate
func (r *DNSResolver) resolveDomains(domains map[string]time.Duration) {
	// Stow domain updates, need to remove unwatched domains first
	r.removeUnwatchedDomain(domains)

	for name, refreshRate := range domains {
		addrs := r.resolve(name, refreshRate)
		log.Debugf("resolve dns , name: %s, addr: %v\n", name, addrs)
		r.updateBPFMap(name, addrs)
	}
}

// removeUnwatchedDomain cancels any scheduled re-resolve for names we no longer care about
func (r *DNSResolver) removeUnwatchedDomain(domains map[string]time.Duration) {
	r.Lock()
	defer r.Unlock()
	for name := range r.cache {
		if _, ok := domains[name]; ok {
			continue
		}
		delete(r.cache, name)
		r.deleteBPFMap(name)
	}
}

// This functions were copied and adapted from github.com/istio/istio/pilot/pkg/model/network.go.
func (r *DNSResolver) resolve(name string, refreshRate time.Duration) []string {
	if entry, ok := r.cache[name]; ok && entry.expiry.After(time.Now()) {
		return entry.value
	}

	r.Lock()
	defer r.Unlock()
	// ideally this will not happen more than once for each name and the cache auto-updates in the background
	// even if it does, this happens on the SotW ingestion path (kube or meshnetworks changes)
	entry := r.cache[name]
	delete(r.cache, name)
	addrs, ttl, err := r.doResolve(name, refreshRate)
	// refresh the dns address periodically by respecting the dnsRefreshRate and ttl, which one is shorter
	if ttl > refreshRate {
		ttl = refreshRate
	}
	expiry := time.Now().Add(ttl)
	if err != nil {
		// gracefully retain old addresses in case the DNS server is unavailable
		addrs = entry.value
	}

	r.cache[name] = domainCacheEntry{
		value:  addrs,
		expiry: expiry,
	}

	dr := &domainWithRefreshRate{
		name:        name,
		refreshRate: refreshRate,
	}
	// push torefresh queue one second before dns expire
	r.dnsRefreshQueue.AddAfter(dr, time.Until(expiry))
	return addrs
}

// refreshDNS is triggered via time.AfterFunc and will recursively schedule itself that way until timer is cleaned
// up via removeUnwatchedDomain.
func (r *DNSResolver) refreshDNS() {
	for {
		element, quit := r.dnsRefreshQueue.Get()
		if quit {
			return
		}
		r.RLock()
		dr := element.(*domainWithRefreshRate)
		old := r.cache[dr.name]
		r.RUnlock()
		addrs := r.resolve(dr.name, dr.refreshRate)
		r.dnsRefreshQueue.Done(element)
		sort.Strings(old.value)
		sort.Strings(addrs)
		if !slices.Equal(old.value, addrs) {
			log.Debugf("update dns , name: %s, old addr: %v, new addr: %v\n", dr.name, old.value, addrs)
			r.updateBPFMap(dr.name, addrs)
		}
	}
}

func (r *DNSResolver) GetCacheResult(name string) []string {
	var res []string
	if entry, ok := r.cache[name]; ok {
		res = entry.value
	}
	return res
}

// TODO:: update the bpf map
func (r *DNSResolver) updateBPFMap(name string, addrs []string) {
	// maps_v2.DNSUpdate(name, addrs)
}

// TODO:: delete the bpf map
func (r *DNSResolver) deleteBPFMap(name string) {
	// maps_v2.DNSDelete(name)
}

// This functions were copied and adapted from github.com/istio/istio/pilot/pkg/model/network.go.
func (r *DNSResolver) doResolve(domain string, refreshRate time.Duration) ([]string, time.Duration, error) {
	var out []string
	ttl := refreshRate
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
		if minTTL := getMinTTL(res, refreshRate); minTTL < ttl {
			ttl = minTTL
		}
	}

	wg.Add(2)
	go doResolve(dns.TypeA)
	go doResolve(dns.TypeAAAA)
	wg.Wait()

	if len(errs) == 2 {
		// return error only if all requests are failed
		return out, refreshRate, fmt.Errorf("upstream dns failure")
	}
	return out, ttl, nil
}

// This functions were copied and adapted from github.com/istio/istio/pilot/pkg/model/network.go.
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
