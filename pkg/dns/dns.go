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
	"net/netip"
	"sort"
	"sync"
	"time"

	"slices"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/miekg/dns"
	"k8s.io/client-go/util/workqueue"

	core_v2 "kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/pkg/controller/ads"
	"kmesh.net/kmesh/pkg/logger"
)

var (
	log = logger.NewLoggerField("dns_resolver")
)

const (
	MaxConcurrency uint32 = 5
	RetryAfter            = 5 * time.Millisecond
)

type DNSResolver struct {
	DnsResolverChan   chan []*clusterv3.Cluster
	client            *dns.Client
	resolvConfServers []string
	cache             map[string]*domainCacheEntry
	// adsCache is used for update bpf map
	adsCache *ads.AdsCache
	// dns refresh priority queue based on exp
	dnsRefreshQueue workqueue.DelayingInterface
	sync.RWMutex
}

type domainCacheEntry struct {
	addresses []string
}

// pending resolve domain info,
// domain name is used for dns resolution
// cluster is used for create the apicluster
type pendingResolveDomain struct {
	domainName  string
	clusters    []*clusterv3.Cluster
	refreshRate time.Duration
}

func overwriteDnsCluster(cluster *clusterv3.Cluster, domain string, addrs []string) bool {
	buildLbEndpoints := func(port uint32) []*endpointv3.LbEndpoint {
		lbEndpoints := make([]*endpointv3.LbEndpoint, 0, len(addrs))
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip == nil {
				continue
			}
			if ip.To4() == nil {
				continue
			}
			lbEndpoint := &endpointv3.LbEndpoint{
				HealthStatus: v3.HealthStatus_HEALTHY,
				HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
					Endpoint: &endpointv3.Endpoint{
						Address: &v3.Address{
							Address: &v3.Address_SocketAddress{
								SocketAddress: &v3.SocketAddress{
									Address: addr,
									PortSpecifier: &v3.SocketAddress_PortValue{
										PortValue: port,
									},
								},
							},
						},
					},
				},
				// TODO: support LoadBalancingWeight
				LoadBalancingWeight: &wrappers.UInt32Value{
					Value: 1,
				},
			}
			lbEndpoints = append(lbEndpoints, lbEndpoint)
		}
		return lbEndpoints
	}

	ready := true
	for _, e := range cluster.LoadAssignment.Endpoints {
		pos := -1
		var lbEndpoints []*endpointv3.LbEndpoint
		for i, le := range e.LbEndpoints {
			socketAddr, ok := le.GetEndpoint().GetAddress().GetAddress().(*v3.Address_SocketAddress)
			if !ok {
				continue
			}
			_, err := netip.ParseAddr(socketAddr.SocketAddress.Address)
			if err != nil {
				if socketAddr.SocketAddress.Address == domain {
					pos = i
					lbEndpoints = buildLbEndpoints(socketAddr.SocketAddress.GetPortValue())
				} else {
					// There is other domains not resolved for this cluster
					ready = false
				}
			}
		}
		if pos >= 0 {
			e.LbEndpoints = slices.Replace(e.LbEndpoints, pos, pos+1, lbEndpoints...)
		}
	}

	return ready
}

func NewDNSResolver(adsCache *ads.AdsCache) (*DNSResolver, error) {
	r := &DNSResolver{
		DnsResolverChan: make(chan []*clusterv3.Cluster),
		cache:           map[string]*domainCacheEntry{},
		adsCache:        adsCache,
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
	go r.refreshWorker()
	go func() {
		<-stopCh
		r.dnsRefreshQueue.ShutDown()
		close(r.DnsResolverChan)
	}()
}

// startResolver watches the DnsResolver Channel
func (r *DNSResolver) startResolver() {
	rateLimiter := make(chan struct{}, MaxConcurrency)
	for clusters := range r.DnsResolverChan {
		rateLimiter <- struct{}{}
		go func(clusters []*clusterv3.Cluster) {
			defer func() { <-rateLimiter }()
			r.resolveDomains(clusters)
		}(clusters)
	}
}

// resolveDomains takes a slice of cluster
func (r *DNSResolver) resolveDomains(clusters []*clusterv3.Cluster) {
	domains := getPendingResolveDomain(clusters)

	// Stow domain updates, need to remove unwatched domains first
	r.removeUnwatchedDomain(domains)
	for _, v := range domains {
		r.Lock()
		if r.cache[v.domainName] == nil {
			r.cache[v.domainName] = &domainCacheEntry{}
		}
		r.Unlock()
		r.dnsRefreshQueue.AddAfter(v, 0)
	}
}

// removeUnwatchedDomain cancels any scheduled re-resolve for names we no longer care about
func (r *DNSResolver) removeUnwatchedDomain(domains map[string]*pendingResolveDomain) {
	r.Lock()
	defer r.Unlock()
	for domain := range r.cache {
		if _, ok := domains[domain]; ok {
			continue
		}
		delete(r.cache, domain)
	}
}

// This functions were copied and adapted from github.com/istio/istio/pilot/pkg/model/network.go.
func (r *DNSResolver) resolve(v *pendingResolveDomain) {
	r.RLock()
	entry := r.cache[v.domainName]
	// This can happen when the domain is deleted before the refresher tick reaches
	if entry == nil {
		r.RUnlock()
		return
	}

	r.RUnlock()

	addrs, ttl, err := r.doResolve(v.domainName, v.refreshRate)
	if err == nil {
		// for the newly resolved domain just push to bpf map
		log.Infof("resolve dns name: %s, addr: %v", v.domainName, addrs)
		// refresh the dns address periodically by respecting the dnsRefreshRate and ttl, which one is shorter
		if ttl > v.refreshRate {
			ttl = v.refreshRate
		}
		if !slices.Equal(entry.addresses, addrs) {
			for _, c := range v.clusters {
				ready := overwriteDnsCluster(c, v.domainName, addrs)
				if ready {
					if !r.adsCache.UpdateApiClusterIfExists(core_v2.ApiStatus_UPDATE, c) {
						log.Debugf("cluster: %s is deleted", c.Name)
						return
					}
				}
			}
		}
		r.Lock()
		entry.addresses = addrs
		r.Unlock()
	} else {
		ttl = RetryAfter
		log.Errorf("resolve domain %s failed: %v, retry after %v", v.domainName, err, ttl)
	}

	// push to refresh queue
	r.dnsRefreshQueue.AddAfter(v, ttl)
}

func (r *DNSResolver) refreshWorker() {
	for r.refreshDNS() {
	}
}

// refreshDNS use a delay working queue to handle dns refresh
func (r *DNSResolver) refreshDNS() bool {
	element, quit := r.dnsRefreshQueue.Get()
	if quit {
		return false
	}
	defer r.dnsRefreshQueue.Done(element)
	dr := element.(*pendingResolveDomain)
	r.RLock()
	_, exist := r.cache[dr.domainName]
	r.RUnlock()
	// if the domain is no longer watched, no need to refresh it
	if !exist {
		return true
	}
	r.resolve(dr)
	r.adsCache.ClusterCache.Flush()
	return true
}

func (r *DNSResolver) GetCacheResult(name string) []string {
	var res []string
	r.RLock()
	defer r.RUnlock()
	if entry, ok := r.cache[name]; ok {
		res = entry.addresses
	}
	return res
}

// doResolve is copied and adapted from github.com/istio/istio/pilot/pkg/model/network.go.
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

// Get domain name and refreshrate from cluster, and also store cluster and port in the return addresses for later use
func getPendingResolveDomain(clusters []*clusterv3.Cluster) map[string]*pendingResolveDomain {
	domains := make(map[string]*pendingResolveDomain)

	for _, cluster := range clusters {
		if cluster.LoadAssignment == nil {
			continue
		}

		for _, e := range cluster.LoadAssignment.Endpoints {
			for _, le := range e.LbEndpoints {
				socketAddr, ok := le.GetEndpoint().GetAddress().GetAddress().(*v3.Address_SocketAddress)
				if !ok {
					continue
				}
				address := socketAddr.SocketAddress.Address
				if _, err := netip.ParseAddr(address); err != nil {
					// This is an ip address
					continue
				}

				if v, ok := domains[address]; ok {
					v.clusters = append(v.clusters, cluster)
				} else {
					domainWithRefreshRate := &pendingResolveDomain{
						domainName:  address,
						clusters:    []*clusterv3.Cluster{cluster},
						refreshRate: cluster.GetDnsRefreshRate().AsDuration(),
					}
					domains[address] = domainWithRefreshRate
				}
			}
		}
	}

	return domains
}
