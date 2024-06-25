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

	config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/miekg/dns"
	"k8s.io/client-go/util/workqueue"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/pkg/controller/ads"
	"kmesh.net/kmesh/pkg/logger"
)

var (
	log = logger.NewLoggerField("ads_controller")
)

const MaxConcurrency uint32 = 5

type DNSResolver struct {
	DnsResolverChan   chan []*config_cluster_v3.Cluster
	client            *dns.Client
	resolvConfServers []string
	cache             map[string]*domainCacheEntry
	// adsCache is used for update bpf map
	adsCache *ads.AdsCache
	// dns refresh priority queue based on exp
	dnsRefreshQueue workqueue.DelayingInterface
	sync.RWMutex
}

// domainCacheEntry stores dns result with expiry time, and also response to trigger dns refresh
type domainCacheEntry struct {
	clusterName string
	value       []string
	expiry      time.Time
}

// pending resolve domain info,
// domain name is used for dns resolution
// cluster is used for create teh apicluster
// port is used for creating the apicluster endpoint
type pendingResolveDomain struct {
	domainName  string
	port        uint32
	cluster     *config_cluster_v3.Cluster
	refreshRate time.Duration
}

func (p *pendingResolveDomain) setAddrsToCluster(addrs []string) {
	lbEndpoints := []*config_endpoint_v3.LbEndpoint{}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() == nil {
			continue
		}
		lbEndpoint := &config_endpoint_v3.LbEndpoint{
			HealthStatus: v3.HealthStatus_HEALTHY,
			HostIdentifier: &config_endpoint_v3.LbEndpoint_Endpoint{
				Endpoint: &config_endpoint_v3.Endpoint{
					Address: &v3.Address{
						Address: &v3.Address_SocketAddress{
							SocketAddress: &v3.SocketAddress{
								Address: addr,
								PortSpecifier: &v3.SocketAddress_PortValue{
									PortValue: uint32(p.port),
								},
							},
						},
					},
				},
			},
		}
		lbEndpoints = append(lbEndpoints, lbEndpoint)
	}

	if p.cluster.LoadAssignment != nil {
		p.cluster.LoadAssignment.Endpoints = []*config_endpoint_v3.LocalityLbEndpoints{
			{
				LbEndpoints: lbEndpoints,
			},
		}
	}
}

func NewDNSResolver() (*DNSResolver, error) {
	r := &DNSResolver{
		DnsResolverChan: make(chan []*config_cluster_v3.Cluster),
		cache:           map[string]*domainCacheEntry{},
		adsCache:        ads.NewAdsCache(),
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
	for clusters := range r.DnsResolverChan {
		temp <- struct{}{}

		go func(clusters []*config_cluster_v3.Cluster) {
			defer func() { <-temp }()
			r.resolveDomains(clusters)
		}(clusters)
	}
}

// resolveDomains takes a map of hostnames and refresh rate
func (r *DNSResolver) resolveDomains(clusters []*config_cluster_v3.Cluster) {
	domains := getPendingResolveDomain(clusters)

	// Stow domain updates, need to remove unwatched domains first
	r.removeUnwatchedDomain(domains)
	for _, v := range domains {
		r.resolve(v)
	}
	r.adsCache.ClusterCache.Flush()
}

// removeUnwatchedDomain cancels any scheduled re-resolve for names we no longer care about
func (r *DNSResolver) removeUnwatchedDomain(domains map[string]*pendingResolveDomain) {
	r.Lock()
	defer r.Unlock()
	for name, value := range r.cache {
		if _, ok := domains[name]; ok {
			continue
		}
		r.adsCache.UpdateApiClusterStatus(value.clusterName, core_v2.ApiStatus_DELETE)
		delete(r.cache, name)
	}
}

// This functions were copied and adapted from github.com/istio/istio/pilot/pkg/model/network.go.
func (r *DNSResolver) resolve(v *pendingResolveDomain) {
	if entry, ok := r.cache[v.domainName]; ok && entry.expiry.After(time.Now()) {
		return
	}

	r.Lock()
	// ideally this will not happen more than once for each name and the cache auto-updates in the background
	// even if it does, this happens on the SotW ingestion path (kube or meshnetworks changes)
	entry := r.cache[v.domainName]
	delete(r.cache, v.domainName)
	r.Unlock()

	addrs, ttl, err := r.doResolve(v.domainName, v.refreshRate)
	// refresh the dns address periodically by respecting the dnsRefreshRate and ttl, which one is shorter
	if ttl > v.refreshRate {
		ttl = v.refreshRate
	}
	expiry := time.Now().Add(ttl)
	if err != nil {
		// gracefully retain old addresses in case the DNS server is unavailable
		addrs = entry.value
	}

	r.cache[v.domainName] = &domainCacheEntry{
		value:       addrs,
		clusterName: v.cluster.GetName(),
		expiry:      expiry,
	}

	// push to refresh queue
	r.dnsRefreshQueue.AddAfter(v, time.Until(expiry))

	if entry == nil {
		// for the newly resolved domain just push to bpf map
		log.Infof("resolve dns , name: %s, addr: %v\n", v.domainName, addrs)
		v.setAddrsToCluster(addrs)
		r.adsCache.CreateApiClusterByCds(core_v2.ApiStatus_UPDATE, v.cluster)
	} else {
		// for the updated domain, push to bpf map only when there are changes
		sort.Strings(entry.value)
		sort.Strings(addrs)
		if !slices.Equal(entry.value, addrs) {
			log.Infof("resolve dns , name: %s, addr: %v\n", v.domainName, addrs)
			v.setAddrsToCluster(addrs)
			r.adsCache.CreateApiClusterByCds(core_v2.ApiStatus_UPDATE, v.cluster)
		}
	}
}

// refreshDNS use a delay working queue to handle dns refresh
func (r *DNSResolver) refreshDNS() {
	for {
		element, quit := r.dnsRefreshQueue.Get()
		if quit {
			return
		}
		r.RLock()
		dr := element.(*pendingResolveDomain)
		old := r.cache[dr.domainName]
		r.RUnlock()

		// is the domain is no longer watched, no need to refresh it
		if old == nil {
			return
		}

		r.resolve(dr)
		r.adsCache.ClusterCache.Flush()
		r.dnsRefreshQueue.Done(element)
	}
}

func (r *DNSResolver) GetCacheResult(name string) []string {
	var res []string
	if entry, ok := r.cache[name]; ok {
		res = entry.value
	}
	return res
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

// Get domain name and refreshrate from cluster, and also store cluster and port in the return value for later use
func getPendingResolveDomain(clusters []*config_cluster_v3.Cluster) map[string]*pendingResolveDomain {
	domains := make(map[string]*pendingResolveDomain)

	for _, cluster := range clusters {
		refreshRate := cluster.GetDnsRefreshRate().AsDuration()
		if cluster.LoadAssignment == nil {
			continue
		}
		if cluster.LoadAssignment.Endpoints == nil {
			continue
		}

		for _, e := range cluster.LoadAssignment.Endpoints {
			for _, le := range e.LbEndpoints {
				socketAddr := le.GetEndpoint().GetAddress().GetAddress().(*core_v3.Address_SocketAddress)
				domainWithRefreshRate := &pendingResolveDomain{
					domainName:  socketAddr.SocketAddress.Address,
					port:        socketAddr.SocketAddress.GetPortValue(),
					cluster:     cluster,
					refreshRate: refreshRate,
				}
				domains[socketAddr.SocketAddress.Address] = domainWithRefreshRate
			}
		}
	}

	return domains
}
