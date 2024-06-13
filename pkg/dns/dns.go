package dns

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/miekg/dns"
)

type DNSResolver struct {
	DnsResolverChan   chan map[string]time.Duration
	client            *dns.Client
	resolvConfServers []string
	cache             map[string]domainCacheEntry
	sync.Mutex
}

// domainCacheEntry stores dns result with expiry time, and also response to trigger dns refresh
type domainCacheEntry struct {
	value  []string
	expiry time.Time
	timer  *time.Timer
}

func NewDNSResolver() (*DNSResolver, error) {
	r := &DNSResolver{
		DnsResolverChan: make(chan map[string]time.Duration),
		cache:           map[string]domainCacheEntry{},
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

func (r *DNSResolver) Start() {
	go r.startResolver()
}

// startResolver watches the DnsResolver Channel
func (r *DNSResolver) startResolver() {
	for domains := range r.DnsResolverChan {
		r.resolveDomains(domains)
	}
}

// resolveDomains takes a map of hostnames and refresh rate
func (r *DNSResolver) resolveDomains(domains map[string]time.Duration) {
	r.Lock()
	defer r.Unlock()

	// Stow domain updates, need to remove unwatched domains first
	r.removeUnwatchedDomain(domains)

	for name, refreshRate := range domains {
		r.resolve(name, refreshRate)
	}
	r.refreshBPFMap()
}

// removeUnwatchedDomain cancels any scheduled re-resolve for names we no longer care about
func (r *DNSResolver) removeUnwatchedDomain(domains map[string]time.Duration) {
	for name, entry := range r.cache {
		if _, ok := domains[name]; ok {
			continue
		}
		entry.timer.Stop()
		delete(r.cache, name)
	}
}

// This functions were copied and adapted from github.com/istio/istio.
func (r *DNSResolver) resolve(name string, refreshRate time.Duration) []string {
	if entry, ok := r.cache[name]; ok && entry.expiry.After(time.Now()) {
		return entry.value
	}
	// ideally this will not happen more than once for each name and the cache auto-updates in the background
	// even if it does, this happens on the SotW ingestion path (kube or meshnetworks changes)
	entry, ok := r.cache[name]
	if ok {
		entry.timer.Stop()
	}
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
		// TTL expires, try to refresh TODO should this be < ttl?
		timer: time.AfterFunc(ttl, r.refreshDNS(name, refreshRate)),
	}

	return addrs
}

// refreshDNS is triggered via time.AfterFunc and will recursively schedule itself that way until timer is cleaned
// up via removeUnwatchedDomain.
func (r *DNSResolver) refreshDNS(name string, refreshRate time.Duration) func() {
	return func() {
		r.Lock()
		old := r.cache[name]
		addrs := r.resolve(name, refreshRate)
		r.Unlock()

		if !slices.Equal(old.value, addrs) {
			r.refreshBPFMap()
		}
	}
}

// TODO:: update the bpf map
func (r *DNSResolver) refreshBPFMap() {
}

// This functions were copied and adapted from github.com/istio/istio.
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

// This functions were copied and adapted from github.com/istio/istio.
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

// This functions were copied and adapted from github.com/istio/istio.
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

// Get domain name and refreshrate from cluster, the STRIC_DNS typed cluster name could be something like
// outbound|8080||test.default.svc.cluster.local, and also it should contains the dns refresh rate.
func GetDoaminAndRefreshRateFromCluster(cluster *config_cluster_v3.Cluster) (string, time.Duration) {
	var name string

	clusterName := cluster.GetName()

	parts := strings.Split(clusterName, "|")

	if len(parts) == 4 {
		name = parts[3]
		refreshRate := cluster.GetDnsRefreshRate().AsDuration()
		return name, refreshRate
	}
	// return 1 minute as default refreshrate to avord Infinite loop
	return name, time.Minute
}
