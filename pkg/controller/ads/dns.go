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

package ads

import (
	"net"
	"net/netip"
	"slices"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	core_v2 "kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/pkg/dns"
)

// adsDnsResolver is DNS resolver of Kernel Native
type dnsController struct {
	Clusters    chan []*clusterv3.Cluster
	cache       *AdsCache
	dnsResolver *dns.DNSResolver
}

// pending resolve domain info of Kennel-Native Mode,
// domain name is used for dns resolution
// cluster is used for create the apicluster
type pendingResolveDomain struct {
	DomainName  string
	Clusters    []*clusterv3.Cluster
	RefreshRate time.Duration
}

func NewDnsResolver(adsCache *AdsCache) (*dnsController, error) {
	resolver, err := dns.NewDNSResolver()
	if err != nil {
		return nil, err
	}
	return &dnsController{
		Clusters:    make(chan []*clusterv3.Cluster),
		cache:       adsCache,
		dnsResolver: resolver,
	}, nil
}

func (r *dnsController) StartKernelNativeDnsController(stopCh <-chan struct{}) {
	go r.startDnsController()
	// start dns resolver
	go r.dnsResolver.StartDnsResolver(stopCh)
	go func() {
		<-stopCh
		close(r.Clusters)
	}()
}

func (r *dnsController) startDnsController() {
	rateLimiter := make(chan struct{}, dns.MaxConcurrency)
	for clusters := range r.Clusters {
		rateLimiter <- struct{}{}
		go func(clusters []*clusterv3.Cluster) {
			defer func() {
				<-rateLimiter
			}()
			r.resolveDomains(clusters)
		}(clusters)
	}
}

func (r *dnsController) resolveDomains(cds []*clusterv3.Cluster) {
	domains := getPendingResolveDomain(cds)
	hostNames := make(map[string]struct{})

	for k := range domains {
		hostNames[k] = struct{}{}
	}

	// delete any scheduled re-resolve for domains we no longer care about
	r.dnsResolver.RemoveUnwatchDomain(hostNames)
	// Directly update the clusters that can find the dns resolution result in the cache
	alreadyResolveDomains := r.dnsResolver.GetAddressesFromCache(hostNames)
	for k, v := range alreadyResolveDomains {
		pendingDomain := domains[k]
		r.adsDnsResolve(pendingDomain, v.Addresses)
		r.cache.ClusterCache.Flush()
		delete(domains, k)
	}

	for k, v := range domains {
		r.dnsResolver.ResolveDomains(k)
		domainInfo := &dns.DomainInfo{
			Domain:      v.DomainName,
			RefreshRate: v.RefreshRate,
		}
		r.dnsResolver.AddDomainIntoRefreshQueue(domainInfo, 0)
	}
	go r.refreshAdsWorker(domains)
}

func (r *dnsController) refreshAdsWorker(domains map[string]*pendingResolveDomain) {
	for !(len(domains) == 0) {
		domain := <-r.dnsResolver.DnsChan
		v, ok := domains[domain]
		// will this happen?
		if !ok {
			continue
		}
		addresses, _ := r.dnsResolver.GetOneDomainFromCache(domain)
		r.adsDnsResolve(v, addresses)
		r.cache.ClusterCache.Flush()
		delete(domains, domain)
	}
}

func (r *dnsController) adsDnsResolve(pendingDomain *pendingResolveDomain, addrs []string) {
	for _, cluster := range pendingDomain.Clusters {
		ready := overwriteDnsCluster(cluster, pendingDomain.DomainName, addrs)
		if ready {
			if !r.cache.UpdateApiClusterIfExists(core_v2.ApiStatus_UPDATE, cluster) {
				log.Debugf("cluster: %s is deleted", cluster.Name)
				return
			}
		}
	}
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
				LoadBalancingWeight: &wrapperspb.UInt32Value{
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

func getPendingResolveDomain(cds []*clusterv3.Cluster) map[string]*pendingResolveDomain {
	domains := make(map[string]*pendingResolveDomain)

	for _, cluster := range cds {
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
				if _, err := netip.ParseAddr(address); err == nil {
					// This is an ip address
					continue
				}

				if v, ok := domains[address]; ok {
					v.Clusters = append(v.Clusters, cluster)
				} else {
					domainWithRefreshRate := &pendingResolveDomain{
						DomainName:  address,
						Clusters:    []*clusterv3.Cluster{cluster},
						RefreshRate: cluster.GetDnsRefreshRate().AsDuration(),
					}
					domains[address] = domainWithRefreshRate
				}
			}
		}
	}

	return domains
}
