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

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/client-go/util/workqueue"

	core_v2 "kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/pkg/dns"
)

// adsDnsResolver is DNS resolver of Kernel Native
type AdsDnsResolver struct {
	Clusters        chan []*clusterv3.Cluster
	adsCache        *AdsCache
	dnsResolver     *dns.DNSResolver
	dnsRefreshQueue workqueue.TypedDelayingInterface[any]
}

func NewAdsDnsResolver(adsCache *AdsCache) (*AdsDnsResolver, error) {
	resolver, err := dns.NewDNSResolver()
	if err != nil {
		return nil, err
	}
	return &AdsDnsResolver{
		Clusters:        make(chan []*clusterv3.Cluster),
		dnsRefreshQueue: workqueue.NewTypedDelayingQueueWithConfig(workqueue.TypedDelayingQueueConfig[any]{Name: "dnsRefreshQueue"}),
		adsCache:        adsCache,
		dnsResolver:     resolver,
	}, nil
}

func (adsResolver *AdsDnsResolver) StartAdsDnsResolver(stopCh <-chan struct{}) {
	go adsResolver.startAdsResolver()
	go adsResolver.refreshAdsWorker()
	go func() {
		<-stopCh
		adsResolver.dnsRefreshQueue.ShutDown()
		close(adsResolver.Clusters)
	}()
}

func (adsResolver *AdsDnsResolver) startAdsResolver() {
	rateLimiter := make(chan struct{}, dns.MaxConcurrency)
	for clusters := range adsResolver.Clusters {
		rateLimiter <- struct{}{}
		go func(clusters []*clusterv3.Cluster) {
			defer func() {
				<-rateLimiter
			}()
			adsResolver.resolveDomains(clusters)
		}(clusters)
	}
}

func (adsResolver *AdsDnsResolver) refreshAdsDns() bool {
	element, quit := adsResolver.dnsRefreshQueue.Get()
	if quit {
		return false
	}
	defer adsResolver.dnsRefreshQueue.Done(element)
	e := element.(*dns.PendingResolveDomain)

	adsResolver.dnsResolver.RLock()
	_, exist := adsResolver.dnsResolver.Cache[e.DomainName]
	adsResolver.dnsResolver.RUnlock()
	// if the domain is no longer watched, no need to refresh it
	if !exist {
		return true
	}
	addresses, ttl, err := adsResolver.dnsResolver.Resolve(e.DomainName)
	if err != nil {
		log.Errorf("failed to dns resolve: %v", err)
		return false
	}
	if ttl > e.RefreshRate {
		ttl = e.RefreshRate
	}
	if ttl == 0 {
		ttl = dns.DeRefreshInterval
	}
	adsResolver.dnsRefreshQueue.AddAfter(e, ttl)

	adsResolver.adsDnsResolve(e, addresses)
	adsResolver.adsCache.ClusterCache.Flush()
	return true
}

func (adsResolver *AdsDnsResolver) resolveDomains(cds []*clusterv3.Cluster) {
	domains := getPendingResolveDomain(cds)

	// Stow domain updates, need to remove unwatched domains first
	adsResolver.dnsResolver.RemoveUnwatchedDomain(domains)
	for k, v := range domains {
		adsResolver.dnsResolver.ResolveDomains(k)
		adsResolver.dnsRefreshQueue.AddAfter(v, 0)
	}
}

func (adsResolver *AdsDnsResolver) refreshAdsWorker() {
	for adsResolver.refreshAdsDns() {
	}
}

func (adsResolver *AdsDnsResolver) adsDnsResolve(pendingDomain *dns.PendingResolveDomain, addrs []string) {
	for _, cluster := range pendingDomain.Clusters {
		ready := overwriteDnsCluster(cluster, pendingDomain.DomainName, addrs)
		if ready {
			if !adsResolver.adsCache.UpdateApiClusterIfExists(core_v2.ApiStatus_UPDATE, cluster) {
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

func getPendingResolveDomain(cds []*clusterv3.Cluster) map[string]*dns.PendingResolveDomain {
	domains := make(map[string]*dns.PendingResolveDomain)

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
					domainWithRefreshRate := &dns.PendingResolveDomain{
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
