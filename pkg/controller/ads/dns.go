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
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	core_v2 "kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/pkg/dns"
)

// adsDnsResolver is DNS resolver of Kernel Native
type dnsController struct {
	Clusters    chan []*clusterv3.Cluster
	cache       *AdsCache
	dnsResolver *dns.DNSResolver
	// Store the copy of pendingResolveDomain.
	clusterCache map[string]*pendingResolveDomain
	// store all pending hostnames in the clusters
	pendingClusterInfo map[string][]string
	sync.RWMutex
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
		Clusters:           make(chan []*clusterv3.Cluster),
		cache:              adsCache,
		dnsResolver:        resolver,
		clusterCache:       make(map[string]*pendingResolveDomain),
		pendingClusterInfo: make(map[string][]string),
	}, nil
}

func (r *dnsController) Run(stopCh <-chan struct{}) {
	// start dns resolver
	go r.dnsResolver.StartDnsResolver(stopCh)
	go r.refreshAdsWorker(stopCh)
	go r.startDnsController()
	go func() {
		<-stopCh
		close(r.Clusters)
	}()
}

func (r *dnsController) startDnsController() {
	for clusters := range r.Clusters {
		r.resolveDomains(clusters)
	}
}

func (r *dnsController) resolveDomains(cds []*clusterv3.Cluster) {
	domains, hostNames := getPendingResolveDomain(cds)

	// store all pending hostnames of clusters in r.hostInfo
	for _, cluster := range cds {
		clusterName := cluster.GetName()
		info := getHostInfo(cluster)
		r.pendingClusterInfo[clusterName] = info
	}

	// delete any scheduled re-resolve for domains we no longer care about
	r.dnsResolver.RemoveUnwatchDomain(hostNames)

	for k, v := range domains {
		addresses := r.dnsResolver.GetDNSAddresses(k)
		// Already have record in dns cache
		if addresses != nil {
			r.updateClusters(v, addresses)
			go r.cache.ClusterCache.Flush()
		} else {
			r.dnsResolver.InitializeDomainInCache(k)
			domainInfo := &dns.DomainInfo{
				Domain:      v.DomainName,
				RefreshRate: v.RefreshRate,
			}
			r.dnsResolver.ScheduleDomainRefresh(domainInfo, 0)
		}
	}
}

func (r *dnsController) refreshAdsWorker(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
			domain := <-r.dnsResolver.DnsChan
			pendingDomain := r.getClustersByDomain(domain)
			addrs := r.dnsResolver.GetDNSAddresses(domain)
			r.updateClusters(pendingDomain, addrs)
		}
	}
}

func (r *dnsController) updateClusters(pendingDomain *pendingResolveDomain, addrs []string) {
	if pendingDomain == nil || addrs == nil {
		return
	}
	for _, cluster := range pendingDomain.Clusters {
		ready, newCluster := r.overwriteDnsCluster(cluster, pendingDomain.DomainName, addrs)
		if ready {
			if !r.cache.UpdateApiClusterIfExists(core_v2.ApiStatus_UPDATE, newCluster) {
				log.Debugf("cluster: %s is deleted", cluster.Name)
				return
			}
		}
	}
}

func (r *dnsController) overwriteDnsCluster(cluster *clusterv3.Cluster, domain string, addrs []string) (bool, *clusterv3.Cluster) {
	ready := true
	hostNames := r.pendingClusterInfo[cluster.GetName()]
	addressesOfHostname := make(map[string][]string)

	for _, hostName := range hostNames {
		addresses := r.dnsResolver.GetDNSAddresses(hostName)
		// There are hostnames in this Cluster that are not resolved.
		if addresses != nil {
			addressesOfHostname[hostName] = addresses
		} else {
			ready = false
		}
	}

	if ready {
		newCluster := cloneCluster(cluster)
		for _, e := range newCluster.LoadAssignment.Endpoints {
			pos := -1
			var lbEndpoints []*endpointv3.LbEndpoint
			for i, le := range e.LbEndpoints {
				socketAddr, ok := le.GetEndpoint().GetAddress().GetAddress().(*v3.Address_SocketAddress)
				if !ok {
					continue
				}
				_, err := netip.ParseAddr(socketAddr.SocketAddress.Address)
				if err != nil {
					host := socketAddr.SocketAddress.Address
					addresses := addressesOfHostname[host]
					fmt.Printf("addresses %#v", addresses)
					pos = i
					lbEndpoints = buildLbEndpoints(socketAddr.SocketAddress.GetPortValue(), addresses)
				}
			}
			e.LbEndpoints = slices.Replace(e.LbEndpoints, pos, pos+1, lbEndpoints...)
		}
		return ready, newCluster
	}

	return ready, nil
}

func buildLbEndpoints(port uint32, addrs []string) []*endpointv3.LbEndpoint {
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

func getHostInfo(cluster *clusterv3.Cluster) []string {
	info := []string{}
	for _, e := range cluster.LoadAssignment.Endpoints {
		for _, le := range e.LbEndpoints {
			socketAddr, ok := le.GetEndpoint().GetAddress().GetAddress().(*v3.Address_SocketAddress)
			if !ok {
				continue
			}
			_, err := netip.ParseAddr(socketAddr.SocketAddress.Address)
			if err != nil {
				info = append(info, socketAddr.SocketAddress.Address)
			}
		}
	}

	return info
}

func getPendingResolveDomain(cds []*clusterv3.Cluster) (map[string]*pendingResolveDomain, map[string]struct{}) {
	domains := make(map[string]*pendingResolveDomain)
	hostNames := make(map[string]struct{})

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
					hostNames[address] = struct{}{}
				}
			}
		}
	}

	return domains, hostNames
}

func (r *dnsController) newClusterCache() {
	if r.clusterCache != nil {
		r.Lock()
		defer r.Unlock()
		log.Debug("clean up dns clusters")
		r.clusterCache = map[string]*pendingResolveDomain{}
		return
	}
}

func (r *dnsController) getClustersByDomain(domain string) *pendingResolveDomain {
	if r.clusterCache != nil {
		r.RLock()
		defer r.RUnlock()
		if v, ok := r.clusterCache[domain]; ok {
			return v
		}
	}
	return nil
}

func cloneCluster(cluster *clusterv3.Cluster) *clusterv3.Cluster {
	if cluster == nil {
		return nil
	}
	clusterCopy := proto.Clone(cluster).(*clusterv3.Cluster)
	return clusterCopy
}
