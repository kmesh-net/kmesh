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
	clustersChan chan []*clusterv3.Cluster
	cache        *AdsCache
	dnsResolver  *dns.DNSResolver
	// Store the copy of pendingResolveDomain.
	clusterCache map[string]*pendingResolveDomain
	// store all pending hostnames in the clusters
	pendingHostnames map[string][]string
	sync.RWMutex
}

// pending resolve domain info of Kennel-Native Mode,
// cluster is used for create the apicluster
type pendingResolveDomain struct {
	Clusters    []*clusterv3.Cluster
	RefreshRate time.Duration
}

func NewDnsController(adsCache *AdsCache) (*dnsController, error) {
	resolver, err := dns.NewDNSResolver()
	if err != nil {
		return nil, err
	}
	return &dnsController{
		clustersChan:     make(chan []*clusterv3.Cluster),
		cache:            adsCache,
		dnsResolver:      resolver,
		clusterCache:     make(map[string]*pendingResolveDomain),
		pendingHostnames: make(map[string][]string),
	}, nil
}

func (r *dnsController) Run(stopCh <-chan struct{}) {
	// Start dns resolver
	go r.dnsResolver.StartDnsResolver(stopCh)
	// Handle cds updates
	go r.refreshWorker(stopCh)
	// Consumption of clusters.
	go r.processClusters()
	go func() {
		<-stopCh
		close(r.clustersChan)
	}()
}

func (r *dnsController) processClusters() {
	for clusters := range r.clustersChan {
		r.processDomains(clusters)
	}
}

func (r *dnsController) processDomains(cds []*clusterv3.Cluster) {
	domains := getPendingResolveDomain(cds)

	// store all pending hostnames of clusters in pendingHostnames
	for _, cluster := range cds {
		clusterName := cluster.GetName()
		info := getHostName(cluster)
		r.pendingHostnames[clusterName] = info
	}

	// delete any scheduled re-resolve for domains we no longer care about
	r.dnsResolver.RemoveUnwatchDomain(domains)

	// Update clusters based on the data in the dns cache.
	for k, v := range domains {
		addresses := r.dnsResolver.GetDNSAddresses(k)
		// Already have record in dns cache
		if addresses != nil {
			// Use a goroutine to update the Cluster, reducing the processing time of functions
			// Avoiding clusterChan blocking
			go r.updateClusters(v.(*pendingResolveDomain), k, addresses)
		} else {
			// Initialize the newly added hostname
			// and add it to the dns queue to be resolved.
			domainInfo := &dns.DomainInfo{
				Domain:      k,
				RefreshRate: v.(*pendingResolveDomain).RefreshRate,
			}
			r.dnsResolver.AddDomainInQueue(domainInfo, 0)
		}
	}
}

// Handle cds updates
func (r *dnsController) refreshWorker(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case domain := <-r.dnsResolver.DnsChan:
			pendingDomain := r.getClustersByDomain(domain)
			addrs := r.dnsResolver.GetDNSAddresses(domain)
			r.updateClusters(pendingDomain, domain, addrs)
		}
	}
}

func (r *dnsController) updateClusters(pendingDomain *pendingResolveDomain, domain string, addrs []string) {
	isClusterUpdate := false
	if pendingDomain == nil || addrs == nil {
		return
	}
	for _, cluster := range pendingDomain.Clusters {
		ready, newCluster := r.overwriteDnsCluster(cluster, domain, addrs)
		if ready {
			if !r.cache.UpdateApiClusterIfExists(core_v2.ApiStatus_UPDATE, newCluster) {
				log.Debugf("cluster: %s is deleted", cluster.Name)
			} else {
				isClusterUpdate = true
			}
		}
	}
	// if one cluster update successful, we will retuen true
	if isClusterUpdate {
		r.cache.ClusterCache.Flush()
	}
}

func (r *dnsController) overwriteDnsCluster(cluster *clusterv3.Cluster, domain string, addrs []string) (bool, *clusterv3.Cluster) {
	ready := true
	hostNames := r.pendingHostnames[cluster.GetName()]
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

// Get the hostname to be resolved in Cluster
func getHostName(cluster *clusterv3.Cluster) []string {
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

func getPendingResolveDomain(cds []*clusterv3.Cluster) map[string]interface{} {
	domains := make(map[string]interface{})
	// hostNames := make(map[string]struct{})

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
					v.(*pendingResolveDomain).Clusters = append(v.(*pendingResolveDomain).Clusters, cluster)
				} else {
					domainWithRefreshRate := &pendingResolveDomain{
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

func (r *dnsController) newClusterCache() {
	r.Lock()
	defer r.Unlock()

	if r.clusterCache != nil {
		log.Debug("clean up dns clusters")
		r.clusterCache = map[string]*pendingResolveDomain{}
		return
	}
}

func (r *dnsController) getClustersByDomain(domain string) *pendingResolveDomain {
	r.RLock()
	defer r.RUnlock()

	if r.clusterCache != nil {
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
