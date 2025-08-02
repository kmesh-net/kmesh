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

package workload

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
	"kmesh.net/kmesh/pkg/dns"
)

const (
	WorkloadDnsRefreshRate = 200 * time.Millisecond // 200ms, used for workload dns refresh rate
)

type dnsController struct {
	workloadsChan chan []*workloadapi.Workload
	cache         cache.WorkloadCache
	dnsResolver   *dns.DNSResolver
	// store the copy of pendingResolveWorkload.
	workloadCache map[string]*pendingResolveDomain
	// store all pending hostnames in the workloads
	pendingHostnames map[string][]string
	sync.RWMutex
}

// pending resolve domain info of Dual-Engine Mode,
// workload is used for create the apiworkload
type pendingResolveDomain struct {
	Workloads   []*workloadapi.Workload
	RefreshRate time.Duration
}

func NewDnsController(cache cache.WorkloadCache) (*dnsController, error) {
	resolver, err := dns.NewDNSResolver()
	if err != nil {
		return nil, err
	}
	return &dnsController{
		workloadsChan:    make(chan []*workloadapi.Workload),
		cache:            cache,
		dnsResolver:      resolver,
		workloadCache:    make(map[string]*pendingResolveDomain),
		pendingHostnames: make(map[string][]string),
	}, nil
}

func (r *dnsController) Run(stopCh <-chan struct{}) {
	go r.dnsResolver.StartDnsResolver(stopCh)
	go r.refreshWorker(stopCh)
	go r.processWorkloads()
	go func() {
		<-stopCh
		close(r.workloadsChan)
	}()
}

func (r *dnsController) processWorkloads() {
	for workloads := range r.workloadsChan {
		r.processDomains(workloads)
	}
}

func (r *dnsController) processDomains(workloads []*workloadapi.Workload) {
	domains := getPendingResolveDomain(workloads)

	// store all pending hostnames of clusters in pendingHostnames
	for _, workload := range workloads {
		workloadName := workload.GetName()
		hostname := workload.GetHostname()
		if _, ok := r.pendingHostnames[workloadName]; !ok {
			r.pendingHostnames[workloadName] = []string{}
		}
		r.pendingHostnames[workloadName] = append(r.pendingHostnames[workloadName], hostname)
		if _, ok := r.workloadCache[hostname]; !ok {
			// Initialize the newly added hostname
			r.workloadCache[hostname] = &pendingResolveDomain{
				Workloads:   make([]*workloadapi.Workload, 0),
				RefreshRate: WorkloadDnsRefreshRate,
			}
		}
		r.workloadCache[hostname].Workloads = append(
			r.workloadCache[hostname].Workloads, workload,
		)
	}

	// delete any scheduled re-resolve for domains we no longer care about
	r.dnsResolver.RemoveUnwatchDomain(domains)

	// update workloadCache with pendingResolveWorkload
	for k, v := range domains {
		addresses := r.dnsResolver.GetDNSAddresses(k)
		if addresses != nil {
			go r.updateWorkloads(v.(*pendingResolveDomain), k, addresses)
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

func (r *dnsController) refreshWorker(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case domain := <-r.dnsResolver.DnsChan:
			pendingDomain := r.getWorkloadsByDomain(domain)
			// log.Infof("dnsController refreshWorker: domain %s, pendingDomain %v", domain, pendingDomain)
			addrs := r.dnsResolver.GetDNSAddresses(domain)
			maxRetry := 3
			for range maxRetry {
				if len(addrs) > 0 {
					r.updateWorkloads(pendingDomain, domain, addrs)
				}
				time.Sleep(1 * time.Second)
			}
		}
	}
}

func (r *dnsController) updateWorkloads(pendingDomain *pendingResolveDomain, domain string, addrs []string) {
	isWorkerUpdate := false
	if pendingDomain == nil || addrs == nil {
		return
	}
	log.Infof("dnsController updateWorkloads: pendingDomain %v, domain %s, addrs %v", pendingDomain, domain, addrs)

	for _, workload := range pendingDomain.Workloads {
		if ready, newWorkload := r.overwriteDnsWorkload(workload, domain, addrs); ready {
			// log.Infof("dnsController update cache for workload %s with addresses %v", workload.ResourceName(), addrs)
			if r.cache.GetWorkloadByUid(workload.GetUid()) != nil {
				r.cache.AddOrUpdateWorkload(newWorkload)
				delete(r.workloadCache, domain)
				isWorkerUpdate = true
			}
		}
	}

	if isWorkerUpdate {
		log.Info("some workloads has been updated")
		// TODO: flush the bpf map
		// r.cache.Flush()
		return
	}
}

func (r *dnsController) overwriteDnsWorkload(workload *workloadapi.Workload, domain string, addrs []string) (bool, *workloadapi.Workload) {
	ready := true
	hostNames := r.pendingHostnames[workload.GetName()]
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
		// log.Infof("overwriteDnsWorkload ready for workload %s with domain %s", workload.ResourceName(), domain)
		newWorkload := cloneWorkload(workload)
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
				newWorkload.Addresses = append(newWorkload.Addresses, netip.MustParseAddr(addr).AsSlice())
			}
		}

		return ready, newWorkload
	}

	return ready, nil
}

func getPendingResolveDomain(workloads []*workloadapi.Workload) map[string]any {
	domains := make(map[string]any)

	for _, workload := range workloads {
		hostname := workload.GetHostname()
		if hostname == "" {
			continue
		}

		if _, err := netip.ParseAddr(hostname); err == nil {
			// This is an ip address
			continue
		}

		// log.Infof("getPendingResolveDomain: processing workload %s with hostname %s", workload.ResourceName(), hostname)
		if v, ok := domains[hostname]; ok {
			v.(*pendingResolveDomain).Workloads = append(v.(*pendingResolveDomain).Workloads, workload)
		} else {
			domainWithRefreshRate := &pendingResolveDomain{
				Workloads:   []*workloadapi.Workload{workload},
				RefreshRate: 15 * time.Second,
			}
			domains[hostname] = domainWithRefreshRate
		}
	}

	return domains
}

func (r *dnsController) newWorkloadCache() {
	r.Lock()
	defer r.Unlock()

	if r.workloadCache != nil {
		log.Debug("clean up dns workloads")
		r.workloadCache = map[string]*pendingResolveDomain{}
		return
	}
}

func (r *dnsController) getWorkloadsByDomain(domain string) *pendingResolveDomain {
	r.RLock()
	defer r.RUnlock()

	if r.workloadCache != nil {
		if v, ok := r.workloadCache[domain]; ok {
			return v
		}
	}
	return nil
}

func cloneWorkload(workload *workloadapi.Workload) *workloadapi.Workload {
	if workload == nil {
		return nil
	}
	workloadCopy := proto.Clone(workload).(*workloadapi.Workload)
	return workloadCopy
}
