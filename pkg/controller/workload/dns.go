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
	cache       cache.WorkloadCache
	dnsResolver *dns.DNSResolver

	workloadsChan         chan *workloadapi.Workload
	ResolvedDomainChanMap map[string]chan *workloadapi.Workload

	// store the copy of pendingResolveWorkload.
	workloadCache map[string]*pendingResolveDomain
	// store all pending hostnames in the workloads
	pendingHostnames map[string]string
	sync.RWMutex
}

// pending resolve domain info of Dual-Engine Mode,
// workload is used for create the apiworkload
type pendingResolveDomain struct {
	Workload    []*workloadapi.Workload
	RefreshRate time.Duration
}

func NewDnsController(cache cache.WorkloadCache) (*dnsController, error) {
	resolver, err := dns.NewDNSResolver()
	if err != nil {
		return nil, err
	}
	dnsController := &dnsController{
		cache:                 cache,
		dnsResolver:           resolver,
		workloadsChan:         make(chan *workloadapi.Workload),
		ResolvedDomainChanMap: make(map[string]chan *workloadapi.Workload),
		workloadCache:         make(map[string]*pendingResolveDomain),
		pendingHostnames:      make(map[string]string),
	}
	dnsController.newWorkloadCache()
	return dnsController, nil
}

func (r *dnsController) Run(stopCh <-chan struct{}) {
	go r.dnsResolver.StartDnsResolver(stopCh)
	go r.refreshWorker(stopCh)
	go func() {
		for workload := range r.workloadsChan {
			r.processDomains(workload)
		}
	}()
	go func() {
		<-stopCh
		close(r.workloadsChan)
	}()
}

func (r *dnsController) processDomains(workload *workloadapi.Workload) {
	if workload == nil {
		log.Warn("received nil workload in processDomains")
		return
	}

	domains := getPendingResolveDomain(workload)
	if len(domains) == 0 {
		log.Debugf("no domains to resolve for workload %s/%s", workload.Namespace, workload.Name)
		return
	}

	workloadName := workload.GetName()
	hostname := workload.GetHostname()

	r.Lock()
	r.pendingHostnames[workloadName] = hostname
	if _, ok := r.workloadCache[hostname]; !ok {
		// Initialize the newly added hostname
		r.workloadCache[hostname] = &pendingResolveDomain{
			Workload:    make([]*workloadapi.Workload, 0),
			RefreshRate: WorkloadDnsRefreshRate,
		}
		log.Debugf("initialized DNS cache for hostname %s", hostname)
	}
	r.workloadCache[hostname].Workload = append(
		r.workloadCache[hostname].Workload, workload,
	)
	r.Unlock()

	// delete any scheduled re-resolve for domains we no longer care about
	r.dnsResolver.RemoveUnwatchDomain(domains)

	// update workloadCache with pendingResolveWorkload
	for k, v := range domains {
		if addresses := r.dnsResolver.GetDNSAddresses(k); addresses != nil {
			log.Debugf("found cached DNS addresses for domain %s: %v", k, addresses)
			go r.updateWorkloads(v.(*pendingResolveDomain), k, addresses)
		} else {
			// Initialize the newly added hostname
			// and add it to the dns queue to be resolved.
			domainInfo := &dns.DomainInfo{
				Domain:      k,
				RefreshRate: v.(*pendingResolveDomain).RefreshRate,
			}
			log.Infof("adding domain %s to DNS resolution queue", k)
			r.dnsResolver.AddDomainInQueue(domainInfo, 0)
		}
	}
}

func (r *dnsController) refreshWorker(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			log.Info("DNS refresh worker stopped")
			return
		case domain := <-r.dnsResolver.DnsChan:
			if domain == "" {
				log.Warn("received empty domain in refresh worker")
				continue
			}
			pendingDomain := r.getWorkloadsByDomain(domain)
			if pendingDomain == nil {
				log.Debugf("no pending workloads found for domain %s", domain)
				continue
			}
			addrs := r.dnsResolver.GetDNSAddresses(domain)
			if len(addrs) == 0 {
				log.Warnf("no DNS addresses found for domain %s", domain)
				continue
			}
			log.Debugf("refreshing workloads for domain %s with addresses %v", domain, addrs)
			r.updateWorkloads(pendingDomain, domain, addrs)
		}
	}
}

func (r *dnsController) updateWorkloads(pendingDomain *pendingResolveDomain, domain string, addrs []string) {
	if pendingDomain == nil || addrs == nil {
		return
	}
	r.Lock()
	defer r.Unlock()

	isWorkerUpdate := false
	for _, workload := range pendingDomain.Workload {
		if ready, newWorkload := r.overwriteDnsWorkload(workload, domain, addrs); ready {
			uid := newWorkload.GetUid()
			if _, ok := r.ResolvedDomainChanMap[uid]; ok {
				r.cache.AddOrUpdateWorkload(newWorkload)
				r.ResolvedDomainChanMap[uid] <- newWorkload
				log.Infof("workload %s/%s/%s addresses updated to %v", newWorkload.Namespace, newWorkload.Name, uid, newWorkload.Addresses)
				close(r.ResolvedDomainChanMap[uid])
				delete(r.ResolvedDomainChanMap, uid)
				delete(r.workloadCache, domain)
				isWorkerUpdate = true
			}
		}
	}

	if isWorkerUpdate {
		// TODO: flush the bpf map if needed
		return
	}
}

func (r *dnsController) overwriteDnsWorkload(workload *workloadapi.Workload, domain string, addrs []string) (bool, *workloadapi.Workload) {
	// Verify the domain matches the workload's hostname
	if workload.GetHostname() != domain {
		log.Warnf("domain mismatch: workload hostname %s != domain %s", workload.GetHostname(), domain)
		return false, nil
	}

	if len(addrs) == 0 {
		log.Warnf("no addresses provided for domain %s", domain)
		return false, nil
	}

	newWorkload := cloneWorkload(workload)
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil {
			// Support both IPv4 and IPv6 addresses
			newWorkload.Addresses = append(newWorkload.Addresses, netip.MustParseAddr(addr).AsSlice())
		} else {
			log.Warnf("invalid IP address: %s for domain %s", addr, domain)
		}
	}

	if len(newWorkload.Addresses) == 0 {
		log.Warnf("no valid addresses after parsing for domain %s", domain)
		return false, nil
	}

	return true, newWorkload
}

func getPendingResolveDomain(workload *workloadapi.Workload) map[string]any {
	domains := make(map[string]any)

	hostname := workload.GetHostname()
	if hostname == "" {
		return domains
	}

	if _, err := netip.ParseAddr(hostname); err == nil {
		// This is an ip address
		return domains
	}

	if v, ok := domains[hostname]; ok {
		v.(*pendingResolveDomain).Workload = append(v.(*pendingResolveDomain).Workload, workload)
	} else {
		domainWithRefreshRate := &pendingResolveDomain{
			Workload:    []*workloadapi.Workload{workload},
			RefreshRate: WorkloadDnsRefreshRate,
		}
		domains[hostname] = domainWithRefreshRate
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
