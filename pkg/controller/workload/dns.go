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
	domains := getPendingResolveDomain(workload)

	workloadName := workload.GetName()
	hostname := workload.GetHostname()
	r.pendingHostnames[workloadName] = hostname
	if _, ok := r.workloadCache[hostname]; !ok {
		// Initialize the newly added hostname
		r.workloadCache[hostname] = &pendingResolveDomain{
			Workload:    make([]*workloadapi.Workload, 0),
			RefreshRate: WorkloadDnsRefreshRate,
		}
	}
	r.workloadCache[hostname].Workload = append(
		r.workloadCache[hostname].Workload, workload,
	)

	// delete any scheduled re-resolve for domains we no longer care about
	r.dnsResolver.RemoveUnwatchDomain(domains)

	// update workloadCache with pendingResolveWorkload
	for k, v := range domains {
		if addresses := r.dnsResolver.GetDNSAddresses(k); addresses != nil {
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
			addrs := r.dnsResolver.GetDNSAddresses(domain)
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
			// uid := workload.GetUid()
			// if r.cache.GetWorkloadByUid(uid) != nil {
			// 	r.cache.AddOrUpdateWorkload(newWorkload)
			// 	delete(r.workloadCache, domain)
			// 	isWorkerUpdate = true
			// }
			// if _, ok := r.workloadCache[domain]; !ok {
			// 	continue
			// }
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
		// log.Info("some workloads has been updated")
		// TODO: flush the bpf map
		// r.cache.Flush()
		return
	}
}

func (r *dnsController) overwriteDnsWorkload(workload *workloadapi.Workload, domain string, addrs []string) (bool, *workloadapi.Workload) {
	hostName := r.pendingHostnames[workload.GetName()]

	if addresses := r.dnsResolver.GetDNSAddresses(hostName); addresses != nil {
		newWorkload := cloneWorkload(workload)
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
				newWorkload.Addresses = append(newWorkload.Addresses, netip.MustParseAddr(addr).AsSlice())
			}
		}
		return true, newWorkload
	}

	return false, nil
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

	// log.Infof("getPendingResolveDomain: processing workload %s with hostname %s", workload.ResourceName(), hostname)
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
