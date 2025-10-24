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
	"net/netip"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
	"kmesh.net/kmesh/pkg/dns"
)

const (
	WorkloadDnsRefreshRate     = 200 * time.Millisecond // DNS refresh rate for workloads
	WorkloadChannelSendTimeout = 100 * time.Millisecond // Timeout for sending to workload channel
)

type dnsController struct {
	cache       cache.WorkloadCache
	dnsResolver *dns.DNSResolver

	workloadsChan         chan *workloadapi.Workload
	ResolvedDomainChanMap map[string]chan *workloadapi.Workload

	workloadCache    map[string]*pendingResolveDomain // hostname -> pending workloads
	pendingHostnames map[string]string                // workload name -> hostname
	sync.RWMutex
}

// pendingResolveDomain stores workloads pending DNS resolution for a domain
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

// processDomains processes workloads requiring DNS resolution.
func (r *dnsController) processDomains(workload *workloadapi.Workload) {
	if workload == nil {
		log.Warn("received nil workload in processDomains")
		return
	}

	domains := getPendingResolveDomain(workload)
	if len(domains) == 0 {
		return
	}

	workloadName := workload.GetName()
	hostname := workload.GetHostname()

	r.Lock()
	r.pendingHostnames[workloadName] = hostname
	if _, ok := r.workloadCache[hostname]; !ok {
		r.workloadCache[hostname] = &pendingResolveDomain{
			Workload:    make([]*workloadapi.Workload, 0),
			RefreshRate: WorkloadDnsRefreshRate,
		}
	}
	r.workloadCache[hostname].Workload = append(
		r.workloadCache[hostname].Workload, workload,
	)
	r.Unlock()

	// Convert to map[string]any for RemoveUnwatchDomain
	unwatchDomains := make(map[string]any, len(domains))
	for k := range domains {
		unwatchDomains[k] = nil
	}
	r.dnsResolver.RemoveUnwatchDomain(unwatchDomains)

	for k, v := range domains {
		if addresses := r.dnsResolver.GetDNSAddresses(k); addresses != nil {
			go r.updateWorkloads(v, k, addresses)
		} else {
			domainInfo := &dns.DomainInfo{
				Domain:      k,
				RefreshRate: v.RefreshRate,
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
				continue
			}

			pendingDomain := r.getWorkloadsByDomain(domain)
			if pendingDomain == nil {
				continue
			}

			addrs := r.dnsResolver.GetDNSAddresses(domain)
			if len(addrs) == 0 {
				log.Warnf("no DNS addresses found for domain %s", domain)
				continue
			}

			r.updateWorkloads(pendingDomain, domain, addrs)
		}
	}
}

// updateWorkloads processes DNS resolution results and updates workloads.
func (r *dnsController) updateWorkloads(pendingDomain *pendingResolveDomain, domain string, addrs []string) {
	if pendingDomain == nil || len(addrs) == 0 {
		return
	}

	var readyWorkloads []*workloadapi.Workload
	for _, workload := range pendingDomain.Workload {
		if ready, newWorkload := r.overwriteDnsWorkload(workload, domain, addrs); ready {
			readyWorkloads = append(readyWorkloads, newWorkload)
		}
	}

	// Send to channels without holding lock to prevent deadlock
	for _, newWorkload := range readyWorkloads {
		uid := newWorkload.GetUid()

		r.Lock()
		ch, ok := r.ResolvedDomainChanMap[uid]
		r.Unlock()

		if ok {
			r.cache.AddOrUpdateWorkload(newWorkload)
			select {
			case ch <- newWorkload:
				log.Infof("workload %s/%s addresses resolved: %v", newWorkload.Namespace, newWorkload.Name, newWorkload.Addresses)
			case <-time.After(WorkloadChannelSendTimeout):
				log.Warnf("timeout sending resolved workload %s/%s", newWorkload.Namespace, newWorkload.Name)
			}

			r.Lock()
			if _, stillExists := r.ResolvedDomainChanMap[uid]; stillExists {
				close(r.ResolvedDomainChanMap[uid])
				delete(r.ResolvedDomainChanMap, uid)
			}
			r.Unlock()
		}
	}

	if len(readyWorkloads) > 0 {
		r.Lock()
		delete(r.workloadCache, domain)
		r.Unlock()
	}
}

// overwriteDnsWorkload creates a new workload with resolved IP addresses.
func (r *dnsController) overwriteDnsWorkload(workload *workloadapi.Workload, domain string, addrs []string) (bool, *workloadapi.Workload) {
	if workload.GetHostname() != domain {
		log.Warnf("domain mismatch: workload hostname %s != domain %s", workload.GetHostname(), domain)
		return false, nil
	}

	if len(addrs) == 0 {
		return false, nil
	}

	newWorkload := cloneWorkload(workload)

	for _, addr := range addrs {
		if parsedAddr, err := netip.ParseAddr(addr); err == nil {
			newWorkload.Addresses = append(newWorkload.Addresses, parsedAddr.AsSlice())
		} else {
			log.Warnf("invalid IP address %s for domain %s: %v", addr, domain, err)
		}
	}

	if len(newWorkload.Addresses) == 0 {
		log.Warnf("no valid addresses resolved for domain %s", domain)
		return false, nil
	}

	return true, newWorkload
}

func getPendingResolveDomain(workload *workloadapi.Workload) map[string]*pendingResolveDomain {
	domains := make(map[string]*pendingResolveDomain)

	hostname := workload.GetHostname()
	if hostname == "" {
		return domains
	}

	// Skip if hostname is already an IP address
	if _, err := netip.ParseAddr(hostname); err == nil {
		return domains
	}

	domains[hostname] = &pendingResolveDomain{
		Workload:    []*workloadapi.Workload{workload},
		RefreshRate: WorkloadDnsRefreshRate,
	}

	return domains
}

// removeWorkloadFromDnsCache removes a specific workload from DNS cache.
// Called when a workload is deleted from the system.
func (r *dnsController) removeWorkloadFromDnsCache(workloadName string) {
	r.Lock()
	defer r.Unlock()

	hostname, exists := r.pendingHostnames[workloadName]
	if !exists {
		return
	}

	delete(r.pendingHostnames, workloadName)

	if pendingDomain, ok := r.workloadCache[hostname]; ok {
		updatedWorkloads := make([]*workloadapi.Workload, 0)
		for _, wl := range pendingDomain.Workload {
			if wl.GetName() != workloadName {
				updatedWorkloads = append(updatedWorkloads, wl)
			}
		}

		if len(updatedWorkloads) == 0 {
			delete(r.workloadCache, hostname)
			r.dnsResolver.RemoveUnwatchDomain(map[string]any{hostname: nil})
		} else {
			pendingDomain.Workload = updatedWorkloads
		}
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
