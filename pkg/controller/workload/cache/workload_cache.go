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

package cache

import (
	"net/netip"
	"sync"

	"google.golang.org/protobuf/proto"

	"kmesh.net/kmesh/api/v2/workloadapi"
)

type WorkloadCache interface {
	GetWorkloadByUid(uid string) *workloadapi.Workload
	GetWorkloadByAddr(networkAddress NetworkAddress) *workloadapi.Workload
	AddOrUpdateWorkload(workload *workloadapi.Workload) (deletedServices []string, newServices []string)
	DeleteWorkload(uid string)
	List() []*workloadapi.Workload
}

type NetworkAddress struct {
	Network string
	Address netip.Addr
}

type cache struct {
	byUid  map[string]*workloadapi.Workload
	byAddr map[NetworkAddress]*workloadapi.Workload
	mutex  sync.RWMutex
}

func NewWorkloadCache() *cache {
	return &cache{
		byUid:  make(map[string]*workloadapi.Workload),
		byAddr: make(map[NetworkAddress]*workloadapi.Workload),
	}
}

func (w *cache) GetWorkloadByUid(uid string) *workloadapi.Workload {
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	return w.byUid[uid]
}

func (w *cache) GetWorkloadByAddr(networkAddress NetworkAddress) *workloadapi.Workload {
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	return w.byAddr[networkAddress]
}

func composeNetworkAddress(network string, addr netip.Addr) NetworkAddress {
	return NetworkAddress{
		Network: network,
		Address: addr,
	}
}

func (w *cache) getUniqueServicesOnLeftWorkload(workload1, workload2 *workloadapi.Workload) []string {
	var diff []string
	if workload1 == nil {
		return diff
	}

	for key := range workload1.Services {
		if workload2 == nil {
			diff = append(diff, key)
			continue
		}
		if _, exist := workload2.Services[key]; !exist {
			diff = append(diff, key)
		}
	}
	return diff
}

func (w *cache) compareWorkloadServices(workload1, workload2 *workloadapi.Workload) ([]string, []string) {
	dels := w.getUniqueServicesOnLeftWorkload(workload1, workload2)
	news := w.getUniqueServicesOnLeftWorkload(workload2, workload1)
	return dels, news
}

func (w *cache) AddOrUpdateWorkload(workload *workloadapi.Workload) ([]string, []string) {
	var deleteServices []string
	var newServices []string

	if workload == nil {
		return deleteServices, newServices
	}
	uid := workload.Uid

	w.mutex.Lock()
	defer w.mutex.Unlock()

	oldWorkload, exist := w.byUid[uid]
	if exist {
		if proto.Equal(workload, oldWorkload) {
			return deleteServices, newServices
		}
		// remove same uid but old address workload, avoid leak workload by address.
		for _, ip := range oldWorkload.Addresses {
			addr, _ := netip.AddrFromSlice(ip)
			networkAddress := composeNetworkAddress(oldWorkload.Network, addr)
			delete(w.byAddr, networkAddress)
		}

		// compare services
		deleteServices, newServices = w.compareWorkloadServices(oldWorkload, workload)
	} else {
		newServices = w.getUniqueServicesOnLeftWorkload(workload, oldWorkload)
	}

	w.byUid[uid] = workload
	for _, ip := range workload.Addresses {
		addr, _ := netip.AddrFromSlice(ip)
		networkAddress := composeNetworkAddress(workload.Network, addr)
		w.byAddr[networkAddress] = workload
	}
	return deleteServices, newServices
}

func (w *cache) DeleteWorkload(uid string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	workload, exist := w.byUid[uid]
	if exist {
		for _, ip := range workload.Addresses {
			addr, _ := netip.AddrFromSlice(ip)
			networkAddress := composeNetworkAddress(workload.Network, addr)
			delete(w.byAddr, networkAddress)
		}

		delete(w.byUid, uid)
	}
}

func (w *cache) List() []*workloadapi.Workload {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	out := make([]*workloadapi.Workload, 0, len(w.byUid))
	for _, workload := range w.byUid {
		out = append(out, workload)
	}

	return out
}
