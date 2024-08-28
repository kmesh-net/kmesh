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
	"istio.io/istio/pkg/util/sets"

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

func getServicesOnWorkload(workload *workloadapi.Workload) sets.String {
	if workload == nil {
		return nil
	}

	sets := sets.New[string]()
	for key := range workload.Services {
		sets.Insert(key)
	}
	return sets
}

func (w *cache) compareWorkloadServices(workload1, workload2 *workloadapi.Workload) ([]string, []string) {
	left := getServicesOnWorkload(workload1)
	right := getServicesOnWorkload(workload2)
	return left.Diff(right)
}

func (w *cache) AddOrUpdateWorkload(workload *workloadapi.Workload) ([]string, []string) {
	var deletedServices, newServices []string

	if workload == nil {
		return nil, nil
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	oldWorkload, exist := w.byUid[workload.Uid]
	if exist {
		if proto.Equal(workload, oldWorkload) {
			return nil, nil
		}
		// compare services
		deletedServices, newServices = w.compareWorkloadServices(oldWorkload, workload)
	} else {
		for key := range workload.Services {
			newServices = append(newServices, key)
		}
	}

	w.byUid[workload.Uid] = workload

	// We should exclude the workloads that use host network mode
	// Since they are using the host ip, we can not use address to identify them
	if workload.NetworkMode != workloadapi.NetworkMode_HOST_NETWORK {
		for _, ip := range workload.Addresses {
			addr, _ := netip.AddrFromSlice(ip)
			networkAddress := composeNetworkAddress(workload.Network, addr)
			w.byAddr[networkAddress] = workload
		}
	}
	return deletedServices, newServices
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
