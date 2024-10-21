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

package bpfcache

import (
	"sync"

	"kmesh.net/kmesh/api/v2/workloadapi"
)

const (
	REGION    = 1 << iota // 000001
	ZONE                  // 000010
	SUBZONE               // 000100
	NODENAME              // 001000
	CLUSTERID             // 010000
	NETWORK               // 100000
)

type localityInfo struct {
	region    string // init from workload.GetLocality().GetRegion()
	zone      string // init from workload.GetLocality().GetZone()
	subZone   string // init from workload.GetLocality().GetSubZone()
	nodeName  string // init from os.Getenv("NODE_NAME"), workload.GetNode()
	clusterId string // init from workload.GetClusterId()
	network   string // workload.GetNetwork()
	mask      uint32 // mask
}

func Valid(s string) bool {
	return s != ""
}

func (l *localityInfo) Set(s string, param uint32) {
	if !Valid(s) {
		return
	}
	switch param {
	case REGION:
		l.region = s
	case ZONE:
		l.zone = s
	case SUBZONE:
		l.subZone = s
	case NODENAME:
		l.nodeName = s
	case CLUSTERID:
		l.clusterId = s
	case NETWORK:
		l.network = s
	}
	l.mask |= param
}

func (l *localityInfo) Clear(param uint32) {
	l.mask &= ^param
}

func (l *localityInfo) IsSet(param uint32) bool {
	return l.mask&param != 0
}

type LocalityCache struct {
	mutex             sync.RWMutex
	localityInfo      localityInfo
	isLocalityInfoSet bool
	workloadWaitQueue map[string]struct{} // workload.GetUid()
}

func NewLocalityCache() LocalityCache {
	return LocalityCache{
		localityInfo:      localityInfo{},
		isLocalityInfoSet: false,
		workloadWaitQueue: make(map[string]struct{}),
	}
}

func (l *LocalityCache) SetLocality(nodeName, clusterId, network string, locality *workloadapi.Locality) {
	// notice: nodeName should set by processor or os.Getenv("NODE_NAME"),
	l.localityInfo.Set(nodeName, NODENAME)
	l.localityInfo.Set(locality.GetRegion(), REGION)
	l.localityInfo.Set(locality.GetSubzone(), SUBZONE)
	l.localityInfo.Set(locality.GetZone(), ZONE)
	l.localityInfo.Set(clusterId, CLUSTERID)
	l.localityInfo.Set(network, NETWORK)

	l.isLocalityInfoSet = true
}

func (l *LocalityCache) IsLocalityInfoSet() bool {
	log.Debugf("isLocalityInfoSet: %#v", l.isLocalityInfoSet)
	return l.isLocalityInfoSet
}

func (l *LocalityCache) CalcuLocalityLBPrio(wl *workloadapi.Workload, rp []workloadapi.LoadBalancing_Scope) uint32 {
	var rank uint32 = 0
	for _, scope := range rp {
		switch scope {
		case workloadapi.LoadBalancing_REGION:
			log.Debugf("l.localityInfo.IsSet(REGION) %#v, Valid(wl.GetLocality().GetRegion()) %#v, l.localityInfo.region %#v, wl.GetLocality().GetRegion() %#v", l.localityInfo.IsSet(REGION), Valid(wl.GetLocality().GetRegion()), l.localityInfo.region, wl.GetLocality().GetRegion())
			if l.localityInfo.IsSet(REGION) && Valid(wl.GetLocality().GetRegion()) && l.localityInfo.region == wl.GetLocality().GetRegion() {
				rank++
			}
		case workloadapi.LoadBalancing_ZONE:
			log.Debugf("l.localityInfo.IsSet(ZONE) %#v, Valid(wl.GetLocality().GetZone()) %#v, l.localityInfo.zone %#v, wl.GetLocality().GetZone() %#v", l.localityInfo.IsSet(ZONE), Valid(wl.GetLocality().GetZone()), l.localityInfo.zone, wl.GetLocality().GetZone())
			if l.localityInfo.IsSet(ZONE) && Valid(wl.GetLocality().GetZone()) && l.localityInfo.zone == wl.GetLocality().GetZone() {
				rank++
			}
		case workloadapi.LoadBalancing_SUBZONE:
			log.Debugf("l.localityInfo.IsSet(SUBZONE) %#v, Valid(wl.GetLocality().GetSubzone()) %#v, l.localityInfo.subZone %#v, wl.GetLocality().GetSubzone() %#v", l.localityInfo.IsSet(SUBZONE), Valid(wl.GetLocality().GetSubzone()), l.localityInfo.subZone, wl.GetLocality().GetSubzone())
			if l.localityInfo.IsSet(SUBZONE) && Valid(wl.GetLocality().GetSubzone()) && l.localityInfo.subZone == wl.GetLocality().GetSubzone() {
				rank++
			}
		case workloadapi.LoadBalancing_NODE:
			log.Debugf("l.localityInfo.IsSet(NODENAME) %#v, Valid(wl.GetNode()) %#v, l.localityInfo.nodeName %#v, wl.GetNode() %#v", l.localityInfo.IsSet(NODENAME), Valid(wl.GetNode()), l.localityInfo.nodeName, wl.GetNode())
			if l.localityInfo.IsSet(NODENAME) && Valid(wl.GetNode()) && l.localityInfo.nodeName == wl.GetNode() {
				rank++
			}
		case workloadapi.LoadBalancing_NETWORK:
			log.Debugf("l.localityInfo.IsSet(NETWORK) %#v, Valid(wl.GetNetwork()) %#v, l.localityInfo.network %#v, wl.GetNetwork() %#v", l.localityInfo.IsSet(NETWORK), Valid(wl.GetNetwork()), l.localityInfo.network, wl.GetNetwork())
			if l.localityInfo.IsSet(NETWORK) && Valid(wl.GetNetwork()) && l.localityInfo.network == wl.GetNetwork() {
				rank++
			}
		case workloadapi.LoadBalancing_CLUSTER:
			log.Debugf("l.localityInfo.IsSet(CLUSTERID) %#v, Valid(wl.GetClusterId()) %#v, l.localityInfo.clusterId %#v, wl.GetClusterId() %#v", l.localityInfo.IsSet(CLUSTERID), Valid(wl.GetClusterId()), l.localityInfo.clusterId, wl.GetClusterId())
			if l.localityInfo.IsSet(CLUSTERID) && Valid(wl.GetClusterId()) && l.localityInfo.clusterId == wl.GetClusterId() {
				rank++
			}
		}
	}
	return uint32(len(rp)) - rank
}

func (l *LocalityCache) SaveToWaitQueue(wl *workloadapi.Workload) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.workloadWaitQueue[wl.Uid] = struct{}{}
}

func (l *LocalityCache) DelWorkloadFromWaitQueue(wl *workloadapi.Workload) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	delete(l.workloadWaitQueue, wl.Uid)
}

func (l *LocalityCache) GetFromWaitQueue() map[string]struct{} {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.workloadWaitQueue
}
