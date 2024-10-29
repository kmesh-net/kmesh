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

// localityInfo records local node workload locality info
type localityInfo struct {
	region    string // init from workload.GetLocality().GetRegion()
	zone      string // init from workload.GetLocality().GetZone()
	subZone   string // init from workload.GetLocality().GetSubZone()
	nodeName  string // init from os.Getenv("NODE_NAME"), workload.GetNode()
	clusterId string // init from workload.GetClusterId()
	network   string // workload.GetNetwork()
}

type LocalityCache struct {
	mutex        sync.RWMutex
	LocalityInfo *localityInfo
}

func NewLocalityCache() LocalityCache {
	return LocalityCache{
		LocalityInfo: nil,
	}
}

func (l *LocalityCache) SetLocality(nodeName, clusterId, network string, locality *workloadapi.Locality) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.LocalityInfo == nil {
		l.LocalityInfo = &localityInfo{}
	}

	// notice: nodeName should set by processor or os.Getenv("NODE_NAME"),
	l.LocalityInfo.region = locality.GetRegion()
	l.LocalityInfo.zone = locality.GetZone()
	l.LocalityInfo.subZone = locality.GetSubzone()
	l.LocalityInfo.nodeName = nodeName
	l.LocalityInfo.clusterId = clusterId
	l.LocalityInfo.network = network
}

func (l *LocalityCache) CalcLocalityLBPrio(wl *workloadapi.Workload, rp []workloadapi.LoadBalancing_Scope) uint32 {
	var rank uint32 = 0
	for _, scope := range rp {
		match := false
		switch scope {
		case workloadapi.LoadBalancing_REGION:
			if l.LocalityInfo.region == wl.GetLocality().GetRegion() {
				match = true
			}
		case workloadapi.LoadBalancing_ZONE:
			if l.LocalityInfo.zone == wl.GetLocality().GetZone() {
				match = true
			}
		case workloadapi.LoadBalancing_SUBZONE:
			if l.LocalityInfo.subZone == wl.GetLocality().GetSubzone() {
				match = true
			}
		case workloadapi.LoadBalancing_NODE:
			if l.LocalityInfo.nodeName == wl.GetNode() {
				match = true
			}
		case workloadapi.LoadBalancing_CLUSTER:
			if l.LocalityInfo.clusterId == wl.GetClusterId() {
				match = true
			}
		case workloadapi.LoadBalancing_NETWORK:
			log.Debugf("l.LocalityInfo.network %#v, wl.GetNetwork() %#v", l.LocalityInfo.network, wl.GetNetwork())
			if l.LocalityInfo.network == wl.GetNetwork() {
				match = true
			}
		}
		if match {
			rank++
		} else {
			break
		}
	}
	return uint32(len(rp)) - rank
}
