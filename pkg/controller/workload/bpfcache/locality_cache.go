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
	l.LocalityInfo.Set(nodeName, NODENAME)
	l.LocalityInfo.Set(locality.GetRegion(), REGION)
	l.LocalityInfo.Set(locality.GetSubzone(), SUBZONE)
	l.LocalityInfo.Set(locality.GetZone(), ZONE)
	l.LocalityInfo.Set(clusterId, CLUSTERID)
	l.LocalityInfo.Set(network, NETWORK)
}

func (l *LocalityCache) CalcLocalityLBPrio(wl *workloadapi.Workload, rp []workloadapi.LoadBalancing_Scope) uint32 {
	var rank uint32 = 0
	for _, scope := range rp {
		match := false
		switch scope {
		case workloadapi.LoadBalancing_REGION:
			log.Debugf("l.LocalityInfo.region %#v, wl.GetLocality().GetRegion() %#v", l.LocalityInfo.region, wl.GetLocality().GetRegion())
			if l.LocalityInfo.region == wl.GetLocality().GetRegion() {
				match = true
			}
		case workloadapi.LoadBalancing_ZONE:
			log.Debugf("l.LocalityInfo.zone %#v, wl.GetLocality().GetZone() %#v", l.LocalityInfo.zone, wl.GetLocality().GetZone())
			if l.LocalityInfo.zone == wl.GetLocality().GetZone() {
				match = true
			}
		case workloadapi.LoadBalancing_SUBZONE:
			log.Debugf("l.LocalityInfo.subZone %#v, wl.GetLocality().GetSubzone() %#v", l.LocalityInfo.subZone, wl.GetLocality().GetSubzone())
			if l.LocalityInfo.subZone == wl.GetLocality().GetSubzone() {
				match = true
			}
		case workloadapi.LoadBalancing_NODE:
			log.Debugf("l.LocalityInfo.nodeName %#v, wl.GetNode() %#v", l.LocalityInfo.nodeName, wl.GetNode())
			if l.LocalityInfo.nodeName == wl.GetNode() {
				match = true
			}
		case workloadapi.LoadBalancing_CLUSTER:
			log.Debugf("l.LocalityInfo.clusterId %#v, wl.GetClusterId() %#v", l.LocalityInfo.clusterId, wl.GetClusterId())
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
