package bpfcache

import (
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
	LbPolicy               uint32
	localityInfo           localityInfo
	LbStrictIndex          uint32 // for failover strict mode
	isLocalityInfoSet      bool
	RoutingPreference      []workloadapi.LoadBalancing_Scope
	isRoutingPreferenceSet bool
	workloadWaitQueue      map[*workloadapi.Workload]struct{}
}

func NewLocalityCache() *LocalityCache {
	return &LocalityCache{
		localityInfo:           localityInfo{},
		isLocalityInfoSet:      false,
		RoutingPreference:      make([]workloadapi.LoadBalancing_Scope, 0),
		isRoutingPreferenceSet: false,
		workloadWaitQueue:      make(map[*workloadapi.Workload]struct{}),
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

func (l *LocalityCache) SetRoutingPreference(s []workloadapi.LoadBalancing_Scope) {
	// notice: s should set by lb.GetRoutingPreference()
	if len(s) > 0 {
		l.RoutingPreference = s
		l.LbStrictIndex = uint32(len(s))
		l.isRoutingPreferenceSet = true
	}
}

func (l *LocalityCache) CanLocalityLB() bool {
	log.Debugf("isLocalityInfoSet: %#v, isRoutingPreferenceSet: %#v", l.isLocalityInfoSet, l.isRoutingPreferenceSet)
	return l.isLocalityInfoSet && l.isRoutingPreferenceSet
}

func (l *LocalityCache) CalcuLocalityLBPrio(wl *workloadapi.Workload) uint32 {
	var rank uint32 = 0
	for scope := range l.RoutingPreference {
		switch scope {
		case int(workloadapi.LoadBalancing_REGION):
			log.Debugf("l.localityInfo.IsSet(REGION) %#v, Valid(wl.GetLocality().GetRegion()) %#v, l.localityInfo.region %#v, wl.GetLocality().GetRegion() %#v", l.localityInfo.IsSet(REGION), Valid(wl.GetLocality().GetRegion()), l.localityInfo.region, wl.GetLocality().GetRegion())
			if l.localityInfo.IsSet(REGION) && Valid(wl.GetLocality().GetRegion()) && l.localityInfo.region == wl.GetLocality().GetRegion() {
				rank++
			}
		case int(workloadapi.LoadBalancing_ZONE):
			log.Debugf("l.localityInfo.IsSet(ZONE) %#v, Valid(wl.GetLocality().GetZone()) %#v, l.localityInfo.zone %#v, wl.GetLocality().GetZone() %#v", l.localityInfo.IsSet(ZONE), Valid(wl.GetLocality().GetZone()), l.localityInfo.zone, wl.GetLocality().GetZone())
			if l.localityInfo.IsSet(ZONE) && Valid(wl.GetLocality().GetZone()) && l.localityInfo.zone == wl.GetLocality().GetZone() {
				rank++
			}
		case int(workloadapi.LoadBalancing_SUBZONE):
			log.Debugf("l.localityInfo.IsSet(SUBZONE) %#v, Valid(wl.GetLocality().GetSubzone()) %#v, l.localityInfo.subZone %#v, wl.GetLocality().GetSubzone() %#v", l.localityInfo.IsSet(SUBZONE), Valid(wl.GetLocality().GetSubzone()), l.localityInfo.subZone, wl.GetLocality().GetSubzone())
			if l.localityInfo.IsSet(SUBZONE) && Valid(wl.GetLocality().GetSubzone()) && l.localityInfo.subZone == wl.GetLocality().GetSubzone() {
				rank++
			}
		case int(workloadapi.LoadBalancing_NODE):
			log.Debugf("l.localityInfo.IsSet(NODENAME) %#v, Valid(wl.GetNode()) %#v, l.localityInfo.nodeName %#v, wl.GetNode() %#v", l.localityInfo.IsSet(NODENAME), Valid(wl.GetNode()), l.localityInfo.nodeName, wl.GetNode())
			if l.localityInfo.IsSet(NODENAME) && Valid(wl.GetNode()) && l.localityInfo.nodeName == wl.GetNode() {
				rank++
			}
		case int(workloadapi.LoadBalancing_NETWORK):
			log.Debugf("l.localityInfo.IsSet(NETWORK) %#v, Valid(wl.GetNetwork()) %#v, l.localityInfo.network %#v, wl.GetNetwork() %#v", l.localityInfo.IsSet(NETWORK), Valid(wl.GetNetwork()), l.localityInfo.network, wl.GetNetwork())
			if l.localityInfo.IsSet(NETWORK) && Valid(wl.GetNetwork()) && l.localityInfo.network == wl.GetNetwork() {
				rank++
			}
		case int(workloadapi.LoadBalancing_CLUSTER):
			log.Debugf("l.localityInfo.IsSet(CLUSTERID) %#v, Valid(wl.GetClusterId()) %#v, l.localityInfo.clusterId %#v, wl.GetClusterId() %#v", l.localityInfo.IsSet(CLUSTERID), Valid(wl.GetClusterId()), l.localityInfo.clusterId, wl.GetClusterId())
			if l.localityInfo.IsSet(CLUSTERID) && Valid(wl.GetClusterId()) && l.localityInfo.clusterId == wl.GetClusterId() {
				rank++
			}
		}
	}
	return rank
}

func (l *LocalityCache) SaveToWaitQueue(wl *workloadapi.Workload) {
	l.workloadWaitQueue[wl] = struct{}{}
}

func (l *LocalityCache) DelWorkloadFromWaitQueue(wl *workloadapi.Workload) {
	delete(l.workloadWaitQueue, wl)
}

func (l *LocalityCache) GetFromWaitQueue() map[*workloadapi.Workload]struct{} {
	return l.workloadWaitQueue
}
