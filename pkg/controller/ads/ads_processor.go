/*
 * Copyright 2023 The Kmesh Authors.
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

package ads

import (
	"fmt"

	config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resource_v3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/slices"
	"k8s.io/apimachinery/pkg/util/sets"

	admin_v2 "kmesh.net/kmesh/api/v2/admin"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/config"
	"kmesh.net/kmesh/pkg/utils/hash"
)

const (
	apiVersionInfo = "v2"
)

type lastNonce struct {
	cdsNonce string
	edsNonce string
	ldsNonce string
	rdsNonce string
}
type processor struct {
	Cache     *AdsCache
	ack       *service_discovery_v3.DiscoveryRequest
	req       *service_discovery_v3.DiscoveryRequest
	lastNonce *lastNonce
	// the channel used to send domains to dns resolver. key is domain name and value is refreshrate
	DnsResolverChan chan []*config_cluster_v3.Cluster
}

func newProcessor() *processor {
	return &processor{
		Cache:     NewAdsCache(),
		ack:       nil,
		req:       nil,
		lastNonce: &lastNonce{},
	}
}

func newAdsRequest(typeUrl string, names []string, nonce string) *service_discovery_v3.DiscoveryRequest {
	return &service_discovery_v3.DiscoveryRequest{
		TypeUrl:       typeUrl,
		VersionInfo:   "",
		ResourceNames: names,
		ResponseNonce: nonce,
		ErrorDetail:   nil,
		Node:          config.GetConfig(constants.AdsMode).GetNode(),
	}
}

func newAckRequest(resp *service_discovery_v3.DiscoveryResponse) *service_discovery_v3.DiscoveryRequest {
	return &service_discovery_v3.DiscoveryRequest{
		TypeUrl:       resp.GetTypeUrl(),
		VersionInfo:   resp.GetVersionInfo(),
		ResourceNames: []string{},
		ResponseNonce: resp.GetNonce(),
		ErrorDetail:   nil,
		Node:          config.GetConfig(constants.AdsMode).GetNode(),
	}
}

// [Eventual consistency considerations](https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol)
// In general, to avoid traffic drop, sequencing of updates should follow a make before break model, wherein:
// * CDS updates (if any) must always be pushed first.
// * EDS updates (if any) must arrive after CDS updates for the respective clusters.
// * LDS updates must arrive after corresponding CDS/EDS updates.
// * RDS updates related to the newly added listeners must arrive after CDS/EDS/LDS updates.
// * VHDS updates (if any) related to the newly added RouteConfigurations must arrive after RDS updates.
// * Stale CDS clusters and related EDS endpoints (ones no longer being referenced) can then be removed.
func (p *processor) processAdsResponse(resp *service_discovery_v3.DiscoveryResponse) {
	var err error

	log.Debugf("handle ads response, %#v\n", resp.GetTypeUrl())

	p.ack = newAckRequest(resp)
	if resp.GetResources() == nil {
		return
	}

	switch resp.GetTypeUrl() {
	case resource_v3.ClusterType:
		err = p.handleCdsResponse(resp)
	case resource_v3.EndpointType:
		err = p.handleEdsResponse(resp)
	case resource_v3.ListenerType:
		err = p.handleLdsResponse(resp)
	case resource_v3.RouteType:
		err = p.handleRdsResponse(resp)
	default:
		err = fmt.Errorf("unsupport type url %s", resp.GetTypeUrl())
	}

	if err != nil {
		log.Error(err)
	}
}

func (p *processor) handleCdsResponse(resp *service_discovery_v3.DiscoveryResponse) error {
	p.lastNonce.cdsNonce = resp.Nonce
	current := sets.New[string]()
	lastEdsClusterNames := p.Cache.edsClusterNames
	p.Cache.edsClusterNames = nil
	dnsClusters := []*config_cluster_v3.Cluster{}
	for _, resource := range resp.GetResources() {
		cluster := &config_cluster_v3.Cluster{}
		if err := anypb.UnmarshalTo(resource, cluster, proto.UnmarshalOptions{}); err != nil {
			log.Errorf("unmarshal cluster error: %v", err)
			continue
		}
		current.Insert(cluster.GetName())

		if cluster.GetType() == config_cluster_v3.Cluster_EDS {
			p.Cache.edsClusterNames = append(p.Cache.edsClusterNames, cluster.GetName())
		} else if cluster.GetType() == config_cluster_v3.Cluster_STRICT_DNS ||
			cluster.GetType() == config_cluster_v3.Cluster_LOGICAL_DNS {
			dnsClusters = append(dnsClusters, cluster)
		}
		// compare part[0] CDS now
		// Cluster_EDS need compare tow parts, compare part[1] EDS in EDS handler
		newHash := hash.Sum64String(resource.String())
		if newHash != p.Cache.ClusterCache.GetCdsHash(cluster.GetName()) {
			var status core_v2.ApiStatus
			if cluster.GetType() == config_cluster_v3.Cluster_EDS {
				status = core_v2.ApiStatus_WAITING
			} else if cluster.GetType() == config_cluster_v3.Cluster_STRICT_DNS ||
				cluster.GetType() == config_cluster_v3.Cluster_LOGICAL_DNS {
				// dns typed cluster will be handled in dns module, skip update bpf map here
				status = core_v2.ApiStatus_WAITING
			} else {
				status = core_v2.ApiStatus_UPDATE
			}

			log.Debugf("[CreateApiClusterByCds] update cluster %s, status %d, cluster.type %v",
				cluster.GetName(), status, cluster.GetType())
			p.Cache.ClusterCache.SetCdsHash(cluster.GetName(), newHash)
			p.Cache.CreateApiClusterByCds(status, cluster)
		} else {
			log.Debugf("unchanged cluster %s", cluster.GetName())
		}
	}

	if len(dnsClusters) > 0 {
		// send dns clusters to dns resolver
		p.DnsResolverChan <- dnsClusters
	}
	removed := p.Cache.ClusterCache.GetResourceNames().Difference(current)
	for key := range removed {
		p.Cache.UpdateApiClusterStatus(key, core_v2.ApiStatus_DELETE)
	}
	if len(removed) > 0 {
		log.Debugf("removed cluster: %v", removed.UnsortedList())
	}

	// Flush the clusters in these cases:
	// 1. clusters need to be deleted
	// 2. dns typed clusters update, we donot need to wait for eds update, because dns cluster has no eds following
	// Note eds typed cluster, we donot flush to bpf map here, we need to wait for eds update.
	p.Cache.ClusterCache.Flush()

	if p.lastNonce.edsNonce == "" {
		// initial subscribe to eds
		p.req = newAdsRequest(resource_v3.EndpointType, p.Cache.edsClusterNames, "")
		return nil
	}

	// when the list of eds typed clusters subscribed changed, we should resubscrbe to new eds.
	if !slices.EqualUnordered(p.Cache.edsClusterNames, lastEdsClusterNames) {
		// we cannot set the nonce here.
		// There is a race: when xds server has pushed eds, but kmesh hasn't a chance to receive and process
		// Then it will lead to this request been ignored, we will lose the new eds resource
		p.req = newAdsRequest(resource_v3.EndpointType, p.Cache.edsClusterNames, "")
	}

	return nil
}

func (p *processor) handleEdsResponse(resp *service_discovery_v3.DiscoveryResponse) error {
	var loadAssignment = &config_endpoint_v3.ClusterLoadAssignment{}
	p.lastNonce.edsNonce = resp.Nonce
	for _, resource := range resp.GetResources() {
		if err := anypb.UnmarshalTo(resource, loadAssignment, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		cluster := p.Cache.ClusterCache.GetApiCluster(loadAssignment.GetClusterName())
		// fix exceptional scenarios: receive eds push after cds has been deleted
		if cluster == nil {
			log.Debugf("cluster %s is deleted", loadAssignment.GetClusterName())
			continue
		}
		apiStatus := cluster.ApiStatus
		newHash := hash.Sum64String(resource.String())
		// part[0] CDS is different or part[1] EDS is different
		if apiStatus == core_v2.ApiStatus_WAITING ||
			newHash != p.Cache.ClusterCache.GetEdsHash(loadAssignment.GetClusterName()) {
			apiStatus = core_v2.ApiStatus_UPDATE
			p.Cache.ClusterCache.SetEdsHash(loadAssignment.GetClusterName(), newHash)
			log.Debugf("[CreateApiClusterByEds] update cluster %s", loadAssignment.GetClusterName())
			p.Cache.CreateApiClusterByEds(apiStatus, loadAssignment)
		} else {
			log.Debugf("handleEdsResponse: unchanged cluster %s", loadAssignment.GetClusterName())
		}
	}

	// EDS ack should contain all the eds cluster names, and since istiod can send partial eds to us, we use those set by handleCdsResponse
	// Ad xds protocol spec, the non wildcard resource ack should contain all the names
	p.ack.ResourceNames = p.Cache.edsClusterNames

	if p.lastNonce.ldsNonce == "" {
		// subscribe to lds only once per stream
		p.req = newAdsRequest(resource_v3.ListenerType, nil, "")
	}

	p.Cache.ClusterCache.Flush()

	return nil
}

func (p *processor) handleLdsResponse(resp *service_discovery_v3.DiscoveryResponse) error {
	var (
		err      error
		listener = &config_listener_v3.Listener{}
	)

	p.lastNonce.ldsNonce = resp.Nonce
	current := sets.New[string]()
	lastRouteNames := p.Cache.routeNames
	p.Cache.routeNames = []string{}
	for _, resource := range resp.GetResources() {
		if err = anypb.UnmarshalTo(resource, listener, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		if listener.GetAddress() == nil {
			// skip the listener without address
			continue
		}
		current.Insert(listener.GetName())
		apiStatus := core_v2.ApiStatus_UPDATE
		newHash := hash.Sum64String(resource.String())
		if newHash != p.Cache.ListenerCache.GetLdsHash(listener.GetName()) {
			p.Cache.ListenerCache.AddOrUpdateLdsHash(listener.GetName(), newHash)
			log.Debugf("[CreateApiListenerByLds] update %s", listener.GetName())
		} else {
			log.Debugf("[CreateApiListenerByLds] unchanged %s", listener.GetName())
			apiStatus = core_v2.ApiStatus_UNCHANGED
		}
		p.Cache.CreateApiListenerByLds(apiStatus, listener)
	}

	removed := p.Cache.ListenerCache.GetResourceNames().Difference(current)
	for key := range removed {
		p.Cache.UpdateApiListenerStatus(key, core_v2.ApiStatus_DELETE)
	}

	p.Cache.ListenerCache.Flush()

	if !slices.EqualUnordered(p.Cache.routeNames, lastRouteNames) {
		// we cannot set the nonce here.
		// There is a race: when xds server has pushed rds, but kmesh hasn't a chance to receive and process
		// Then it will lead to this request been ignored, we will lose the new rds resource
		p.req = newAdsRequest(resource_v3.RouteType, p.Cache.routeNames, "")
	}
	return nil
}

func (p *processor) handleRdsResponse(resp *service_discovery_v3.DiscoveryResponse) error {
	routeConfiguration := &config_route_v3.RouteConfiguration{}

	p.lastNonce.rdsNonce = resp.Nonce
	current := sets.New[string]()
	for _, resource := range resp.GetResources() {
		if err := anypb.UnmarshalTo(resource, routeConfiguration, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		current.Insert(routeConfiguration.GetName())
		newHash := hash.Sum64String(resource.String())
		if newHash != p.Cache.RouteCache.GetRdsHash(routeConfiguration.GetName()) {
			p.Cache.RouteCache.SetRdsHash(routeConfiguration.GetName(), newHash)
			log.Debugf("[CreateApiRouteByRds] update %s", routeConfiguration.GetName())
			p.Cache.CreateApiRouteByRds(core_v2.ApiStatus_UPDATE, routeConfiguration)
		} else {
			log.Debugf("[CreateApiRouteByRds] unchanged %s", routeConfiguration.GetName())
		}
		// if rds has no virtualhost, no need to subscribe this rds again in response
		if routeConfiguration.GetVirtualHosts() != nil {
			p.ack.ResourceNames = append(p.ack.ResourceNames, routeConfiguration.GetName())
		}
	}

	removed := p.Cache.RouteCache.GetResourceNames().Difference(current)
	for key := range removed {
		p.Cache.RouteCache.UpdateApiRouteStatus(key, core_v2.ApiStatus_DELETE)
	}
	p.Cache.RouteCache.Flush()
	return nil
}

func (p *processor) Reset() {
	if p == nil {
		return
	}
	p.lastNonce = &lastNonce{}
}

func ConfigResourcesIsEmpty(resources *admin_v2.ConfigResources) bool {
	if resources == nil {
		return true
	}

	count := len(resources.GetClusterConfigs()) + len(resources.GetRouteConfigs()) + len(resources.GetListenerConfigs())
	return count == 0
}

func SetApiVersionInfo(resources *admin_v2.ConfigResources) {
	if !ConfigResourcesIsEmpty(resources) {
		resources.VersionInfo = apiVersionInfo
	}
}
