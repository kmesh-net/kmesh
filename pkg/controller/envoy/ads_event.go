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

package envoy

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
	"kmesh.net/kmesh/pkg/controller/config"
	"kmesh.net/kmesh/pkg/utils/hash"
)

const (
	apiVersionInfo   = "v2"
	maxAdminRequests = 16
)

type lastNonce struct {
	cdsNonce string
	edsNonce string
	ldsNonce string
	rdsNonce string
}
type ServiceEvent struct {
	DynamicLoader *AdsLoader
	ack           *service_discovery_v3.DiscoveryRequest
	rqt           *service_discovery_v3.DiscoveryRequest
	adminChan     chan *admin_v2.ConfigResources
	LastNonce     *lastNonce
}

func NewServiceEvent() *ServiceEvent {
	return &ServiceEvent{
		DynamicLoader: NewAdsLoader(),
		ack:           nil,
		rqt:           nil,
		adminChan:     make(chan *admin_v2.ConfigResources, maxAdminRequests),
		LastNonce:     NewLastNonce(),
	}
}

func NewLastNonce() *lastNonce {
	return &lastNonce{
		cdsNonce: "",
		edsNonce: "",
		ldsNonce: "",
		rdsNonce: "",
	}
}

func (svc *ServiceEvent) Destroy() {
	if svc.adminChan != nil {
		close(svc.adminChan)
	}
	*svc = ServiceEvent{}
}

func newAdsRequest(typeUrl string, names []string, nonce string) *service_discovery_v3.DiscoveryRequest {
	return &service_discovery_v3.DiscoveryRequest{
		TypeUrl:       typeUrl,
		VersionInfo:   "",
		ResourceNames: names,
		ResponseNonce: nonce,
		ErrorDetail:   nil,
		Node:          config.GetConfig().GetNode(),
	}
}

func newAckRequest(resp *service_discovery_v3.DiscoveryResponse) *service_discovery_v3.DiscoveryRequest {
	return &service_discovery_v3.DiscoveryRequest{
		TypeUrl:       resp.GetTypeUrl(),
		VersionInfo:   resp.GetVersionInfo(),
		ResourceNames: []string{},
		ResponseNonce: resp.GetNonce(),
		ErrorDetail:   nil,
		Node:          config.GetConfig().GetNode(),
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
func (svc *ServiceEvent) processAdsResponse(resp *service_discovery_v3.DiscoveryResponse) {
	var err error

	log.Debugf("handle ads response, %#v\n", resp.GetTypeUrl())

	svc.ack = newAckRequest(resp)
	if resp.GetResources() == nil {
		return
	}

	switch resp.GetTypeUrl() {
	case resource_v3.ClusterType:
		err = svc.handleCdsResponse(resp)
	case resource_v3.EndpointType:
		err = svc.handleEdsResponse(resp)
	case resource_v3.ListenerType:
		err = svc.handleLdsResponse(resp)
	case resource_v3.RouteType:
		err = svc.handleRdsResponse(resp)
	default:
		err = fmt.Errorf("unsupport type url %s", resp.GetTypeUrl())
	}

	if err != nil {
		log.Error(err)
	}
}

func (svc *ServiceEvent) handleCdsResponse(resp *service_discovery_v3.DiscoveryResponse) error {
	var (
		err     error
		cluster = &config_cluster_v3.Cluster{}
	)

	svc.LastNonce.cdsNonce = resp.Nonce
	current := sets.New[string]()
	lastEdsClusterNames := svc.DynamicLoader.edsClusterNames
	svc.DynamicLoader.edsClusterNames = []string{}
	for _, resource := range resp.GetResources() {
		if err = anypb.UnmarshalTo(resource, cluster, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		current.Insert(cluster.GetName())
		if cluster.GetType() == config_cluster_v3.Cluster_EDS {
			svc.DynamicLoader.edsClusterNames = append(svc.DynamicLoader.edsClusterNames, cluster.GetName())
		}
		// compare part[0] CDS now
		// Cluster_EDS need compare tow parts, compare part[1] EDS in EDS handler
		apiStatus := core_v2.ApiStatus_UPDATE
		newHash := hash.Sum64String(resource.String())
		if newHash != svc.DynamicLoader.ClusterCache.GetCdsHash(cluster.GetName()) {
			svc.DynamicLoader.ClusterCache.SetCdsHash(cluster.GetName(), newHash)
			log.Debugf("[CreateApiClusterByCds] update cluster %s, status %d, cluster.type %v",
				cluster.GetName(), apiStatus, cluster.GetType())
			svc.DynamicLoader.CreateApiClusterByCds(apiStatus, cluster)
		} else {
			log.Debugf("unchanged cluster %s", cluster.GetName())
		}
	}

	removed := svc.DynamicLoader.ClusterCache.GetResourceNames().Difference(current)
	for key := range removed {
		svc.DynamicLoader.UpdateApiClusterStatus(key, core_v2.ApiStatus_DELETE)
	}

	// TODO: maybe we don't need to wait until all clusters ready before loading, like cluster delete

	// when the list of eds typed clusters subscribed changed, we should resubscrbe to new eds.
	if !slices.EqualUnordered(svc.DynamicLoader.edsClusterNames, lastEdsClusterNames) {
		svc.rqt = newAdsRequest(resource_v3.EndpointType, svc.DynamicLoader.edsClusterNames, svc.LastNonce.edsNonce)
	} else {
		svc.DynamicLoader.ClusterCache.Flush()
	}
	return nil
}

func (svc *ServiceEvent) handleEdsResponse(resp *service_discovery_v3.DiscoveryResponse) error {
	var (
		err            error
		loadAssignment = &config_endpoint_v3.ClusterLoadAssignment{}
	)

	svc.LastNonce.edsNonce = resp.Nonce
	for _, resource := range resp.GetResources() {
		if err = anypb.UnmarshalTo(resource, loadAssignment, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		cluster := svc.DynamicLoader.ClusterCache.GetApiCluster(loadAssignment.GetClusterName())
		// fix exceptional scenarios: receive eds push after cds has been deleted
		if cluster == nil {
			continue
		}
		apiStatus := cluster.ApiStatus
		newHash := hash.Sum64String(resource.String())
		// part[0] CDS is different or part[1] EDS is different
		if apiStatus == core_v2.ApiStatus_UPDATE ||
			newHash != svc.DynamicLoader.ClusterCache.GetEdsHash(loadAssignment.GetClusterName()) {
			apiStatus = core_v2.ApiStatus_UPDATE
			svc.DynamicLoader.ClusterCache.SetEdsHash(loadAssignment.GetClusterName(), newHash)
			log.Debugf("[CreateApiClusterByEds] update cluster %s", loadAssignment.GetClusterName())
			svc.DynamicLoader.CreateApiClusterByEds(apiStatus, loadAssignment)
		}
		svc.ack.ResourceNames = append(svc.ack.ResourceNames, loadAssignment.GetClusterName())
	}

	svc.rqt = newAdsRequest(resource_v3.ListenerType, nil, svc.LastNonce.ldsNonce)
	svc.DynamicLoader.ClusterCache.Flush()
	return nil
}

func (svc *ServiceEvent) handleLdsResponse(resp *service_discovery_v3.DiscoveryResponse) error {
	var (
		err      error
		listener = &config_listener_v3.Listener{}
	)

	svc.LastNonce.ldsNonce = resp.Nonce
	current := sets.New[string]()
	lastRouteNames := svc.DynamicLoader.routeNames
	svc.DynamicLoader.routeNames = []string{}
	for _, resource := range resp.GetResources() {
		if err = anypb.UnmarshalTo(resource, listener, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		current.Insert(listener.GetName())
		apiStatus := core_v2.ApiStatus_UPDATE
		newHash := hash.Sum64String(resource.String())
		if newHash != svc.DynamicLoader.ListenerCache.GetLdsHash(listener.GetName()) {
			svc.DynamicLoader.ListenerCache.AddOrUpdateLdsHash(listener.GetName(), newHash)
			log.Debugf("[CreateApiListenerByLds] update %s", listener.GetName())
		} else {
			log.Debugf("[CreateApiListenerByLds] unchanged %s", listener.GetName())
			apiStatus = core_v2.ApiStatus_UNCHANGED
		}
		svc.DynamicLoader.CreateApiListenerByLds(apiStatus, listener)
	}

	removed := svc.DynamicLoader.ListenerCache.GetResourceNames().Difference(current)
	for key := range removed {
		svc.DynamicLoader.UpdateApiListenerStatus(key, core_v2.ApiStatus_DELETE)
	}

	svc.DynamicLoader.ListenerCache.Flush()

	if !slices.EqualUnordered(svc.DynamicLoader.routeNames, lastRouteNames) {
		svc.rqt = newAdsRequest(resource_v3.RouteType, svc.DynamicLoader.routeNames, svc.LastNonce.rdsNonce)
	}
	return nil
}

func (svc *ServiceEvent) handleRdsResponse(resp *service_discovery_v3.DiscoveryResponse) error {
	var (
		err                error
		routeConfiguration = &config_route_v3.RouteConfiguration{}
	)

	svc.LastNonce.rdsNonce = resp.Nonce
	current := sets.New[string]()
	for _, resource := range resp.GetResources() {
		if err = anypb.UnmarshalTo(resource, routeConfiguration, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		current.Insert(routeConfiguration.GetName())
		newHash := hash.Sum64String(resource.String())
		if newHash != svc.DynamicLoader.RouteCache.GetRdsHash(routeConfiguration.GetName()) {
			svc.DynamicLoader.RouteCache.SetRdsHash(routeConfiguration.GetName(), newHash)
			log.Debugf("[CreateApiRouteByRds] update %s", routeConfiguration.GetName())
			svc.DynamicLoader.CreateApiRouteByRds(core_v2.ApiStatus_UPDATE, routeConfiguration)
		} else {
			log.Debugf("[CreateApiRouteByRds] unchanged %s", routeConfiguration.GetName())
		}
		// if rds has no virtualhost, no need to subscribe this rds again in response
		if routeConfiguration.GetVirtualHosts() != nil {
			svc.ack.ResourceNames = append(svc.ack.ResourceNames, routeConfiguration.GetName())
		}
	}
	removed := svc.DynamicLoader.RouteCache.GetResourceNames().Difference(current)
	for key := range removed {
		svc.DynamicLoader.RouteCache.UpdateApiRouteStatus(key, core_v2.ApiStatus_DELETE)
	}

	svc.rqt = nil
	svc.DynamicLoader.RouteCache.Flush()
	return nil
}

func (svc *ServiceEvent) NewAdminRequest(resources *admin_v2.ConfigResources) {
	svc.adminChan <- resources
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
