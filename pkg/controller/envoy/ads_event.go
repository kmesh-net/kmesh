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

 * Author: LemmyHuang
 * Create: 2022-01-08
 */

package envoy

import (
	"context"
	"fmt"

	config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resource_v3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/apimachinery/pkg/util/sets"

	admin_v2 "kmesh.net/kmesh/api/v2/admin"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/pkg/utils/hash"
)

const (
	apiVersionInfo   = "v2"
	maxAdminRequests = 16
)

type ServiceEvent struct {
	StaticLoader  *AdsLoader
	DynamicLoader *AdsLoader
	ack           *service_discovery_v3.DiscoveryRequest
	rqt           *service_discovery_v3.DiscoveryRequest
	adminChan     chan *admin_v2.ConfigResources
}

func NewServiceEvent() *ServiceEvent {
	return &ServiceEvent{
		StaticLoader:  NewAdsLoader(),
		DynamicLoader: NewAdsLoader(),
		ack:           nil,
		rqt:           nil,
		adminChan:     make(chan *admin_v2.ConfigResources, maxAdminRequests),
	}
}

func (svc *ServiceEvent) Destroy() {
	if svc.adminChan != nil {
		close(svc.adminChan)
	}
	*svc = ServiceEvent{}
}

func newAdsRequest(typeUrl string, names []string) *service_discovery_v3.DiscoveryRequest {
	return &service_discovery_v3.DiscoveryRequest{
		TypeUrl:       typeUrl,
		VersionInfo:   "",
		ResourceNames: names,
		ResponseNonce: "",
		ErrorDetail:   nil,
		Node:          config.getNode(),
	}
}

func newAckRequest(rsp *service_discovery_v3.DiscoveryResponse) *service_discovery_v3.DiscoveryRequest {
	return &service_discovery_v3.DiscoveryRequest{
		TypeUrl:       rsp.GetTypeUrl(),
		VersionInfo:   rsp.GetVersionInfo(),
		ResourceNames: []string{},
		ResponseNonce: rsp.GetNonce(),
		ErrorDetail:   nil,
		Node:          config.getNode(),
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
func (svc *ServiceEvent) processAdsResponse(rsp *service_discovery_v3.DiscoveryResponse) {
	var err error

	log.Debugf("handle ads response, %#v\n", rsp.GetTypeUrl())

	svc.ack = newAckRequest(rsp)
	if rsp.GetResources() == nil {
		return
	}

	switch rsp.GetTypeUrl() {
	case resource_v3.ClusterType:
		err = svc.handleCdsResponse(rsp)
	case resource_v3.EndpointType:
		err = svc.handleEdsResponse(rsp)
	case resource_v3.ListenerType:
		err = svc.handleLdsResponse(rsp)
	case resource_v3.RouteType:
		err = svc.handleRdsResponse(rsp)
	default:
		err = fmt.Errorf("unsupport type url %s", rsp.GetTypeUrl())
	}

	if err != nil {
		log.Error(err)
	}
}

func (svc *ServiceEvent) handleCdsResponse(rsp *service_discovery_v3.DiscoveryResponse) error {
	var (
		err     error
		cluster = &config_cluster_v3.Cluster{}
	)

	current := sets.New[string]()
	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, cluster, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		current.Insert(cluster.GetName())
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

	if len(svc.DynamicLoader.clusterNames) > 0 {
		svc.rqt = newAdsRequest(resource_v3.EndpointType, svc.DynamicLoader.clusterNames)
		svc.DynamicLoader.clusterNames = nil
	} else {
		svc.DynamicLoader.ClusterCache.Flush()
	}
	return nil
}

func (svc *ServiceEvent) handleEdsResponse(rsp *service_discovery_v3.DiscoveryResponse) error {
	var (
		err            error
		loadAssignment = &config_endpoint_v3.ClusterLoadAssignment{}
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, loadAssignment, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		apiStatus := svc.DynamicLoader.ClusterCache.GetApiCluster(loadAssignment.GetClusterName()).ApiStatus
		newHash := hash.Sum64String(resource.String())
		// part[0] CDS is different or part[1] EDS is different
		if apiStatus == core_v2.ApiStatus_UPDATE ||
			newHash != svc.DynamicLoader.ClusterCache.GetEdsHash(loadAssignment.GetClusterName()) {
			apiStatus = core_v2.ApiStatus_UPDATE
			svc.DynamicLoader.ClusterCache.SetEdsHash(loadAssignment.GetClusterName(), newHash)
			log.Debugf("[CreateApiClusterByEds] update cluster %s", loadAssignment.GetClusterName())
			svc.DynamicLoader.CreateApiClusterByEds(apiStatus, loadAssignment)
		}
	}

	svc.rqt = newAdsRequest(resource_v3.ListenerType, nil)
	svc.DynamicLoader.ClusterCache.Flush()
	return nil
}

func (svc *ServiceEvent) handleLdsResponse(rsp *service_discovery_v3.DiscoveryResponse) error {
	var (
		err      error
		listener = &config_listener_v3.Listener{}
	)
	current := sets.New[string]()
	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, listener, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		current.Insert(listener.GetName())
		newHash := hash.Sum64String(resource.String())
		if newHash != svc.DynamicLoader.ListenerCache.GetLdsHash(listener.GetName()) {
			svc.DynamicLoader.ListenerCache.AddOrUpdateLdsHash(listener.GetName(), newHash)
			log.Debugf("[CreateApiListenerByLds] update %s", listener.GetName())
			svc.DynamicLoader.CreateApiListenerByLds(core_v2.ApiStatus_UPDATE, listener)
		} else {
			log.Debugf("[CreateApiListenerByLds] unchanged %s", listener.GetName())
		}
	}

	removed := svc.DynamicLoader.ListenerCache.GetResourceNames().Difference(current)
	for key := range removed {
		svc.DynamicLoader.UpdateApiClusterStatus(key, core_v2.ApiStatus_DELETE)
	}

	svc.DynamicLoader.ListenerCache.Flush()

	if len(svc.DynamicLoader.routeNames) > 0 {
		svc.rqt = newAdsRequest(resource_v3.RouteType, svc.DynamicLoader.routeNames)
		svc.DynamicLoader.routeNames = nil
	}
	return nil
}

func (svc *ServiceEvent) handleRdsResponse(rsp *service_discovery_v3.DiscoveryResponse) error {
	var (
		err                error
		routeConfiguration = &config_route_v3.RouteConfiguration{}
	)

	current := sets.New[string]()
	for _, resource := range rsp.GetResources() {
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

func (svc *ServiceEvent) processAdminResponse(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case resources := <-svc.adminChan:
			if err := svc.handleAdminResponse(resources); err != nil {
				log.Errorf("handleAdminResponse failed err: %s", err)
			}
		}
	}
}

func (svc *ServiceEvent) handleAdminResponse(resources *admin_v2.ConfigResources) error {
	if ConfigResourcesIsEmpty(resources) {
		return nil
	}

	for _, cluster := range resources.GetClusterConfigs() {
		svc.StaticLoader.ClusterCache.SetApiCluster(cluster.GetName(), cluster)
	}
	for _, listener := range resources.GetListenerConfigs() {
		svc.StaticLoader.ListenerCache.SetApiListener(listener.GetName(), listener)
	}
	for _, route := range resources.GetRouteConfigs() {
		svc.StaticLoader.RouteCache.SetApiRouteConfig(route.GetName(), route)
	}

	svc.StaticLoader.ClusterCache.Flush()
	svc.StaticLoader.ListenerCache.Flush()
	svc.StaticLoader.RouteCache.Flush()

	return nil
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
