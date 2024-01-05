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

	admin_v2 "kmesh.net/kmesh/api/v2/admin"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	cache_v2 "kmesh.net/kmesh/pkg/cache/v2"
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
	return
}

func (svc *ServiceEvent) handleCdsResponse(rsp *service_discovery_v3.DiscoveryResponse) error {
	var (
		err     error
		cluster = &config_cluster_v3.Cluster{}
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, cluster, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		// compare part[0] CDS now
		// Cluster_EDS need compare tow parts, compare part[1] EDS in EDS handler
		apiStatus := core_v2.ApiStatus_UPDATE
		newCdsString := resource.String()
		if newCdsString != svc.DynamicLoader.ClusterCache.GetCdsResource(cluster.GetName()) {
			svc.DynamicLoader.ClusterCache.SetCdsResource(cluster.GetName(), newCdsString)
			log.Debugf("[CreateApiClusterByCds]update cluster %s, status %d, cluster.type %v",
				cluster.GetName(), apiStatus, cluster.GetType())
		} else {
			apiStatus = core_v2.ApiStatus_UNCHANGED
		}
		svc.DynamicLoader.CreateApiClusterByCds(apiStatus, cluster)
	}

	if len(svc.DynamicLoader.clusterNames) > 0 {
		svc.rqt = newAdsRequest(resource_v3.EndpointType, svc.DynamicLoader.clusterNames)
		svc.DynamicLoader.clusterNames = nil
	} else {
		cache_v2.CacheFlush(svc.DynamicLoader.ClusterCache)
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
		apiStatus := svc.DynamicLoader.ClusterCache.GetApiClusterCache(loadAssignment.GetClusterName()).ApiStatus
		newEdsString := resource.String()
		//part[0] CDS is different or part[1] EDS is different
		if apiStatus == core_v2.ApiStatus_UPDATE ||
			newEdsString != svc.DynamicLoader.ClusterCache.GetEdsResource(loadAssignment.GetClusterName()){
			apiStatus = core_v2.ApiStatus_UPDATE
			svc.DynamicLoader.ClusterCache.SetEdsResource(loadAssignment.GetClusterName(), newEdsString)
			log.Debugf("[CreateApiClusterByEds] update cluster %s", loadAssignment.GetClusterName())
		} else {
			apiStatus = core_v2.ApiStatus_UNCHANGED
		}
		svc.DynamicLoader.CreateApiClusterByEds(apiStatus, loadAssignment)
	}

	svc.rqt = newAdsRequest(resource_v3.ListenerType, nil)
	cache_v2.CacheFlush(svc.DynamicLoader.ClusterCache)
	return nil
}

func (svc *ServiceEvent) handleLdsResponse(rsp *service_discovery_v3.DiscoveryResponse) error {
	var (
		err      error
		listener = &config_listener_v3.Listener{}
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, listener, proto.UnmarshalOptions{}); err != nil {
			continue
		}

		apiStatus := core_v2.ApiStatus_UPDATE
		newLdsResource := resource.String()
		if newLdsResource != svc.DynamicLoader.ListenerCache.GetLdsResource(listener.GetName()) {
			svc.DynamicLoader.ListenerCache.SetLdsResource(listener.GetName(), newLdsResource)
			log.Debugf("[CreateApiListenerByLds]update %s", listener.GetName())
		} else {
			apiStatus = core_v2.ApiStatus_UNCHANGED
		}

		svc.DynamicLoader.CreateApiListenerByLds(apiStatus, listener)
	}

	cache_v2.CacheFlush(svc.DynamicLoader.ListenerCache)
	if len(svc.DynamicLoader.routeNames) > 0 {
		svc.rqt = newAdsRequest(resource_v3.RouteType, svc.DynamicLoader.routeNames)
		svc.DynamicLoader.routeNames = nil
	} else {
		cache_v2.CacheFlush(svc.DynamicLoader.RouteCache)
	}

	return nil
}

func (svc *ServiceEvent) handleRdsResponse(rsp *service_discovery_v3.DiscoveryResponse) error {
	var (
		err                error
		routeConfiguration = &config_route_v3.RouteConfiguration{}
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, routeConfiguration, proto.UnmarshalOptions{}); err != nil {
			continue
		}

		apiStatus := core_v2.ApiStatus_UPDATE
		newRdsResource := resource.String()
		if newRdsResource != svc.DynamicLoader.RouteCache.GetRdsResource(routeConfiguration.GetName()) {
			svc.DynamicLoader.RouteCache.SetRdsResource(routeConfiguration.GetName(), newRdsResource)
			log.Debugf("[CreateApiRouteByRds] update %s", routeConfiguration.GetName())
		} else {
			apiStatus = core_v2.ApiStatus_UNCHANGED
		}

		svc.DynamicLoader.CreateApiRouteByRds(apiStatus, routeConfiguration)
	}

	svc.rqt = nil
	cache_v2.CacheFlush(svc.DynamicLoader.RouteCache)
	return nil
}

func (svc *ServiceEvent) NewAdminRequest(resources *admin_v2.ConfigResources) {
	svc.adminChan <- resources
}

func (svc *ServiceEvent) processAdminResponse(ctx context.Context) {
	for true {
		select {
		case <-ctx.Done():
			return
		case resources := <-svc.adminChan:
			if err := svc.handleAdminResponse(resources); err != nil {
				log.Error("handleAdminResponse failed err:%s", err)
			}
		}
	}
}

func (svc *ServiceEvent) handleAdminResponse(resources *admin_v2.ConfigResources) error {
	if ConfigResourcesIsEmpty(resources) {
		return nil
	}

	for _, cluster := range resources.GetClusterConfigs() {
		svc.StaticLoader.ClusterCache.SetApiClusterCache(cluster.GetName(), cluster)
	}
	for _, listener := range resources.GetListenerConfigs() {
		svc.StaticLoader.ListenerCache.SetApiListenerCache(listener.GetName(), listener)
	}
	for _, route := range resources.GetRouteConfigs() {
		svc.StaticLoader.RouteCache.SetApiRouteConfigCache(route.GetName(), route)
	}

	cache_v2.CacheDeltaFlush(svc.StaticLoader.ClusterCache)
	cache_v2.CacheDeltaFlush(svc.StaticLoader.ListenerCache)
	cache_v2.CacheDeltaFlush(svc.StaticLoader.RouteCache)

	return nil
}

func ConfigResourcesIsEmpty(resources *admin_v2.ConfigResources) bool {
	if resources == nil {
		return true
	}

	count := len(resources.GetClusterConfigs()) + len(resources.GetRouteConfigs()) + len(resources.GetListenerConfigs())
	if count == 0 {
		return true
	}

	return false
}

func SetApiVersionInfo(resources *admin_v2.ConfigResources) {
	if !ConfigResourcesIsEmpty(resources) {
		resources.VersionInfo = apiVersionInfo
	}
}