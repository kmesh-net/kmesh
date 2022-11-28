/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
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

	admin_v2 "openeuler.io/mesh/api/v2/admin"
	core_v2 "openeuler.io/mesh/api/v2/core"
	cache_v2 "openeuler.io/mesh/pkg/cache/v2"
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

		svc.DynamicLoader.CreateApiClusterByCds(core_v2.ApiStatus_UPDATE, cluster)
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
		svc.DynamicLoader.CreateApiClusterByEds(core_v2.ApiStatus_UPDATE, loadAssignment)
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
		svc.DynamicLoader.CreateApiListenerByLds(core_v2.ApiStatus_UPDATE, listener)
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
		svc.DynamicLoader.CreateApiRouteByRds(core_v2.ApiStatus_UPDATE, routeConfiguration)
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
		svc.StaticLoader.ClusterCache[cluster.GetName()] = cluster
	}
	for _, listener := range resources.GetListenerConfigs() {
		svc.StaticLoader.ListenerCache[listener.GetName()] = listener
	}
	for _, route := range resources.GetRouteConfigs() {
		svc.StaticLoader.RouteCache[route.GetName()] = route
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
