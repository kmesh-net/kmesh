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
	configClusterV3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	configEndpointV3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	configListenerV3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	configRouteV3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	serviceDiscoveryV3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourceV3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	core_v2 "openeuler.io/mesh/api/v2/core"
	cache_v2 "openeuler.io/mesh/pkg/cache/v2"
)

type serviceEvent struct {
	loader *adsLoader
	ack *serviceDiscoveryV3.DiscoveryRequest
	rqt *serviceDiscoveryV3.DiscoveryRequest
}

func newServiceEvent() *serviceEvent {
	return &serviceEvent{
		loader: newAdsLoader(),
		ack:    nil,
		rqt:    nil,
	}
}

func (svc *serviceEvent) destroy() {
	*svc = serviceEvent{}
}

func newAdsRequest(typeUrl string, names []string) *serviceDiscoveryV3.DiscoveryRequest {
	return &serviceDiscoveryV3.DiscoveryRequest{
		TypeUrl:       typeUrl,
		VersionInfo:   "",
		ResourceNames: names,
		ResponseNonce: "",
		ErrorDetail:   nil,
		Node:          config.getNode(),
	}
}

func newAckRequest(rsp *serviceDiscoveryV3.DiscoveryResponse) *serviceDiscoveryV3.DiscoveryRequest {
	return &serviceDiscoveryV3.DiscoveryRequest{
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
func (svc *serviceEvent) processResponse(rsp *serviceDiscoveryV3.DiscoveryResponse) {
	var err error

	log.Debugf("handle ads response, %#v\n", rsp.GetTypeUrl())

	svc.ack = newAckRequest(rsp)
	if rsp.GetResources() == nil {
		return
	}

	switch rsp.GetTypeUrl() {
	case resourceV3.ClusterType:
		err = svc.handleCdsResponse(rsp)
	case resourceV3.EndpointType:
		err = svc.handleEdsResponse(rsp)
	case resourceV3.ListenerType:
		err = svc.handleLdsResponse(rsp)
	case resourceV3.RouteType:
		err = svc.handleRdsResponse(rsp)
	default:
		log.Errorf("unsupport type url %s", rsp.GetTypeUrl())
	}

	if err != nil {
		log.Error(err)
	}
	return
}

func (svc *serviceEvent) handleCdsResponse(rsp *serviceDiscoveryV3.DiscoveryResponse) error {
	var (
		err error
		cluster = &configClusterV3.Cluster{}
		clusterNames []string
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, cluster, proto.UnmarshalOptions{}); err != nil {
			continue
		}

		svc.loader.createApiClusterByCDS(core_v2.ApiStatus_UPDATE, cluster)

		if cluster.GetType() == configClusterV3.Cluster_EDS {
			clusterNames = append(clusterNames, cluster.GetName())
		}
	}

	if len(clusterNames) > 0 {
		svc.rqt = newAdsRequest(resourceV3.EndpointType, clusterNames)
	} else {
		cache_v2.CacheFlush(svc.loader.clusterCache)
	}
	return nil
}

func (svc *serviceEvent) handleEdsResponse(rsp *serviceDiscoveryV3.DiscoveryResponse) error {
	var (
		err error
		loadAssignment = &configEndpointV3.ClusterLoadAssignment{}
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, loadAssignment, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		svc.loader.createApiClusterByEDS(core_v2.ApiStatus_UPDATE, loadAssignment)
	}

	svc.rqt = newAdsRequest(resourceV3.ListenerType, nil)
	cache_v2.CacheFlush(svc.loader.clusterCache)
	return nil
}

func (svc *serviceEvent) handleLdsResponse(rsp *serviceDiscoveryV3.DiscoveryResponse) error {
	var (
		err error
		listener = &configListenerV3.Listener{}
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, listener, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		svc.loader.createApiListenerByLDS(core_v2.ApiStatus_UPDATE, listener)
	}

	svc.rqt = newAdsRequest(resourceV3.RouteType, nil)
	cache_v2.CacheFlush(svc.loader.listenerCache)
	return nil
}

func (svc *serviceEvent) handleRdsResponse(rsp *serviceDiscoveryV3.DiscoveryResponse) error {
	var (
		err error
		routeConfiguration = &configRouteV3.RouteConfiguration{}
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, routeConfiguration, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		svc.loader.createApiRouteByRDS(core_v2.ApiStatus_UPDATE, routeConfiguration)
	}

	svc.rqt = nil
	cache_v2.CacheFlush(svc.loader.routeCache)
	return nil
}
