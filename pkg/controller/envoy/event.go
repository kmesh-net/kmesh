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
	"openeuler.io/mesh/pkg/cache/v1"
)

type serviceHandle struct {
	listener cache_v1.ListenerCache
	clusters clusterLoadCache

	ack *serviceDiscoveryV3.DiscoveryRequest
	rqt *serviceDiscoveryV3.DiscoveryRequest
}

func newServiceHandle() *serviceHandle {
	return &serviceHandle{
		listener: make(cache_v1.ListenerCache),
		clusters: make(clusterLoadCache),
		ack:      nil,
		rqt:      nil,
	}
}

func (svc *serviceHandle) destroy() {
	*svc = serviceHandle{}
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
func (svc *serviceHandle) processResponse(rsp *serviceDiscoveryV3.DiscoveryResponse) {
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

func (svc *serviceHandle) handleCdsResponse(rsp *serviceDiscoveryV3.DiscoveryResponse) error {
	var (
		err error
		cluster = &configClusterV3.Cluster{}
		clusterNames []string
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, cluster, proto.UnmarshalOptions{}); err != nil {
			continue
		}

		switch cluster.GetType() {
		case configClusterV3.Cluster_EDS:
			clusterNames = append(clusterNames, cluster.GetName())
		case configClusterV3.Cluster_STATIC:
			extractEndpointCache(svc.clusters, cache_v1.CacheFlagUpdate, cluster.GetLoadAssignment())
		case configClusterV3.Cluster_STRICT_DNS:
		case configClusterV3.Cluster_LOGICAL_DNS:
		case configClusterV3.Cluster_ORIGINAL_DST:
		default:
		}

		//fmt.Println(cluster.String())
		//fmt.Println("")
	}

	if len(clusterNames) > 0 {
		svc.rqt = newAdsRequest(resourceV3.EndpointType, clusterNames)
	} else {
		svc.flushEndpoint()
	}

	return nil
}

func (svc *serviceHandle) handleEdsResponse(rsp *serviceDiscoveryV3.DiscoveryResponse) error {
	var (
		err error
		lbAssignment = &configEndpointV3.ClusterLoadAssignment{}
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, lbAssignment, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		extractEndpointCache(svc.clusters, cache_v1.CacheFlagUpdate, lbAssignment)
	}

	svc.rqt = newAdsRequest(resourceV3.ListenerType, nil)
	return nil
}

func (svc *serviceHandle) handleLdsResponse(rsp *serviceDiscoveryV3.DiscoveryResponse) error {
	var (
		err error
		listener = &configListenerV3.Listener{}
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, listener, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		extractClusterCache(svc.clusters, cache_v1.CacheFlagUpdate, listener)
		extractListenerCache(svc.listener, cache_v1.CacheFlagUpdate, listener)
	}
	svc.flushEndpoint()
	svc.flushCluster()
	svc.flushListener()

	svc.rqt = newAdsRequest(resourceV3.RouteType, nil)
	return nil
}

func (svc *serviceHandle) handleRdsResponse(rsp *serviceDiscoveryV3.DiscoveryResponse) error {
	var (
		err error
		routes = &configRouteV3.RouteConfiguration{}
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource, routes, proto.UnmarshalOptions{}); err != nil {
			continue
		}
		extractRouteCache(nil, cache_v1.CacheFlagUpdate, rsp)
	}

	svc.rqt = nil
	return nil
}

func (svc *serviceHandle) flushEndpoint() {
	for _, load := range svc.clusters {
		load.endpoint.ResetFlag(cache_v1.CacheFlagNone, cache_v1.CacheFlagDelete)
		load.endpoint.Flush(cache_v1.CacheFlagUpdate, load.endpointsCount, load.endpointsAddressToMapKey)
		load.endpoint.Flush(cache_v1.CacheFlagDelete, load.endpointsCount, load.endpointsAddressToMapKey)

		load.endpoint.DeleteFlag(cache_v1.CacheFlagDelete)
		load.endpoint.ResetFlag(cache_v1.CacheFlagUpdate, cache_v1.CacheFlagNone)
	}
}

func (svc *serviceHandle) flushCluster() {
	for _, load := range svc.clusters {
		load.cluster.ResetFlag(cache_v1.CacheFlagNone, cache_v1.CacheFlagDelete)
		load.cluster.Flush(cache_v1.CacheFlagUpdate, load.clusterCount)
		load.cluster.Flush(cache_v1.CacheFlagDelete, load.clusterCount)

		load.cluster.DeleteFlag(cache_v1.CacheFlagDelete)
		load.cluster.ResetFlag(cache_v1.CacheFlagUpdate, cache_v1.CacheFlagNone)
	}
}

func (svc *serviceHandle) flushListener() {
	svc.listener.ResetFlag(cache_v1.CacheFlagNone, cache_v1.CacheFlagDelete)
	svc.listener.Flush(cache_v1.CacheFlagUpdate)
	svc.listener.Flush(cache_v1.CacheFlagDelete)

	svc.listener.DeleteFlag(cache_v1.CacheFlagDelete)
	svc.listener.ResetFlag(cache_v1.CacheFlagUpdate, cache_v1.CacheFlagNone)
}
