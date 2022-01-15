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
 * Create: 2021-10-09
 */

package envoy

import (
	envoyServiceDiscoveryV3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourceV3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

type serviceHandle struct {

}

func initAdsRequest(typeUrl string) *envoyServiceDiscoveryV3.DiscoveryRequest {
	return &envoyServiceDiscoveryV3.DiscoveryRequest{
		TypeUrl:       typeUrl,
		VersionInfo:   "",
		ResourceNames: []string{},
		ResponseNonce: "",
		ErrorDetail:   nil,
		Node:          config.getNode(),
	}
}

func newAckRequest(rsp *envoyServiceDiscoveryV3.DiscoveryResponse) *envoyServiceDiscoveryV3.DiscoveryRequest {
	return &envoyServiceDiscoveryV3.DiscoveryRequest{
		TypeUrl:       rsp.GetTypeUrl(),
		VersionInfo:   rsp.GetVersionInfo(),
		ResourceNames: []string{},
		ResponseNonce: rsp.GetNonce(),
		ErrorDetail:   nil,
		Node:          config.getNode(),
	}
}

func (svc *serviceHandle) handleAds(rsp *envoyServiceDiscoveryV3.DiscoveryResponse) error {
	var err error

	log.Debugf("handle ads response, %#v\n", rsp)

	if rsp.GetResources() == nil {
		return nil
	}

	switch rsp.GetTypeUrl() {
	case resourceV3.ListenerType:
		err = svc.handleLdsResponse(rsp)
	case resourceV3.ClusterType:
		err = svc.handleCdsResponse(rsp)
	case resourceV3.RouteType:
		err = svc.handleRdsResponse(rsp)
	case resourceV3.EndpointType:
		err = svc.handleEdsResponse(rsp)
	case resourceV3.ExtensionConfigType:
	default:

	}

	return err
}

func (svc *serviceHandle) handleLdsResponse(rsp *envoyServiceDiscoveryV3.DiscoveryResponse) error {
	return nil
}

func (svc *serviceHandle) handleCdsResponse(rsp *envoyServiceDiscoveryV3.DiscoveryResponse) error {
	return nil
}

func (svc *serviceHandle) handleRdsResponse(rsp *envoyServiceDiscoveryV3.DiscoveryResponse) error {
	return nil
}

func (svc *serviceHandle) handleEdsResponse(rsp *envoyServiceDiscoveryV3.DiscoveryResponse) error {
	return nil
}