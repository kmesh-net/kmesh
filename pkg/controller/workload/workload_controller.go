/*
 * Copyright 2024 The Kmesh Authors.
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

package workload

import (
	"context"
	"fmt"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"kmesh.net/kmesh/pkg/auth"
	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	AddressType       = "type.googleapis.com/istio.workload.Address"
	AuthorizationType = "type.googleapis.com/istio.security.Authorization"
)

var log = logger.NewLoggerField("workload_controller")

type Controller struct {
	Stream         discoveryv3.AggregatedDiscoveryService_DeltaAggregatedResourcesClient
	Processor      *Processor
	Rbac           *auth.Rbac
	bpfWorkloadObj *bpf.BpfKmeshWorkload
}

func NewController(bpfWorkload *bpf.BpfKmeshWorkload) *Controller {
	c := &Controller{
		Processor:      newProcessor(bpfWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps),
		bpfWorkloadObj: bpfWorkload,
	}
	c.Rbac = auth.NewRbac(c.Processor.WorkloadCache)
	return c
}

func (c *Controller) Run(ctx context.Context) {
	go c.Rbac.Run(ctx, c.bpfWorkloadObj.SockOps.MapOfTuple, c.bpfWorkloadObj.XdpAuth.MapOfAuth)
}

func (c *Controller) WorkloadStreamCreateAndSend(client discoveryv3.AggregatedDiscoveryServiceClient, ctx context.Context) error {
	var (
		err                     error
		initialResourceVersions map[string]string
	)

	c.Stream, err = client.DeltaAggregatedResources(ctx)
	if err != nil {
		return fmt.Errorf("DeltaAggregatedResources failed, %s", err)
	}

	if c.Processor != nil {
		cachedServices := c.Processor.ServiceCache.List()
		cachedWorkloads := c.Processor.WorkloadCache.List()
		initialResourceVersions = make(map[string]string, len(cachedServices)+len(cachedWorkloads))

		// add cached resource names
		for _, service := range cachedServices {
			initialResourceVersions[service.ResourceName()] = ""
		}

		for _, workload := range cachedWorkloads {
			initialResourceVersions[workload.ResourceName()] = ""
		}
	}

	log.Debugf("send initial request with address resources: %v", initialResourceVersions)
	if err := c.Stream.Send(newDeltaRequest(AddressType, nil, initialResourceVersions)); err != nil {
		return fmt.Errorf("send request failed, %s", err)
	}

	initialResourceVersions = c.Rbac.GetAllPolicies()
	log.Debugf("send initial request with authorization resources: %v", initialResourceVersions)
	if err = c.Stream.Send(newDeltaRequest(AuthorizationType, nil, initialResourceVersions)); err != nil {
		return fmt.Errorf("authorization subscribe failed, %s", err)
	}

	return nil
}

func (c *Controller) HandleWorkloadStream() error {
	var (
		err      error
		rspDelta *discoveryv3.DeltaDiscoveryResponse
	)

	if rspDelta, err = c.Stream.Recv(); err != nil {
		return fmt.Errorf("stream recv failed, %s", err)
	}

	c.Processor.processWorkloadResponse(rspDelta, c.Rbac)

	if err = c.Stream.Send(c.Processor.ack); err != nil {
		return fmt.Errorf("stream send ack failed, %s", err)
	}

	if c.Processor.req != nil {
		if err = c.Stream.Send(c.Processor.req); err != nil {
			return fmt.Errorf("stream send req failed, %s", err)
		}
	}

	return nil
}
