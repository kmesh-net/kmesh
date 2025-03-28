/*
 * Copyright The Kmesh Authors.
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
	"sync"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"kmesh.net/kmesh/pkg/auth"
	"kmesh.net/kmesh/pkg/bpf/restart"
	bpfwl "kmesh.net/kmesh/pkg/bpf/workload"
	"kmesh.net/kmesh/pkg/controller/telemetry"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	AddressType       = "type.googleapis.com/istio.workload.Address"
	AuthorizationType = "type.googleapis.com/istio.security.Authorization"
)

var log = logger.NewLoggerScope("workload_controller")

type Controller struct {
	Stream                    discoveryv3.AggregatedDiscoveryService_DeltaAggregatedResourcesClient
	Processor                 *Processor
	Rbac                      *auth.Rbac
	MetricController          *telemetry.MetricController
	MapMetricController       *telemetry.MapMetricController
	OperationMetricController *telemetry.BpfProgMetric
	bpfWorkloadObj            *bpfwl.BpfWorkload
}

func NewController(bpfWorkload *bpfwl.BpfWorkload, enableMonitoring, enablePerfMonitor bool) *Controller {
	c := &Controller{
		Processor:      NewProcessor(bpfWorkload.SockConn.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps),
		bpfWorkloadObj: bpfWorkload,
	}
	// do some initialization when restart
	// restore endpoint index, otherwise endpoint number can double
	if restart.GetStartType() == restart.Restart {
		c.Processor.bpf.RestoreEndpointKeys()
	}
	c.Rbac = auth.NewRbac(c.Processor.WorkloadCache)
	c.MetricController = telemetry.NewMetric(c.Processor.WorkloadCache, c.Processor.ServiceCache, enableMonitoring)
	if enablePerfMonitor {
		c.OperationMetricController = telemetry.NewBpfProgMetric()
		c.MapMetricController = telemetry.NewMapMetric()
	}
	return c
}

func (c *Controller) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		<-c.Processor.addressDone
		wg.Done()
	}()
	go func() {
		<-c.Processor.authzDone
		wg.Done()
	}()
	go func() {
		wg.Wait()
		c.Rbac.Run(ctx, c.bpfWorkloadObj.SockOps.KmAuthReq, c.bpfWorkloadObj.XdpAuth.KmAuthRes)
	}()

	go c.MetricController.Run(ctx, c.bpfWorkloadObj.SockConn.KmTcpProbe)
	if c.MapMetricController != nil {
		go c.MapMetricController.Run(ctx)
	}
	if c.OperationMetricController != nil {
		go c.OperationMetricController.Run(ctx, c.bpfWorkloadObj.SockConn.KmPerfInfo)
	}
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
		_ = c.Stream.CloseSend()
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

func (c *Controller) SetMonitoringTrigger(enabled bool) {
	c.MetricController.EnableMonitoring.Store(enabled)
}

func (c *Controller) GetMonitoringTrigger() bool {
	return c.MetricController.EnableMonitoring.Load()
}

func (c *Controller) SetAccesslogTrigger(enabled bool) {
	c.MetricController.EnableAccesslog.Store(enabled)
}

func (c *Controller) GetAccesslogTrigger() bool {
	return c.MetricController.EnableAccesslog.Load()
}

func (c *Controller) SetWorkloadMetricTrigger(enable bool) {
	c.MetricController.EnableWorkloadMetric.Store(enable)
}
