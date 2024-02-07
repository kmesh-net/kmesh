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

 * Author: LemmyHuang
 * Create: 2022-01-08
 */

package workload

import (
	"context"
	"fmt"
	"time"

	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"

	"kmesh.net/kmesh/pkg/nets"
)

type WorkloadClient struct {
	ctx    context.Context
	cancel context.CancelFunc
	Event  *ServiceEvent

	discoveryAddress string
	grpcConn         *grpc.ClientConn
	service          service_discovery_v3.AggregatedDiscoveryServiceClient
	stream           service_discovery_v3.AggregatedDiscoveryService_DeltaAggregatedResourcesClient
}

func NewWorkloadClient(address string) (*WorkloadClient, error) {
	client := &WorkloadClient{
		discoveryAddress: address,
	}

	client.ctx, client.cancel = context.WithCancel(context.Background())
	client.Event = NewServiceEvent()

	err := client.CreateStream()
	return client, err
}

func (c *WorkloadClient) CreateStream() error {
	if !config.EnableWorkload {
		return nil
	}

	var err error
	if c.grpcConn, err = nets.GrpcConnect(c.discoveryAddress); err != nil {
		return fmt.Errorf("workload grpc connect failed: %v", err)
	}

	c.service = service_discovery_v3.NewAggregatedDiscoveryServiceClient(c.grpcConn)
	// DeltaAggregatedResources() is supported from istio-1.12.x
	c.stream, err = c.service.DeltaAggregatedResources(c.ctx)
	if err != nil {
		return fmt.Errorf("workload DeltaAggregatedResources failed, %s", err)
	}

	if err = c.stream.Send(newWorkloadRequest(AddressType, nil)); err != nil {
		return fmt.Errorf("address subscribe failed, %s", err)
	}

	return nil
}

func (c *WorkloadClient) recoverConnection() error {
	var (
		err      error
		interval = time.Second
	)

	c.closeStreamClient()
	for count := 0; count < nets.MaxRetryCount; count++ {
		if err = c.CreateStream(); err == nil {
			return nil
		}

		log.Errorf("workload grpc connect failed, %s", err)
		c.closeStreamClient()
		time.Sleep(interval + nets.CalculateRandTime(RandTimeSed))
		interval = nets.CalculateInterval(interval)
	}

	return fmt.Errorf("retry %d times", nets.MaxRetryCount)
}

func (c *WorkloadClient) runControlPlane(ctx context.Context) {
	var (
		err          error
		reconnect    = false
		rsp          *service_discovery_v3.DeltaDiscoveryResponse
		connectAgain = false
	)

	if !config.EnableWorkload {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if reconnect {
				log.Warnf("reconnect due to %s", err)
				if err = c.recoverConnection(); err != nil {
					log.Errorf("workload recover connection failed, %s", err)
					return
				}
				reconnect = false
				connectAgain = true
			}

			if rsp, err = c.stream.Recv(); err != nil {
				reconnect = true
				continue
			}

			if !connectAgain {
				c.Event.processWorkloadResponse(rsp)
			}
			connectAgain = false

			if err = c.stream.Send(c.Event.ack); err != nil {
				reconnect = true
				continue
			}
			if c.Event.rqt != nil {
				if err = c.stream.Send(c.Event.rqt); err != nil {
					reconnect = true
					continue
				}
			}
		}
	}
}

func (c *WorkloadClient) Run(stopCh <-chan struct{}) error {
	go c.runControlPlane(c.ctx)

	go func() {
		<-stopCh

		c.closeStreamClient()

		if c.cancel != nil {
			c.cancel()
		}
	}()

	return nil
}

func (c *WorkloadClient) closeStreamClient() {
	if c.stream != nil {
		_ = c.stream.CloseSend()
	}
	if c.grpcConn != nil {
		_ = c.grpcConn.Close()
	}
}

func (c *WorkloadClient) Close() error {
	if c.Event != nil {
		c.Event.Destroy()
	}
	*c = WorkloadClient{}
	return nil
}
