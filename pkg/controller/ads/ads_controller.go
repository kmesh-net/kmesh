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

package ads

import (
	"context"
	"fmt"

	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resource_v3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"kmesh.net/kmesh/pkg/logger"
)

var (
	log = logger.NewLoggerField("ads_controller")
)

type Controller struct {
	Stream    service_discovery_v3.AggregatedDiscoveryService_StreamAggregatedResourcesClient
	Processor *processor
}

func NewController() *Controller {
	return &Controller{
		Processor: newProcessor(),
	}
}

func (c *Controller) AdsStreamCreateAndSend(client service_discovery_v3.AggregatedDiscoveryServiceClient, ctx context.Context) error {
	var err error

	c.Stream, err = client.StreamAggregatedResources(ctx)
	if err != nil {
		return fmt.Errorf("StreamAggregatedResources failed, %s", err)
	}

	if err := c.Stream.Send(newAdsRequest(resource_v3.ClusterType, nil, "")); err != nil {
		return fmt.Errorf("send request failed, %s", err)
	}

	return nil
}

func (c *Controller) HandleAdsStream() error {
	var (
		err error
		rsp *service_discovery_v3.DiscoveryResponse
	)

	if rsp, err = c.Stream.Recv(); err != nil {
		return fmt.Errorf("stream recv failed, %s", err)
	}

	c.Processor.processAdsResponse(rsp)

	if err = c.Stream.Send(c.Processor.ack); err != nil {
		return fmt.Errorf("stream send ack failed, %s", err)
	}

	if c.Processor.req != nil {
		if err = c.Stream.Send(c.Processor.req); err != nil {
			return fmt.Errorf("stream send rqt failed, %s", err)
		}
	}

	return nil
}
