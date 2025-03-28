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

package ads

import (
	"context"
	"fmt"

	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resource_v3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"istio.io/istio/pkg/channels"

	bpfads "kmesh.net/kmesh/pkg/bpf/ads"
	"kmesh.net/kmesh/pkg/logger"
)

var (
	log = logger.NewLoggerScope("ads_controller")
)

type Controller struct {
	Processor             *processor
	dnsResolverController *dnsController
	con                   *connection
}

type connection struct {
	Stream       service_discovery_v3.AggregatedDiscoveryService_StreamAggregatedResourcesClient
	requestsChan *channels.Unbounded[*service_discovery_v3.DiscoveryRequest]
	stopCh       chan struct{}
}

func NewController(bpfAds *bpfads.BpfAds) *Controller {
	processor := newProcessor(bpfAds)
	// create kernel-native mode ads resolver controller
	dnsResolverController, err := NewDnsController(processor.Cache)
	if err != nil {
		log.Errorf("dns resolver of Kernel-Native mode create failed: %v", err)
		return nil
	}
	processor.DnsResolverChan = dnsResolverController.clustersChan

	return &Controller{
		dnsResolverController: dnsResolverController,
		Processor:             processor,
	}
}

func (c *Controller) AdsStreamCreateAndSend(client service_discovery_v3.AggregatedDiscoveryServiceClient, ctx context.Context) error {
	if c.con != nil {
		close(c.con.stopCh)
	}

	stream, err := client.StreamAggregatedResources(ctx)
	if err != nil {
		return fmt.Errorf("StreamAggregatedResources failed, %s", err)
	}

	c.con = &connection{
		Stream:       stream,
		requestsChan: channels.NewUnbounded[*service_discovery_v3.DiscoveryRequest](),
		stopCh:       make(chan struct{}),
	}

	c.Processor.Reset()
	if err := stream.Send(newAdsRequest(resource_v3.ClusterType, nil, "")); err != nil {
		return fmt.Errorf("send request failed, %s", err)
	}
	go sendUpstream(c.con)

	return nil
}

func (c *Controller) HandleAdsStream() error {
	var (
		err error
		rsp *service_discovery_v3.DiscoveryResponse
	)
	if rsp, err = c.con.Stream.Recv(); err != nil {
		_ = c.con.Stream.CloseSend()
		return fmt.Errorf("stream recv failed, %s", err)
	}

	// Because Kernel-Native mode is full update.
	// So the original clusterCache is deleted when a new resp is received.
	c.dnsResolverController.newClusterCache()
	c.Processor.processAdsResponse(rsp)
	c.con.requestsChan.Put(c.Processor.ack)
	if c.Processor.req != nil {
		c.con.requestsChan.Put(c.Processor.req)
		c.Processor.req = nil
	}

	return nil
}

func sendUpstream(con *connection) {
	for {
		select {
		case req := <-con.requestsChan.Get():
			con.requestsChan.Load()
			if err := con.Stream.Send(req); err != nil {
				log.Errorf("send error for type url %s: %v", req.TypeUrl, err)
				return
			}
		case <-con.stopCh:
			return
		}
	}
}

func (c *Controller) Close() {
	if c.con != nil {
		close(c.con.stopCh)
		_ = c.con.Stream.CloseSend()
	}
}

func (c *Controller) StartDnsController(stopCh <-chan struct{}) {
	if c.dnsResolverController != nil {
		c.dnsResolverController.Run(stopCh)
	}
}
