/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
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
	"time"

	config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resource_v3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/grpc"

	"openmesh.io/mesh/pkg/nets"
)

const (
	RandTimeSed = 1000
)

type AdsClient struct {
	ctx    context.Context
	cancel context.CancelFunc
	Event  *ServiceEvent

	// config.EnableAds
	grpcConn *grpc.ClientConn
	service  service_discovery_v3.AggregatedDiscoveryServiceClient
	stream   service_discovery_v3.AggregatedDiscoveryService_StreamAggregatedResourcesClient
}

func NewAdsClient(ads *AdsSet) (*AdsClient, error) {
	client := &AdsClient{}

	client.ctx, client.cancel = context.WithCancel(context.Background())
	client.Event = NewServiceEvent()

	err := client.CreateStream(ads)
	return client, err
}

func (c *AdsClient) CreateStream(ads *AdsSet) error {
	var err error

	if !config.EnableAds {
		return nil
	}

	switch ads.APIType {
	case config_core_v3.ApiConfigSource_GRPC:
		// just using the first address
		if c.grpcConn, err = nets.GrpcConnect(ads.Clusters[0].Address[0]); err != nil {
			return fmt.Errorf("ads grpc connect failed, %s", err)
		}
	default:
		return fmt.Errorf("ads invalid APIType, %v", ads.APIType)
	}

	c.service = service_discovery_v3.NewAggregatedDiscoveryServiceClient(c.grpcConn)
	// DeltaAggregatedResources() is supported from istio-1.12.x
	c.stream, err = c.service.StreamAggregatedResources(c.ctx)
	if err != nil {
		return fmt.Errorf("ads StreamAggregatedResources failed, %s", err)
	}

	if err = c.stream.Send(newAdsRequest(resource_v3.ClusterType, nil)); err != nil {
		return fmt.Errorf("ads subscribe failed, %s", err)
	}

	return nil
}

func (c *AdsClient) recoverConnection() error {
	var (
		err      error
		interval = time.Second
	)

	c.closeStreamClient()
	for count := 0; count < nets.MaxRetryCount; count++ {
		if err = c.CreateStream(config.adsSet); err == nil {
			return nil
		}

		log.Errorf("ads grpc connect failed, %s", err)
		c.closeStreamClient()
		time.Sleep(interval + nets.CalculateRandTime(RandTimeSed))
		interval = nets.CalculateInterval(interval)
	}

	return fmt.Errorf("retry %d times", nets.MaxRetryCount)
}

func (c *AdsClient) runControlPlane(ctx context.Context) {
	var (
		err       error
		reconnect = false
		rsp       *service_discovery_v3.DiscoveryResponse
	)

	if !config.EnableAds {
		return
	}

	for true {
		select {
		case <-ctx.Done():
			return
		default:
			if reconnect {
				log.Warnf("reconnect due to %s", err)
				if err = c.recoverConnection(); err != nil {
					log.Errorf("ads recover connection failed, %s", err)
					return
				}
				reconnect = false
			}

			if rsp, err = c.stream.Recv(); err != nil {
				reconnect = true
				continue
			}

			c.Event.processAdsResponse(rsp)

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

func (c *AdsClient) Run(stopCh <-chan struct{}) error {
	go c.Event.processAdminResponse(c.ctx)
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

func (c *AdsClient) closeStreamClient() {
	if c.stream != nil {
		c.stream.CloseSend()
	}
	if c.grpcConn != nil {
		c.grpcConn.Close()
	}
}

func (c *AdsClient) Close() error {
	if c.Event != nil {
		c.Event.Destroy()
	}
	*c = AdsClient{}
	return nil
}
