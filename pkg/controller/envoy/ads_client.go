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
	configCoreV3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	serviceDiscoveryV3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourceV3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/grpc"
	"openeuler.io/mesh/pkg/nets"
	"time"
)

type AdsClient struct {
	grpcConn *grpc.ClientConn
	service  serviceDiscoveryV3.AggregatedDiscoveryServiceClient
	stream   serviceDiscoveryV3.AggregatedDiscoveryService_StreamAggregatedResourcesClient
	cancel   context.CancelFunc
	event    *serviceEvent
}

func NewAdsClient(ads *AdsConfig) (*AdsClient, error) {
	client := &AdsClient{}
	err := client.CreateStream(ads)

	return client, err
}

func (c *AdsClient) CreateStream(ads *AdsConfig) error {
	var err error

	switch ads.APIType {
	case configCoreV3.ApiConfigSource_GRPC:
		// just using the first address
		if c.grpcConn, err = nets.GrpcConnect(ads.Clusters[0].Address[0]); err != nil {
			return fmt.Errorf("ads grpc connect failed, %s", err)
		}
	default:
		return fmt.Errorf("ads invalid APIType, %v", ads.APIType)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel

	c.service = serviceDiscoveryV3.NewAggregatedDiscoveryServiceClient(c.grpcConn)
	// DeltaAggregatedResources() is supported from istio-1.12.x
	c.stream, err = c.service.StreamAggregatedResources(ctx)
	if err != nil {
		return fmt.Errorf("ads StreamAggregatedResources failed, %s", err)
	}

	if err = c.stream.Send(newAdsRequest(resourceV3.ClusterType, nil)); err != nil {
		return fmt.Errorf("ads subscribe failed, %s", err)
	}

	c.event = newServiceEvent()
	return nil
}

func (c *AdsClient) recoverConnection() error {
	var (
		err error
		interval = time.Second
	)

	c.Close()
	for count := 0; count < nets.MaxRetryCount; count++ {
		if c.grpcConn, err = nets.GrpcConnect(config.Ads.Clusters[0].Address[0]); err != nil {
			log.Debugf("ads grpc connect failed, %s", err)
			time.Sleep(interval + nets.CalculateRandTime(1000))
			interval = nets.CalculateInterval(interval)
		} else {
			return c.CreateStream(config.Ads)
		}
	}

	return err
}

func (c *AdsClient) runWorker() {
	var (
		err error
		reconnect = false
		rsp *serviceDiscoveryV3.DiscoveryResponse
	)

	for true {
		if c.cancel == nil {
			return
		}
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

		c.event.processResponse(rsp)

		if err = c.stream.Send(c.event.ack); err != nil {
			reconnect = true
			continue
		}
		if c.event.rqt != nil {
			if err = c.stream.Send(c.event.rqt); err != nil {
				reconnect = true
				continue
			}
		}
	}
}

func (c *AdsClient) Run(stopCh <-chan struct{}) error {
	go c.runWorker()

	go func() {
		<-stopCh
		if c.cancel != nil {
			c.cancel()
			c.cancel = nil
		}
	}()

	return nil
}

func (c *AdsClient) Close() error {
	if c.stream != nil {
		c.stream.CloseSend()
	}
	if c.grpcConn != nil {
		c.grpcConn.Close()
	}
	*c = AdsClient{}
	return nil
}
