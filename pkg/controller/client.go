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

package controller

import (
	"context"
	"fmt"
	"time"

	"kmesh.net/kmesh/pkg/constants"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	istiogrpc "istio.io/istio/pilot/pkg/grpc"

	"kmesh.net/kmesh/pkg/auth"
	"kmesh.net/kmesh/pkg/controller/config"
	"kmesh.net/kmesh/pkg/controller/envoy"
	"kmesh.net/kmesh/pkg/controller/workload"
	"kmesh.net/kmesh/pkg/nets"
)

const (
	RandTimeSed = 1000
)

type XdsClient struct {
	mode           string
	ctx            context.Context
	cancel         context.CancelFunc
	grpcConn       *grpc.ClientConn
	client         discoveryv3.AggregatedDiscoveryServiceClient
	AdsStream      *envoy.AdsStream
	workloadStream *workload.WorkloadStream
	xdsConfig      *config.XdsConfig
	rbac           *auth.Rbac
}

func NewXdsClient(mode string) *XdsClient {
	client := &XdsClient{
		mode:      mode,
		xdsConfig: config.GetConfig(),
		AdsStream: &envoy.AdsStream{
			Event: envoy.NewServiceEvent(),
		},
		workloadStream: &workload.WorkloadStream{
			Event: workload.NewServiceEvent(),
		},
	}

	client.ctx, client.cancel = context.WithCancel(context.Background())
	if mode == constants.WorkloadMode {
		client.rbac = auth.NewRbac()
	}

	return client
}

func (c *XdsClient) createGrpcStreamClient() error {
	var err error

	if c.grpcConn, err = nets.GrpcConnect(c.xdsConfig.DiscoveryAddress); err != nil {
		return fmt.Errorf("grpc connect failed: %s", err)
	}

	c.client = discoveryv3.NewAggregatedDiscoveryServiceClient(c.grpcConn)

	if c.mode == constants.WorkloadMode {
		if err = c.workloadStream.WorklaodStreamCreateAndSend(c.client, c.ctx); err != nil {
			_ = c.grpcConn.Close()
			return fmt.Errorf("create workload stream failed, %s", err)
		}
	} else if bpfConfig.AdsEnabled() {
		if err = c.AdsStream.AdsStreamCreateAndSend(c.client, c.ctx); err != nil {
			_ = c.grpcConn.Close()
			return fmt.Errorf("create ads stream failed, %s", err)
		}
	}

	return nil
}

func (c *XdsClient) recoverConnection() {
	var (
		err      error
		interval = time.Second
	)

	for {
		if err = c.createGrpcStreamClient(); err == nil {
			log.Infof("grpc reconnect succeed")
			return
		}

		log.Errorf("grpc reconnect failed, %s", err)
		time.Sleep(interval + nets.CalculateRandTime(RandTimeSed))
		interval = nets.CalculateInterval(interval)
	}
}

func (c *XdsClient) handleUpstream(ctx context.Context) {
	var (
		err       error
		reconnect = false
	)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if reconnect {
				c.recoverConnection()
				reconnect = false
			}

			if c.mode == constants.AdsMode {
				if err = c.AdsStream.AdsStreamProcess(); err != nil {
					_ = c.AdsStream.Stream.CloseSend()
				}
			} else if c.mode == constants.WorkloadMode {
				if err = c.workloadStream.WorkloadStreamProcess(c.rbac); err != nil {
					_ = c.workloadStream.Stream.CloseSend()
				}
			}
			if err != nil && !istiogrpc.IsExpectedGRPCError(err) {
				_ = c.grpcConn.Close()
				reconnect = true
			}
		}
	}
}

func (c *XdsClient) Run(stopCh <-chan struct{}) error {
	if err := c.createGrpcStreamClient(); err != nil {
		return fmt.Errorf("create client and stream failed, %s", err)
	}

	go c.handleUpstream(c.ctx)
	if c.rbac != nil {
		go c.rbac.Run(c.ctx)
	}

	go func() {
		<-stopCh
		c.closeStreamClient()
		if c.cancel != nil {
			c.cancel()
		}
	}()

	return nil
}

func (c *XdsClient) closeStreamClient() {
	if c.AdsStream != nil && c.AdsStream.Stream != nil {
		_ = c.AdsStream.Stream.CloseSend()
	}
	if c.workloadStream != nil && c.workloadStream.Stream != nil {
		_ = c.workloadStream.Stream.CloseSend()
	}

	if c.grpcConn != nil {
		_ = c.grpcConn.Close()
	}
}

func (c *XdsClient) Close() error {
	if c.AdsStream != nil && c.AdsStream.Event != nil {
		c.AdsStream.Event.Destroy()
	}

	if c.workloadStream != nil && c.workloadStream.Event != nil {
		c.workloadStream.Event.Destroy()
	}

	return nil
}
