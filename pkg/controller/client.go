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

package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"
	istioGrpc "istio.io/istio/pilot/pkg/grpc"

	bpfads "kmesh.net/kmesh/pkg/bpf/ads"
	bpfwl "kmesh.net/kmesh/pkg/bpf/workload"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/ads"
	"kmesh.net/kmesh/pkg/controller/config"
	"kmesh.net/kmesh/pkg/controller/workload"
	"kmesh.net/kmesh/pkg/nets"
)

const (
	RandTimeSed = 1000
)

type XdsClient struct {
	mode               string
	ctx                context.Context
	cancel             context.CancelFunc
	mu                 sync.RWMutex
	grpcConn           *grpc.ClientConn
	client             discoveryv3.AggregatedDiscoveryServiceClient
	AdsController      *ads.Controller
	WorkloadController *workload.Controller
	xdsConfig          *config.XdsConfig
	reconnectCount     uint64
	lastConnect        time.Time
}

func NewXdsClient(mode string, bpfAds *bpfads.BpfAds, bpfWorkload *bpfwl.BpfWorkload, enableMonitoring, enableProfiling bool) (*XdsClient, error) {
	client := &XdsClient{
		mode:      mode,
		xdsConfig: config.GetConfig(mode),
	}

	switch mode {
	case constants.DualEngineMode:
		var err error
		client.WorkloadController, err = workload.NewController(bpfWorkload, enableMonitoring, enableProfiling)
		if err != nil {
			return nil, fmt.Errorf("failed to create workload controller: %w", err)
		}
	case constants.KernelNativeMode:
		client.AdsController = ads.NewController(bpfAds)
	}

	client.ctx, client.cancel = context.WithCancel(context.Background())
	client.ctx = metadata.AppendToOutgoingContext(client.ctx, "ClusterID", client.xdsConfig.Metadata.ClusterID.String())
	return client, nil
}

func (c *XdsClient) createGrpcStreamClient() error {
	var err error

	c.mu.Lock()
	if c.grpcConn, err = nets.GrpcConnect(c.xdsConfig.DiscoveryAddress); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("grpc connect failed: %s", err)
	}

	c.client = discoveryv3.NewAggregatedDiscoveryServiceClient(c.grpcConn)
	c.lastConnect = time.Now()
	c.mu.Unlock()

	if c.mode == constants.DualEngineMode {
		if err = c.WorkloadController.WorkloadStreamCreateAndSend(c.client, c.ctx); err != nil {
			_ = c.grpcConn.Close()
			return fmt.Errorf("create workload stream failed, %s", err)
		}
	} else if c.mode == constants.KernelNativeMode {
		if err = c.AdsController.AdsStreamCreateAndSend(c.client, c.ctx); err != nil {
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

		c.mu.Lock()
		c.reconnectCount++
		c.mu.Unlock()

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

			if c.mode == constants.KernelNativeMode {
				err = c.AdsController.HandleAdsStream()
			} else if c.mode == constants.DualEngineMode {
				err = c.WorkloadController.HandleWorkloadStream()
			}
			if err != nil {
				if istioGrpc.GRPCErrorType(err) == istioGrpc.UnexpectedError {
					log.Errorf("Failed to establish grpc link to control plane: %v", err)
				}
				c.mu.Lock()
				if c.grpcConn != nil {
					_ = c.grpcConn.Close()
				}
				c.mu.Unlock()
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
	if c.AdsController != nil {
		c.AdsController.Close()
	}
	if c.WorkloadController != nil && c.WorkloadController.Stream != nil {
		_ = c.WorkloadController.Stream.CloseSend()
	}

	c.mu.Lock()
	if c.grpcConn != nil {
		_ = c.grpcConn.Close()
	}
	c.mu.Unlock()
}

func (c *XdsClient) Close() error {
	return nil
}

func (c *XdsClient) IsReady() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.grpcConn == nil {
		return false
	}
	if c.grpcConn.GetState() != connectivity.Ready {
		return false
	}
	if c.AdsController != nil {
		return c.AdsController.IsReady()
	}
	if c.WorkloadController != nil {
		return c.WorkloadController.IsReady()
	}
	return false
}

func (c *XdsClient) GetGrpcState() string {
	if c == nil {
		return connectivity.Shutdown.String()
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.grpcConn == nil {
		return connectivity.Shutdown.String()
	}
	return c.grpcConn.GetState().String()
}

func (c *XdsClient) GetControllerStatus() string {
	if c == nil {
		return "not initialized"
	}
	if c.AdsController != nil {
		if c.AdsController.IsReady() {
			return "ok"
		}
		return "not ready"
	}
	if c.WorkloadController != nil {
		if c.WorkloadController.IsReady() {
			return "ok"
		}
		return "not ready"
	}
	return "not initialized"
}

func (c *XdsClient) GetXdsStreamStability() string {
	if c == nil {
		return "not initialized"
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return fmt.Sprintf("reconnects: %d, last_connect: %v", c.reconnectCount, c.lastConnect.Format(time.RFC3339))
}
