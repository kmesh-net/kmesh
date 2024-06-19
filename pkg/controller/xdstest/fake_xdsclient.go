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

package xdstest

import (
	"context"
	"fmt"
	"net"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type XDSClient struct {
	Client      discoveryv3.AggregatedDiscoveryServiceClient
	AdsClient   discoveryv3.AggregatedDiscoveryService_StreamAggregatedResourcesClient
	DeltaClient discoveryv3.AggregatedDiscoveryService_DeltaAggregatedResourcesClient
	conn        *grpc.ClientConn
}

func NewClient(xdsServer *XDSServer) (*XDSClient, error) {
	conn, err := grpc.Dial("buffcon",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return xdsServer.Listener.Dial()
		}))
	if err != nil {
		return nil, fmt.Errorf("grpc connection client create failed, %s", err)
	}
	client := discoveryv3.NewAggregatedDiscoveryServiceClient(conn)
	deltaClient, err := client.DeltaAggregatedResources(context.Background())
	if err != nil {
		return nil, fmt.Errorf("DeltaAggregatedResources failed, %s", err)
	}
	adsClient, err := client.StreamAggregatedResources(context.Background())
	if err != nil {
		return nil, fmt.Errorf("StreamAggregatedResources failed, %s", err)
	}

	return &XDSClient{
		Client:      client,
		AdsClient:   adsClient,
		DeltaClient: deltaClient,
		conn:        conn,
	}, nil
}

func (c *XDSClient) Cleanup() {
	if c.AdsClient != nil {
		_ = c.AdsClient.CloseSend()
	}
	if c.DeltaClient != nil {
		_ = c.DeltaClient.CloseSend()
	}
	c.conn.Close()
}
