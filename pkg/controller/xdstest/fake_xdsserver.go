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
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"istio.io/pkg/log"
)

type MockDiscovery struct {
	Listener       *bufconn.Listener
	responses      chan *discoveryv3.DiscoveryResponse
	deltaResponses chan *discoveryv3.DeltaDiscoveryResponse
	close          chan struct{}
}

func NewMockServer(t *testing.T) *MockDiscovery {
	s := &MockDiscovery{
		close:          make(chan struct{}),
		responses:      make(chan *discoveryv3.DiscoveryResponse),
		deltaResponses: make(chan *discoveryv3.DeltaDiscoveryResponse),
	}

	buffer := 1024 * 1024
	listener := bufconn.Listen(buffer)
	grpcServer := grpc.NewServer()
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(grpcServer, s)
	go func() {
		if err := grpcServer.Serve(listener); err != nil && !(err == grpc.ErrServerStopped || err.Error() == "closed") {
			return
		}
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		close(s.close)
	})
	s.Listener = listener
	return s
}

func (f *MockDiscovery) StreamAggregatedResources(server discoveryv3.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	numberOfSends := 0
	for {
		select {
		case <-f.close:
			return nil
		case resp := <-f.responses:
			numberOfSends++
			log.Infof("sending response from mock: %v", numberOfSends)
			if err := server.Send(resp); err != nil {
				return err
			}
		}
	}
}

func (f *MockDiscovery) DeltaAggregatedResources(server discoveryv3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer) error {
	numberOfSends := 0
	for {
		select {
		case <-f.close:
			return nil
		case resp := <-f.deltaResponses:
			numberOfSends++
			log.Infof("sending delta response from mock: %v", numberOfSends)
			if err := server.Send(resp); err != nil {
				return err
			}
		}
	}
}
