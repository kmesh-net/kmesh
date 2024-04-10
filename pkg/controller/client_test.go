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
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"gotest.tools/assert"

	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/controller/envoy"
	"kmesh.net/kmesh/pkg/controller/workload"
	"kmesh.net/kmesh/pkg/nets"
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

func TestRecoverConnection(t *testing.T) {
	t.Run("test reconnect success", func(t *testing.T) {
		utClient := NewXdsClient()
		patches := gomonkey.NewPatches()
		defer patches.Reset()
		iteration := 0
		patches.ApplyPrivateMethod(reflect.TypeOf(utClient), "createStreamClient",
			func(_ *XdsClient) error {
				// more than 2 link failures will result in a long test time
				if iteration < 2 {
					iteration++
					return errors.New("cant connect to client")
				} else {
					return nil
				}
			})
		err := utClient.recoverConnection()
		assert.NilError(t, err)
		assert.Equal(t, 2, iteration)
	})
}

func TestClientResponseProcess(t *testing.T) {
	utConfig := bpf.GetConfig()
	utConfig.EnableKmesh = true
	utConfig.EnableKmeshWorkload = false
	bpfConfig = utConfig
	t.Run("ads stream process failed, test reconnect", func(t *testing.T) {
		netPatches := gomonkey.NewPatches()
		defer netPatches.Reset()
		netPatches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error) {
			mockDiscovery := NewMockServer(t)
			return grpc.Dial("buffcon",
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return mockDiscovery.Listener.Dial()
				}))
		})

		utClient := NewXdsClient()
		err := utClient.createStreamClient()
		assert.NilError(t, err)

		reConnectPatches := gomonkey.NewPatches()
		defer reConnectPatches.Reset()
		iteration := 0
		reConnectPatches.ApplyPrivateMethod(reflect.TypeOf(utClient), "createStreamClient",
			func(_ *XdsClient) error {
				// more than 2 link failures will result in a long test time
				if iteration < 2 {
					iteration++
					return errors.New("cant connect to client")
				} else {
					return nil
				}
			})
		streamPatches := gomonkey.NewPatches()
		defer streamPatches.Reset()
		streamPatches.ApplyMethod(reflect.TypeOf(utClient.AdsStream), "AdsStreamProcess",
			func(_ *envoy.AdsStream) error {
				if iteration < 2 {
					return errors.New("stream recv failed")
				} else {
					utClient.cancel()
					return nil
				}
			})
		utClient.clientResponseProcess(utClient.ctx)
		assert.Equal(t, 2, iteration)
	})

	t.Run("workload stream process failed, test reconnect", func(t *testing.T) {
		utConfig.EnableKmesh = false
		utConfig.EnableKmeshWorkload = true

		netPatches := gomonkey.NewPatches()
		defer netPatches.Reset()
		netPatches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error) {
			mockDiscovery := NewMockServer(t)
			return grpc.Dial("buffcon",
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return mockDiscovery.Listener.Dial()
				}))
		})

		utClient := NewXdsClient()
		err := utClient.createStreamClient()
		assert.NilError(t, err)

		reConnectPatches := gomonkey.NewPatches()
		defer reConnectPatches.Reset()
		iteration := 0
		reConnectPatches.ApplyPrivateMethod(reflect.TypeOf(utClient), "createStreamClient",
			func(_ *XdsClient) error {
				// more than 2 link failures will result in a long test time
				if iteration < 2 {
					iteration++
					return errors.New("cant connect to client")
				} else {
					return nil
				}
			})
		streamPatches := gomonkey.NewPatches()
		defer streamPatches.Reset()
		streamPatches.ApplyMethod(reflect.TypeOf(utClient.workloadStream), "WorkloadStreamProcess",
			func(_ *workload.WorkloadStream) error {
				if iteration < 2 {
					return errors.New("stream recv failed")
				} else {
					utClient.cancel()
					return nil
				}
			})
		utClient.clientResponseProcess(utClient.ctx)
		assert.Equal(t, 2, iteration)
	})
}
