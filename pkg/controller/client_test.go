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
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/workload"
	"kmesh.net/kmesh/pkg/controller/xdstest"
	"kmesh.net/kmesh/pkg/nets"
)

func TestRecoverConnection(t *testing.T) {
	t.Run("test reconnect success", func(t *testing.T) {
		utClient := NewXdsClient(constants.AdsMode, &bpf.BpfKmeshWorkload{})
		patches := gomonkey.NewPatches()
		defer patches.Reset()
		iteration := 0
		netPatches := gomonkey.NewPatches()
		defer netPatches.Reset()
		netPatches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error) {
			// // more than 2 link failures will result in a long test time
			if iteration < 2 {
				iteration++
				return nil, errors.New("failed to create grpc connect")
			} else {
				// returns a fake grpc connection
				mockDiscovery := xdstest.NewXdsServer(t)
				return grpc.Dial("buffcon",
					grpc.WithTransportCredentials(insecure.NewCredentials()),
					grpc.WithBlock(),
					grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
						return mockDiscovery.Listener.Dial()
					}))
			}
		})
		utClient.recoverConnection()
		assert.Equal(t, 2, iteration)
	})
}

func TestClientResponseProcess(t *testing.T) {
	t.Run("ads stream process failed, test reconnect", func(t *testing.T) {
		netPatches := gomonkey.NewPatches()
		defer netPatches.Reset()
		netPatches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error) {
			mockDiscovery := xdstest.NewXdsServer(t)
			return grpc.Dial("buffcon",
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return mockDiscovery.Listener.Dial()
				}))
		})

		utClient := NewXdsClient(constants.AdsMode, &bpf.BpfKmeshWorkload{})
		err := utClient.createGrpcStreamClient()
		assert.NoError(t, err)

		reConnectPatches := gomonkey.NewPatches()
		defer reConnectPatches.Reset()
		iteration := 0
		reConnectPatches.ApplyPrivateMethod(reflect.TypeOf(utClient), "createGrpcStreamClient",
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
		streamPatches.ApplyMethod(reflect.TypeOf(utClient.AdsController), "HandleAdsStream",
			func() error {
				// if the number of loops is less than or equal to two, an error is reported and a retry is triggered.
				if iteration < 2 {
					return errors.New("stream recv failed")
				} else {
					// it's been cycled more than twice, use context.cancel() to end the current grpc connection.
					utClient.cancel()
					return nil
				}
			})
		utClient.handleUpstream(utClient.ctx)
		assert.Equal(t, 2, iteration)
	})

	t.Run("workload stream process failed, test reconnect", func(t *testing.T) {
		netPatches := gomonkey.NewPatches()
		defer netPatches.Reset()
		netPatches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error) {
			mockDiscovery := xdstest.NewXdsServer(t)
			return grpc.Dial("buffcon",
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return mockDiscovery.Listener.Dial()
				}))
		})

		utClient := NewXdsClient(constants.WorkloadMode, &bpf.BpfKmeshWorkload{})
		err := utClient.createGrpcStreamClient()
		assert.NoError(t, err)

		reConnectPatches := gomonkey.NewPatches()
		defer reConnectPatches.Reset()
		iteration := 0
		reConnectPatches.ApplyPrivateMethod(reflect.TypeOf(utClient), "createGrpcStreamClient",
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
		streamPatches.ApplyMethod(reflect.TypeOf(utClient.WorkloadController), "HandleWorkloadStream",
			func(_ *workload.Controller) error {
				if iteration < 2 {
					return errors.New("stream recv failed")
				} else {
					utClient.cancel()
					return nil
				}
			})
		utClient.handleUpstream(utClient.ctx)
		assert.Equal(t, 2, iteration)
	})
}
