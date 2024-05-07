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

package workload

import (
	"context"
	"fmt"

	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"kmesh.net/kmesh/pkg/auth"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	AddressType       = "type.googleapis.com/istio.workload.Address"
	AuthorizationType = "type.googleapis.com/istio.security.Authorization"
)

var (
	log = logger.NewLoggerField("controller/workload")
)

type WorkloadStream struct {
	Stream service_discovery_v3.AggregatedDiscoveryService_DeltaAggregatedResourcesClient
	Event  *ServiceEvent
}

func (ws *WorkloadStream) WorklaodStreamCreateAndSend(client service_discovery_v3.AggregatedDiscoveryServiceClient, ctx context.Context) error {
	var err error

	ws.Stream, err = client.DeltaAggregatedResources(ctx)
	if err != nil {
		return fmt.Errorf("DeltaAggregatedResources failed, %s", err)
	}

	if err := ws.Stream.Send(newWorkloadRequest(AddressType, nil)); err != nil {
		return fmt.Errorf("send request failed, %s", err)
	}

	if err = ws.Stream.Send(newWorkloadRequest(AuthorizationType, nil)); err != nil {
		return fmt.Errorf("authorization subscribe failed, %s", err)
	}

	return nil
}

func (ws *WorkloadStream) HandleWorkloadStream(rbac *auth.Rbac) error {
	var (
		err      error
		rspDelta *service_discovery_v3.DeltaDiscoveryResponse
	)

	if rspDelta, err = ws.Stream.Recv(); err != nil {
		return fmt.Errorf("stream recv failed, %s", err)
	}

	ws.Event.processWorkloadResponse(rspDelta, rbac)

	if err = ws.Stream.Send(ws.Event.ack); err != nil {
		return fmt.Errorf("stream send ack failed, %s", err)
	}

	if ws.Event.req != nil {
		if err = ws.Stream.Send(ws.Event.req); err != nil {
			return fmt.Errorf("stream send req failed, %s", err)
		}
	}

	return nil
}
