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

package version

import (
	"context"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"kmesh.net/kmesh/pkg/kube"
)

// fakeCLIClient is a minimal fake implementing kube.CLIClient for unit tests.
type fakeCLIClient struct {
	forwarder    kube.PortForwarder
	forwarderErr error
}

func (f *fakeCLIClient) Kube() kubernetes.Interface             { return nil }
func (f *fakeCLIClient) GatewayAPI() gatewayapiclient.Interface { return nil }

func (f *fakeCLIClient) PodsForSelector(ctx context.Context, ns string, sel ...string) (*v1.PodList, error) {
	return &v1.PodList{}, nil
}

func (f *fakeCLIClient) NewPortForwarder(podName, ns, addr string, localPort, podPort int) (kube.PortForwarder, error) {
	if f.forwarderErr != nil {
		return nil, f.forwarderErr
	}
	return f.forwarder, nil
}

// fakePortForwarder is a minimal fake implementing kube.PortForwarder.
type fakePortForwarder struct {
	startErr error
	address  string
}

func (f *fakePortForwarder) Start() error    { return f.startErr }
func (f *fakePortForwarder) Address() string { return f.address }
func (f *fakePortForwarder) Close()          {}
