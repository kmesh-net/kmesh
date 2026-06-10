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

package kube

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	istio "istio.io/istio/pkg/kube"
)

const (
	DefaultLocalAddress      = "localhost"
	DefaultPodRunningTimeout = 30 * time.Second
	KmeshNamespace           = "kmesh-system"
)

// Client defines the interface for accessing Kubernetes clients and resources.
type Client interface {
	// Kube returns the core kube client
	Kube() kubernetes.Interface

	// GatewayAPI returns the gateway-api kube client.
	GatewayAPI() gatewayapiclient.Interface
}

// CLIClient extends the Client interface with additional functionality for CLI operations.
type CLIClient interface {
	Client

	// PodsForSelector finds pods matching selector.
	PodsForSelector(ctx context.Context, namespace string, labelSelectors ...string) (*v1.PodList, error)

	// NewPortForwarder creates a new PortForwarder configured for the given pod. If localPort=0, a port will be
	// dynamically selected. If localAddress is empty, "localhost" is used.
	NewPortForwarder(podName string, ns string, localAddress string, localPort int, podPort int) (PortForwarder, error)
	
	ApplyYAMLContents(namespace string, yamls ...string) error 
}

func NewCLIClient(opts ...ClientOption) (CLIClient, error) {
	return newClientInternal(opts...)
}

type ClientOption func(CLIClient) CLIClient

type client struct {
	config *rest.Config

	kube          kubernetes.Interface
	gatewayapi    gatewayapiclient.Interface
	clientFactory *genericclioptions.ConfigFlags
	istioClient   istio.CLIClient
}

func (c *client) ApplyYAMLContents(namespace string, yamls ...string) error {
	c.istioClient, _ = istio.NewCLIClient(istio.NewClientConfigForRestConfig(c.config))
	return c.istioClient.ApplyYAMLContents(namespace, yamls...)
}

func (c *client) NewPortForwarder(podName string, ns string, localAddress string, localPort int, podPort int) (PortForwarder, error) {
	return newPortForwarder(c, podName, ns, localAddress, localPort, podPort)
}

func newPortForwarder(cliClient *client, podName string, ns string, localAddress string, localPort int, podPort int) (PortForwarder, error) {
	ctx, cancel := context.WithCancel(context.Background())

	if localAddress == "" {
		localAddress = DefaultLocalAddress
	}

	if localPort == 0 {
		var err error
		localPort, err = getAvailablePort()
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to find an available port: %v", err)
		}
	}

	cmd := &cobra.Command{}
	cmd.Flags().Duration("pod-running-timeout", DefaultPodRunningTimeout, "Timeout for waiting for pod to be running")
	cmd.Flags().String("namespace", KmeshNamespace, "Specify the namespace to use")
	cmd.Flags().StringSlice("address", []string{DefaultLocalAddress}, "Specify the addresses to bind")
	return &portForwarder{
		cmd:              cmd,
		RESTClientGetter: cliClient.clientFactory,
		ctx:              ctx,
		cancel:           cancel,
		podName:          podName,
		ns:               ns,
		localAddress:     localAddress,
		localPort:        localPort,
		podPort:          podPort,
		errCh:            make(chan error, 1),
	}, nil
}

func newClientInternal(opts ...ClientOption) (*client, error) {
	var c client
	var err error

	// Initialize config flags with namespace
	configFlags := genericclioptions.NewConfigFlags(true).
		WithDeprecatedPasswordFlag().
		WithDiscoveryBurst(300).
		WithDiscoveryQPS(50.0)
	configFlags.Namespace = ptr.To(KmeshNamespace)
	c.clientFactory = configFlags

	c.config, err = configFlags.ToRESTConfig()
	if err != nil {
		return nil, err
	}

	for _, opt := range opts {
		opt(&c)
	}

	c.kube, err = kubernetes.NewForConfig(c.config)
	if err != nil {
		return nil, err
	}

	c.gatewayapi, err = gatewayapiclient.NewForConfig(c.config)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func (c *client) Kube() kubernetes.Interface {
	return c.kube
}

func (c *client) GatewayAPI() gatewayapiclient.Interface {
	return c.gatewayapi
}

func (c *client) PodsForSelector(ctx context.Context, namespace string, labelSelectors ...string) (*v1.PodList, error) {
	return c.kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: strings.Join(labelSelectors, ","),
	})
}
