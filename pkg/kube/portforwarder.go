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
	"io"
	"net"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/kubectl/pkg/cmd/portforward"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

// PortForwarder manages the forwarding of a single port.
type PortForwarder interface {
	// Start runs this forwarder.
	Start() error

	// Address returns the local forwarded address. Only valid while the forwarder is running.
	Address() string

	// Close this forwarder and release an resources.
	Close()
}

var _ PortForwarder = &portForwarder{}

type portForwarder struct {
	cmd *cobra.Command
	genericclioptions.RESTClientGetter
	ctx          context.Context
	cancel       context.CancelFunc
	podName      string
	ns           string
	localAddress string
	localPort    int
	podPort      int
	errCh        chan error
}

// namespacedConfigLoader wraps a clientcmd.ClientConfig and overrides the
// namespace returned by Namespace() with a fixed value, without mutating the
// state of the wrapped loader. It delegates explicitly (instead of embedding)
// because the interface itself declares a method named ClientConfig, which an
// embedded field would shadow.
type namespacedConfigLoader struct {
	delegate clientcmd.ClientConfig
	ns       string
}

func (l namespacedConfigLoader) RawConfig() (clientcmdapi.Config, error) {
	return l.delegate.RawConfig()
}

func (l namespacedConfigLoader) ClientConfig() (*rest.Config, error) {
	return l.delegate.ClientConfig()
}

func (l namespacedConfigLoader) Namespace() (string, bool, error) {
	// Always treat the namespace as explicitly set so it takes precedence
	// over in-cluster namespace detection, context defaults, etc.
	return l.ns, true, nil
}

func (l namespacedConfigLoader) ConfigAccess() clientcmd.ConfigAccess {
	return l.delegate.ConfigAccess()
}

// namespacedRESTClientGetter wraps a RESTClientGetter and serves its raw kube
// config loader through namespacedConfigLoader, so that consumers of this
// getter (e.g. portforward.PortForwardOptions.Complete via cmdutil.Factory)
// resolve the namespace from the value supplied to newPortForwarder instead
// of the one baked into the shared client factory. All other calls are
// delegated unchanged to the wrapped getter.
type namespacedRESTClientGetter struct {
	genericclioptions.RESTClientGetter
	ns string
}

var _ genericclioptions.RESTClientGetter = &namespacedRESTClientGetter{}

func (g *namespacedRESTClientGetter) ToRawKubeConfigLoader() clientcmd.ClientConfig {
	return namespacedConfigLoader{delegate: g.RESTClientGetter.ToRawKubeConfigLoader(), ns: g.ns}
}

func (g *namespacedRESTClientGetter) ToRESTConfig() (*rest.Config, error) {
	return g.RESTClientGetter.ToRESTConfig()
}

func (g *namespacedRESTClientGetter) ToDiscoveryClient() (discovery.CachedDiscoveryInterface, error) {
	return g.RESTClientGetter.ToDiscoveryClient()
}

func (g *namespacedRESTClientGetter) ToRESTMapper() (meta.RESTMapper, error) {
	return g.RESTClientGetter.ToRESTMapper()
}

// getAvailablePort returns an available port by binding a listener to a port in the ephemeral range.
func getAvailablePort() (int, error) {
	listener, err := net.Listen("tcp", ":0") // ":0" will assign a random available port
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

func (p *portForwarder) Start() error {
	address, err := p.cmd.Flags().GetStringSlice("address")
	if err != nil {
		return err
	}

	ports := fmt.Sprintf("%d:%d", p.localPort, p.podPort)
	ioStreams := genericiooptions.IOStreams{In: os.Stdin, Out: io.Discard, ErrOut: os.Stderr}
	pfOptions := portforward.NewDefaultPortForwardOptions(ioStreams)
	pfOptions.Address = address

	f := cmdutil.NewFactory(&namespacedRESTClientGetter{RESTClientGetter: p.RESTClientGetter, ns: p.ns})
	if err := pfOptions.Complete(f, p.cmd, []string{p.podName, ports}); err != nil {
		return fmt.Errorf("complete failed: %v", err)
	}

	go func() {
		if err := pfOptions.RunPortForwardContext(p.ctx); err != nil {
			p.errCh <- fmt.Errorf("error running port forward: %v", err)
			return
		}
	}()

	select {
	case <-pfOptions.ReadyChannel:
		return nil
	case err := <-p.errCh:
		return fmt.Errorf("failure running port forward process: %v", err)
	}
}

func (p *portForwarder) Address() string {
	return net.JoinHostPort(p.localAddress, strconv.Itoa(p.localPort))
}

func (p *portForwarder) Close() {
	if p.cancel != nil {
		p.cancel()
	}
}
