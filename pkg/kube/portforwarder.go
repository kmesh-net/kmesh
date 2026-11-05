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
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	clientportforward "k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
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

// capturingForwarder runs client-go's port forwarder and captures it so the
// actual bound local port can be read back via GetPorts. This lets the local
// port be assigned by the OS at bind time (port 0), so concurrent forwarders
// can never collide on the same ephemeral port.
type capturingForwarder struct {
	genericiooptions.IOStreams
	mu sync.Mutex
	fw *clientportforward.PortForwarder
}

func (c *capturingForwarder) ForwardPorts(method string, u *url.URL, opts portforward.PortForwardOptions) error {
	dialer, err := newForwardDialer(method, u, opts)
	if err != nil {
		return err
	}
	fw, err := clientportforward.NewOnAddresses(dialer, opts.Address, opts.Ports, opts.StopChannel, opts.ReadyChannel, c.Out, c.ErrOut)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.fw = fw
	c.mu.Unlock()
	return fw.ForwardPorts()
}

func (c *capturingForwarder) GetPorts() ([]clientportforward.ForwardedPort, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fw == nil {
		return nil, fmt.Errorf("port forwarder not started")
	}
	return c.fw.GetPorts()
}

// newForwardDialer mirrors kubectl's internal dialer construction: SPDY over
// websocket first (when enabled), falling back to plain SPDY.
func newForwardDialer(method string, u *url.URL, opts portforward.PortForwardOptions) (httpstream.Dialer, error) {
	transport, upgrader, err := spdy.RoundTripperFor(opts.Config)
	if err != nil {
		return nil, err
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, method, u)
	if !cmdutil.PortForwardWebsockets.IsDisabled() {
		tunnelingDialer, err := clientportforward.NewSPDYOverWebsocketDialer(u, opts.Config)
		if err != nil {
			return nil, err
		}
		dialer = clientportforward.NewFallbackDialer(tunnelingDialer, dialer, func(err error) bool {
			return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
		})
	}
	return dialer, nil
}

func (p *portForwarder) Start() error {
	if p.ns != "" {
		if err := p.cmd.Flags().Set("namespace", p.ns); err != nil {
			return err
		}
	}

	address, err := p.cmd.Flags().GetStringSlice("address")
	if err != nil {
		return err
	}

	// localPort 0 means an OS-assigned ephemeral port, resolved via GetPorts
	// after the forwarder is ready. This makes concurrent forwarders race-free.
	ports := fmt.Sprintf("%d:%d", p.localPort, p.podPort)
	ioStreams := genericiooptions.IOStreams{In: os.Stdin, Out: io.Discard, ErrOut: os.Stderr}
	pfOptions := portforward.NewDefaultPortForwardOptions(ioStreams)
	pfOptions.Address = address

	f := cmdutil.NewFactory(p.RESTClientGetter)
	if err := pfOptions.Complete(f, p.cmd, []string{p.podName, ports}); err != nil {
		return fmt.Errorf("complete failed: %v", err)
	}

	cf := &capturingForwarder{IOStreams: ioStreams}
	pfOptions.PortForwarder = cf

	go func() {
		if err := pfOptions.RunPortForwardContext(p.ctx); err != nil {
			p.errCh <- fmt.Errorf("error running port forward: %v", err)
			return
		}
	}()

	select {
	case <-pfOptions.ReadyChannel:
		fwdPorts, err := cf.GetPorts()
		if err != nil {
			return fmt.Errorf("failed to resolve forwarded port: %v", err)
		}
		if len(fwdPorts) > 0 {
			p.localPort = int(fwdPorts[0].Local)
		}
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
