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
	"net"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
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
	ioStreams := genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}
	pfOptions := portforward.NewDefaultPortForwardOptions(ioStreams)
	pfOptions.Address = address

	f := cmdutil.NewFactory(p.RESTClientGetter)
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
