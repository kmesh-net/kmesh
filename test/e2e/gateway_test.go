//go:build integ
// +build integ

// CODE Copied and modified from https://github.com/istio/istio
// more specifically: https://github.com/istio/istio/blob/master/pkg/test/framework/components/istio/ingress.go
//
// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kmesh

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"istio.io/istio/pkg/http/headers"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/cluster"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/test/framework/components/echo/common"
	"istio.io/istio/pkg/test/framework/components/environment/kube"
	"istio.io/istio/pkg/test/framework/components/istio/ingress"
	"istio.io/istio/pkg/test/framework/resource"
	"istio.io/istio/pkg/test/scopes"
	"istio.io/istio/pkg/test/util/retry"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	defaultIngressIstioNameLabel   = "ingressgateway"
	defaultIngressIstioLabel       = "istio=" + defaultIngressIstioNameLabel
	defaultIngressServiceName      = "istio-" + defaultIngressIstioNameLabel
	defaultIngressServiceNamespace = "istio-system"

	discoveryPort = 15012
)

var (
	getAddressTimeout = retry.Timeout(3 * time.Minute)
	getAddressDelay   = retry.BackoffDelay(500 * time.Millisecond)

	_ ingress.Instance = &ingressImpl{}
	_ io.Closer        = &ingressImpl{}
)

type ingressConfig struct {
	// Service is the kubernetes Service name for the cluster
	Service types.NamespacedName
	// LabelSelector is the value for the label on the ingress kubernetes objects
	LabelSelector string

	// Cluster to be used in a multicluster environment
	Cluster cluster.Cluster
}

func newIngress(ctx resource.Context, cfg ingressConfig) (i ingress.Instance) {
	if cfg.LabelSelector == "" {
		cfg.LabelSelector = defaultIngressIstioLabel
	}
	c := &ingressImpl{
		service:       cfg.Service,
		labelSelector: cfg.LabelSelector,
		env:           ctx.Environment().(*kube.Environment),
		cluster:       ctx.Clusters().GetOrDefault(cfg.Cluster),
		caller:        common.NewCaller(),
	}
	return c
}

type ingressImpl struct {
	service       types.NamespacedName
	labelSelector string

	env     *kube.Environment
	cluster cluster.Cluster
	caller  *common.Caller
}

func (c *ingressImpl) Close() error {
	return c.caller.Close()
}

// getAddressesInner returns the external addresses for the given port. When we don't have support for LoadBalancer,
// the returned list will contain will have the externally reachable NodePort address and port.
func (c *ingressImpl) getAddressesInner(port int) ([]string, []int, error) {
	attempts := 0
	remoteAddrs, err := retry.UntilComplete(func() (addrs any, completed bool, err error) {
		attempts++
		addrs, completed, err = getRemoteServiceAddresses(c.env.Settings(), c.cluster, c.service.Namespace, c.labelSelector, c.service.Name, port)
		if err != nil && attempts > 1 {
			// Log if we fail more than once to avoid test appearing to hang
			// LB provision be slow, so timeout here needs to be long we should give context
			scopes.Framework.Warnf("failed to get address for port %v: %v", port, err)
		}
		return
	}, getAddressTimeout, getAddressDelay)
	var anyRemoteAddrs []interface{}
	// Perform type assertion and construct a new slice of `any`
	anyRemoteAddrs, _ = remoteAddrs.([]any)

	if err != nil {
		return nil, nil, err
	}
	var addrs []string
	var ports []int
	for _, addr := range anyRemoteAddrs {
		switch v := addr.(type) {
		case string:
			host, portStr, err := net.SplitHostPort(v)
			if err != nil {
				return nil, nil, err
			}
			mappedPort, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, nil, err
			}
			addrs = append(addrs, host)
			ports = append(ports, mappedPort)
		case netip.AddrPort:
			addrs = append(addrs, v.Addr().String())
			ports = append(ports, int(v.Port()))
		}
	}
	if len(addrs) > 0 {
		return addrs, ports, nil
	}

	return nil, nil, fmt.Errorf("failed to get address for port %v", port)
}

// AddressForPort returns the externally reachable host and port of the component for the given port.
func (c *ingressImpl) AddressesForPort(port int) ([]string, []int) {
	addrs, ports, err := c.getAddressesInner(port)
	if err != nil {
		scopes.Framework.Error(err)
		return nil, nil
	}
	return addrs, ports
}

func (c *ingressImpl) Cluster() cluster.Cluster {
	return c.cluster
}

// HTTPAddresses returns the externally reachable HTTP hosts and port (80) of the component.
func (c *ingressImpl) HTTPAddresses() ([]string, []int) {
	return c.AddressesForPort(80)
}

// TCPAddresses returns the externally reachable TCP hosts and port (31400) of the component.
func (c *ingressImpl) TCPAddresses() ([]string, []int) {
	return c.AddressesForPort(31400)
}

// HTTPSAddresses returns the externally reachable TCP hosts and port (443) of the component.
func (c *ingressImpl) HTTPSAddresses() ([]string, []int) {
	return c.AddressesForPort(443)
}

// DiscoveryAddresses returns the externally reachable discovery addresses (15012) of the component.
func (c *ingressImpl) DiscoveryAddresses() []netip.AddrPort {
	hosts, ports := c.AddressesForPort(discoveryPort)
	var addrs []netip.AddrPort
	if hosts == nil {
		return []netip.AddrPort{{}}
	}
	for i, host := range hosts {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return []netip.AddrPort{}
		}
		addrs = append(addrs, netip.AddrPortFrom(ip, uint16(ports[i])))
	}

	return addrs
}

func (c *ingressImpl) Call(options echo.CallOptions) (echo.CallResult, error) {
	return c.callEcho(options)
}

func (c *ingressImpl) CallOrFail(t test.Failer, options echo.CallOptions) echo.CallResult {
	t.Helper()
	resp, err := c.Call(options)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (c *ingressImpl) callEcho(opts echo.CallOptions) (echo.CallResult, error) {
	var (
		addr string
		port int
	)
	opts = opts.DeepCopy()
	var addrs []string
	var ports []int
	if opts.Port.ServicePort == 0 {
		s, err := c.schemeFor(opts)
		if err != nil {
			return echo.CallResult{}, err
		}
		opts.Scheme = s

		// Default port based on protocol
		switch s {
		case scheme.HTTP:
			addrs, ports = c.HTTPAddresses()
		case scheme.HTTPS:
			addrs, ports = c.HTTPSAddresses()
		case scheme.TCP:
			addrs, ports = c.TCPAddresses()
		default:
			return echo.CallResult{}, fmt.Errorf("ingress: scheme %v not supported. Options: %v+", s, opts)
		}
	} else {
		addrs, ports = c.AddressesForPort(opts.Port.ServicePort)
	}
	if len(addrs) == 0 || len(ports) == 0 {
		scopes.Framework.Warnf("failed to get host and port for %s/%d", opts.Port.Protocol, opts.Port.ServicePort)
		return echo.CallResult{}, fmt.Errorf("failed to get host or port for %s/%d", opts.Port.Protocol, opts.Port.ServicePort)
	}
	addr = addrs[0]
	port = ports[0]
	// Even if they set ServicePort, when load balancer is disabled, we may need to switch to NodePort, so replace it.
	opts.Port.ServicePort = port
	if opts.HTTP.Headers == nil {
		opts.HTTP.Headers = map[string][]string{}
	}
	if host := opts.GetHost(); len(host) > 0 {
		opts.HTTP.Headers.Set(headers.Host, host)
	}
	// Default address based on port
	opts.Address = addr
	if len(c.cluster.HTTPProxy()) > 0 && !c.cluster.ProxyKubectlOnly() {
		opts.HTTP.HTTPProxy = c.cluster.HTTPProxy()
	}
	return c.caller.CallEcho(c, opts)
}

func (c *ingressImpl) schemeFor(opts echo.CallOptions) (scheme.Instance, error) {
	if opts.Scheme == "" && opts.Port.Protocol == "" {
		return "", fmt.Errorf("must provide either protocol or scheme")
	}

	if opts.Scheme != "" {
		return opts.Scheme, nil
	}

	return opts.Port.Scheme()
}

func (c *ingressImpl) PodID(i int) (string, error) {
	pods, err := c.env.Clusters().Default().PodsForSelector(context.TODO(), c.service.Namespace, c.labelSelector)
	if err != nil {
		return "", fmt.Errorf("unable to get ingressImpl gateway stats: %v", err)
	}
	if i < 0 || i >= len(pods.Items) {
		return "", fmt.Errorf("pod index out of boundary (%d): %d", len(pods.Items), i)
	}
	return pods.Items[i].Name, nil
}

func (c *ingressImpl) Namespace() string {
	return c.service.Namespace
}

// NOTE: make sure the istio ingress gateway is deployed in the istio-system namespace.
func defaultIngress(t test.Failer, ctx resource.Context) ingress.Instance {
	return newIngress(ctx, ingressConfig{
		Cluster: ctx.Clusters().Default(),
		Service: types.NamespacedName{
			Name:      defaultIngressServiceName,
			Namespace: defaultIngressServiceNamespace,
		},
		LabelSelector: defaultIngressIstioLabel,
	})
}

func getRemoteServiceAddresses(s *kube.Settings, cluster cluster.Cluster, ns, label, svcName string,
	port int,
) ([]any, bool, error) {
	if !s.LoadBalancerSupported {
		pods, err := cluster.PodsForSelector(context.TODO(), ns, label)
		if err != nil {
			return nil, false, err
		}

		names := make([]string, 0, len(pods.Items))
		for _, p := range pods.Items {
			names = append(names, p.Name)
		}
		scopes.Framework.Debugf("Querying remote service %s, pods:%v", svcName, names)
		if len(pods.Items) == 0 {
			return nil, false, fmt.Errorf("no remote service pod found")
		}

		scopes.Framework.Debugf("Found pod: %v", pods.Items[0].Name)
		ip := pods.Items[0].Status.HostIP
		if ip == "" {
			return nil, false, fmt.Errorf("no Host IP available on the remote service node yet")
		}

		svc, err := cluster.Kube().CoreV1().Services(ns).Get(context.TODO(), svcName, metav1.GetOptions{})
		if err != nil {
			return nil, false, err
		}

		if len(svc.Spec.Ports) == 0 {
			return nil, false, fmt.Errorf("no ports found in service: %s/%s", ns, svcName)
		}

		var nodePort int32
		for _, svcPort := range svc.Spec.Ports {
			if svcPort.Protocol == "TCP" && svcPort.Port == int32(port) {
				nodePort = svcPort.NodePort
				break
			}
		}
		if nodePort == 0 {
			return nil, false, fmt.Errorf("no port %d found in service: %s/%s", port, ns, svcName)
		}

		ipAddr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, false, err
		}
		return []any{netip.AddrPortFrom(ipAddr, uint16(nodePort))}, true, nil
	}

	// Otherwise, get the load balancer IP.
	svc, err := cluster.Kube().CoreV1().Services(ns).Get(context.TODO(), svcName, metav1.GetOptions{})
	if err != nil {
		return nil, false, err
	}

	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		return nil, false, fmt.Errorf("service %s/%s is not available yet: no ingress", svc.Namespace, svc.Name)
	}
	var addrs []any
	for _, ingr := range svc.Status.LoadBalancer.Ingress {
		if ingr.IP == "" && ingr.Hostname == "" {
			return nil, false, fmt.Errorf("service %s/%s is not available yet: no ingress", svc.Namespace, svc.Name)
		}
		if ingr.IP != "" {
			ipaddr, err := netip.ParseAddr(ingr.IP)
			if err != nil {
				return nil, false, err
			}
			addrs = append(addrs, netip.AddrPortFrom(ipaddr, uint16(port)))
		} else {
			addrs = append(addrs, net.JoinHostPort(ingr.Hostname, strconv.Itoa(port)))
		}
	}
	return addrs, true, nil
}

func TestIngress(t *testing.T) {
	runIngressTest(t, func(t framework.TestContext, src ingress.Instance, dst echo.Instance, opt echo.CallOptions) {
		t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
			"Destination": dst.Config().Service,
		}, `apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: gateway
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts: ["*"]
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: route
spec:
  gateways:
  - gateway
  hosts:
  - "*"
  http:
  - route:
    - destination:
        host: "{{.Destination}}"
`).ApplyOrFail(t)
		src.CallOrFail(t, opt)
	})
}

func runIngressTest(t *testing.T, f func(t framework.TestContext, src ingress.Instance, dst echo.Instance, opt echo.CallOptions)) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		svcs := apps.All
		for _, dst := range svcs {
			t.NewSubTestf("to %v", dst.Config().Service).Run(func(t framework.TestContext) {
				dst := dst
				opt := echo.CallOptions{
					Port:    echo.Port{Name: "http"},
					Scheme:  scheme.HTTP,
					Count:   5,
					Timeout: time.Second * 2,
					Check:   check.OK(),
					To:      dst,
				}
				f(t, defaultIngress(t, t), dst, opt)
			})
		}
	})
}

const (
	defaultEgressServiceName      = "istio-egressgateway"
	defaultEgressServiceNamespace = "istio-system"
)

// TestEgress verifies that traffic from mesh pods can be routed through the egress gateway before reaching an external service. We use one of the existing echo apps as the "external" backend (registered under a fake hostname) so the test doesn't need real internet access.
func TestEgress(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		dst := apps.EnrolledToKmesh
		if len(dst) == 0 {
			t.Skip("no enrolled-to-kmesh instances found")
			return
		}

		dstIP := dst[0].Address()
		dstPort := dst[0].Config().Ports.MustForName("http").ServicePort

		// the virtual IP below is IPv4 — skip in IPv6-only clusters
		if ip := net.ParseIP(dstIP); ip != nil && ip.To4() == nil {
			t.Skip("skipping egress test in IPv6-only environment: ServiceEntry virtual IP is IPv4")
			return
		}

		// 240.240.0.100 is in the range Istio reserves for ServiceEntry virtual IPs, so it won't clash
		// with any real pod or service address.
		const (
			externalHost = "external-svc.example.com"
			externalVIP  = "240.240.0.100"
		)

		// Apply config once for all source subtests — it only depends on dst, not src.
		t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
			"ExternalHost": externalHost,
			"ExternalVIP":  externalVIP,
			"DstIP":        dstIP,
			"DstPort":      fmt.Sprintf("%d", dstPort),
			"EgressSvc":    defaultEgressServiceName,
			"EgressNs":     defaultEgressServiceNamespace,
		}, `
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: external-svc
spec:
  hosts:
  - "{{.ExternalHost}}"
  addresses:
  - {{.ExternalVIP}}
  ports:
  - number: 80
    name: http
    protocol: HTTP
  location: MESH_EXTERNAL
  resolution: STATIC
  endpoints:
  - address: {{.DstIP}}
    ports:
      http: {{.DstPort}}
---
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: egress-gateway
spec:
  selector:
    istio: egressgateway
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "{{.ExternalHost}}"
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: external-svc-via-egress
spec:
  hosts:
  - "{{.ExternalHost}}"
  gateways:
  - egress-gateway
  - mesh
  http:
  # traffic from mesh pods: divert it to the egress gateway first
  - match:
    - gateways:
      - mesh
      port: 80
    route:
    - destination:
        host: {{.EgressSvc}}.{{.EgressNs}}.svc.cluster.local
        port:
          number: 80
  # traffic arriving at the egress gateway: forward to the actual destination
  - match:
    - gateways:
      - egress-gateway
      port: 80
    route:
    - destination:
        host: "{{.ExternalHost}}"
        port:
          number: 80
`).ApplyOrFail(t)

		for _, src := range apps.All {
			src := src
			t.NewSubTestf("from %v", src.Config().Service).Run(func(t framework.TestContext) {
				opt := echo.CallOptions{
					// Do NOT set To — we route by raw Address+Port so the echo caller
					// doesn't try to resolve endpoints from the Instances slice.
					Address: externalVIP,
					Port:    echo.Port{ServicePort: 80},
					Scheme:  scheme.HTTP,
					Count:   5,
					Timeout: time.Second * 10,
					Check:   check.OK(),
					HTTP: echo.HTTP{
						Headers: map[string][]string{},
					},
				}
				opt.HTTP.Headers.Set(headers.Host, externalHost)
				src.CallOrFail(t, opt)
			})
		}
	})
}
