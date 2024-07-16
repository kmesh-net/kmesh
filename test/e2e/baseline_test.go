//go:build integ
// +build integ

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

// NOTE: THE CODE IN THIS FILE IS MAINLY REFERENCED FROM ISTIO INTEGRATION
// FRAMEWORK(https://github.com/istio/istio/tree/master/tests/integration)
// AND ADAPTED FOR KMESH.

package kmesh

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/util/sets"
)

var (
	callOptions = []echo.CallOptions{
		{
			Port:   echo.Port{Name: "http"},
			Scheme: scheme.HTTP,
			Count:  10,
		},
		{
			Port:   echo.Port{Name: "tcp"},
			Scheme: scheme.TCP,
			Count:  1,
		},
	}
)

func TestTrafficSplit(t *testing.T) {
	runTest(t, func(t framework.TestContext, src echo.Instance, dst echo.Instance, opt echo.CallOptions) {
		// Need at least one waypoint proxy and HTTP
		if opt.Scheme != scheme.HTTP {
			return
		}
		if !dst.Config().HasServiceAddressedWaypointProxy() {
			return
		}
		if src.Config().IsUncaptured() {
			// TODO: fix this and remove this skip
			t.Skip("https://github.com/istio/istio/issues/43238")
		}
		t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
			"Destination": dst.Config().Service,
		}, `apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: route
spec:
  hosts:
  - "{{.Destination}}"
  http:
  - match:
    - headers:
        user:
          exact: kmesh-custom-user
    route:
    - destination:
        host: "{{.Destination}}"
        subset: v2
  - route:
    - destination:
        host: "{{.Destination}}"
        subset: v1
`).ApplyOrFail(t)
		t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
			"Destination": dst.Config().Service,
		}, `apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: dr
spec:
  host: "{{.Destination}}"
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
`).ApplyOrFail(t)
		t.NewSubTest("v1").Run(func(t framework.TestContext) {
			opt = opt.DeepCopy()
			opt.Count = 5
			opt.Timeout = time.Second * 10
			opt.Check = check.And(
				check.OK(),
				func(result echo.CallResult, _ error) error {
					for _, r := range result.Responses {
						if r.Version != "v1" {
							return fmt.Errorf("expected service version %q, got %q", "v1", r.Version)
						}
					}
					return nil
				})
			src.CallOrFail(t, opt)
		})

		t.NewSubTest("v2").Run(func(t framework.TestContext) {
			opt = opt.DeepCopy()
			opt.Count = 5
			opt.Timeout = time.Second * 10
			if opt.HTTP.Headers == nil {
				opt.HTTP.Headers = map[string][]string{}
			}
			opt.HTTP.Headers.Set("user", "kmesh-custom-user")
			opt.Check = check.And(
				check.OK(),
				func(result echo.CallResult, _ error) error {
					for _, r := range result.Responses {
						if r.Version != "v2" {
							return fmt.Errorf("expected service version %q, got %q", "v2", r.Version)
						}
					}
					return nil
				})
			opt.HTTP.Headers.Set("user", "kmesh-custom-user")
			src.CallOrFail(t, opt)
		})
	})
}

func TestServerSideLB(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		runTestToServiceWaypoint(t, func(t framework.TestContext, src echo.Instance, dst echo.Instance, opt echo.CallOptions) {
			// Need HTTP
			if opt.Scheme != scheme.HTTP {
				return
			}
			var singleHost echo.Checker = func(result echo.CallResult, _ error) error {
				hostnames := make([]string, len(result.Responses))
				for i, r := range result.Responses {
					hostnames[i] = r.Hostname
				}
				unique := sets.SortedList(sets.New(hostnames...))
				if len(unique) != 1 {
					return fmt.Errorf("excepted only one destination, got: %v", unique)
				}
				return nil
			}
			var multipleHost echo.Checker = func(result echo.CallResult, _ error) error {
				hostnames := make([]string, len(result.Responses))
				for i, r := range result.Responses {
					hostnames[i] = r.Hostname
				}
				unique := sets.SortedList(sets.New(hostnames...))
				want := dst.WorkloadsOrFail(t)
				wn := []string{}
				for _, w := range want {
					wn = append(wn, w.PodName())
				}
				if len(unique) != len(wn) {
					return fmt.Errorf("excepted all destinations (%v), got: %v", wn, unique)
				}
				return nil
			}

			shouldBalance := dst.Config().HasServiceAddressedWaypointProxy()
			// Istio client will not reuse connections for HTTP/1.1
			opt.HTTP.HTTP2 = true
			// Make sure we make multiple calls
			opt.Count = 10
			c := singleHost
			if shouldBalance {
				c = multipleHost
			}
			opt.Check = check.And(check.OK(), c)
			opt.NewConnectionPerRequest = false
			src.CallOrFail(t, opt)
		})
	})
}

func TestServerRouting(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		runTestToServiceWaypoint(t, func(t framework.TestContext, src echo.Instance, dst echo.Instance, opt echo.CallOptions) {
			// Need waypoint proxy and HTTP
			if opt.Scheme != scheme.HTTP {
				return
			}
			t.NewSubTest("set header").Run(func(t framework.TestContext) {
				t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
					"Destination": dst.Config().Service,
				}, `apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: route
spec:
  hosts:
  - "{{.Destination}}"
  http:
  - headers:
      request:
        add:
          kmesh-custom-header: user-defined-value
    route:
    - destination:
        host: "{{.Destination}}"
`).ApplyOrFail(t)
				opt.Check = check.And(
					check.OK(),
					check.RequestHeader("Kmesh-Custom-Header", "user-defined-value"))
				src.CallOrFail(t, opt)
			})
			t.NewSubTest("route to a specific subnet").Run(func(t framework.TestContext) {
				t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
					"Destination": dst.Config().Service,
				}, `apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: route
spec:
  hosts:
  - "{{.Destination}}"
  http:
  - route:
    - destination:
        host: "{{.Destination}}"
        subset: v1
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: route
  namespace:
spec:
  host: "{{.Destination}}"
  subsets:
  - labels:
      version: v1
    name: v1
  - labels:
      version: v2
    name: v2
`).ApplyOrFail(t)
				var exp string
				for _, w := range dst.WorkloadsOrFail(t) {
					if strings.Contains(w.PodName(), "-v1") {
						exp = w.PodName()
					}
				}
				opt.Count = 10
				opt.Check = check.And(
					check.OK(),
					check.Hostname(exp))
				src.CallOrFail(t, opt)
			})
		})
	})
}

func TestWaypointEnvoyFilter(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		runTestToServiceWaypoint(t, func(t framework.TestContext, src echo.Instance, dst echo.Instance, opt echo.CallOptions) {
			// Need at least one waypoint proxy and HTTP
			if opt.Scheme != scheme.HTTP {
				return
			}
			t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
				"Destination": "waypoint",
			}, `apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: inbound
spec:
  workloadSelector:
    labels:
      gateway.networking.k8s.io/gateway-name: "{{.Destination}}"
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
            subFilter:
              name: "envoy.filters.http.router"
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.lua
        typed_config:
          "@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua"
          inlineCode: |
            function envoy_on_request(request_handle)
              request_handle:headers():add("x-lua-inbound", "hello world")
            end
  - applyTo: VIRTUAL_HOST
    match:
      context: SIDECAR_INBOUND
    patch:
      operation: MERGE
      value:
        request_headers_to_add:
        - header:
            key: x-vhost-inbound
            value: "hello world"
  - applyTo: CLUSTER
    match:
      context: SIDECAR_INBOUND
      cluster: {}
    patch:
      operation: MERGE
      value:
        http2_protocol_options: {}
`).ApplyOrFail(t)
			opt.Count = 5
			opt.Timeout = time.Second * 10
			opt.Check = check.And(
				check.OK(),
				check.RequestHeaders(map[string]string{
					"X-Lua-Inbound":   "hello world",
					"X-Vhost-Inbound": "hello world",
				}))
			src.CallOrFail(t, opt)
		})
	})
}

func runTest(t *testing.T, f func(t framework.TestContext, src echo.Instance, dst echo.Instance, opt echo.CallOptions)) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		runTestContext(t, f)
	})
}

// runTestToServiceWaypoint runs a given function against every src/dst pair where a call will traverse a service waypoint
func runTestToServiceWaypoint(t framework.TestContext, f func(t framework.TestContext, src echo.Instance, dst echo.Instance, opt echo.CallOptions)) {
	runTestContext(t, func(t framework.TestContext, src echo.Instance, dst echo.Instance, opt echo.CallOptions) {
		if !dst.Config().HasServiceAddressedWaypointProxy() {
			return
		}
		if !src.Config().HasProxyCapabilities() {
			// Only respected if the client knows about waypoints
			return
		}
		if src.Config().HasSidecar() {
			// TODO: sidecars do not currently respect waypoints
			t.Skip("https://github.com/istio/istio/issues/51445")
		}
		f(t, src, dst, opt)
	})
}

func runTestContext(t framework.TestContext, f func(t framework.TestContext, src echo.Instance, dst echo.Instance, opt echo.CallOptions)) {
	svcs := apps.All
	for _, src := range svcs {
		t.NewSubTestf("from %v", src.Config().Service).Run(func(t framework.TestContext) {
			for _, dst := range svcs {
				t.NewSubTestf("to %v", dst.Config().Service).Run(func(t framework.TestContext) {
					for _, opt := range callOptions {
						src, dst, opt := src, dst, opt
						t.NewSubTestf("%v", opt.Scheme).Run(func(t framework.TestContext) {
							opt = opt.DeepCopy()
							opt.To = dst
							opt.Check = check.OK()
							f(t, src, dst, opt)
						})
					}
				})
			}
		})
	}
}
