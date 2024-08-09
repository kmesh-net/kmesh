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
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/config/constants"
	echot "istio.io/istio/pkg/test/echo"
	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/test/framework/components/echo/common/ports"
	"istio.io/istio/pkg/util/sets"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func IsL7() echo.Checker {
	return check.Each(func(r echot.Response) error {
		// TODO: response headers?
		_, f := r.RequestHeaders[http.CanonicalHeaderKey("X-Request-Id")]
		if !f {
			return fmt.Errorf("X-Request-Id not set, is L7 processing enabled?")
		}
		return nil
	})
}

func IsL4() echo.Checker {
	return check.Each(func(r echot.Response) error {
		// TODO: response headers?
		_, f := r.RequestHeaders[http.CanonicalHeaderKey("X-Request-Id")]
		if f {
			return fmt.Errorf("X-Request-Id set, is L7 processing enabled unexpectedly?")
		}
		return nil
	})
}

var (
	httpValidator = check.And(check.OK(), IsL7())
	tcpValidator  = check.And(check.OK(), IsL4())
	callOptions   = []echo.CallOptions{
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

func supportsL7(opt echo.CallOptions, src, dst echo.Instance) bool {
	isL7Scheme := opt.Scheme == scheme.HTTP || opt.Scheme == scheme.GRPC || opt.Scheme == scheme.WebSocket
	return dst.Config().HasAnyWaypointProxy() && isL7Scheme
}

func OriginalSourceCheck(t framework.TestContext, src echo.Instance) echo.Checker {
	// Check that each response saw one of the workload IPs for the src echo instance
	addresses := sets.New(src.WorkloadsOrFail(t).Addresses()...)
	return check.Each(func(response echot.Response) error {
		if !addresses.Contains(response.IP) {
			return fmt.Errorf("expected original source (%v) to be propagated, but got %v", addresses.UnsortedList(), response.IP)
		}
		return nil
	})
}

// Test access to service, enabling L7 processing and propagating original src when  appropriate.
func TestServices(t *testing.T) {
	runTest(t, func(t framework.TestContext, src echo.Instance, dst echo.Instance, opt echo.CallOptions) {
		if opt.Scheme != scheme.HTTP {
			return
		}
		if supportsL7(opt, src, dst) {
			opt.Check = httpValidator
		} else {
			opt.Check = tcpValidator
		}

		if !dst.Config().HasServiceAddressedWaypointProxy() {
			// Check original source, unless there is a waypoint in the path. For waypoint, we don't (yet?) propagate original src.
			opt.Check = check.And(opt.Check, OriginalSourceCheck(t, src))
		}

		src.CallOrFail(t, opt)
	})
}

// Test access directly using pod IP.
func TestPodIP(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		for _, src := range apps.All {
			for _, srcWl := range src.WorkloadsOrFail(t) {
				srcWl := srcWl
				t.NewSubTestf("from %v %v", src.Config().Service, srcWl.Address()).Run(func(t framework.TestContext) {
					for _, dst := range apps.All {
						for _, dstWl := range dst.WorkloadsOrFail(t) {
							t.NewSubTestf("to %v %v", dst.Config().Service, dstWl.Address()).Run(func(t framework.TestContext) {
								src, dst, srcWl, dstWl := src, dst, srcWl, dstWl
								if src.Config().HasSidecar() {
									t.Skip("not supported yet")
								}
								for _, opt := range callOptions {
									opt := opt.DeepCopy()
									opt.Check = tcpValidator

									opt.Address = dstWl.Address()
									opt.Check = check.And(opt.Check, check.Hostname(dstWl.PodName()))

									opt.Port = echo.Port{ServicePort: ports.All().MustForName(opt.Port.Name).WorkloadPort}
									opt.ToWorkload = dst.WithWorkloads(dstWl)

									t.NewSubTestf("%v", opt.Scheme).RunParallel(func(t framework.TestContext) {
										src.WithWorkloads(srcWl).CallOrFail(t, opt)
									})
								}
							})
						}
					}
				})
			}
		}
	})
}

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

// Test add/remove waypoint at pod granularity.
func TestAddRemovePodWaypoint(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		waypoint := "pod-waypoint"
		newWaypointProxyOrFail(t, t, apps.Namespace, waypoint, constants.WorkloadTraffic)

		t.Cleanup(func() {
			deleteWaypointProxyOrFail(t, t, apps.Namespace, waypoint)
		})

		dst := apps.EnrolledToKmesh
		t.NewSubTest("before").Run(func(t framework.TestContext) {
			for _, src := range apps.All {
				if src.Config().IsUncaptured() {
					continue
				}
				for _, dstWl := range dst.WorkloadsOrFail(t) {
					t.NewSubTestf("from %v", src.Config().Service).Run(func(t framework.TestContext) {
						c := IsL4()
						opt := echo.CallOptions{
							Address: dstWl.Address(),
							Port:    echo.Port{ServicePort: ports.All().MustForName("http").WorkloadPort},
							Scheme:  scheme.HTTP,
							Count:   10,
							Check:   check.And(check.OK(), c),
						}
						src.CallOrFail(t, opt)
					})
				}

			}
		})

		// Configure pods to use waypoint.
		for _, dstWl := range dst.WorkloadsOrFail(t) {
			SetWaypoint(t, apps.Namespace.Name(), dstWl.PodName(), waypoint, Workload)
			t.Cleanup(func() {
				UnsetWaypoint(t, apps.Namespace.Name(), dstWl.PodName(), Workload)
			})
		}

		// Now should always be L7.
		t.NewSubTest("after").Run(func(t framework.TestContext) {
			for _, src := range apps.All {
				if src.Config().IsUncaptured() {
					continue
				}
				for _, dstWl := range dst.WorkloadsOrFail(t) {
					t.NewSubTestf("from %v", src.Config().Service).Run(func(t framework.TestContext) {
						c := IsL4()
						opt := echo.CallOptions{
							Address: dstWl.Address(),
							Port:    echo.Port{ServicePort: ports.All().MustForName("http").WorkloadPort},
							Scheme:  scheme.HTTP,
							Count:   10,
							Check:   check.And(check.OK(), c),
						}
						src.CallOrFail(t, opt)
					})
				}

			}
		})
	})
}

// Test add/remove waypoint at ns or service granularity.
func TestRemoveAddNsOrServiceWaypoint(t *testing.T) {
	for _, granularity := range []Granularity{Service, Namespace} {
		framework.NewTest(t).Run(func(t framework.TestContext) {
			var waypoint, name string
			switch granularity {
			case Namespace:
				waypoint = "namespace-waypoint"
				name = "namespace"
			case Service:
				waypoint = "service-waypoint"
				name = "service"
			}

			newWaypointProxyOrFail(t, t, apps.Namespace, waypoint, constants.ServiceTraffic)

			t.NewSubTest(fmt.Sprintf("%s granularity, before set waypoint", name)).Run(func(t framework.TestContext) {
				dst := apps.EnrolledToKmesh
				for _, src := range apps.All {
					if src.Config().IsUncaptured() {
						continue
					}
					t.NewSubTestf("from %v", src.Config().Service).Run(func(t framework.TestContext) {
						c := IsL4()
						opt := echo.CallOptions{
							To:     dst,
							Port:   echo.Port{Name: "http"},
							Scheme: scheme.HTTP,
							Count:  10,
							Check:  check.And(check.OK(), c),
						}
						src.CallOrFail(t, opt)
					})
				}
			})

			SetWaypoint(t, apps.Namespace.Name(), EnrolledToKmesh, waypoint, granularity)

			// Now should always be L7
			t.NewSubTest(fmt.Sprintf("%s granularity, after set waypoint", name)).Run(func(t framework.TestContext) {
				dst := apps.EnrolledToKmesh
				for _, src := range apps.All {
					if src.Config().IsUncaptured() {
						continue
					}
					t.NewSubTestf("from %v", src.Config().Service).Run(func(t framework.TestContext) {
						opt := echo.CallOptions{
							To:     dst,
							Port:   echo.Port{Name: "http"},
							Scheme: scheme.HTTP,
							Count:  10,
							Check:  check.And(check.OK(), IsL7()),
						}
						src.CallOrFail(t, opt)
					})
				}
			})

			UnsetWaypoint(t, apps.Namespace.Name(), EnrolledToKmesh, granularity)
			deleteWaypointProxyOrFail(t, t, apps.Namespace, waypoint)
		})
	}
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

type Granularity int

const (
	Namespace Granularity = iota
	Service
	Workload
)

func UnsetWaypoint(t framework.TestContext, ns string, name string, granularity Granularity) {
	SetWaypoint(t, ns, name, "", granularity)
}

func SetWaypoint(t framework.TestContext, ns string, name string, waypoint string, granularity Granularity) {
	for _, c := range t.Clusters() {
		setWaypoint := func(waypoint string) error {
			if waypoint == "" {
				waypoint = "null"
			} else {
				waypoint = fmt.Sprintf("%q", waypoint)
			}
			label := []byte(fmt.Sprintf(`{"metadata":{"labels":{"%s":%s}}}`, constants.AmbientUseWaypointLabel, waypoint))

			switch granularity {
			case Namespace:
				_, err := c.Kube().CoreV1().Namespaces().Patch(context.TODO(), ns, types.MergePatchType, label, metav1.PatchOptions{})
				return err
			case Service:
				_, err := c.Kube().CoreV1().Services(ns).Patch(context.TODO(), name, types.MergePatchType, label, metav1.PatchOptions{})
				return err
			case Workload:
				_, err := c.Kube().CoreV1().Pods(ns).Patch(context.TODO(), name, types.MergePatchType, label, metav1.PatchOptions{})
				return err
			}

			return nil
		}

		if err := setWaypoint(waypoint); err != nil {
			t.Fatal(err)
		}
	}
}
