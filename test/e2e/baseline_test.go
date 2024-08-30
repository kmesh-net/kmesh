//go:build integ
// +build integ

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

// NOTE: THE CODE IN THIS FILE IS MAINLY REFERENCED FROM ISTIO INTEGRATION
// FRAMEWORK(https://github.com/istio/istio/tree/master/tests/integration)
// AND ADAPTED FOR KMESH.

package kmesh

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/test"
	echot "istio.io/istio/pkg/test/echo"
	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/cluster"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/test/framework/components/echo/common/ports"
	"istio.io/istio/pkg/test/framework/components/prometheus"
	testKube "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/shell"
	"istio.io/istio/pkg/test/util/retry"
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

// Test when ns waypoint and service waypoint are deployed together, applications can access each other
// and all pass through waypoint.
func TestMixNsAndServiceWaypoint(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		waypoint := "namespace-waypoint"

		newWaypointProxyOrFail(t, t, apps.Namespace, waypoint, constants.ServiceTraffic)
		t.Cleanup(func() {
			deleteWaypointProxyOrFail(t, t, apps.Namespace, waypoint)
		})

		SetWaypoint(t, apps.Namespace.Name(), "", waypoint, Namespace)
		t.Cleanup(func() {
			UnsetWaypoint(t, apps.Namespace.Name(), "", Namespace)
		})

		runTestContext(t, func(t framework.TestContext, src echo.Instance, dst echo.Instance, opt echo.CallOptions) {
			if opt.Scheme != scheme.HTTP {
				return
			}
			opt.Check = check.And(
				check.OK(),
				// All traffic should pass through waypoint.
				IsL7(),
			)
			src.CallOrFail(t, opt)
		})
	})
}

func TestBookinfo(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		namespace := apps.Namespace.Name()
		// Install bookinfo.
		if _, err := shell.Execute(true, fmt.Sprintf("kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.22/samples/bookinfo/platform/kube/bookinfo.yaml -n %s", namespace)); err != nil {
			t.Fatalf("failed to install bookinfo: %v", err)
		}
		t.Cleanup(func() {
			if _, err := shell.Execute(true, fmt.Sprintf("kubectl delete -f https://raw.githubusercontent.com/istio/istio/release-1.22/samples/bookinfo/platform/kube/bookinfo.yaml -n %s", namespace)); err != nil {
				t.Fatalf("failed to delete bookinfo: %v", err)
			}
		})

		// Install sleep as client.
		if _, err := shell.Execute(true, fmt.Sprintf("kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.22/samples/sleep/sleep.yaml -n %s", namespace)); err != nil {
			t.Fatalf("failed to install sleep as client of bookinfo: %v", err)
		}
		t.Cleanup(func() {
			if _, err := shell.Execute(true, fmt.Sprintf("kubectl delete -f https://raw.githubusercontent.com/istio/istio/release-1.22/samples/sleep/sleep.yaml -n %s", namespace)); err != nil {
				t.Fatalf("failed to delete sleep as client of bookinfo: %v", err)
			}
		})

		fetchFn := testKube.NewSinglePodFetch(t.Clusters().Default(), namespace)
		if _, err := testKube.WaitUntilPodsAreReady(fetchFn); err != nil {
			t.Fatalf("failed to wait bookinfo pods to be ready: %v", err)
		}

		// It's used to check that all services of bookinfo are accessed correctly.
		checkBookinfo := func() bool {
			output, err := shell.Execute(true, fmt.Sprintf("kubectl exec deploy/sleep -n %s -- curl -s http://productpage:9080/productpage", namespace))
			if err != nil {
				t.Logf("failed to execute access command: %v, output is %s", err, output)
				return false
			}

			// Check the response content to confirm that the details, reviews and ratings services were accessed correctly.
			for _, key := range []string{"Book Details", "Book Reviews", "full stars"} {
				if !strings.Contains(output, key) {
					t.Logf("response doesn't contain keyword %s", key)
					return false
				}
			}

			return true
		}

		if err := retry.Until(checkBookinfo, retry.Timeout(60*time.Second), retry.BackoffDelay(1*time.Second)); err != nil {
			t.Fatal("failed to access bookinfo correctly: %v", err)
		}

		// Set namespace waypoint to verify that bookinfo could be accessed normally event if each hop
		// is processed by waypoint.
		waypoint := "namespace-waypoint"

		newWaypointProxyOrFail(t, t, apps.Namespace, waypoint, constants.ServiceTraffic)
		t.Cleanup(func() {
			deleteWaypointProxyOrFail(t, t, apps.Namespace, waypoint)
		})

		SetWaypoint(t, namespace, "", waypoint, Namespace)
		t.Cleanup(func() {
			UnsetWaypoint(t, namespace, "", Namespace)
		})

		if err := retry.Until(checkBookinfo, retry.Timeout(60*time.Second), retry.BackoffDelay(1*time.Second)); err != nil {
			t.Fatal("failed to access bookinfo correctly when there is a namespace waypoint: %v", err)
		}
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

func TestL4Telemetry(t *testing.T) {
	framework.NewTest(t).Run(func(tc framework.TestContext) {
		for _, src := range apps.EnrolledToKmesh {
			for _, dst := range apps.EnrolledToKmesh {
				tc.NewSubTestf("from %q to %q", src.Config().Service, dst.Config().Service).Run(func(stc framework.TestContext) {
					localDst := dst
					localSrc := src
					opt := echo.CallOptions{
						Port:    echo.Port{Name: "tcp"},
						Scheme:  scheme.TCP,
						Count:   5,
						Timeout: time.Second,
						Check:   check.OK(),
						To:      localDst,
					}

					query := buildL4Query(localSrc, localDst)
					stc.Logf("prometheus query: %#v", query)
					err := retry.Until(func() bool {
						stc.Logf("sending call from %q to %q", deployName(localSrc), localDst.Config().Service)
						localSrc.CallOrFail(stc, opt)
						reqs, err := prom.QuerySum(localSrc.Config().Cluster, query)
						if err != nil {
							stc.Logf("could not query for traffic from %q to %q: %v", deployName(localSrc), localDst.Config().Service, err)
							return false
						}
						if reqs == 0.0 {
							stc.Logf("found zero-valued sum for traffic from %q to %q: %v", deployName(localSrc), localDst.Config().Service, err)
							return false
						}
						return true
					}, retry.Timeout(15*time.Second), retry.BackoffDelay(1*time.Second))
					if err != nil {
						PromDiff(t, prom, localSrc.Config().Cluster, query)
						stc.Errorf("could not validate L4 telemetry for %q to %q: %v", deployName(localSrc), localDst.Config().Service, err)
					}
				})
			}
		}
	})
}

func buildL4Query(src, dst echo.Instance) prometheus.Query {
	query := prometheus.Query{}

	srcns := src.NamespaceName()
	destns := dst.NamespaceName()

	labels := map[string]string{
		"reporter":                       "destination",
		"connection_security_policy":     "mutual_tls",
		"response_flags":                 "-",
		"request_protocol":               "tcp",
		"destination_canonical_service":  dst.ServiceName(),
		"destination_canonical_revision": dst.Config().Version,
		"destination_service":            fmt.Sprintf("%s.%s.svc.cluster.local", dst.Config().Service, destns),
		"destination_service_name":       fmt.Sprintf("%s.%s.svc.cluster.local", dst.Config().Service, destns),
		"destination_service_namespace":  destns,
		"destination_principal":          "-",
		"destination_version":            dst.Config().Version,
		"destination_workload":           deployName(dst),
		"destination_workload_namespace": destns,
		"destination_cluster":            "Kubernetes",
		"source_canonical_service":       src.ServiceName(),
		"source_canonical_revision":      src.Config().Version,
		"source_principal":               "-",
		"source_version":                 src.Config().Version,
		"source_workload":                deployName(src),
		"source_workload_namespace":      srcns,
		"source_cluster":                 "Kubernetes",
	}

	query.Metric = "kmesh_tcp_connections_opened_total"
	query.Labels = labels

	return query
}

func deployName(inst echo.Instance) string {
	return inst.ServiceName() + "-" + inst.Config().Version
}

func PromDiff(t test.Failer, prom prometheus.Instance, cluster cluster.Cluster, query prometheus.Query) {
	t.Helper()
	unlabelled := prometheus.Query{Metric: query.Metric}
	v, _ := prom.Query(cluster, unlabelled)
	if v == nil {
		t.Logf("no metrics found for %v", unlabelled)
		return
	}
	switch v.Type() {
	case model.ValVector:
		value := v.(model.Vector)
		var allMismatches []map[string]string
		full := []model.Metric{}
		for _, s := range value {
			misMatched := map[string]string{}
			for k, want := range query.Labels {
				got := string(s.Metric[model.LabelName(k)])
				if want != got {
					misMatched[k] = got
				}
			}
			if len(misMatched) == 0 {
				continue
			}
			allMismatches = append(allMismatches, misMatched)
			full = append(full, s.Metric)
		}
		if len(allMismatches) == 0 {
			t.Logf("no diff found")
			return
		}
		sort.Slice(allMismatches, func(i, j int) bool {
			return len(allMismatches[i]) < len(allMismatches[j])
		})
		t.Logf("query %q returned %v series, but none matched our query exactly.", query.Metric, len(value))
		t.Logf("Original query: %v", query.String())
		for i, m := range allMismatches {
			t.Logf("Series %d (source: %v/%v)", i, full[i]["namespace"], full[i]["pod"])
			missing := []string{}
			for k, v := range m {
				if v == "" {
					missing = append(missing, k)
				} else {
					t.Logf("  for label %q, wanted %q but got %q", k, query.Labels[k], v)
				}
			}
			if len(missing) > 0 {
				t.Logf("  missing labels: %v", missing)
			}
		}

	default:
		t.Fatalf("PromDiff expects Vector, got %v", v.Type())

	}
}
