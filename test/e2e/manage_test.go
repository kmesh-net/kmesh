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
	"testing"

	"istio.io/api/label"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/test/framework/components/echo/common/ports"
	"istio.io/istio/pkg/test/framework/components/echo/deployment"
	"istio.io/istio/pkg/test/framework/components/echo/match"
	"istio.io/istio/pkg/test/framework/components/namespace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Test the workloads in a managed ns, when adding label `istio.io/dataplane-mode=none`, they
// will be removed from mesh. After deleting the label, it will be re-managed.
func TestManageWorkloadsDataplaneNone(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		dst := apps.ServiceWithWaypointAtServiceGranularity
		src := apps.EnrolledToKmesh
		t.NewSubTest("in managed ns, before workloads add label `istio.io/dataplane-mode=none`").Run(func(t framework.TestContext) {
			for _, s := range src {
				// Traffic passes through the waypoint indicates that the pods are managed by Kmesh.
				c := IsL7()
				opt := echo.CallOptions{
					To:     dst,
					Port:   echo.Port{Name: "http"},
					Scheme: scheme.HTTP,
					Count:  10,
					Check:  check.And(check.OK(), c),
				}
				s.CallOrFail(t, opt)
			}
		})

		unenrollWorkloadsOrFail(t, apps.Namespace.Name(), apps.EnrolledToKmesh.WorkloadsOrFail(t))

		t.NewSubTest("in managed ns, after workloads add label `istio.io/dataplane-mode=none`").Run(func(t framework.TestContext) {
			dst := apps.ServiceWithWaypointAtServiceGranularity

			for _, s := range src {
				// Traffic no longer passes through the waypoint indicates that the pods are no longer managed by Kmesh.
				c := IsL4()
				opt := echo.CallOptions{
					To:     dst,
					Port:   echo.Port{Name: "http"},
					Scheme: scheme.HTTP,
					Count:  10,
					Check:  check.And(check.OK(), c),
				}
				s.CallOrFail(t, opt)
			}
		})

		enrollWorkloadsInManagedNsOrFail(t, apps.Namespace.Name(), apps.EnrolledToKmesh.WorkloadsOrFail(t))

		t.NewSubTest("in managed ns, after workloads unset label `istio.io/dataplane-mode=none`").Run(func(t framework.TestContext) {
			dst := apps.ServiceWithWaypointAtServiceGranularity

			for _, s := range src {
				// Traffic passes through the waypoint again indicates that the pods are managed by Kmesh again.
				c := IsL7()
				opt := echo.CallOptions{
					To:     dst,
					Port:   echo.Port{Name: "http"},
					Scheme: scheme.HTTP,
					Count:  10,
					Check:  check.And(check.OK(), c),
				}
				s.CallOrFail(t, opt)
			}
		})
	})
}

func enrollWorkloadsOrFail(t framework.TestContext, ns string, workloads echo.Workloads) {
	for _, workload := range workloads {
		err := setPodLabel(t, ns, workload.PodName(), label.IoIstioDataplaneMode.Name, DataplaneModeKmesh)
		if err != nil {
			t.Fatalf("failed to enroll workload %s/%s: %v", ns, workload.PodName(), err)
		}
	}
}

func enrollWorkloadsInManagedNsOrFail(t framework.TestContext, ns string, workloads echo.Workloads) {
	for _, workload := range workloads {
		err := setPodLabel(t, ns, workload.PodName(), label.IoIstioDataplaneMode.Name, "null")
		if err != nil {
			t.Fatalf("failed to enroll workload %s/%s in managed ns: %v", ns, workload.PodName(), err)
		}
	}
}

func unenrollWorkloadsOrFail(t framework.TestContext, ns string, workloads echo.Workloads) {
	for _, workload := range workloads {
		err := setPodLabel(t, ns, workload.PodName(), label.IoIstioDataplaneMode.Name, constants.DataplaneModeNone)
		if err != nil {
			t.Fatalf("failed to unenroll workload %s/%s: %v", ns, workload.PodName(), err)
		}
	}
}

func setPodLabel(t framework.TestContext, ns string, name string, key string, value string) error {
	label := []byte(fmt.Sprintf(`{"metadata":{"labels":{"%s":"%s"}}}`, key, value))

	for _, c := range t.Clusters() {
		if _, err := c.Kube().CoreV1().Pods(ns).Patch(context.TODO(), name, types.MergePatchType, label, metav1.PatchOptions{}); err != nil {
			return err
		}
	}

	return nil
}

// This test creates a new namespace which is not managed by Kmesh by default. It contains two services,
// one managed and one not managed by Kmesh. Verify whether the test result is consistent with expectations.
// Then manage the namespace and verify that all services in it are indeed managed.
func TestCrossNamespace(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		anotherNS, err := namespace.New(t, namespace.Config{
			Prefix: "another",
			Inject: false,
		})
		if err != nil {
			t.Fatalf("failed to create another namespace: %v", err)
		}

		enrolled := "enrolled"
		unenrolled := "unenrolled"

		builder := deployment.New(t).
			WithClusters(t.Clusters()...).
			WithConfig(echo.Config{
				Service:   enrolled,
				Namespace: anotherNS,
				Ports:     ports.All(),
				Subsets: []echo.SubsetConfig{
					{
						Replicas: 1,
						Labels: map[string]string{
							label.IoIstioDataplaneMode.Name: DataplaneModeKmesh,
						},
					},
				},
			}).
			WithConfig(echo.Config{
				Service:   unenrolled,
				Namespace: anotherNS,
				Ports:     ports.All(),
			})

		all, err := builder.Build()
		if err != nil {
			t.Fatalf("failed to build services in %s: %v", anotherNS.Name())
		}

		enrolledService := match.ServiceName(echo.NamespacedName{Name: enrolled, Namespace: anotherNS}).GetMatches(all)
		unenrolledService := match.ServiceName(echo.NamespacedName{Name: unenrolled, Namespace: anotherNS}).GetMatches(all)

		dst := apps.ServiceWithWaypointAtServiceGranularity

		unenrolledNSTest := func() {
			tests := []struct {
				svc      echo.Instances
				enrolled bool
			}{
				{
					svc:      enrolledService,
					enrolled: true,
				},
				{
					svc:      unenrolledService,
					enrolled: false,
				},
			}

			for _, test := range tests {
				for _, src := range test.svc {
					c := IsL4()
					if test.enrolled {
						// Traffic from the enrolled service will pass through waypoint, indicating that the service is ineeded managed by Kmesh.
						c = IsL7()
					}
					opt := echo.CallOptions{
						To:     dst,
						Port:   echo.Port{Name: "http"},
						Scheme: scheme.HTTP,
						Count:  10,
						Check:  check.And(check.OK(), c),
					}
					src.CallOrFail(t, opt)
				}
			}
		}

		t.NewSubTest("cross namespace access, the new namespace is not managed by Kmesh").Run(func(t framework.TestContext) {
			unenrolledNSTest()
		})

		enrollNamespaceOrFail(t, anotherNS.Name())

		t.NewSubTest("cross namespace access, the new namespace is managed by Kmesh").Run(func(t framework.TestContext) {
			for _, src := range all {
				opt := echo.CallOptions{
					To:     dst,
					Port:   echo.Port{Name: "http"},
					Scheme: scheme.HTTP,
					Count:  10,
					// Now all traffic will pass through waypoint, indicating all the pods in the new namespace have been managed by Kmesh.
					Check: check.And(check.OK(), IsL7()),
				}
				src.CallOrFail(t, opt)
			}
		})

		unenrollNamespaceOrFail(t, anotherNS.Name())

		t.NewSubTest("cross namespace access, the new namespace is not managed by Kmesh **AGAIN**").Run(func(t framework.TestContext) {
			unenrolledNSTest()
		})
	})
}

func enrollNamespaceOrFail(t framework.TestContext, ns string) {
	if err := setNamespaceLabel(t, ns, label.IoIstioDataplaneMode.Name, DataplaneModeKmesh); err != nil {
		t.Fatalf("failed to enroll namespace %s: %v", ns, err)
	}
}

func unenrollNamespaceOrFail(t framework.TestContext, ns string) {
	if err := setNamespaceLabel(t, ns, label.IoIstioDataplaneMode.Name, constants.DataplaneModeNone); err != nil {
		t.Fatalf("failed to enroll namespace %s: %v", ns, err)
	}
}

func setNamespaceLabel(t framework.TestContext, ns string, key string, value string) error {
	label := []byte(fmt.Sprintf(`{"metadata":{"labels":{"%s":"%s"}}}`, key, value))

	for _, c := range t.Clusters() {
		if _, err := c.Kube().CoreV1().Namespaces().Patch(context.TODO(), ns, types.MergePatchType, label, metav1.PatchOptions{}); err != nil {
			return err
		}
	}

	return nil
}
