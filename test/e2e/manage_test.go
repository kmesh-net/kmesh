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
	"testing"

	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
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
				// Traffic passes through the waypoint again indicates that the pods are no longer managed by Kmesh again.
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
		err := setPodLabel(t, ns, workload.PodName(), constants.DataplaneModeLabel, DataplaneModeKmesh)
		if err != nil {
			t.Fatalf("failed to enroll workload %s/%s: %v", ns, workload.PodName(), err)
		}
	}
}

func enrollWorkloadsInManagedNsOrFail(t framework.TestContext, ns string, workloads echo.Workloads) {
	for _, workload := range workloads {
		err := setPodLabel(t, ns, workload.PodName(), constants.DataplaneModeLabel, "null")
		if err != nil {
			t.Fatalf("failed to enroll workload %s/%s in managed ns: %v", ns, workload.PodName(), err)
		}
	}
}

func unenrollWorkloadsOrFail(t framework.TestContext, ns string, workloads echo.Workloads) {
	for _, workload := range workloads {
		err := setPodLabel(t, ns, workload.PodName(), constants.DataplaneModeLabel, constants.DataplaneModeNone)
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
