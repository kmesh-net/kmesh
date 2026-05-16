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
	"time"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/util/traffic"
	"istio.io/istio/pkg/test/util/retry"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	kernelNativeModeEnv   = "KMESH_E2E_KERNEL_NATIVE"
	largeScaleReplicasEnv = "KMESH_E2E_SCALE_REPLICAS"
)

func TestKernelNativeRestart(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		requireKernelNativeMode(t)
		requireEnhancedKernelForKernelNative(t)

		// if dns proxy is enabled, when kmesh restarts, the DNS query will fail
		configureDNSProxy(t, false)
		defer configureDNSProxy(t, true)

		src := apps.EnrolledToKmesh[0]
		dst := apps.ServiceWithWaypointAtServiceGranularity
		options := echo.CallOptions{
			To:    dst,
			Count: 1,
			// Determine whether it is managed by Kmesh by passing through Waypoint.
			Check: httpValidator,
			Port: echo.Port{
				Name: "http",
			},
			Retry: echo.Retry{NoRetry: true},
		}

		g := traffic.NewGenerator(t, traffic.Config{
			Source:   src,
			Options:  options,
			Interval: 50 * time.Millisecond,
		}).Start()

		restartKmesh(t)

		g.Stop().CheckSuccessRate(t, 1)
	})
}

func TestKernelNativeLargeScale(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		requireKernelNativeMode(t)
		requireEnhancedKernelForKernelNative(t)

		replicas := int32(getEnvInt(largeScaleReplicasEnv, 10))
		if replicas < 2 {
			t.Skipf("%s must be >= 2 for large-scale test (got %d)", largeScaleReplicasEnv, replicas)
		}

		ns := apps.Namespace.Name()
		srcSelector := fmt.Sprintf("app=%s", EnrolledToKmesh)
		dstSelector := fmt.Sprintf("app=%s", ServiceWithWaypointAtServiceGranularity)

		srcOriginal, err := scaleDeployments(t, ns, srcSelector, replicas)
		if err != nil {
			t.Fatalf("failed to scale source deployments: %v", err)
		}
		defer restoreDeployments(t, ns, srcOriginal)

		dstOriginal, err := scaleDeployments(t, ns, dstSelector, replicas)
		if err != nil {
			t.Fatalf("failed to scale destination deployments: %v", err)
		}
		defer restoreDeployments(t, ns, dstOriginal)

		if err := waitForDeploymentsReady(t, ns, srcOriginal, replicas, 3*time.Minute); err != nil {
			t.Fatalf("source deployments not ready: %v", err)
		}
		if err := waitForDeploymentsReady(t, ns, dstOriginal, replicas, 3*time.Minute); err != nil {
			t.Fatalf("destination deployments not ready: %v", err)
		}

		expectedDstWorkloads := int(replicas) * len(dstOriginal)
		if err := waitForWorkloadCount(t, apps.ServiceWithWaypointAtServiceGranularity, expectedDstWorkloads, 2*time.Minute); err != nil {
			t.Fatalf("unexpected destination workload count: %v", err)
		}

		src := apps.EnrolledToKmesh[0]
		dst := apps.ServiceWithWaypointAtServiceGranularity
		options := echo.CallOptions{
			To:    dst,
			Count: 1,
			Check: httpValidator,
			Port: echo.Port{
				Name: "http",
			},
			Retry: echo.Retry{NoRetry: true},
		}

		g := traffic.NewGenerator(t, traffic.Config{
			Source:   src,
			Options:  options,
			Interval: 25 * time.Millisecond,
		}).Start()

		time.Sleep(20 * time.Second)

		g.Stop().CheckSuccessRate(t, 0.99)
	})
}

type deploymentScale struct {
	name     string
	replicas int32
}

func scaleDeployments(t framework.TestContext, ns, selector string, replicas int32) ([]deploymentScale, error) {
	client := t.Clusters().Default().Kube().AppsV1().Deployments(ns)
	list, err := client.List(context.Background(), metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, fmt.Errorf("no deployments found for selector %q", selector)
	}

	originals := make([]deploymentScale, 0, len(list.Items))
	for i := range list.Items {
		d := &list.Items[i]
		current := int32(1)
		if d.Spec.Replicas != nil {
			current = *d.Spec.Replicas
		}
		originals = append(originals, deploymentScale{name: d.Name, replicas: current})

		d.Spec.Replicas = &replicas
		if _, err := client.Update(context.Background(), d, metav1.UpdateOptions{}); err != nil {
			return originals, err
		}
	}

	return originals, nil
}

func restoreDeployments(t framework.TestContext, ns string, originals []deploymentScale) {
	client := t.Clusters().Default().Kube().AppsV1().Deployments(ns)
	for _, d := range originals {
		replicas := d.replicas
		if replicas < 1 {
			replicas = 1
		}
		dep, err := client.Get(context.Background(), d.name, metav1.GetOptions{})
		if err != nil {
			t.Logf("failed to get deployment %s for restore: %v", d.name, err)
			continue
		}
		dep.Spec.Replicas = &replicas
		if _, err := client.Update(context.Background(), dep, metav1.UpdateOptions{}); err != nil {
			t.Logf("failed to restore deployment %s replicas: %v", d.name, err)
		}
	}
}

func waitForDeploymentsReady(t framework.TestContext, ns string, originals []deploymentScale, replicas int32, timeout time.Duration) error {
	client := t.Clusters().Default().Kube().AppsV1().Deployments(ns)
	for _, d := range originals {
		name := d.name
		if err := retry.UntilSuccess(func() error {
			dep, err := client.Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			if dep.Status.ReadyReplicas < replicas {
				return fmt.Errorf("deployment %s ready replicas %d/%d", name, dep.Status.ReadyReplicas, replicas)
			}
			if dep.Status.UpdatedReplicas < replicas {
				return fmt.Errorf("deployment %s updated replicas %d/%d", name, dep.Status.UpdatedReplicas, replicas)
			}
			return nil
		}, retry.Timeout(timeout), retry.Delay(2*time.Second)); err != nil {
			return err
		}
	}
	return nil
}

func waitForWorkloadCount(t framework.TestContext, instances echo.Instances, expected int, timeout time.Duration) error {
	return retry.UntilSuccess(func() error {
		workloads, err := instances.Workloads()
		if err != nil {
			return err
		}
		if len(workloads) < expected {
			return fmt.Errorf("workloads not ready: got %d, want %d", len(workloads), expected)
		}
		return nil
	}, retry.Timeout(timeout), retry.Delay(2*time.Second))
}
