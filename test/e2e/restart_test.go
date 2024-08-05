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
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/util/traffic"
	kubetest "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/util/retry"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestKmeshRestart(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
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

func restartKmesh(t framework.TestContext) {
	patchOpts := metav1.PatchOptions{}
	patchData := fmt.Sprintf(`{
			"spec": {
				"template": {
					"metadata": {
						"annotations": {
							"kubectl.kubernetes.io/restartedAt": %q
						}
					}
				}
			}
		}`, time.Now().Format(time.RFC3339))
	ds := t.Clusters().Default().Kube().AppsV1().DaemonSets(KmeshNamespace)
	_, err := ds.Patch(context.Background(), KmeshDaemonsetName, types.StrategicMergePatchType, []byte(patchData), patchOpts)
	if err != nil {
		t.Fatal(err)
	}

	if err := retry.UntilSuccess(func() error {
		d, err := ds.Get(context.Background(), KmeshDaemonsetName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if !daemonsetsetComplete(d) {
			return fmt.Errorf("rollout is not yet done")
		}
		return nil
	}, retry.Timeout(60*time.Second), retry.Delay(2*time.Second)); err != nil {
		t.Fatal("failed to wait for Kmesh rollout status for: %v", err)
	}
	if _, err := kubetest.CheckPodsAreReady(kubetest.NewPodFetch(t.AllClusters()[0], KmeshNamespace, "app=kmesh")); err != nil {
		t.Fatal(err)
	}
}

func daemonsetsetComplete(ds *appsv1.DaemonSet) bool {
	return ds.Status.UpdatedNumberScheduled == ds.Status.DesiredNumberScheduled && ds.Status.NumberReady == ds.Status.DesiredNumberScheduled && ds.Status.ObservedGeneration >= ds.Generation
}
