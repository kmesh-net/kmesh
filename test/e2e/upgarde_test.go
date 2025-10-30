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
	"os"
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

// TestKmeshUpgrade performs a rolling upgrade of the kmesh daemonset image
// while continuous traffic is flowing, and asserts there is no traffic disruption.
func TestKmeshUpgrade(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		configureDNSProxy(t, false)

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
			Interval: 50 * time.Millisecond,
		}).Start()

		upgradeKmesh(t)

		g.Stop().CheckSuccessRate(t, 1)

		configureDNSProxy(t, true)
	})
}

// upgradeKmesh patches the daemonset image to the value of KMESH_UPGRADE_IMAGE and waits for rollout.
func upgradeKmesh(t framework.TestContext) {
	newImage := os.Getenv("KMESH_UPGRADE_IMAGE")
	if newImage == "" {
		newImage = "localhost:5000/kmesh"
	}

	patchData := fmt.Sprintf(`{
		"spec": {
			"template": {
				"metadata": {
					"annotations": {
						"kmesh-upgrade-at": %q
					}
				},
				"spec": {
					"containers": [
						{
							"name": "kmesh",
							"image": "%s"
						}
					]
				}
			}
		}
	}`, time.Now().Format(time.RFC3339), newImage)

	patchKmesh_upgrade(t, patchData)
}

// patchKmesh applies a strategic merge patch to the Kmesh DaemonSet and waits for rollout completion.
func patchKmesh_upgrade(t framework.TestContext, patchData string) {
	patchOpts := metav1.PatchOptions{}
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
		if !daemonsetsetComplete_upgrade(d) {
			return fmt.Errorf("rollout is not yet done")
		}
		return nil
	}, retry.Timeout(120*time.Second), retry.Delay(2*time.Second)); err != nil {
		t.Fatalf("failed to wait for Kmesh rollout status: %v", err)
	}

	if _, err := kubetest.CheckPodsAreReady(kubetest.NewPodFetch(t.AllClusters()[0], KmeshNamespace, "app=kmesh")); err != nil {
		t.Fatal(err)
	}
}

// daemonsetsetComplete returns true when DaemonSet rollout appears complete.
func daemonsetsetComplete_upgrade(ds *appsv1.DaemonSet) bool {
	return ds.Status.UpdatedNumberScheduled == ds.Status.DesiredNumberScheduled &&
		ds.Status.NumberReady == ds.Status.DesiredNumberScheduled &&
		ds.Status.ObservedGeneration >= ds.Generation
}
