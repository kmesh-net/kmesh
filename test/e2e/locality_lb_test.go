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

package kmesh

import (
	"context"
	"fmt"
	"testing"
	"time"

	echot "istio.io/istio/pkg/test/echo"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/test/framework/components/echo/common/ports"
	"istio.io/istio/pkg/test/framework/components/echo/deployment"
	"istio.io/istio/pkg/test/framework/components/echo/match"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/util/retry"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestLocalityLB(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		// 1. Create a namespace
		ns, err := namespace.New(t, namespace.Config{
			Prefix: "locality",
			Inject: false,
		})
		if err != nil {
			t.Fatalf("failed to create namespace: %v", err)
		}

		enrollNamespaceOrFail(t, ns.Name())

		// 2. Setup Topology (Label Nodes)
		nodes, err := t.Clusters().Default().Kube().CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			t.Fatalf("failed to list nodes: %v", err)
		}
		if len(nodes.Items) < 2 {
			t.Skip("At least 2 nodes required for Locality LB Failover test")
		}

		var node1, node2 string
		for _, node := range nodes.Items {
			if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
				node2 = node.Name
			} else {
				node1 = node.Name
			}
		}

		if node1 == "" || node2 == "" {
			t.Fatalf("failed to identify worker and control-plane nodes")
		}

		// Use dynamic zone labels
		setNodeLabel(t, node1, "topology.kubernetes.io/region", "region1")
		setNodeLabel(t, node1, "topology.kubernetes.io/zone", "zone1")
		setNodeLabel(t, node1, "topology.kubernetes.io/subzone", "subzone1")
		setNodeLabel(t, node2, "topology.kubernetes.io/region", "region1")
		setNodeLabel(t, node2, "topology.kubernetes.io/zone", "zone2")
		setNodeLabel(t, node2, "topology.kubernetes.io/subzone", "subzone2")

		t.Cleanup(func() {
			removeNodeLabel(t, node1, "topology.kubernetes.io/region")
			removeNodeLabel(t, node1, "topology.kubernetes.io/zone")
			removeNodeLabel(t, node1, "topology.kubernetes.io/subzone")
			removeNodeLabel(t, node2, "topology.kubernetes.io/region")
			removeNodeLabel(t, node2, "topology.kubernetes.io/zone")
			removeNodeLabel(t, node2, "topology.kubernetes.io/subzone")
		})

		// 3. Deploy Client (in zone1) and Server (v1 in zone1, v2 in zone2)
		builder := deployment.New(t).
			WithClusters(t.Clusters()...).
			WithConfig(echo.Config{
				Service:   "client",
				Namespace: ns,
				Ports:     ports.All(),
				Subsets: []echo.SubsetConfig{{
					Replicas: 1,
					Version:  "client",
					Labels:   map[string]string{"app": "client"},
				}},
			}).
			WithConfig(echo.Config{
				Service:   "server",
				Namespace: ns,
				Ports:     ports.All(),
				Subsets: []echo.SubsetConfig{
					{
						Replicas: 1,
						Version:  "v1", // Local to client
						Labels:   map[string]string{"app": "server", "version": "v1"},
					},
					{
						Replicas: 1,
						Version:  "v2", // Remote to client
						Labels:   map[string]string{"app": "server", "version": "v2"},
					},
				},
			})

		echos, err := builder.Build()
		if err != nil {
			t.Fatalf("failed to build apps: %v", err)
		}

		client := match.ServiceName(echo.NamespacedName{Name: "client", Namespace: ns}).GetMatches(echos)[0]
		server := match.ServiceName(echo.NamespacedName{Name: "server", Namespace: ns}).GetMatches(echos)[0]

		// Patch deployments to force node affinity/tolerations
		patchDeployment(t, ns.Name(), "client-client", node1, false)
		patchDeployment(t, ns.Name(), "server-v1", node1, false)
		patchDeployment(t, ns.Name(), "server-v2", node2, true)

		// 4. Apply DestinationRule with Locality LB
		t.ConfigIstio().Eval(ns.Name(), map[string]string{
			"Destination": "server",
		}, `apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: server-dr
spec:
  host: "{{.Destination}}"
  trafficPolicy:
    loadBalancer:
      localityLbSetting:
        enabled: true
      simple: ROUND_ROBIN
`).ApplyOrFail(t)

		// 5. Verification
		t.NewSubTest("locality priority").Run(func(t framework.TestContext) {
			// Traffic from client (zone1) should hit server-v1 (zone1)
			retry.UntilSuccessOrFail(t, func() error {
				_, err := client.Call(echo.CallOptions{
					To:    server,
					Port:  echo.Port{Name: "http"},
					Count: 5,
					Check: check.And(
						check.OK(),
						check.Each(func(r echot.Response) error {
							if r.Version != "v1" {
								return fmt.Errorf("expected version v1, got %s", r.Version)
							}
							return nil
						}),
					),
				})
				return err
			}, retry.Timeout(time.Minute), retry.Delay(time.Second))
		})

		t.NewSubTest("failover").Run(func(t framework.TestContext) {
			// Initial state: server-v1 should be present
			retry.UntilSuccessOrFail(t, func() error {
				_, err := client.Call(echo.CallOptions{
					To:    server,
					Port:  echo.Port{Name: "http"},
					Count: 1,
					Check: check.And(
						check.OK(),
						check.Each(func(r echot.Response) error {
							if r.Version != "v1" {
								return fmt.Errorf("expected version v1, got %s", r.Version)
							}
							return nil
						}),
					),
				})
				return err
			}, retry.Timeout(time.Minute), retry.Delay(time.Second*2))

			// Scale down server-v1
			retry.UntilSuccessOrFail(t, func() error {
				scaler := t.Clusters().Default().Kube().AppsV1().Deployments(ns.Name())
				scale, err := scaler.GetScale(context.TODO(), "server-v1", metav1.GetOptions{})
				if err != nil {
					return err
				}
				scale.Spec.Replicas = 0
				_, err = scaler.UpdateScale(context.TODO(), "server-v1", scale, metav1.UpdateOptions{})
				return err
			}, retry.Timeout(time.Second*30), retry.Delay(time.Second*2))

			// Now traffic should hit server-v2 (zone2)
			retry.UntilSuccessOrFail(t, func() error {
				_, err := client.Call(echo.CallOptions{
					To:    server,
					Port:  echo.Port{Name: "http"},
					Count: 5,
					Check: check.And(
						check.OK(),
						check.Each(func(r echot.Response) error {
							if r.Version != "v2" {
								return fmt.Errorf("expected version v2, got %s", r.Version)
							}
							return nil
						}),
					),
				})
				return err
			}, retry.Timeout(time.Minute*2), retry.Delay(time.Second*5))
		})

	})
}

func setNodeLabel(t framework.TestContext, name string, key string, value string) error {
	label := []byte(fmt.Sprintf(`{"metadata":{"labels":{"%s":"%s"}}}`, key, value))
	for _, c := range t.Clusters() {
		if _, err := c.Kube().CoreV1().Nodes().Patch(context.TODO(), name, types.MergePatchType, label, metav1.PatchOptions{}); err != nil {
			return err
		}
	}
	return nil
}

func patchDeployment(t framework.TestContext, ns, name, nodeName string, includeTolerations bool) {
	var patch string
	if includeTolerations {
		patch = fmt.Sprintf(`{"spec":{"template":{"spec":{"nodeSelector":{"kubernetes.io/hostname":"%s"},"tolerations":[{"key":"node-role.kubernetes.io/control-plane","operator":"Exists","effect":"NoSchedule"}]}}}}`, nodeName)
	} else {
		patch = fmt.Sprintf(`{"spec":{"template":{"spec":{"nodeSelector":{"kubernetes.io/hostname":"%s"}}}}}`, nodeName)
	}

	retry.UntilSuccessOrFail(t, func() error {
		_, err := t.Clusters().Default().Kube().AppsV1().Deployments(ns).Patch(context.TODO(), name, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
		return err
	}, retry.Timeout(time.Second*15))
}

func removeNodeLabel(t framework.TestContext, name string, key string) error {
	label := []byte(fmt.Sprintf(`{"metadata":{"labels":{"%s":null}}}`, key))
	for _, c := range t.Clusters() {
		if _, err := c.Kube().CoreV1().Nodes().Patch(context.TODO(), name, types.MergePatchType, label, metav1.PatchOptions{}); err != nil {
			return err
		}
	}
	return nil
}
