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
	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/test/framework/components/echo/common/ports"
	"istio.io/istio/pkg/test/framework/components/echo/deployment"
	"istio.io/istio/pkg/test/framework/components/echo/match"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/shell"
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

		node1 := nodes.Items[0].Name // worker
		node2 := nodes.Items[1].Name // control-plane

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
		// We use builder but leave out NodeSelector/Tolerations for now,
		// we'll patch them if the framework builder doesn't support them.
		// Actually, let's use the builder but check if it provides a way.
		// If not, we'll patch after build.

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
		// Note: node2 might need tolerations if it's a control-plane node
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

		t.NewSubTest("PreferClose annotation").Run(func(t framework.TestContext) {
			// Create a service with PreferClose annotation
			t.ConfigIstio().Eval(ns.Name(), map[string]string{
				"Service": "server-prefer-close",
			}, `apiVersion: v1
kind: Service
metadata:
  name: "{{.Service}}"
  annotations:
    networking.istio.io/traffic-distribution: PreferClose
spec:
  selector:
    app: server
  ports:
  - name: http
    port: 80
    targetPort: 80
`).ApplyOrFail(t)

			// Traffic should prefer v1 (local zone)
			retry.UntilSuccessOrFail(t, func() error {
				_, err := client.Call(echo.CallOptions{
					Address: "server-prefer-close",
					Port:    echo.Port{ServicePort: 80},
					Scheme:  scheme.HTTP,
					Count:   5,
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
			})
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
			})

			// Scale down server-v1
			_, err := shell.Execute(true, fmt.Sprintf("kubectl scale deployment server-v1 -n %s --replicas=0", ns.Name()))
			if err != nil {
				t.Fatalf("failed to scale down server-v1: %v", err)
			}

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

		t.NewSubTest("internalTrafficPolicy local").Run(func(t framework.TestContext) {
			// Create a service with internalTrafficPolicy: Local
			// We can't easily change the existing service via framework, so we create a new one
			t.ConfigIstio().Eval(ns.Name(), map[string]string{
				"Service": "server-local",
			}, `apiVersion: v1
kind: Service
metadata:
  name: "{{.Service}}"
spec:
  selector:
    app: server
  ports:
  - name: http
    port: 80
    targetPort: 80
  internalTrafficPolicy: Local
`).ApplyOrFail(t)

			// Scale up v1 again
			_, err := shell.Execute(true, fmt.Sprintf("kubectl scale deployment server-v1 -n %s --replicas=1", ns.Name()))
			if err != nil {
				t.Fatalf("failed to scale up server-v1: %v", err)
			}

			// Wait for v1 to be ready
			retry.UntilSuccessOrFail(t, func() error {
				_, err := client.Call(echo.CallOptions{
					To:    server, // Check via old service first to ensure it's up
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
			})

			// Now traffic to server-local should only hit v1 (local node)
			retry.UntilSuccessOrFail(t, func() error {
				_, err := client.Call(echo.CallOptions{
					Address: "server-local",
					Port:    echo.Port{ServicePort: 80},
					Scheme:  scheme.HTTP,
					Count:   5,
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
			})

			// Now scale down v1, it should FAIL because of sidecar/dataplane policy
			// (Assuming node1 has no more server pods)
			_, err = shell.Execute(true, fmt.Sprintf("kubectl scale deployment server-v1 -n %s --replicas=0", ns.Name()))
			if err != nil {
				t.Fatalf("failed to scale down server-v1: %v", err)
			}

			retry.UntilSuccessOrFail(t, func() error {
				_, err := client.Call(echo.CallOptions{
					Address: "server-local",
					Port:    echo.Port{ServicePort: 80},
					Scheme:  scheme.HTTP,
					Count:   1,
				})
				if err == nil {
					return fmt.Errorf("expected call to server-local to fail when no local pods exist")
				}
				return nil
			}, retry.Timeout(time.Minute), retry.Delay(time.Second*2))
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
	patch := fmt.Sprintf(`{"spec":{"template":{"spec":{"nodeSelector":{"kubernetes.io/hostname":"%s"}`, nodeName)
	if includeTolerations {
		patch += `,"tolerations":[{"key":"node-role.kubernetes.io/control-plane","operator":"Exists","effect":"NoSchedule"}]`
	}
	patch += `}}}}`

	_, err := shell.Execute(true, fmt.Sprintf("kubectl patch deployment %s -n %s --patch '%s'", name, ns, patch))
	if err != nil {
		t.Fatalf("failed to patch deployment %s: %v", name, err)
	}
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
